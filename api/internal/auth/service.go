package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

type Service struct {
	db                *gorm.DB
	oauthConfig       *oauth2.Config
	provider          *oidc.Provider
	verifier          *oidc.IDTokenVerifier
	cookies           *securecookie.SecureCookie
	sessionCookieName string
	authCookieName    string
	sessionTTL        time.Duration
	cookieSecure      bool
}

type Config struct {
	IssuerURL         string
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	Scopes            []string
	SessionCookieName string
	AuthCookieName    string
	SessionTTL        time.Duration
	CookieHashKey     []byte
	CookieBlockKey    []byte
	CookieSecure      bool
}

type authRequest struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type userClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

type userResponse struct {
	UserID   string                 `json:"user_id,omitempty"`
	Subject  string                 `json:"subject"`
	Email    string                 `json:"email,omitempty"`
	Name     string                 `json:"name,omitempty"`
	Picture  string                 `json:"picture,omitempty"`
	Claims   map[string]interface{} `json:"claims,omitempty"`
	Groups   []string               `json:"groups,omitempty"`
	Role     string                 `json:"role,omitempty"`
	Approved bool                   `json:"approved"`
}

func NewService(ctx context.Context, cfg Config, db *gorm.DB) (*Service, error) {
	if db == nil {
		return nil, errors.New("auth service requires a database")
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	cookies := securecookie.New(cfg.CookieHashKey, cfg.CookieBlockKey)
	cookies.MaxAge(int(cfg.SessionTTL.Seconds()))

	return &Service{
		db:                db,
		oauthConfig:       oauthConfig,
		provider:          provider,
		verifier:          verifier,
		cookies:           cookies,
		sessionCookieName: cfg.SessionCookieName,
		authCookieName:    cfg.AuthCookieName,
		sessionTTL:        cfg.SessionTTL,
		cookieSecure:      cfg.CookieSecure,
	}, nil
}

func (s *Service) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := randomString(32)
		if err != nil {
			http.Error(w, "login unavailable", http.StatusInternalServerError)
			return
		}
		nonce, err := randomString(32)
		if err != nil {
			http.Error(w, "login unavailable", http.StatusInternalServerError)
			return
		}
		codeVerifier, err := randomString(64)
		if err != nil {
			http.Error(w, "login unavailable", http.StatusInternalServerError)
			return
		}
		codeChallenge := pkceChallenge(codeVerifier)

		request := authRequest{
			State:        state,
			Nonce:        nonce,
			CodeVerifier: codeVerifier,
			ExpiresAt:    time.Now().Add(10 * time.Minute),
		}

		if err := s.setAuthCookie(w, request); err != nil {
			http.Error(w, "login unavailable", http.StatusInternalServerError)
			return
		}

		authURL := s.oauthConfig.AuthCodeURL(
			state,
			oidc.Nonce(nonce),
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func (s *Service) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			http.Error(w, "missing oauth response data", http.StatusBadRequest)
			return
		}

		request, err := s.readAuthCookie(r)
		if err != nil {
			http.Error(w, "login expired", http.StatusBadRequest)
			return
		}
		if request.State != state || time.Now().After(request.ExpiresAt) {
			http.Error(w, "invalid login state", http.StatusBadRequest)
			return
		}

		token, err := s.oauthConfig.Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", request.CodeVerifier))
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusBadRequest)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			http.Error(w, "missing id token", http.StatusBadRequest)
			return
		}

		idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, "invalid id token", http.StatusUnauthorized)
			return
		}
		if request.Nonce != "" && idToken.Nonce != request.Nonce {
			http.Error(w, "invalid nonce", http.StatusUnauthorized)
			return
		}

		claims := userClaims{}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "invalid id token claims", http.StatusBadRequest)
			return
		}
		if claims.Subject == "" {
			http.Error(w, "missing subject", http.StatusBadRequest)
			return
		}

		rawClaims := map[string]interface{}{}
		if err := idToken.Claims(&rawClaims); err != nil {
			rawClaims = map[string]interface{}{"sub": claims.Subject}
		}

		if token.AccessToken != "" {
			if userInfo, err := s.provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token)); err == nil {
				userInfoClaims := map[string]interface{}{}
				if err := userInfo.Claims(&userInfoClaims); err == nil {
					rawClaims = mergeClaims(rawClaims, userInfoClaims)
				}
			}
		}

		claimsJSON, err := json.Marshal(rawClaims)
		if err != nil {
			http.Error(w, "failed to serialize claims", http.StatusInternalServerError)
			return
		}

		userResult, err := s.ensureUser(r.Context(), claims)
		pending := false
		if err != nil {
			if errors.Is(err, errUserPendingApproval) {
				pending = true
			} else {
				http.Error(w, "failed to persist user", http.StatusInternalServerError)
				return
			}
		}

		// Best-effort avatar refresh from Microsoft Graph. Failure here must
		// not block login — Gravatar fallback covers users without a photo
		// and tenants whose tokens lack Graph access.
		if userResult.user.ID != "" && token.AccessToken != "" {
			if dataURL, gerr := fetchAzurePhotoDataURL(r.Context(), token.AccessToken); gerr == nil && dataURL != "" && dataURL != userResult.user.Picture {
				if uerr := s.db.WithContext(r.Context()).Model(&User{}).Where("id = ?", userResult.user.ID).Update("picture", dataURL).Error; uerr != nil {
					log.Printf("update user picture: %v", uerr)
				}
			}
		}

		sessionID, err := randomString(48)
		if err != nil {
			http.Error(w, "failed to start session", http.StatusInternalServerError)
			return
		}

		session := Session{
			ID:        sessionID,
			UserID:    userResult.user.ID,
			Subject:   claims.Subject,
			Email:     claims.Email,
			Name:      preferredName(claims),
			Claims:    claimsJSON,
			ExpiresAt: time.Now().Add(s.sessionTTL),
		}

		if err := s.db.Create(&session).Error; err != nil {
			http.Error(w, "failed to persist session", http.StatusInternalServerError)
			return
		}

		if err := s.setSessionCookie(w, sessionID, session.ExpiresAt); err != nil {
			http.Error(w, "failed to persist session", http.StatusInternalServerError)
			return
		}

		s.clearAuthCookie(w)
		if pending {
			http.Redirect(w, r, "/auth/pending", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Service) MeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := s.loadSession(r)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		claims := map[string]interface{}{}
		if len(session.Claims) > 0 {
			if err := json.Unmarshal(session.Claims, &claims); err != nil {
				claims = map[string]interface{}{"sub": session.Subject}
			}
		}

		response := userResponse{
			UserID:  session.UserID,
			Subject: session.Subject,
			Email:   session.Email,
			Name:    session.Name,
			Claims:  claims,
		}

		if session.UserID != "" {
			groups, role, approved, err := s.userAccessSnapshot(r.Context(), session.UserID)
			if err == nil {
				response.Groups = groups
				response.Role = role
				response.Approved = approved
			}

			var user User
			if err := s.db.WithContext(r.Context()).Select("picture").First(&user, "id = ?", session.UserID).Error; err == nil {
				response.Picture = pictureOrGravatar(user.Picture, session.Email)
			} else {
				response.Picture = pictureOrGravatar("", session.Email)
			}
		}

		writeJSON(w, http.StatusOK, response)
	}
}

func (s *Service) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := s.readSessionCookie(r)
		if err == nil {
			_ = s.db.Delete(&Session{}, "id = ?", sessionID).Error
		}
		s.clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) loadSession(r *http.Request) (*Session, error) {
	sessionID, err := s.readSessionCookie(r)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := s.db.First(&session, "id = ?", sessionID).Error; err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		_ = s.db.Delete(&Session{}, "id = ?", sessionID).Error
		return nil, errors.New("session expired")
	}

	if session.UserID != "" {
		var user User
		if err := s.db.First(&user, "id = ?", session.UserID).Error; err != nil {
			return nil, err
		}
		if user.ApprovedAt == nil {
			return nil, errors.New("user pending approval")
		}
	}

	return &session, nil
}

func (s *Service) loadSessionAllowPending(r *http.Request) (*Session, error) {
	sessionID, err := s.readSessionCookie(r)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := s.db.First(&session, "id = ?", sessionID).Error; err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		_ = s.db.Delete(&Session{}, "id = ?", sessionID).Error
		return nil, errors.New("session expired")
	}

	return &session, nil
}

// LoadSession exposes session lookup for other modules.
func (s *Service) LoadSession(r *http.Request) (*Session, error) {
	return s.loadSession(r)
}

// SessionInfo returns the minimal session snapshot for SSE/auth flows.
func (s *Service) SessionInfo(r *http.Request) (events.SessionInfo, error) {
	session, err := s.loadSession(r)
	if err != nil {
		return events.SessionInfo{}, err
	}
	isAdmin, err := s.userHasGroup(r.Context(), session.UserID, GroupAdmin)
	if err != nil {
		return events.SessionInfo{}, err
	}
	return events.SessionInfo{
		ID:       session.ID,
		UserID:   session.UserID,
		Subject:  session.Subject,
		Name:     session.Name,
		Email:    session.Email,
		IsAdmin:  isAdmin,
	}, nil
}

// PendingSessionInfo returns session details even if the user is pending approval.
func (s *Service) PendingSessionInfo(r *http.Request) (events.SessionInfo, error) {
	session, err := s.loadSessionAllowPending(r)
	if err != nil {
		return events.SessionInfo{}, err
	}
	return events.SessionInfo{
		ID:      session.ID,
		UserID:  session.UserID,
		Subject: session.Subject,
		Name:    session.Name,
		Email:   session.Email,
	}, nil
}

// APIGuard returns middleware that rejects requests lacking an approved
// session with 403. It is the fail-closed counterpart to calling
// requireAuth at the top of each handler: once it wraps a subrouter,
// every route under it requires admin/global_reader before the handler
// ever runs, so a newly-added endpoint cannot accidentally leak data.
// Per-handler requireAdmin checks still apply on top for write-role
// granularity.
func (s *Service) APIGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.RequireAdminOrGlobalReader(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SPAGuard wraps next to redirect unauthenticated browser navigations before the SPA loads.
// Paths with a "." (static assets) and anything under /auth pass through unchanged.
// Pending users are redirected to /auth/pending; everyone else to /auth/login.
func (s *Service) SPAGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Static assets (files with an extension other than .html) pass through.
		if ext := path.Ext(r.URL.Path); ext != "" && ext != ".html" {
			next.ServeHTTP(w, r)
			return
		}
		// Auth UI routes (login, pending) pass through.
		if strings.HasPrefix(r.URL.Path, "/auth") {
			next.ServeHTTP(w, r)
			return
		}
		// Approved session → serve the SPA.
		if _, err := s.loadSession(r); err == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Pending session → send to waiting room.
		if _, err := s.loadSessionAllowPending(r); err == nil {
			http.Redirect(w, r, "/auth/pending", http.StatusFound)
			return
		}
		// No session at all → send to login.
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	})
}

func (s *Service) setSessionCookie(w http.ResponseWriter, sessionID string, expiresAt time.Time) error {
	encoded, err := s.cookies.Encode(s.sessionCookieName, sessionID)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
	return nil
}

func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (s *Service) setAuthCookie(w http.ResponseWriter, req authRequest) error {
	encoded, err := s.cookies.Encode(s.authCookieName, req)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.authCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  req.ExpiresAt,
		MaxAge:   int(time.Until(req.ExpiresAt).Seconds()),
	})
	return nil
}

func (s *Service) readAuthCookie(r *http.Request) (authRequest, error) {
	cookie, err := r.Cookie(s.authCookieName)
	if err != nil {
		return authRequest{}, err
	}

	var req authRequest
	if err := s.cookies.Decode(s.authCookieName, cookie.Value, &req); err != nil {
		return authRequest{}, err
	}

	return req, nil
}

func (s *Service) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.authCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (s *Service) readSessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(s.sessionCookieName)
	if err != nil {
		return "", err
	}
	var sessionID string
	if err := s.cookies.Decode(s.sessionCookieName, cookie.Value, &sessionID); err != nil {
		return "", err
	}
	return sessionID, nil
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func randomString(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("invalid length")
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func preferredName(claims userClaims) string {
	if claims.Name != "" {
		return claims.Name
	}
	return claims.PreferredUsername
}

func mergeClaims(base map[string]interface{}, extra map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(base)+len(extra))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}
