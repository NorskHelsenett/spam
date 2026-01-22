# Spam Application Helm Chart

This Helm chart deploys the Spam application with PostgreSQL and OIDC authentication support.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- An OIDC provider (e.g., Keycloak, Auth0, Okta, Azure AD)

## Configuration

### Required Secrets

The application requires several secrets for OIDC authentication and session management. You can either:

1. **Let Helm auto-generate the secrets** (recommended for development)
2. **Create secrets manually** (recommended for production)

### Option 1: Auto-Generated Secrets (Development)

Set the values in `values.yaml`:

```yaml
appSecret:
  enabled: true
  oidc:
    issuerUrl: "https://auth.example.com"
    clientId: "your-client-id"
    clientSecret: "your-client-secret"
    redirectUrl: "https://spam.example.com/api/auth/callback"
    scopes: "openid profile email"
```

The session cookie keys will be automatically generated on first installation.

### Option 2: Manual Secret Creation (Production)

#### Step 1: Generate Random Keys

```bash
# Generate HMAC key for cookie signing (≥32 bytes)
SESSION_COOKIE_HASH_KEY=$(openssl rand -base64 32)

# Generate AES key for cookie encryption (32 bytes recommended)
SESSION_COOKIE_BLOCK_KEY=$(openssl rand -base64 32)

echo "SESSION_COOKIE_HASH_KEY: $SESSION_COOKIE_HASH_KEY"
echo "SESSION_COOKIE_BLOCK_KEY: $SESSION_COOKIE_BLOCK_KEY"
```

#### Step 2: Create Kubernetes Secret

```bash
kubectl create secret generic spam-app-secret \
  --from-literal=OIDC_ISSUER_URL='https://auth.example.com' \
  --from-literal=OIDC_CLIENT_ID='your-client-id' \
  --from-literal=OIDC_CLIENT_SECRET='your-client-secret' \
  --from-literal=OIDC_REDIRECT_URL='https://spam.example.com/api/auth/callback' \
  --from-literal=OIDC_SCOPES='openid profile email' \
  --from-literal=SESSION_COOKIE_HASH_KEY="$SESSION_COOKIE_HASH_KEY" \
  --from-literal=SESSION_COOKIE_BLOCK_KEY="$SESSION_COOKIE_BLOCK_KEY" \
  --namespace spam
```

#### Step 3: Reference Existing Secret

In `values.yaml`:

```yaml
appSecret:
  enabled: true
  existingSecret: "spam-app-secret"
```

### Using Sealed Secrets (Recommended for GitOps)

If you're using [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets):

```bash
# Create a temporary secret file
cat <<EOF > app-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: spam-app-secret
  namespace: spam
type: Opaque
stringData:
  OIDC_ISSUER_URL: "https://auth.example.com"
  OIDC_CLIENT_ID: "your-client-id"
  OIDC_CLIENT_SECRET: "your-client-secret"
  OIDC_REDIRECT_URL: "https://spam.example.com/api/auth/callback"
  OIDC_SCOPES: "openid profile email"
  SESSION_COOKIE_HASH_KEY: "$(openssl rand -base64 32)"
  SESSION_COOKIE_BLOCK_KEY: "$(openssl rand -base64 32)"
EOF

# Seal the secret
kubeseal --format yaml < app-secret.yaml > sealed-app-secret.yaml

# Clean up the temporary file
rm app-secret.yaml

# Apply the sealed secret
kubectl apply -f sealed-app-secret.yaml
```

### Using External Secrets Operator

If you're using [External Secrets Operator](https://external-secrets.io/):

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: spam-app-secret
  namespace: spam
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: spam-app-secret
    creationPolicy: Owner
  data:
    - secretKey: OIDC_ISSUER_URL
      remoteRef:
        key: spam/oidc
        property: issuerUrl
    - secretKey: OIDC_CLIENT_ID
      remoteRef:
        key: spam/oidc
        property: clientId
    - secretKey: OIDC_CLIENT_SECRET
      remoteRef:
        key: spam/oidc
        property: clientSecret
    - secretKey: OIDC_REDIRECT_URL
      remoteRef:
        key: spam/oidc
        property: redirectUrl
    - secretKey: OIDC_SCOPES
      remoteRef:
        key: spam/oidc
        property: scopes
    - secretKey: SESSION_COOKIE_HASH_KEY
      remoteRef:
        key: spam/session
        property: hashKey
    - secretKey: SESSION_COOKIE_BLOCK_KEY
      remoteRef:
        key: spam/session
        property: blockKey
```

## Environment Variables Reference

The application uses the following environment variables:

### Required Variables (via appSecret)

| Variable | Description | Example |
|----------|-------------|---------|
| `OIDC_ISSUER_URL` | OIDC provider URL | `https://auth.example.com` |
| `OIDC_CLIENT_ID` | OIDC client ID | `spam-web` |
| `OIDC_CLIENT_SECRET` | OIDC client secret | `your-secret-here` |
| `OIDC_REDIRECT_URL` | OAuth callback URL | `https://spam.example.com/api/auth/callback` |
| `OIDC_SCOPES` | OAuth scopes | `openid profile email` |
| `SESSION_COOKIE_HASH_KEY` | HMAC key for cookies (base64, ≥32 bytes) | Auto-generated |
| `SESSION_COOKIE_BLOCK_KEY` | AES key for cookies (base64, 16/24/32 bytes) | Auto-generated |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HTTP_PORT` | HTTP server port | `8080` |
| `SESSION_COOKIE_NAME` | Session cookie name | `spam_session` |
| `AUTH_STATE_COOKIE_NAME` | Auth state cookie name | `spam_oidc` |
| `SESSION_TTL` | Session duration | `8h` |
| `COOKIE_SECURE` | Require HTTPS for cookies | `true` |

### PostgreSQL Variables (when postgresql.enabled=true)

These are automatically configured:

| Variable | Value |
|----------|-------|
| `POSTGRES_HOST` | `{{ .Release.Name }}-postgresql` |
| `POSTGRES_PORT` | `5432` |
| `POSTGRES_DB` | `spam` |
| `POSTGRES_USER` | `spam` |
| `POSTGRES_PASSWORD` | From secret |
| `POSTGRES_SSLMODE` | `disable` |

## Installation

### Basic Installation

```bash
helm install spam .helm/ \
  --namespace spam \
  --create-namespace \
  --set appSecret.oidc.issuerUrl="https://auth.example.com" \
  --set appSecret.oidc.clientId="your-client-id" \
  --set appSecret.oidc.clientSecret="your-client-secret" \
  --set appSecret.oidc.redirectUrl="https://spam.example.com/api/auth/callback" \
  --set postgresql.enabled=true
```

### With Custom Values

```bash
helm install spam .helm/ \
  --namespace spam \
  --create-namespace \
  --values my-values.yaml
```

### Using Existing Secret

```bash
# First create the secret (see above)
kubectl create secret generic spam-app-secret ...

# Then install with existing secret
helm install spam .helm/ \
  --namespace spam \
  --create-namespace \
  --set appSecret.existingSecret="spam-app-secret" \
  --set postgresql.enabled=true
```

## Upgrade

```bash
helm upgrade spam .helm/ \
  --namespace spam \
  --values my-values.yaml
```

## Uninstall

```bash
helm uninstall spam --namespace spam
```

## Security Notes

### Session Cookie Keys

The application uses **two separate keys** for session cookies:

1. **SESSION_COOKIE_HASH_KEY** (HMAC/Signing Key)
   - Used for authentication/integrity verification
   - Ensures cookies haven't been tampered with
   - Must be ≥32 bytes (base64 encoded)

2. **SESSION_COOKIE_BLOCK_KEY** (Encryption Key)
   - Used for confidentiality/encryption
   - Encrypts cookie contents so they can't be read
   - Must be exactly 16, 24, or 32 bytes (base64 encoded)

**Both keys are required** and serve different cryptographic purposes. This follows the security best practice of **key separation** - using different keys for signing and encryption.

### Key Rotation

To rotate session keys:

1. Generate new keys:
   ```bash
   NEW_HASH_KEY=$(openssl rand -base64 32)
   NEW_BLOCK_KEY=$(openssl rand -base64 32)
   ```

2. Update the secret:
   ```bash
   kubectl patch secret spam-app-secret -n spam --type='json' \
     -p="[{\"op\": \"replace\", \"path\": \"/data/SESSION_COOKIE_HASH_KEY\", \"value\":\"$(echo -n $NEW_HASH_KEY | base64)\"}]"
   
   kubectl patch secret spam-app-secret -n spam --type='json' \
     -p="[{\"op\": \"replace\", \"path\": \"/data/SESSION_COOKIE_BLOCK_KEY\", \"value\":\"$(echo -n $NEW_BLOCK_KEY | base64)\"}]"
   ```

3. Restart pods:
   ```bash
   kubectl rollout restart deployment/spam -n spam
   ```

**Note:** Rotating keys will invalidate all existing user sessions.

## Troubleshooting

### Check Secret Values

```bash
# View all secret keys
kubectl get secret spam-app-secret -n spam -o json | jq '.data | keys'

# Decode a specific value
kubectl get secret spam-app-secret -n spam -o json | \
  jq -r '.data.OIDC_ISSUER_URL' | base64 -d
```

### Check Pod Logs

```bash
kubectl logs -n spam deployment/spam
```

### Verify Environment Variables

```bash
kubectl exec -n spam deployment/spam -- env | grep -E "OIDC|SESSION|POSTGRES"
```
