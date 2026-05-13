package runner

import (
	"context"
	"strings"

	"github.com/NorskHelsenett/spam/internal/cache"
)

func invalidateRepoMetadataCache(ctx context.Context, c cache.Store, repoID string) {
	repoID = strings.TrimSpace(repoID)
	if c == nil || repoID == "" {
		return
	}
	_ = cache.Delete(ctx, c, "repo:metadata:"+repoID)
}
