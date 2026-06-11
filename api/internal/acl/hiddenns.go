package acl

import "context"

// hiddenNamespaceClause, when set, compiles the admin-curated hidden-
// namespace patterns into a WHERE fragment over the given namespace
// column. The acl clause builders carry no DB handle, so the server
// main wires this to hiddenns.Clause at boot. Nil (e.g. in tests or
// the worker) means no namespace filtering.
//
// It is consulted only on the cluster→image inheritance branch, and
// only for subjects that aren't admin/global_reader — those return
// Unrestricted before the branch is compiled. Hidden namespaces trim
// noise (platform agents, operators) from regular users' image and
// vuln views; they are not an access-control boundary.
var hiddenNamespaceClause func(ctx context.Context, col string) (string, []any)

// SetHiddenNamespaceClause registers the hidden-namespace fragment
// provider. Called once from main before the router starts serving.
func SetHiddenNamespaceClause(fn func(ctx context.Context, col string) (string, []any)) {
	hiddenNamespaceClause = fn
}

func hiddenNamespaceExclusion(ctx context.Context, col string) (string, []any) {
	if hiddenNamespaceClause == nil {
		return "", nil
	}
	return hiddenNamespaceClause(ctx, col)
}
