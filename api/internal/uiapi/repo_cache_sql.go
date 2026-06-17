package uiapi

// repoCacheSQL exposes the kv_store repo:cache:{repoID} entries
// (assets.RepoCacheData) with the column shape of the legacy repo_caches
// table, so queries can keep their rc.* references. repo_caches itself was
// transient (d371158→65632a7) — fresh installs never have it and nothing
// writes it — so any query still reading it returns no rows. Expired cache
// entries are filtered the same way cache.PostgresStore.Get does.
const repoCacheSQL = `(
	SELECT
		substring(kv.key from 12) AS repo_id,
		COALESCE(kv.value->>'details_json', '') AS details_json,
		COALESCE(kv.value->>'readme_content', '') AS readme_content,
		COALESCE(kv.value->>'commits_json', '') AS commits_json,
		COALESCE(kv.value->>'contributors_json', '') AS contributors_json,
		(kv.value->>'synced_at')::timestamptz AS synced_at
	FROM kv_store kv
	WHERE kv.key LIKE 'repo:cache:%'
	  AND (kv.expires_at IS NULL OR kv.expires_at > now())
)`
