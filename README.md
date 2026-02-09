# SPAM - Software Package Asset Management

A comprehensive and secure dashboard for managing all your third party component in your organization based around SBOM (Software Bill of Materials)

## Featureset
- OIDC login
- SBOM injection
- HA
- Kubernetes helm charts
- CVE database and alerts
- Plug and play git repo ingestion using OIDC login features and not API tokens

Cleanup all jobs

```bash
kubectl delete jobs --all -n spam
```

start `mocc with mocc --host 0.0.0.0 --users users.yaml`
