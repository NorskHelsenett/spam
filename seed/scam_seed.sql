-- SCAM seed data: two realistic clusters with containers, services, ingresses, and routes.
-- Cluster 1: t-prod-001 (tanzu, production workloads)
-- Cluster 2: t-dev-001  (tanzu, development/staging)

-- ============================================================================
-- Cleanup
-- ============================================================================

DELETE from cluster_record;

-- ============================================================================
-- Cluster 1: t-prod-001 — production
-- ============================================================================

-- Containers: nginx ingress controller
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:01Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"ingress-nginx","pod_uid":"11111111-aaaa-bbbb-cccc-111111111111","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"ingress-nginx-controller",
  "pod":"ingress-nginx-controller-7b4c9f8d6-x2k9m","pod_labels":{"app.kubernetes.io/name":"ingress-nginx"},
  "container_kind":"main","container":"controller",
  "registry":"registry.k8s.io","image":"ingress-nginx/controller","tag":"v1.12.1",
  "digest":"sha256:d2fbc4ec70d8aa2050dd91a91506e998765e86c96f32cffb56c503c9c34eed5b",
  "image_spec":"registry.k8s.io/ingress-nginx/controller:v1.12.1",
  "image_id":"registry.k8s.io/ingress-nginx/controller@sha256:d2fbc4ec70d8aa2050dd91a91506e998765e86c96f32cffb56c503c9c34eed5b"
}', NOW() - INTERVAL '5 minutes');

-- Containers: argocd server
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:02Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"argocd","pod_uid":"22222222-aaaa-bbbb-cccc-222222222222","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"argocd-server",
  "pod":"argocd-server-6f8b9c7d5-p3q7r","pod_labels":{"app.kubernetes.io/name":"argocd-server"},
  "container_kind":"main","container":"argocd-server",
  "registry":"quay.io","image":"argoproj/argocd","tag":"v2.14.2",
  "digest":"sha256:018f6444077deb39eac7c549a0ffe68d75da71751dd19899e05d3b60e1c2476f",
  "image_spec":"quay.io/argoproj/argocd:v2.14.2",
  "image_id":"quay.io/argoproj/argocd@sha256:018f6444077deb39eac7c549a0ffe68d75da71751dd19899e05d3b60e1c2476f"
}', NOW() - INTERVAL '5 minutes');

-- Containers: vaultwarden
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:03Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"vaultwarden","pod_uid":"33333333-aaaa-bbbb-cccc-333333333333","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"vaultwarden",
  "pod":"vaultwarden-5f6d7e8c9-k4m2n","pod_labels":{"app":"vaultwarden"},
  "container_kind":"main","container":"vaultwarden",
  "registry":"docker.io","image":"vaultwarden/server","tag":"1.35.4",
  "digest":"sha256:43498a94b22f9563f2a94b53760ab3e710eefc0d0cac2efda4b12b9eb8690664",
  "image_spec":"vaultwarden/server:1.35.4",
  "image_id":"docker.io/vaultwarden/server@sha256:43498a94b22f9563f2a94b53760ab3e710eefc0d0cac2efda4b12b9eb8690664"
}', NOW() - INTERVAL '5 minutes');

-- Containers: postgres (for vaultwarden)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:04Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"vaultwarden","pod_uid":"44444444-aaaa-bbbb-cccc-444444444444","pod_phase":"Running",
  "owner_kind":"StatefulSet","owner":"vaultwarden-db",
  "pod":"vaultwarden-db-0","pod_labels":{"app":"vaultwarden-db"},
  "container_kind":"main","container":"postgres",
  "registry":"docker.io","image":"postgres","tag":"17.4",
  "digest":"sha256:304ab813518754228f9f792f79d6da36359b82d8ecf418096c636725f8c930ad",
  "image_spec":"postgres:17.4",
  "image_id":"docker.io/library/postgres@sha256:304ab813518754228f9f792f79d6da36359b82d8ecf418096c636725f8c930ad"
}', NOW() - INTERVAL '5 minutes');

-- Containers: grafana
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:05Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"monitoring","pod_uid":"55555555-aaaa-bbbb-cccc-555555555555","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"grafana",
  "pod":"grafana-7c8d9e0f1-j5l3n","pod_labels":{"app.kubernetes.io/name":"grafana"},
  "container_kind":"main","container":"grafana",
  "registry":"docker.io","image":"grafana/grafana","tag":"11.6.0",
  "digest":"sha256:62d2b9d20a19714ebfe48d1bb405086081bc602aa053e28cf6d73c7537640dfb",
  "image_spec":"grafana/grafana:11.6.0",
  "image_id":"docker.io/grafana/grafana@sha256:62d2b9d20a19714ebfe48d1bb405086081bc602aa053e28cf6d73c7537640dfb"
}', NOW() - INTERVAL '5 minutes');

-- Containers: prometheus
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:06Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"monitoring","pod_uid":"66666666-aaaa-bbbb-cccc-666666666666","pod_phase":"Running",
  "owner_kind":"StatefulSet","owner":"prometheus",
  "pod":"prometheus-0","pod_labels":{"app.kubernetes.io/name":"prometheus"},
  "container_kind":"main","container":"prometheus",
  "registry":"quay.io","image":"prometheus/prometheus","tag":"v3.3.0",
  "digest":"sha256:339ce86a59413be18d0e445472891d022725b4803fab609069110205e79fb2f1",
  "image_spec":"quay.io/prometheus/prometheus:v3.3.0",
  "image_id":"quay.io/prometheus/prometheus@sha256:339ce86a59413be18d0e445472891d022725b4803fab609069110205e79fb2f1"
}', NOW() - INTERVAL '5 minutes');

-- Containers: spam (this app, running in-cluster)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:07Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"spam","pod_uid":"77777777-aaaa-bbbb-cccc-777777777777","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"spam",
  "pod":"spam-5d6e7f8a9-b2c3d","pod_labels":{"app.kubernetes.io/name":"spam"},
  "container_kind":"main","container":"spam",
  "registry":"ghcr.io","image":"norskhelsenett/spam","tag":"latest",
  "digest":"sha256:e9322615749a68ab71915401abc27969814d4dc6d8e49f195a463d5997de99ab",
  "image_spec":"ghcr.io/norskhelsenett/spam:latest",
  "image_id":"ghcr.io/norskhelsenett/spam@sha256:e9322615749a68ab71915401abc27969814d4dc6d8e49f195a463d5997de99ab"
}', NOW() - INTERVAL '5 minutes');

-- Containers: scam agent
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:08Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "namespace":"scam","pod_uid":"88888888-aaaa-bbbb-cccc-888888888888","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"scam",
  "pod":"scam-4c5d6e7f8-a9b0c","pod_labels":{"app.kubernetes.io/name":"scam"},
  "container_kind":"main","container":"scam",
  "registry":"ghcr.io","image":"norskhelsenett/scam","tag":"latest",
  "digest":"sha256:ca58ba65cc5d35a8b6e5b55c4158189d739f9f531c2eeadbb9eaedab4d0ee6ab",
  "image_spec":"ghcr.io/norskhelsenett/scam:latest",
  "image_id":"ghcr.io/norskhelsenett/scam@sha256:ca58ba65cc5d35a8b6e5b55c4158189d739f9f531c2eeadbb9eaedab4d0ee6ab"
}', NOW() - INTERVAL '5 minutes');

-- Services: prod cluster
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:10Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa","namespace":"vaultwarden","name":"vaultwarden",
  "labels":{"app":"vaultwarden"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.42.10"],"external_ips":[],"external_name":"",
  "selector":{"app":"vaultwarden"},"ports":[{"name":"http","port":80,"target_port":"8080","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:11Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"bbbbbbbb-1111-2222-3333-bbbbbbbbbbbb","namespace":"monitoring","name":"grafana",
  "labels":{"app.kubernetes.io/name":"grafana"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.42.20"],"external_ips":[],"external_name":"",
  "selector":{"app.kubernetes.io/name":"grafana"},"ports":[{"name":"http","port":3000,"target_port":"3000","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:12Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"cccccccc-1111-2222-3333-cccccccccccc","namespace":"argocd","name":"argocd-server",
  "labels":{"app.kubernetes.io/name":"argocd-server"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.42.30"],"external_ips":[],"external_name":"",
  "selector":{"app.kubernetes.io/name":"argocd-server"},"ports":[{"name":"https","port":443,"target_port":"8080","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:13Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"dddddddd-1111-2222-3333-dddddddddddd","namespace":"spam","name":"spam",
  "labels":{"app.kubernetes.io/name":"spam"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.42.40"],"external_ips":[],"external_name":"",
  "selector":{"app.kubernetes.io/name":"spam"},"ports":[{"name":"http","port":8080,"target_port":"8080","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:14Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"eeeeeeee-1111-2222-3333-444444444444","namespace":"vaultwarden","name":"vaultwarden-db",
  "labels":{"app":"vaultwarden-db"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.42.50"],"external_ips":[],"external_name":"",
  "selector":{"app":"vaultwarden-db"},"ports":[{"name":"postgres","port":5432,"target_port":"5432","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:15Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"ffffffff-1111-2222-3333-555555555555","namespace":"monitoring","name":"prometheus",
  "labels":{"app.kubernetes.io/name":"prometheus"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.42.60"],"external_ips":[],"external_name":"",
  "selector":{"app.kubernetes.io/name":"prometheus"},"ports":[{"name":"http","port":9090,"target_port":"9090","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

-- Ingresses: prod cluster (internet-facing)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:20Z","level":"INFO","msg":"INITIAL","kind":"Ingress",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"eeeeeeee-1111-2222-3333-eeeeeeeeeeee","namespace":"vaultwarden","name":"vaultwarden",
  "labels":{"app":"vaultwarden"},"ingress_class":"nginx",
  "rules":[{"host":"vault.example.com","paths":[{"path":"/","path_type":"Prefix","backend_kind":"Service","backend_name":"vaultwarden","backend_port":"80"}]}],
  "tls":[{"hosts":["vault.example.com"],"secret":"vaultwarden-tls"}],
  "lb_ips":["10.0.1.100"],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:21Z","level":"INFO","msg":"INITIAL","kind":"Ingress",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"ffffffff-1111-2222-3333-ffffffffffff","namespace":"monitoring","name":"grafana",
  "labels":{"app.kubernetes.io/name":"grafana"},"ingress_class":"nginx",
  "rules":[{"host":"grafana.example.com","paths":[{"path":"/","path_type":"Prefix","backend_kind":"Service","backend_name":"grafana","backend_port":"3000"}]}],
  "tls":[{"hosts":["grafana.example.com"],"secret":"grafana-tls"}],
  "lb_ips":["10.0.1.100"],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:22Z","level":"INFO","msg":"INITIAL","kind":"Ingress",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"11111111-2222-3333-4444-aaaaaaaaaaaa","namespace":"argocd","name":"argocd-server",
  "labels":{"app.kubernetes.io/name":"argocd-server"},"ingress_class":"nginx",
  "rules":[{"host":"argocd.example.com","paths":[{"path":"/","path_type":"Prefix","backend_kind":"Service","backend_name":"argocd-server","backend_port":"443"}]}],
  "tls":[{"hosts":["argocd.example.com"],"secret":"argocd-tls"}],
  "lb_ips":["10.0.1.100"],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:23Z","level":"INFO","msg":"INITIAL","kind":"Ingress",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"22222222-3333-4444-5555-bbbbbbbbbbbb","namespace":"spam","name":"spam",
  "labels":{"app.kubernetes.io/name":"spam"},"ingress_class":"nginx",
  "rules":[{"host":"spam.sikkerhet.nhn.no","paths":[{"path":"/","path_type":"Prefix","backend_kind":"Service","backend_name":"spam","backend_port":"8080"}]}],
  "tls":[{"hosts":["spam.sikkerhet.nhn.no"],"secret":"spam-tls"}],
  "lb_ips":["10.0.1.100"],"lb_hostnames":[]
}', NOW() - INTERVAL '5 minutes');

-- Ingress with missing/null optional fields (edge case: no lb_ips, no tls, no paths backends)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:24Z","level":"INFO","msg":"INITIAL","kind":"Ingress",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"44444444-5555-6666-7777-dddddddddddd","namespace":"legacy","name":"legacy-app",
  "labels":{},"ingress_class":"nginx",
  "rules":[{"host":"legacy.example.com","paths":[{"path":"/","path_type":"Prefix","backend_kind":"Service","backend_name":"legacy-svc","backend_port":"80"}]}],
  "tls":null,
  "lb_ips":null,"lb_hostnames":null
}', NOW() - INTERVAL '5 minutes');

-- IngressClass
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:00:25Z","level":"INFO","msg":"INITIAL","kind":"IngressClass",
  "cluster":"t-prod-001","cluster_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","environment":"production",
  "uid":"33333333-4444-5555-6666-cccccccccccc","name":"nginx",
  "labels":{},"controller":"k8s.io/ingress-nginx"
}', NOW() - INTERVAL '5 minutes');


-- ============================================================================
-- Cluster 2: t-dev-001 — development
-- ============================================================================

-- Containers: traefik ingress
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:01Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "namespace":"traefik","pod_uid":"99999999-aaaa-bbbb-cccc-999999999999","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"traefik",
  "pod":"traefik-6a7b8c9d0-e1f2g","pod_labels":{"app.kubernetes.io/name":"traefik"},
  "container_kind":"main","container":"traefik",
  "registry":"docker.io","image":"traefik","tag":"v3.3.5",
  "digest":"sha256:104204dadedf5d1284f8ef8f97f705649ac81aa6f7a6c9abf13e2c59245b8abc",
  "image_spec":"traefik:v3.3.5",
  "image_id":"docker.io/library/traefik@sha256:104204dadedf5d1284f8ef8f97f705649ac81aa6f7a6c9abf13e2c59245b8abc"
}', NOW() - INTERVAL '2 minutes');

-- Containers: dev app (frontend)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:02Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "namespace":"app","pod_uid":"aaaaaaaa-bbbb-cccc-dddd-aaaaaaaaaaaa","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"paste",
  "pod":"paste-3b4c5d6e7-f8g9h","pod_labels":{"app":"paste","version":"latest"},
  "container_kind":"main","container":"paste",
  "registry":"ghcr.io","image":"jonasbg/paste","tag":"latest",
  "digest":"sha256:9388b6327d29fa0b5bf1bea24e3c2dee88166ee16547636fbc28438bd2fcd94b",
  "image_spec":"ghcr.io/jonasbg/paste:latest",
  "image_id":"ghcr.io/jonasbg/paste@sha256:9388b6327d29fa0b5bf1bea24e3c2dee88166ee16547636fbc28438bd2fcd94b"
}', NOW() - INTERVAL '2 minutes');

-- Containers: dev app (backend api)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:03Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "namespace":"app","pod_uid":"bbbbbbbb-cccc-dddd-eeee-bbbbbbbbbbbb","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"chase",
  "pod":"chase-2a3b4c5d6-e7f8g","pod_labels":{"app":"chase","version":"latest"},
  "container_kind":"main","container":"chase",
  "registry":"ghcr.io","image":"norskhelsenett/chase","tag":"latest",
  "digest":"sha256:922de8f51c2d375c38e903e725e7e7fe690a75ad63bff8babcd4e8664cdbb259",
  "image_spec":"ghcr.io/norskhelsenett/chase:latest",
  "image_id":"ghcr.io/norskhelsenett/chase@sha256:922de8f51c2d375c38e903e725e7e7fe690a75ad63bff8babcd4e8664cdbb259"
}', NOW() - INTERVAL '2 minutes');

-- Containers: redis (sidecar cache)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:04Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "namespace":"app","pod_uid":"cccccccc-dddd-eeee-ffff-cccccccccccc","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"redis",
  "pod":"redis-1a2b3c4d5-e6f7g","pod_labels":{"app":"redis"},
  "container_kind":"main","container":"redis",
  "registry":"docker.io","image":"redis","tag":"7.4",
  "digest":"sha256:24ea35ee039d7345bef2377611e3b1a615231746de4cfea74c1414575ee56167",
  "image_spec":"redis:7.4",
  "image_id":"docker.io/library/redis@sha256:24ea35ee039d7345bef2377611e3b1a615231746de4cfea74c1414575ee56167"
}', NOW() - INTERVAL '2 minutes');

-- Containers: scam agent (dev cluster)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:05Z","level":"INFO","msg":"INITIAL","kind":"Container",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "namespace":"scam","pod_uid":"dddddddd-eeee-ffff-0000-dddddddddddd","pod_phase":"Running",
  "owner_kind":"Deployment","owner":"scam",
  "pod":"scam-8e9f0a1b2-c3d4e","pod_labels":{"app.kubernetes.io/name":"scam"},
  "container_kind":"main","container":"scam",
  "registry":"ghcr.io","image":"norskhelsenett/scam","tag":"latest",
  "digest":"sha256:ca58ba65cc5d35a8b6e5b55c4158189d739f9f531c2eeadbb9eaedab4d0ee6ab",
  "image_spec":"ghcr.io/norskhelsenett/scam:latest",
  "image_id":"ghcr.io/norskhelsenett/scam@sha256:ca58ba65cc5d35a8b6e5b55c4158189d739f9f531c2eeadbb9eaedab4d0ee6ab"
}', NOW() - INTERVAL '2 minutes');

-- Services: dev cluster
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:10Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "uid":"eeeeeeee-4444-5555-6666-eeeeeeeeeeee","namespace":"app","name":"paste",
  "labels":{"app":"paste"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.50.10"],"external_ips":[],"external_name":"",
  "selector":{"app":"paste"},"ports":[{"name":"http","port":80,"target_port":"3000","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '2 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:11Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "uid":"ffffffff-4444-5555-6666-ffffffffffff","namespace":"app","name":"chase",
  "labels":{"app":"chase"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.50.20"],"external_ips":[],"external_name":"",
  "selector":{"app":"chase"},"ports":[{"name":"http","port":8080,"target_port":"8080","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '2 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:12Z","level":"INFO","msg":"INITIAL","kind":"Service",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "uid":"aaaaaaaa-5555-6666-7777-111111111111","namespace":"app","name":"redis",
  "labels":{"app":"redis"},"service_type":"ClusterIP",
  "cluster_ips":["10.96.50.30"],"external_ips":[],"external_name":"",
  "selector":{"app":"redis"},"ports":[{"name":"redis","port":6379,"target_port":"6379","protocol":"TCP"}],
  "lb_ips":[],"lb_hostnames":[]
}', NOW() - INTERVAL '2 minutes');

-- Traefik IngressRoute: dev cluster (internet-facing)
INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:20Z","level":"INFO","msg":"INITIAL","kind":"IngressRoute",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "api_version":"traefik.io/v1",
  "uid":"bbbbbbbb-5555-6666-7777-222222222222","namespace":"app","name":"paste",
  "labels":{"app":"paste"},"entry_points":["websecure"],
  "hosts":["dev.example.com"],
  "tls_secret":"dev-tls",
  "backends":[{"namespace":"app","name":"paste"}]
}', NOW() - INTERVAL '2 minutes');

INSERT INTO cluster_record (id, data, received_at) VALUES (gen_random_uuid(), '{
  "time":"2026-04-16T08:01:21Z","level":"INFO","msg":"INITIAL","kind":"IngressRoute",
  "cluster":"t-dev-001","cluster_id":"d1e2f3a4-b5c6-7890-1234-abcdef123456","environment":"development",
  "api_version":"traefik.io/v1",
  "uid":"cccccccc-5555-6666-7777-333333333333","namespace":"app","name":"chase",
  "labels":{"app":"chase"},"entry_points":["websecure"],
  "hosts":["api.dev.example.com"],
  "tls_secret":"dev-api-tls",
  "backends":[{"namespace":"app","name":"chase"}]
}', NOW() - INTERVAL '2 minutes');
