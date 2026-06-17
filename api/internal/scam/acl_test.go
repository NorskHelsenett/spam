package scam

import (
	"net/http/httptest"
	"testing"

	"github.com/NorskHelsenett/spam/internal/acl"
)

func TestClusterACLFilter_GlobalReaderUnrestricted(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/clusters/summary", nil)
	req = req.WithContext(acl.WithSubject(req.Context(), acl.Subject{
		UserID:         "u1",
		IsGlobalReader: true,
	}))

	frag, args, deny := clusterACLFilterCol(req, "cs.cluster_id")
	if deny {
		t.Fatalf("global_reader must not be denied")
	}
	if frag != "TRUE" {
		t.Fatalf("global_reader should get unrestricted fragment, got %q", frag)
	}
	if len(args) != 0 {
		t.Fatalf("global_reader should not bind ACL args, got %#v", args)
	}
}

func TestCanReadCluster_GlobalReader(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/cluster/prod", nil)
	req = req.WithContext(acl.WithSubject(req.Context(), acl.Subject{
		UserID:         "u1",
		IsGlobalReader: true,
	}))

	ok, err := canReadCluster(req, nil, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("global_reader should be able to read any cluster")
	}
}
