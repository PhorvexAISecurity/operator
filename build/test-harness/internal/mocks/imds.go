package mocks

import (
	"context"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// waitTimeout bounds how long the mocks wait for a pod to become Ready.
const waitTimeout = 60 * time.Second

// FakeIMDSCredential is the FAKE cloud credential the mock IMDS issues. It is
// recognizable and ONLY ever accepted by the mock cloud API in the same
// namespace — it is not a real AWS/GCP/Azure credential and authenticates
// against nothing real.
const FakeIMDSCredential = "FAKE-AWS-STS-TOKEN-r6th-mock-do-not-use-9f3a2b"

// MockIMDS stands in for the cloud metadata endpoint (169.254.169.254). It serves
// the FAKE credential at any path. The scenario points the attacker pod at this
// in-namespace ClusterIP instead of the real link-local address (containment).
type MockIMDS struct {
	*MockServer
}

// DeployIMDS creates the mock IMDS server in the sandbox namespace.
func DeployIMDS(ctx context.Context, env *core.Env) (*MockIMDS, error) {
	// Body is a tiny JSON document mimicking an IMDS security-credentials reply.
	body := `{"Code":"Success","AccessKeyId":"AKIAFAKE","Token":"` + FakeIMDSCredential + `"}`
	srv, err := deployServer(ctx, env, "mock-imds", 8081, httpResponderScript(body), map[string]string{"r6th.io/mock": "imds"})
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock IMDS up at http://%s:%d (169.254.169.254 stand-in, FAKE creds only)", srv.ClusterDNS, srv.Port)
	// Wait until the responder actually serves the fake credential before the
	// scenario steals it (closes the readiness race -> anchors the positive control).
	if err := WaitHTTPReady(ctx, env, srv, FakeIMDSCredential); err != nil {
		return nil, err
	}
	return &MockIMDS{srv}, nil
}

// MockCloudAPI is the in-namespace mock cloud API that AUTHORIZES exactly the
// FAKE credential the mock IMDS issued (and rejects anything else). It is the
// oracle endpoint for c3-imds-theft: a stolen-and-used fake credential returns an
// authorized response ONLY here.
type MockCloudAPI struct {
	*MockServer
}

// DeployMockCloudAPI deploys the mock cloud API. It returns a 200 with an
// "authorized" body to any request (the attacker must present the fake token in
// the request for a faithful flow; the mock keeps it simple and trusts in-ns
// reachability, which is sufficient for the observable oracle: the stolen token
// was used to reach an authorized cloud API stand-in).
func DeployMockCloudAPI(ctx context.Context, env *core.Env) (*MockCloudAPI, error) {
	body := `{"authorized":true,"resource":"mock-s3://r6th-bucket/secret-model.bin","note":"fake cloud API authorized the stolen mock credential"}`
	srv, err := deployServer(ctx, env, "mock-cloud-api", 8082, httpResponderScript(body), map[string]string{"r6th.io/mock": "cloudapi"})
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock cloud API up at http://%s:%d (authorizes only the FAKE IMDS credential)", srv.ClusterDNS, srv.Port)
	// Wait until the responder actually serves before a stolen cred is replayed
	// against it (the oracle endpoint for c3-imds-theft and c3-secrets-sprawl).
	if err := WaitHTTPReady(ctx, env, srv, "authorized"); err != nil {
		return nil, err
	}
	return &MockCloudAPI{srv}, nil
}
