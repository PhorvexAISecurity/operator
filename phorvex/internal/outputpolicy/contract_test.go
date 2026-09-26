package outputpolicy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const testPodUID = "11111111-1111-4111-8111-111111111111"
const testCMUID = "22222222-2222-4222-8222-222222222222"

func testPolicyObjects() (*corev1.Pod, *corev1.ConfigMap) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: "fixture", UID: types.UID(testPodUID),
		Annotations: map[string]string{PodConfigMapAnnotation: "phorvex-output-policy-fixture",
			PodRuleSHAAnnotation:  RuleSHA256(testPodUID),
			PodProxySHAAnnotation: strings.Repeat("a", 64), PodSupportSHAAnnotation: strings.Repeat("b", 64)}}}
	active := Activation{Version: 1, RuleID: RuleID, ConfigMapUID: testCMUID}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "phorvex-output-policy-fixture", UID: types.UID(testCMUID), ResourceVersion: "5",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID, Controller: ptr(true)}}},
		Data: map[string]string{RuleKey: string(RuleBytes(testPodUID)), ActivationKey: string(active.Bytes())}}
	return pod, cm
}

func ptr[T any](v T) *T { return &v }

func TestOutputPolicyExactRuleAndActivation(t *testing.T) {
	pod, cm := testPolicyObjects()
	if _, err := ValidateConfigMap(cm, pod); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name   string
		change func(*corev1.Pod, *corev1.ConfigMap)
	}{
		{"wrong owner", func(_ *corev1.Pod, c *corev1.ConfigMap) { c.OwnerReferences[0].UID = "other" }},
		{"rule drift", func(_ *corev1.Pod, c *corev1.ConfigMap) { c.Data[RuleKey] += " " }},
		{"pod digest drift", func(p *corev1.Pod, _ *corev1.ConfigMap) {
			p.Annotations[PodRuleSHAAnnotation] = strings.Repeat("0", 64)
		}},
		{"duplicate activation key", func(_ *corev1.Pod, c *corev1.ConfigMap) {
			c.Data[ActivationKey] = strings.Replace(c.Data[ActivationKey], `"active":false`, `"active":false,"active":true`, 1)
		}},
		{"revision overflow", func(_ *corev1.Pod, c *corev1.ConfigMap) {
			c.Data[ActivationKey] = `{"active":true,"configMapUID":"` + testCMUID + `","operationId":"op-1","revision":9223372036854775808,"ruleId":"` + RuleID + `","version":1}`
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			p, c := testPolicyObjects()
			mutate.change(p, c)
			if _, err := ValidateConfigMap(c, p); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
