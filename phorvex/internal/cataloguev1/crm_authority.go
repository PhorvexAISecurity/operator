package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	crmSourceSHA = "328f37a8d6d3692fb3bd6d4db2637e72d54becf8e9e4396d5e47f4ab5f909350"
	crmBaseImage = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
	crmLockSHA   = "50143dfea339319c70edcc4e37c5d852031446f5e609ef4f538c68a0436f956a"
)

var crmUIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var crmImagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$`)

type crmManifest struct {
	Schema                   string            `json:"schema"`
	CRMImage                 string            `json:"crmImage"`
	MongoImage               string            `json:"mongoImage"`
	BaseImageDigest          string            `json:"baseImageDigest"`
	SourceSHA256             string            `json:"sourceSHA256"`
	DependencyLockSHA256     string            `json:"dependencyLockSHA256"`
	WheelhouseManifestSHA256 string            `json:"wheelhouseManifestSHA256"`
	Dependencies             map[string]string `json:"dependencies"`
}

func crmReadManifest(r CRMCapabilityRuntime) (crmManifest, error) {
	var manifest crmManifest
	info, err := crmPinnedRegular(r.ManifestFile, 16<<10)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 16<<10 {
		return manifest, errors.New("CRM owner manifest is unavailable or unbounded")
	}
	raw, err := os.ReadFile(r.ManifestFile)
	if err != nil {
		return manifest, err
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != r.ManifestSHA256 {
		return manifest, errors.New("CRM owner manifest hash differs")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return manifest, errors.New("CRM owner manifest has trailing data")
	}
	if manifest.Schema != "phorvex.crm-fixture.v1" || manifest.BaseImageDigest != crmBaseImage || manifest.SourceSHA256 != crmSourceSHA || manifest.DependencyLockSHA256 != crmLockSHA ||
		!hex64Pattern.MatchString(manifest.WheelhouseManifestSHA256) || !crmImagePattern.MatchString(manifest.CRMImage) || !crmImagePattern.MatchString(manifest.MongoImage) {
		return manifest, errors.New("CRM owner manifest source, dependency or immutable image authority differs")
	}
	want := map[string]string{"fastapi": "0.115.14", "pydantic": "2.13.4", "pymongo": "4.17.0", "uvicorn": "0.30.6"}
	if len(manifest.Dependencies) != len(want) {
		return manifest, errors.New("CRM owner manifest dependency set differs")
	}
	for name, version := range want {
		if manifest.Dependencies[name] != version {
			return manifest, fmt.Errorf("CRM owner manifest %s differs", name)
		}
	}
	return manifest, nil
}

// Kubernetes projected keys resolve through ..data links. The resolved file
// must stay inside its mount and its bytes are independently hash-pinned.
func crmPinnedRegular(path string, max int64) (os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	if resolved != path && !strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
		return nil, errors.New("CRM authority symlink escapes its mount")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > max {
		return nil, errors.New("CRM authority file missing, nonregular or unbounded")
	}
	return info, nil
}

func ValidateCRMLocalAuthority(r CRMCapabilityRuntime) error {
	if !r.Enabled {
		return errors.New("CRM fixed suite disabled")
	}
	if r.Namespace == "" || r.Namespace == "crm" || r.ServiceAccountName == "" || !crmUIDPattern.MatchString(r.NamespaceUID) || !hex64Pattern.MatchString(r.ManifestSHA256) || !hex64Pattern.MatchString(r.HarnessSHA256) || !hex64Pattern.MatchString(r.KubeconfigSHA256) || r.KubeContext == "" {
		return errors.New("CRM fixed suite namespace, context or hash pin invalid")
	}
	for _, path := range []string{r.ManifestFile, r.HarnessBinary, r.HarnessDir, r.KubeconfigPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("CRM fixed suite path must be canonical absolute")
		}
	}
	for _, path := range []string{r.ManifestFile, r.HarnessBinary, r.KubeconfigPath} {
		if _, err := crmPinnedRegular(path, 512<<20); err != nil {
			return fmt.Errorf("CRM authority path invalid: %s: %w", path, err)
		}
	}
	if _, err := crmReadManifest(r); err != nil {
		return err
	}
	info, err := crmPinnedRegular(r.HarnessBinary, 512<<20)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() < 1 || info.Size() > 512<<20 {
		return errors.New("CRM harness binary unavailable")
	}
	sum, err := fileSHA256(r.HarnessBinary, 512<<20)
	if err != nil || sum != r.HarnessSHA256 {
		return errors.New("CRM harness binary SHA-256 differs")
	}
	if info, err := os.Lstat(r.HarnessDir); err != nil || !info.IsDir() {
		return errors.New("CRM harness directory unavailable")
	}
	if _, err := crmPinnedRegular(r.KubeconfigPath, 1<<20); err != nil {
		return errors.New("CRM scoped kubeconfig unavailable")
	}
	sum, err = fileSHA256(r.KubeconfigPath, 1<<20)
	if err != nil || sum != r.KubeconfigSHA256 {
		return errors.New("CRM scoped kubeconfig SHA-256 differs")
	}
	raw, err := os.ReadFile(r.KubeconfigPath)
	if err != nil || len(raw) < 1 || len(raw) > 1<<20 {
		return errors.New("CRM scoped kubeconfig bytes unavailable")
	}
	kc, err := clientcmd.Load(raw)
	if err != nil {
		return fmt.Errorf("CRM scoped kubeconfig invalid: %w", err)
	}
	contextEntry := kc.Contexts[r.KubeContext]
	if contextEntry == nil {
		return errors.New("CRM scoped kubeconfig context absent")
	}
	auth := kc.AuthInfos[contextEntry.AuthInfo]
	if auth == nil || auth.Exec != nil || auth.AuthProvider != nil || auth.Impersonate != "" || auth.ImpersonateUID != "" || len(auth.ImpersonateGroups) != 0 || len(auth.ImpersonateUserExtra) != 0 || auth.Username != "" || auth.Password != "" || auth.ClientCertificate != "" || len(auth.ClientCertificateData) != 0 || auth.ClientKey != "" || len(auth.ClientKeyData) != 0 || auth.Token == "" && auth.TokenFile == "" {
		return errors.New("CRM scoped kubeconfig must use only the pinned fixture bearer identity")
	}
	return nil
}

// Current launch admission and the worker share this read-only UID gate.
func ValidateCRMRuntime(r CRMCapabilityRuntime) error {
	if err := ValidateCRMLocalAuthority(r); err != nil {
		return err
	}
	loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: r.KubeconfigPath}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{CurrentContext: r.KubeContext}).ClientConfig()
	if err != nil {
		return fmt.Errorf("CRM scoped kubeconfig: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := crmCheckServiceAccount(ctx, client, r.Namespace, r.ServiceAccountName); err != nil {
		return err
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.DeletionTimestamp != nil || ns.Labels["phorvex.ai/crm-capability-fixture"] != "true" {
		return fmt.Errorf("CRM dedicated fixture namespace UID or label unavailable or changed: %v", err)
	}
	return nil
}

func crmCheckServiceAccount(ctx context.Context, client kubernetes.Interface, namespace, serviceAccount string) error {
	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || review.Status.UserInfo.Username != "system:serviceaccount:"+namespace+":"+serviceAccount {
		return fmt.Errorf("CRM scoped fixture identity unavailable or changed: %v", err)
	}
	return nil
}
