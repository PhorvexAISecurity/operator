package cataloguev1

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kfake "k8s.io/client-go/kubernetes/fake"
)

const fakeVoiceMongo = `import json,os
P=os.environ["FAKE_VOICE_DB"]
FIRST="CA11111111111111111111111111111111"
SECOND="CA22222222222222222222222222222222"
def load():
 with open(P) as f:return json.load(f)
def save(x):
 with open(P,"w") as f:json.dump(x,f)
class Cursor:
 def __init__(self,rows):self.rows=rows
 def max_time_ms(self,ms):
  assert ms==3000
  return self
 def limit(self,count):return self.rows[:count]
 def __iter__(self):return iter(self.rows)
class Collection:
 def find(self,query):
  state=load()
  sid=query.get("call_sid")
  if sid==FIRST:
   state["queries"]+=1
   if state["queries"]>=2 and not state["secondAdded"]:
    state["docs"].append({"_id":"2"*24,"call_sid":SECOND,"synthetic":"second"})
    state["secondAdded"]=True
   save(state)
  return Cursor([dict(d) for d in state["docs"] if all(d.get(k)==v for k,v in query.items())])
 def find_one(self,query):
  rows=self.find(query).limit(1)
  return rows[0] if rows else None
 def delete_one(self,original):
  state=load();state["deletes"]+=1
  before=len(state["docs"])
  state["docs"]=[d for d in state["docs"] if d!=original]
  save(state)
  return type("R",(),{"deleted_count":before-len(state["docs"])})()
 def count_documents(self,query):
  return sum(all(d.get(k)==v for k,v in query.items()) for d in load()["docs"])
class Database:
 def __getitem__(self,key):return Collection()
class MongoClient:
 def __init__(self,uri,**kw):
  assert uri=="memory" and kw["retryWrites"] is False
  assert kw["connectTimeoutMS"]==3000 and kw["socketTimeoutMS"]==3000
 def __getitem__(self,key):return Database()
`

func TestVoiceCleanupActualPythonProducerDelayedSecondSID(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python is needed to exercise the embedded cleanup producer")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pymongo.py"), []byte(fakeVoiceMongo), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bson"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bson", "__init__.py"), []byte("class ObjectId(str): pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bson", "json_util.py"), []byte("import json\ndef dumps(value,**kwargs):return json.dumps(value,**kwargs)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "db.json")
	first := map[string]string{"_id": strings.Repeat("1", 24), "call_sid": cleanupFirstSID, "synthetic": "first"}
	raw, _ := json.Marshal(map[string]any{"queries": 0, "deletes": 0, "secondAdded": false, "docs": []any{first}})
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-a", Namespace: "voice", UID: types.UID("pod-a"), Labels: map[string]string{"app": "voice-bot"}}}
	runtime := &kubeVoiceRuntime{kube: kfake.NewSimpleClientset(pod), voice: VoiceRuntime{TranscriptPodSelector: "app=voice-bot", TranscriptContainer: "bot"}}
	runtime.execOverride = func(ctx context.Context, namespace, name, container string, command []string) (string, error) {
		if namespace != "voice" || name != "voice-bot-a" || container != "bot" || len(command) < 3 || command[0] != "python3" || command[1] != "-c" {
			t.Fatal("unexpected exec authority")
		}
		cmd := exec.CommandContext(ctx, python, append([]string{"-c", command[2]}, command[3:]...)...)
		cmd.Env = append(os.Environ(), "PYTHONPATH="+root, "FAKE_VOICE_DB="+statePath, "MONGO_URI=memory")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("embedded producer failed: %v output=%s", err, output)
		}
		return string(output), nil
	}
	runtime.pauseOverride = func(context.Context, time.Duration) error { return nil }
	intents, results := 0, 0
	outcome := runtime.CleanupTranscripts(context.Background(), testVoiceConfig(VoiceReplacementRecovery), VoicePod{Name: "voice-bot-a", UID: "pod-a"}, []string{cleanupFirstSID, cleanupSecondSID},
		func(TranscriptRef) error { intents++; return nil }, func(TranscriptRef) error { results++; return nil })
	stateRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Queries int               `json:"queries"`
		Deletes int               `json:"deletes"`
		Docs    []json.RawMessage `json:"docs"`
	}
	if err = json.Unmarshal(stateRaw, &state); err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "PASS" || outcome.UnsafeToRetry || state.Deletes != 2 || len(state.Docs) != 0 || intents != 2 || results != 2 || state.Queries < 10 {
		t.Fatalf("actual producer did not clean both exact SIDs: outcome=%+v state=%+v intents=%d results=%d", outcome, state, intents, results)
	}
}

func TestVoiceCleanupEmbeddedDeleteRejectsContentDriftWithoutMutation(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python is needed to exercise the embedded cleanup producer")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pymongo.py"), []byte(fakeVoiceMongo), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bson"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bson", "__init__.py"), []byte("class ObjectId(str): pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bson", "json_util.py"), []byte("import json\ndef dumps(value,**kwargs):return json.dumps(value,**kwargs)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "db.json")
	objectID := strings.Repeat("1", 24)
	writeState := func(synthetic string, queries int) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"queries": queries, "deletes": 0, "secondAdded": true,
			"docs": []any{map[string]string{"_id": objectID, "call_sid": cleanupFirstSID, "synthetic": synthetic}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeState("before", 0)
	run := func(program string, args ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.Command(python, append([]string{"-c", program}, args...)...)
		cmd.Env = append(os.Environ(), "PYTHONPATH="+root, "FAKE_VOICE_DB="+statePath, "MONGO_URI=memory")
		return cmd.CombinedOutput()
	}
	queryOut, err := run(transcriptQueryProgram, cleanupFirstSID)
	if err != nil {
		t.Fatalf("owned query failed: %v", err)
	}
	refs, err := parseTranscriptRefs(string(queryOut), []string{cleanupFirstSID})
	if err != nil || len(refs) != 1 {
		t.Fatalf("owned query shape differs: %v, count=%d", err, len(refs))
	}
	writeState("after", 1)
	deleteOut, err := run(transcriptDeleteProgram, cleanupFirstSID, objectID, refs[0].ContentSHA256)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 || !strings.Contains(string(deleteOut), `"content-hash-drift"`) {
		t.Fatalf("drift was not rejected by embedded producer: exit=%v output=%q", err, deleteOut)
	}
	stateRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Deletes int               `json:"deletes"`
		Docs    []json.RawMessage `json:"docs"`
	}
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		t.Fatal(err)
	}
	var remaining struct {
		Synthetic string `json:"synthetic"`
	}
	if len(state.Docs) == 1 {
		if err := json.Unmarshal(state.Docs[0], &remaining); err != nil {
			t.Fatal(err)
		}
	}
	if state.Deletes != 0 || len(state.Docs) != 1 || remaining.Synthetic != "after" {
		t.Fatalf("drift mutated the exact owned document: deletes=%d docs=%d", state.Deletes, len(state.Docs))
	}
}
