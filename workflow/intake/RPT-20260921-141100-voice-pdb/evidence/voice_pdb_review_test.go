package feasibility
import("testing"; "github.com/phorvex/phorvex/internal/model")
func TestLeadVoicePDBFloorReproduction(t *testing.T){
 v:=&model.WorkloadView{Pod:model.Pod{ReadyReplicas:2,DesiredReplicas:3},Physics:model.NeutralPhysics()}
 v.Physics.PDBMinAvailable=2;v.Physics.PDBDisruptionsAllowed=0
 p:=model.Policy{MinAvailableReplicas:1}
 move:=model.Move{Action:model.ActionRotate}
 t.Run("policy-floor-positive",func(t *testing.T){strict:=p;strict.MinAvailableReplicas=2;if (availabilityFloor{}).Check(v,move,strict).Feasible{t.Fatal("existing policy-floor control failed")}})
 t.Run("matching-pdb-zero-headroom",func(t *testing.T){if (availabilityFloor{}).Check(v,move,p).Feasible{t.Fatal("BUG: rotate admitted at Ready=2 with PDB minAvailable=2 and disruptionsAllowed=0")}})
 t.Run("nonremoving-positive",func(t *testing.T){if !(availabilityFloor{}).Check(v,model.Move{Action:model.ActionKVReset},p).Feasible{t.Fatal("in-process control unexpectedly blocked")}})
}
