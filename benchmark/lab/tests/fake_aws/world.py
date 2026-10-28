"""A small stateful AWS account for the offline teardown tests.

The account lives in the JSON file $STUB_WORLD: {"account": ..., "items": [...]}.
Account-level settings sit beside the items: eks_versions ({"1.36":
"STANDARD_SUPPORT"}), gpu_quota (vCPUs), instance_types ({"g4dn.xlarge": 4}),
budgets (names), active_cost_tags (keys) and collide_labs (every
phorvex-281-lab-* name "exists"). Each item has a kind (cluster, nodegroup, stack, elb, vpc, eni, sg, instance,
volume, nat, eip, oidc, loggroup, ecr, other), identifiers (id, name, arn),
tags, and optionally a state, a vpc, security groups, the stack that owns it
("owner"), and the instance it is attached to ("attached_to").

It models the behaviour teardown has to survive:
- a cluster stack fails (DELETE_FAILED) while any of the cluster's other
  stacks still exist (their imports block it), or while an ENI, security group
  or ELB it does not own is still in its VPC; its other resources are deleted
  first, as CloudFormation does, and only the VPC stays behind;
- deleting a stack deletes what it owns; a terminated instance releases its
  volumes, and a leaked CNI ENI ("leaks": true) becomes available;
- terminated instances, deleted NAT gateways and DELETE_COMPLETE stacks stay
  describable, as on AWS.
"""
import json
import os

GONE_STATE = {"instance": "terminated", "stack": "DELETE_COMPLETE", "nat": "deleted"}


class World:
    def __init__(self, path=None):
        self.path = path or os.environ["STUB_WORLD"]
        with open(self.path) as f:
            self.data = json.load(f)
        self.account = self.data["account"]
        self.items = self.data["items"]

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.path)

    def gone(self, it):
        return bool(it.get("deleted")) or it.get("state") == GONE_STATE.get(it["kind"], object())

    def live(self, kind=None):
        return [it for it in self.items if not self.gone(it) and kind in (None, it["kind"])]

    def find(self, kind, **match):
        for it in self.live(kind):
            if all(it.get(k) == v for k, v in match.items()):
                return it
        return None

    def remove(self, it):
        if it["kind"] == "instance":
            it["state"] = "terminated"
            for other in self.live():
                if other.get("attached_to") == it["id"]:
                    other["attached_to"] = None
                    if other["kind"] == "eni" and not other.get("leaks"):
                        other["deleted"] = True
                    else:
                        other["state"] = "available"
        elif it["kind"] == "nat":
            it["state"] = "deleted"
        else:
            it["deleted"] = True

    def delete_stack(self, name):
        stack = self.find("stack", name=name)
        if stack is None:
            return
        cluster = stack.get("cluster")
        if name == f"eksctl-{cluster}-cluster":
            if any(s is not stack and s.get("cluster") == cluster for s in self.live("stack")):
                stack["state"] = "DELETE_FAILED"
                return
        owned = [it for it in self.live() if it.get("owner") == name]
        vpcs = {it["id"] for it in owned if it["kind"] == "vpc"}
        for it in owned:
            if it["kind"] != "vpc":
                self.remove(it)
        blockers = [it for it in self.live() if it["kind"] in ("eni", "sg", "elb")
                    and it.get("vpc") in vpcs and it.get("owner") != name]
        if blockers:
            stack["state"] = "DELETE_FAILED"
            return
        for it in owned:
            if it["kind"] == "vpc":
                it["deleted"] = True
        stack["state"] = "DELETE_COMPLETE"


def tag_list(it):
    return [{"Key": k, "Value": v} for k, v in (it.get("tags") or {}).items()]


def log_call(tool, argv):
    with open(os.environ["STUB_LOG"], "a") as f:
        f.write("\t".join([tool, *argv]) + "\n")
