"""Prepare M1b from complete nonsecret owner snapshots; no cluster access."""
import argparse
import hashlib
import json
from pathlib import Path
import yaml
from render import canonical
from render_metrics import render, SOURCE_ANNOTATION


def prepare(inputs, values_path, baseline_bindings=None):
    def read(name):
        return json.loads((inputs / name).read_text())
    values = yaml.safe_load(values_path.read_text())
    console = values["phorvex"]["phorvex"]["console"]
    profiles = read("profiles.json")
    active = json.loads(baseline_bindings.read_text()) if baseline_bindings else console["litellmLive"]
    # The only enabled gateway-source profile in the current chart is litellmLive.
    # Output's separate seed-hash profile is unchanged and must not be synthesized.
    if not active["enabled"] or len(profiles) != 1:
        raise ValueError("complete active source-bound profile closure required")
    profile = profiles[0]
    raw = profile["data"]["profile.json"]
    if (profile["metadata"]["name"] != active["configMapName"] or
            hashlib.sha256(raw.encode()).hexdigest() != active["profileSHA256"]):
        raise ValueError("active values/profile closure differs")
    deployment = read("deployment.json")
    source = read("gateway-source.json")
    old_sha = deployment["spec"]["template"]["metadata"]["annotations"][SOURCE_ANNOTATION]
    if (source.get("immutable") is not True or set(source.get("data", {})) != {"gateway.py"} or
            source.get("binaryData") or not source["metadata"].get("uid") or
            source["metadata"]["name"] != active["sourceConfigMapName"] or
            hashlib.sha256(source["data"]["gateway.py"].encode()).hexdigest() != old_sha):
        raise ValueError("observed immutable source bytes/values differ")
    clients = read("clients.json")
    p = json.loads(raw)
    if (clients.get("immutable") is not True or set(clients.get("data", {})) != {"clients.json"} or
            clients.get("binaryData") or hashlib.sha256(clients["data"]["clients.json"].encode()).hexdigest() != p["clientsSHA256"]):
        raise ValueError("observed client inventory differs")
    labels = read("prometheus-labels.json")
    stable_labels = {key: labels[key] for key in ("app.kubernetes.io/name", "prometheus")}
    service = read("service.json")
    if (service["metadata"]["uid"] != deployment["spec"]["template"]["metadata"]["annotations"]["phorvex.ai/litellm-live-service-uid"] or
            service["spec"]["selector"] != {"app": "litellm"} or
            len(service["spec"]["ports"]) != 1 or service["spec"]["ports"][0]["targetPort"] != 4001):
        raise ValueError("observed serving Service differs")
    policies = read("networkpolicies.json")
    # After the compatible chart release its inert, opt-in policy already exists.
    # Exclude only our exact reviewed spec; every other policy remains inventoried.
    expected_path = Path(__file__).resolve().parents[4] / "deploy/helm/phorvex-stack/files/litellm-m1b/metrics-networkpolicy.json"
    original_policies = []
    for policy in policies:
        if policy.get("metadata", {}).get("name") == "phorvex-litellm-gateway-metrics":
            if policy.get("spec") != json.loads(expected_path.read_text())["spec"]:
                raise ValueError("staged metrics NetworkPolicy spec drift")
        else:
            original_policies.append(policy)
    objects = render(deployment, profiles, original_policies, stable_labels, read("output-policy.json"),
                     enabled=True, preserve_unisolated_ingress=not original_policies)
    closure = objects["metrics-closure.json"]
    if baseline_bindings:
        current = console["litellmLive"]
        binding = closure["profiles"][0]
        if (current["configMapName"] != binding["configMapName"] or
                current["profileSHA256"] != binding["profileSHA256"] or
                current["sourceConfigMapName"] != closure["sourceConfigMapName"]):
            raise ValueError("M1b values do not match complete derived active closure")
    closure["owner"] = {"gateway": "external manual Deployment; never Helm-adopted",
                        "activationManifests": "deploy/helm/phorvex-stack/templates/litellm-gateway-metrics.yaml",
                        "activeProfileValues": "phorvex.phorvex.console.litellmLive"}
    closure["baseline"] = {"deploymentUID": deployment["metadata"]["uid"],
        "deploymentSpecSHA256": hashlib.sha256(canonical(deployment["spec"]).encode()).hexdigest(),
        "sourceUID": source["metadata"]["uid"], "serviceUID": service["metadata"]["uid"],
        "profiles": [{"name": profile["metadata"]["name"], "uid": profile["metadata"]["uid"],
                      "profileSHA256": active["profileSHA256"]}],
        "prometheusPodLabels": stable_labels,
        "inputsSHA256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(inputs.glob("*.json"))}}
    # Network isolation is not inferred from a NetworkPolicy object existing.
    closure["gates"] = ["compatible engine and Console released", "published image actual-image proof",
        "fresh UID/spec/source guards", "idle catalogue and no prepared client/output operations",
        "quiescent installed output policy", "network enforcement enabled and allowed/denied data-plane controls",
        "Hami native vLLM scrape healthy and existing generic bridge advancing"]
    return objects


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-bindings", type=Path)
    args=parser.parse_args()
    objects=prepare(args.inputs,args.values,args.baseline_bindings)
    args.output.mkdir(parents=True,exist_ok=False)
    for name,obj in objects.items():
        (args.output/name).write_text(canonical(obj)+"\n")
    print(canonical(objects["metrics-closure.json"]))

if __name__=="__main__":main()
