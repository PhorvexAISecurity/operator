import json, math, hashlib
rows = json.load(open('/tmp/live-pods.json'))
N = len(rows)

def clamp01(x): return 0.0 if x < 0 else (1.0 if x > 1 else x)
def rarity(count, n):                      # platform.go:169-176
    if count <= 0 or n < 2: return 1.0
    return 1 + clamp01(math.log2(n/count)/math.log2(n))
def epss_mult(e, c): return 1 + clamp01(0.5*e + 0.5*c/10.0)   # platform.go epssMultiplier
CORES_CAP, MAXMULT = 4.0, 4.0
def bound(m): return 1.0 if m < 1 else (MAXMULT if m > MAXMULT else m)

imgCount, nodeTenants = {}, {}
for r in rows:
    imgCount[r['img']] = imgCount.get(r['img'], 0) + 1
    nodeTenants.setdefault(r['node'], set()).add(r['ns'])

# ModelRarity: measured 1.0 live (all model-serving pods run the same model)
MODEL_RARITY = 1.0

LIVE_EPSS = {
 "docker.io/vllm/vllm-openai@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2":(0.00676,7.5),
 "ghcr.io/berriai/litellm@sha256:afdc3cc37493d4f86d485ad7ac4445e7154c568a8d47c01bad15c9cf062c66b5":(0.99999,7.5),
 "public.ecr.aws/nginx/nginx@sha256:2e498e99757ae225fe9f1fb34144bc64f7abb8e49d2a35c84508b209f1319aa8":(0.52838,7.7),
 "753556437180.dkr.ecr.us-east-2.amazonaws.com/mock-rag-chatbot@sha256:99e22d25c345eaf016ec35fb10095f69110cf45b9a23ba4274c36e0dbdd26b17":(0.01386,7.5),
}
# deterministic plausible score per digest, drawn from the observed spread
def synth(img):
    h = int(hashlib.sha256(img.encode()).hexdigest()[:8], 16)/0xFFFFFFFF
    return (round(h**3, 5), round(4.0 + 6.0*((h*7919) % 1), 1))   # heavy-tailed EPSS, CVSS 4-10

def scalars(mode):
    out = {}
    for r in rows:
        ir = rarity(imgCount[r['img']], N)
        cr = 1 + clamp01((len(nodeTenants[r['node']])-1)/CORES_CAP)
        if mode == 'today':
            ep = epss_mult(*LIVE_EPSS[r['img']]) if r['img'] in LIVE_EPSS else 1.0
        elif mode == 'full':
            ep = epss_mult(*LIVE_EPSS[r['img']]) if r['img'] in LIVE_EPSS else epss_mult(*synth(r['img']))
        else:  # uniform control
            ep = 1.5
        s = ir * ep * cr
        if r['gpu']: s *= MODEL_RARITY
        out[r['ns']+'/'+r['pod']] = (s, bound(s))
    return out

a, b = scalars('today'), scalars('full')
def summarize(tag, d):
    raw = [v[0] for v in d.values()]; cl = [v[1] for v in d.values()]
    pinned = sum(1 for x in cl if abs(x-MAXMULT) < 1e-9)
    print(f"{tag:>8}: raw {min(raw):.3f}-{max(raw):.3f} | clamped {min(cl):.3f}-{max(cl):.3f} | "
          f"pinned at cap {pinned}/{len(cl)} ({100*pinned/len(cl):.0f}%) | distinct clamped {len({round(x,6) for x in cl})}")
summarize('today', a); summarize('full', b)

changed = [k for k in a if abs(a[k][1]-b[k][1]) > 1e-9]
print(f"\npods whose CLAMPED scalar changes: {len(changed)}/{len(a)}")

def order(d):   # rank by clamped scalar, tie-break by name for determinism
    return [k for k,_ in sorted(d.items(), key=lambda kv: (-kv[1][1], kv[0]))]
oa, ob = order(a), order(b)
print("ordering identical:", oa == ob)
if oa != ob:
    moved = sum(1 for i,k in enumerate(oa) if ob[i] != k)
    print(f"  positions differing: {moved}/{len(oa)}")
    print("  top-10 today:", [x.split('/')[0] for x in oa[:10]])
    print("  top-10 full :", [x.split('/')[0] for x in ob[:10]])

print("\n" + "="*74)
print("CAP SWEEP — what MaxDispersionMult preserves discrimination? (input for PHVX-24 item 2)")
print("="*74)
print(f"{'cap':>6} {'today: pinned':>16} {'today: distinct':>16} {'full: pinned':>16} {'full: distinct':>16}")
raw_a = {k: v[0] for k, v in a.items()}
raw_b = {k: v[0] for k, v in b.items()}
for cap in [4.0, 4.5, 5.0, 5.5, 6.0, 6.5, 7.0, 7.5, 8.0]:
    def stat(raw):
        cl = [min(x, cap) for x in raw.values()]
        pin = sum(1 for x in cl if abs(x - cap) < 1e-9)
        return f"{pin}/{len(cl)} ({100*pin/len(cl):.0f}%)", len({round(x, 6) for x in cl})
    pa, da = stat(raw_a)
    pb, db = stat(raw_b)
    print(f"{cap:>6.1f} {pa:>16} {da:>16} {pb:>16} {db:>16}")

print("\nTOP-GROUP SIZE at the live budget B=1 (how many assets tie for first on physics alone):")
for tag, raw in (("today", raw_a), ("full", raw_b)):
    for cap in (4.0, 7.5):
        cl = [min(x, cap) for x in raw.values()]
        top = max(cl)
        print(f"  {tag:>5} cap={cap}: {sum(1 for x in cl if abs(x-top) < 1e-9)} assets tied at the top value {top:.3f}")
