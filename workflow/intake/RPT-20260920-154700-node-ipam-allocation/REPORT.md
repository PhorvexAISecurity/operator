# Catalogue first-run producer failure: independent IPAM investigation

Read-only investigation on 2026-09-20 UTC. No cluster resource was changed.

## Finding

The first catalogue execution is invalid because the real producer Pod could
not obtain a sandbox IP on
`ip-172-27-12-11.us-east-2.compute.internal`. This is a pre-existing node/IPAM
condition, not a failure introduced by the Round 3 network-policy enable/restore
rollout.

The failed row must remain invalid and the run cannot satisfy the reviewed
six-valid-row gate. This finding does not authorize a silent rerun and is not
evidence about either catalogue arm's functional effect.

## Evidence

- The catalogue namespace events show `c2-session-producer` scheduled on node
  `ip-172-27-12-11...` and repeated `FailedCreatePodSandBox` events from
  15:25:53 through 15:26:49: AWS CNI `failed to assign an IP address to
  container`. The target scheduled and became Ready on `ip-172-27-12-233...`.
- The affected node was created at 12:56:07, UID
  `df90038a-098d-412b-82b2-e05976351c65`. Four unrelated Pods currently remain
  Pending there (`ebs-csi-node`, NVIDIA device plugin, cAdvisor and voice-bot),
  while host-network/system Pods run.
- The retained cluster-wide events establish the same AWS CNI allocation
  failure on those unrelated Pods beginning at 12:58:18--12:58:25. This is
  nearly two hours before Round 3's first enable dispatch at 14:51:41.
- The pre-enable 14:33 health snapshot already recorded this same node Ready and
  its then-current `aws-node-gmrfn` UID
  `0e46cc95-7a01-4119-93b4-298299c7a531` with both containers Ready and zero
  restarts. Thus node/CNI readiness did not establish that a new ordinary Pod
  could obtain an address.
- The current replacement `aws-node-j6jtr` is likewise Ready with zero restarts,
  exact restored images, prefix delegation enabled, warm-prefix target 1,
  standard mode and network-policy agent disabled. The current EC2 instance
  `i-047850bba674a27b0` has one in-use primary ENI containing only primary IP
  `172.27.12.11` and no IPv4 prefix. The subnet reports 69 available addresses.
  Available-address count does not prove that an aligned `/28` prefix can be
  allocated.

Relevant raw receipts:

- `review/catalogue-ipam-investigation/all-events.json`, SHA-256
  `384d2e8d2a730088c499d0a3335736829718cba799b37932e1c29880b616144a`
- `review/catalogue-ipam-investigation/node-pods.json`, SHA-256
  `30dd77a76d61bacaa71d9f6eb55fe92a664b934d455170f2c1617b04a9f2173f`
- `review/catalogue-ipam-investigation/cni-pod.json`, SHA-256
  `5625fd836f4584ce6453b096e610fce9c730e299617657ef836ce6050c8003d2`
- `review/catalogue-ipam-investigation/aws-instance-network.json`, SHA-256
  `ac79296e2c377f3c26e702dbca925f3108fc28c24d1e983aead3975ebe3e3adf`
- `review/catalogue-ipam-investigation/aws-subnet.json`, SHA-256
  `91ba33cdc50b2640561f75aa0429757ddb9afb7c17473c33b82dfdb63f747bd9`

## Proven and unknown

The timestamps prove that Round 3 did not originate this node's inability to
network new Pods. The live CNI rollout also did not repair it. Current `Ready`
conditions cover node and daemon health, not successful fresh-Pod IP
allocation.

The exact reason no prefix is attached remains unknown. Candidate causes such
as subnet prefix fragmentation, EC2/IPAM limits or an authorization/API error
cannot be selected from the retained evidence. The `aws-node` container logs to
the host-mounted `ipamd.log`; the shipped container has no `tail` executable, so
the attempted read-only exec could not retrieve that file. The failed attempts
are retained and do not count as log evidence.

## Next safe decision

Treat node `...12-11` as an unhealthy destination for ordinary Pods until a
DevOps check explains and repairs its prefix/IP allocation. Any later catalogue
execution needs a new reviewed execution identity and must retain this failed
run. A retry based only on scheduler luck would not resolve the infrastructure
condition. Pinning or constraining all scenario Pods would require an explicit
harness/source design and validation; it should not be represented as a result
of this failed execution.
