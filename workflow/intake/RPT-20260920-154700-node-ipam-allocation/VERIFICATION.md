# IPAM cause update: no assignable aligned prefix

Read-only evidence, September20,15:53--15:55 UTC. This adds to the preserved
first-run investigation; the node failure remains unrepaired.

The affected aws-node metrics endpoint was reached through the Kubernetes Pod
proxy without adding any workload or reading host files. It reports1,032 failed
AssignPrivateIpAddresses calls labelled InsufficientCidrBlocks,516 failed
CreateNetworkInterface calls labelled InvalidParameterValue, and zero allocated
IPv4 prefixes. The exact CNI Pod is aws-node-j6jtr on node172.27.12.11.

A complete EC2 ENI/private-address/prefix census for subnet172.27.12.0/24,
plus subnet CIDR reservations, independently explains the prefix failure:69
addresses remain unallocated, but none of the16 aligned /28 blocks is wholly
available. Eleven prefixes are already allocated. The other blocks contain
individual addresses or AWS-reserved addresses; there are no CIDR reservations.
The raw reads are sequential snapshots, not an atomic EC2 transaction.
See BLOCK-ANALYSIS.json for each block and input hashes.

This is concrete evidence of exhausted contiguous prefix capacity rather than a
Phorvex decision failure. The separate InvalidParameterValue cause is not yet
explained. AWS requires contiguous /28 blocks for IPv4 prefix assignment; see
[the official EKS prefix-mode guidance](https://docs.aws.amazon.com/eks/latest/best-practices/prefix-mode-linux.html).

Repair requires an explicit network allocation plan: make an aligned block
available and reserve it for prefix assignment, or place future nodes into a
suitable existing subnet. A reservation alone cannot free occupied addresses.
Do not delete live ENIs, switch prefix mode globally, or replace nodes merely to
make this test pass. No such changes were made. A repair is accepted only after
this exact node, or its documented replacement, allocates an address to a fresh
ordinary Pod and that Pod passes its own traffic/cleanup controls.

Private raw evidence: .git/phorvex-workflow/post25-live-20260920/review/catalogue-ipam-proxy.
