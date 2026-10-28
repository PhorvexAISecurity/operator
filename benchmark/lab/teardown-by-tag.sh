#!/usr/bin/env bash
# Deletes every AWS resource of one benchmark lab run, by its derived names and
# tags only, then proves read-only that nothing of the run remains (ticket
# Part 2 P8, A2a). Stateless and idempotent: it reads no local state, so anyone
# with AWS credentials can run it again, at any time, from any machine.
#
#   teardown-by-tag.sh --run-id ID --account A [--region us-east-2] [--proof FILE] [--plan]
#
# Safety, one rule: ID is 6 hex digits, LAB=phorvex-281-lab-ID and
# REPO=phorvex-281-temp-ID. A resource is deleted only if the selector that
# found it embeds LAB or ID exactly: a derived name, the tag key
# kubernetes.io/cluster/LAB, or the tags alpha.eksctl.io/cluster-name=LAB,
# cluster.k8s.amazonaws.com/name=LAB or phorvex.ai/lab-run=ID. The cluster, its
# stacks and the ECR repository must also carry phorvex.ai/lab-run=ID. Reads
# may filter region-wide; no delete is region-wide. --plan deletes nothing.
#
# Steps 2-9 are best effort: a failed step is logged and the next one runs.
# Only the step-10 proofs decide: PASS and exit 0, or the leftovers and exit 70.
# There are no internal retries; run the command again. If run.sh or the host
# died, first stop any orphan `eksctl ... phorvex-281-lab-ID` process.
# Exit 2: bad arguments, or AWS credentials for another account.
set -uo pipefail

usage() {
  printf '%s\n' "usage: teardown-by-tag.sh --run-id ID --account A [--region R] [--proof FILE] [--plan]" "teardown: $*" >&2
  exit 2
}
id='' account='' region=us-east-2 proof='' plan=0 dev_cluster=phorvex-dev-eks
while (($#)); do
  case $1 in
    --plan) plan=1; shift; continue ;;
    --run-id|--account|--region|--proof|--dev-cluster) (($# >= 2)) || usage "$1 needs a value" ;;
    *) usage "unknown argument: $1" ;;
  esac
  case $1 in
    --run-id) id=$2 ;; --account) account=$2 ;; --region) region=$2 ;; --proof) proof=$2 ;; --dev-cluster) dev_cluster=$2 ;;
  esac
  shift 2
done
[[ $id =~ ^[0-9a-f]{6}$ ]] || usage "--run-id must be 6 lowercase hex digits"
[[ $account =~ ^[0-9]{12}$ ]] || usage "--account must be 12 digits"
[[ $region =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || usage "--region is not an AWS region name: $region"
[[ -z $proof || -d $(dirname -- "$proof") ]] || usage "--proof directory does not exist"
for v in TEARDOWN_WAIT_STACKS TEARDOWN_WAIT_ELB TEARDOWN_WAIT_SG TEARDOWN_POLL TEARDOWN_EKSCTL_TIMEOUT; do
  [[ ${!v:-0} =~ ^[0-9]+$ ]] || usage "$v must be a whole number of seconds"
done
wait_stacks=${TEARDOWN_WAIT_STACKS:-1800} wait_elb=${TEARDOWN_WAIT_ELB:-300} wait_sg=${TEARDOWN_WAIT_SG:-300}
poll=${TEARDOWN_POLL:-30} eksctl_timeout=${TEARDOWN_EKSCTL_TIMEOUT:-5400}
command -v aws >/dev/null && command -v jq >/dev/null || usage "aws and jq must be on PATH"

LAB=phorvex-281-lab-$id REPO=phorvex-281-temp-$id RUN_KEY=phorvex.ai/lab-run
ALPHA=alpha.eksctl.io/cluster-name K8S_KEY=kubernetes.io/cluster/$LAB
export AWS_PAGER=''
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
if [[ -n $proof ]]; then : >"$proof"; fi

log() {
  printf '[teardown %s] %s\n' "$id" "$*" >&2
  if [[ -n $proof ]]; then printf '%s\n' "$*" >>"$proof"; fi
}
q() { aws --region "$region" --output json "$@" 2>"$tmp/err"; }
not_found() { grep -qE 'NotFound|does not exist' "$tmp/err"; }
# Writes go through here: printed in --plan, otherwise run and logged.
mutate() {
  if ((plan)); then log "PLAN: aws $*"; return 0; fi
  log "aws $*"
  q "$@" >/dev/null || { log "  failed: $(head -c 300 "$tmp/err")"; return 1; }
}
step() {
  local n=$1 name=$2; shift 2
  log "step $n: $name"
  "$@" || log "step $n: $name did not complete; continuing"
}
# 0 if the resource exists, 1 if AWS says it does not. Any other error counts
# as present, so a throttled or denied describe can never produce a false PASS.
exists() { q "$@" >/dev/null && return 0; not_found && return 1; return 0; }

lab_stacks() {
  q cloudformation list-stacks | jq -r --arg p "eksctl-$LAB-" \
    '.StackSummaries[] | select((.StackName | startswith($p)) and .StackStatus != "DELETE_COMPLETE") | [.StackName, .StackStatus] | @tsv'
}
lab_vpcs() { q ec2 describe-vpcs --filters "Name=tag:$ALPHA,Values=$LAB" | jq -r '.Vpcs[].VpcId'; }
lab_enis() {  # available ENIs tagged for LAB, in VPC $1 if given
  local -a vpc=()
  [[ -z ${1:-} ]] || vpc=("Name=vpc-id,Values=$1")
  { q ec2 describe-network-interfaces --filters "${vpc[@]}" Name=status,Values=available "Name=tag:cluster.k8s.amazonaws.com/name,Values=$LAB" &&
    q ec2 describe-network-interfaces --filters "${vpc[@]}" Name=status,Values=available "Name=tag-key,Values=$K8S_KEY"; } |
    jq -r '.NetworkInterfaces[].NetworkInterfaceId' | sort -u
}
lab_volumes() {
  { q ec2 describe-volumes --filters Name=status,Values=available "Name=tag:$RUN_KEY,Values=$id" &&
    q ec2 describe-volumes --filters Name=status,Values=available "Name=tag-key,Values=$K8S_KEY"; } |
    jq -r '.Volumes[].VolumeId' | sort -u
}
lab_instances() {
  q ec2 describe-instances --filters "Name=tag:eks:cluster-name,Values=$LAB" \
    Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped |
    jq -r '.Reservations[].Instances[] | "\(.InstanceId) \(.State.Name)"'
}
lab_security_groups() {
  { q ec2 describe-security-groups --filters "Name=tag-key,Values=$K8S_KEY" &&
    q ec2 describe-security-groups --filters "Name=tag:$ALPHA,Values=$LAB"; } |
    jq -r '.SecurityGroups[].GroupId' | sort -u
}
lab_nat_gateways() {
  q ec2 describe-nat-gateways --filter "Name=tag:$ALPHA,Values=$LAB" |
    jq -r '.NatGateways[] | select(.State != "deleted") | .NatGatewayId'
}
lab_eips() { q ec2 describe-addresses --filters "Name=tag:$ALPHA,Values=$LAB" | jq -r '.Addresses[].AllocationId'; }
lab_oidc() {  # providers tagged for LAB; fails if any provider's tags cannot be read
  local arn arns tags rc=0
  arns=$(q iam list-open-id-connect-providers | jq -r '.OpenIDConnectProviderList[].Arn') || return 1
  for arn in $arns; do
    tags=$(q iam list-open-id-connect-provider-tags --open-id-connect-provider-arn "$arn") || { rc=1; continue; }
    if jq -e --arg k "$ALPHA" --arg v "$LAB" 'any(.Tags[]?; .Key == $k and .Value == $v)' <<<"$tags" >/dev/null; then
      printf '%s\n' "$arn"
    fi
  done
  return "$rc"
}
lab_log_group() {
  q logs describe-log-groups --log-group-name-prefix "/aws/eks/$LAB/cluster" |
    jq -r --arg n "/aws/eks/$LAB/cluster" '.logGroups[] | select(.logGroupName == $n) | .logGroupName'
}
tagged_arns() {  # tag filter, then optional resource type
  q resourcegroupstaggingapi get-resources --tag-filters "$1" ${2:+--resource-type-filters "$2"} |
    jq -r '.ResourceTagMappingList[].ResourceARN'
}
is_elbv2() { [[ $1 == *:loadbalancer/app/* || $1 == *:loadbalancer/net/* || $1 == *:loadbalancer/gwy/* ]]; }
elb_exists() {
  if is_elbv2 "$1"; then exists elbv2 describe-load-balancers --load-balancer-arns "$1"
  else exists elb describe-load-balancers --load-balancer-names "${1##*:loadbalancer/}"; fi
}
has_run_tag() { jq -e --arg k "$RUN_KEY" --arg v "$id" "$1" >/dev/null; }

# 2. Let any eksctl create or delete still in progress finish first.
wait_in_progress() {
  local deadline=$((SECONDS + wait_stacks)) busy
  while :; do
    busy=$(lab_stacks | awk -F'\t' '$2 ~ /_IN_PROGRESS$/ {print $1}') || return 1
    [[ -z $busy ]] && return 0
    if ((plan)); then log "in progress: $busy"; return 0; fi
    ((SECONDS < deadline)) || { log "still in progress after ${wait_stacks}s: $busy"; return 1; }
    sleep "$poll"
  done
}

# 3. The cluster first, while its API may still be up: eksctl then deletes the
# LoadBalancer Services, so the controller removes their ELBs and groups.
delete_cluster() {
  local out
  if ! out=$(q eks describe-cluster --name "$LAB"); then
    not_found && { log "cluster $LAB is absent"; return 0; }
    log "describe-cluster failed: $(head -c 300 "$tmp/err")"; return 1
  fi
  has_run_tag '.cluster.tags[$k] == $v' <<<"$out" || { log "cluster $LAB is not tagged $RUN_KEY=$id; not deleting it"; return 1; }
  if ((plan)); then log "PLAN: eksctl delete cluster --name $LAB --region $region --disable-nodegroup-eviction --wait"; return 0; fi
  command -v eksctl >/dev/null || { log "eksctl is not on PATH; relying on the stack sweep"; return 1; }
  log "eksctl delete cluster --name $LAB --region $region --disable-nodegroup-eviction --wait"
  # A throwaway kubeconfig: eksctl never reads or writes the real one.
  KUBECONFIG=$(mktemp "$tmp/kubeconfig.XXXXXX") timeout "$eksctl_timeout" \
    eksctl delete cluster --name "$LAB" --region "$region" --disable-nodegroup-eviction --wait 2>&1 |
    while IFS= read -r line; do log "  eksctl: $line"; done
}

# 4. ELBs the in-cluster controllers made, by the cluster tag key.
delete_elbs() {
  local rc=0 arn deadline=$((SECONDS + wait_elb)) arns
  arns=$(tagged_arns "Key=$K8S_KEY" elasticloadbalancing:loadbalancer) || return 1
  for arn in $arns; do
    if is_elbv2 "$arn"; then mutate elbv2 delete-load-balancer --load-balancer-arn "$arn" || rc=1
    else mutate elb delete-load-balancer --load-balancer-name "${arn##*:loadbalancer/}" || rc=1; fi
  done
  ((plan)) && return "$rc"
  for arn in $arns; do
    while elb_exists "$arn"; do
      ((SECONDS < deadline)) || { log "ELB still present: $arn"; rc=1; break; }
      sleep "$poll"
    done
  done
  return "$rc"
}

# 5. Leftover available ENIs in the lab VPC.
delete_enis() {
  local rc=0 vpc eni
  for vpc in $(lab_vpcs); do
    for eni in $(lab_enis "$vpc"); do mutate ec2 delete-network-interface --network-interface-id "$eni" || rc=1; done
  done
  return "$rc"
}

# 6. Controller-made security groups in the lab VPC that no ENI uses.
delete_security_groups() {
  local rc=0 vpc sg deadline=$((SECONDS + wait_sg)) pending
  for vpc in $(lab_vpcs); do
    while :; do
      pending=()
      for sg in $(q ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc" "Name=tag-key,Values=$K8S_KEY" |
          jq -r '.SecurityGroups[].GroupId'); do
        if [[ -n $(q ec2 describe-network-interfaces --filters "Name=group-id,Values=$sg" | jq -r '.NetworkInterfaces[].NetworkInterfaceId') ]]; then
          pending+=("$sg (in use)"); continue
        fi
        mutate ec2 delete-security-group --group-id "$sg" || pending+=("$sg")
      done
      ((${#pending[@]} == 0 || plan)) && break
      ((SECONDS < deadline)) || { log "security groups not deleted: ${pending[*]}"; rc=1; break; }
      sleep "$poll"
    done
  done
  return "$rc"
}

# 7. Whatever eksctl left of its stacks: nodegroups, then addons, then any
# other, then the cluster stack, which also removes the VPC. Terminating the
# nodes is what releases leaked CNI ENIs, which then block the VPC, so steps 5
# and 6 run once more just before the cluster stack. Without that, a lab whose
# API was unreachable in step 3 needs a second run to pass.
delete_stacks() {
  local rc=0 group name status
  for group in nodegroup addon other cluster; do
    if [[ $group == cluster ]] && ((!plan)); then
      log "re-sweeping ENIs and security groups released by the nodes"
      delete_enis || rc=1
      delete_security_groups || rc=1
    fi
    local -a started=()
    while IFS=$'\t' read -r name status; do
      case $group in
        nodegroup) [[ $name == "eksctl-$LAB-nodegroup-"* ]] ;;
        addon) [[ $name == "eksctl-$LAB-addon-"* ]] ;;
        cluster) [[ $name == "eksctl-$LAB-cluster" ]] ;;
        other) [[ $name != "eksctl-$LAB-nodegroup-"* && $name != "eksctl-$LAB-addon-"* && $name != "eksctl-$LAB-cluster" ]] ;;
      esac || continue
      if ! q cloudformation describe-stacks --stack-name "$name" | has_run_tag 'any(.Stacks[0].Tags[]?; .Key == $k and .Value == $v)'; then
        log "stack $name ($status) is not tagged $RUN_KEY=$id; not deleting it"; rc=1; continue
      fi
      mutate cloudformation delete-stack --stack-name "$name" && started+=("$name") || rc=1
    done < <(lab_stacks)
    ((plan)) && continue
    for name in "${started[@]}"; do
      aws --region "$region" cloudformation wait stack-delete-complete --stack-name "$name" 2>"$tmp/err" \
        || { log "stack $name did not finish deleting: $(head -c 300 "$tmp/err")"; rc=1; }
    done
  done
  return "$rc"
}

# 8. The OIDC provider, the control-plane log group and released volumes.
delete_oidc_logs_volumes() {
  local rc=0 arn group vol
  for arn in $(lab_oidc); do mutate iam delete-open-id-connect-provider --open-id-connect-provider-arn "$arn" || rc=1; done
  for group in $(lab_log_group); do mutate logs delete-log-group --log-group-name "$group" || rc=1; done
  for vol in $(lab_volumes); do mutate ec2 delete-volume --volume-id "$vol" || rc=1; done
  return "$rc"
}

# 9. The run's ECR repository, only if it is this run's.
delete_ecr() {
  local arn
  if ! arn=$(q ecr describe-repositories --repository-names "$REPO" | jq -r '.repositories[0].repositoryArn'); then
    not_found && return 0
    log "describe-repositories failed: $(head -c 300 "$tmp/err")"; return 1
  fi
  q ecr list-tags-for-resource --resource-arn "$arn" | has_run_tag 'any(.tags[]?; .Key == $k and .Value == $v)' \
    || { log "ECR repository $REPO is not tagged $RUN_KEY=$id; not deleting it"; return 1; }
  mutate ecr delete-repository --repository-name "$REPO" --force
}

# 10. Read-only proofs. Anything that cannot be checked counts as a leftover.
leftovers=()
left() { leftovers+=("$*"); }
check_list() {  # description, then a command that prints one present item per line
  local what=$1 out; shift
  if ! out=$("$@"); then left "$what: could not be checked"; return; fi
  while IFS= read -r line; do [[ -z $line ]] || left "$what: $line"; done <<<"$out"
}
# 0 if the tagged resource still exists; unknown types count as present.
arn_exists() {
  local arn=$1 out rest
  case $arn in
    arn:*:ec2:*:instance/*)
      out=$(q ec2 describe-instances --instance-ids "${arn##*/}") || { not_found && return 1; return 0; }
      [[ $(jq -r '[.Reservations[].Instances[].State.Name][0] // "terminated"' <<<"$out") != terminated ]] ;;
    arn:*:ec2:*:natgateway/*)
      out=$(q ec2 describe-nat-gateways --nat-gateway-ids "${arn##*/}") || { not_found && return 1; return 0; }
      [[ $(jq -r '.NatGateways[0].State // "deleted"' <<<"$out") != deleted ]] ;;
    arn:*:ec2:*)
      out=$(q ec2 describe-tags --filters "Name=resource-id,Values=${arn##*/}") || return 0
      [[ $(jq '.Tags | length' <<<"$out") -gt 0 ]] ;;
    arn:*:ecr:*:repository/*) exists ecr describe-repositories --repository-names "${arn#*:repository/}" ;;
    arn:*:eks:*:cluster/*) exists eks describe-cluster --name "${arn##*/}" ;;
    arn:*:eks:*:nodegroup/*)
      rest=${arn#*:nodegroup/}
      exists eks describe-nodegroup --cluster-name "${rest%%/*}" --nodegroup-name "$(cut -d/ -f2 <<<"$rest")" ;;
    arn:*:cloudformation:*:stack/*)
      out=$(q cloudformation describe-stacks --stack-name "$arn") || { not_found && return 1; return 0; }
      [[ $(jq -r '.Stacks[0].StackStatus' <<<"$out") != DELETE_COMPLETE ]] ;;
    arn:*:elasticloadbalancing:*) elb_exists "$arn" ;;
    arn:*:logs:*:log-group:*)
      rest=${arn#*:log-group:}; rest=${rest%:\*}
      out=$(q logs describe-log-groups --log-group-name-prefix "$rest") || return 0
      jq -e --arg n "$rest" 'any(.logGroups[]; .logGroupName == $n)' <<<"$out" >/dev/null ;;
    *) return 0 ;;
  esac
}
present_arns() {  # tagged ARNs that a describe confirms still exist
  local arns arn
  arns=$(tagged_arns "$@") || return 1
  for arn in $arns; do if arn_exists "$arn"; then printf '%s\n' "$arn"; fi; done
}
proofs() {
  exists eks describe-cluster --name "$dev_cluster" || left "dev cluster $dev_cluster is not visible"
  if exists eks describe-cluster --name "$LAB"; then left "EKS cluster $LAB"; fi
  check_list "CloudFormation stack" lab_stacks
  check_list "EC2 instance" lab_instances
  check_list "load balancer" present_arns "Key=$K8S_KEY" elasticloadbalancing:loadbalancer
  check_list "security group" lab_security_groups
  check_list "available ENI" lab_enis
  check_list "available EBS volume" lab_volumes
  check_list "NAT gateway" lab_nat_gateways
  check_list "Elastic IP" lab_eips
  check_list "VPC" lab_vpcs
  check_list "OIDC provider" lab_oidc
  check_list "log group" lab_log_group
  if exists ecr describe-repositories --repository-names "$REPO"; then left "ECR repository $REPO"; fi
  check_list "tagged $RUN_KEY=$id" present_arns "Key=$RUN_KEY,Values=$id"
}

log "run $id: lab $LAB, repository $REPO, account $account, region $region$( ((plan)) && echo ', PLAN: nothing is deleted')"
actual=$(q sts get-caller-identity | jq -r .Account) || usage "aws sts get-caller-identity failed; check AWS credentials"
[[ $actual == "$account" ]] || usage "AWS credentials are for account $actual, not --account $account"

step 2 "wait for eksctl stacks in progress" wait_in_progress
step 3 "delete the cluster with eksctl" delete_cluster
step 4 "delete load balancers tagged $K8S_KEY" delete_elbs
step 5 "delete available ENIs in the lab VPC" delete_enis
step 6 "delete unused security groups in the lab VPC" delete_security_groups
step 7 "delete remaining eksctl-$LAB-* stacks" delete_stacks
step 8 "delete the OIDC provider, log group and available volumes" delete_oidc_logs_volumes
step 9 "delete ECR repository $REPO" delete_ecr
log "step 10: proofs"
proofs

if ((plan)); then
  log "PLAN complete: nothing was deleted; ${#leftovers[@]} item(s) of run $id currently present"
  for l in "${leftovers[@]}"; do echo "PRESENT $l"; done
  exit 0
fi
if ((${#leftovers[@]} == 0)); then
  log "PASS"
  echo PASS
  exit 0
fi
for l in "${leftovers[@]}"; do log "LEFTOVER $l"; echo "LEFTOVER $l"; done
log "FAIL: ${#leftovers[@]} leftover(s); run this command again: $0 --run-id $id --region $region --account $account"
echo "FAIL: ${#leftovers[@]} leftover(s)"
exit 70
