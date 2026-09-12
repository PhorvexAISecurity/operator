#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

registry="${REG-}"
version="${V-}"
markers="${MARKERS-}"
mode="${SOURCE_MODE-}"
release_from="${RELEASE_FROM-}"
operator_digest="${OPERATOR_DIGEST-}"
console_digest="${CONSOLE_DIGEST-}"

[[ "$registry" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?$ ]] || \
  fail "REG must be a registry hostname with an optional numeric port"

valid_tag() {
  local value="$1"
  [ "${#value}" -le 128 ] && [[ "$value" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]
}

valid_digest() {
  local value="$1"
  [ "${#value}" -eq 71 ] && [[ "$value" =~ ^sha256:[0-9a-f]+$ ]]
}

valid_tag "$version" || fail "V is not a valid image tag"
[ -n "$markers" ] || fail "MARKERS must select at least one image"

case "$mode" in
  digest)
    [ -z "$release_from" ] || fail "RELEASE_FROM is only valid in tag mode"
    ;;
  tag)
    valid_tag "$release_from" || fail "forced tag mode requires a valid RELEASE_FROM image tag"
    ;;
  *)
    fail "SOURCE_MODE must be 'digest' or 'tag'"
    ;;
esac

sources=()
targets=()
seen=" "
for marker in $markers; do
  case "$marker" in
    ci:phorvex-tag)
      repo="phorvex"
      digest="$operator_digest"
      ;;
    ci:console-tag)
      repo="phorvex-console"
      digest="$console_digest"
      ;;
    *)
      fail "unknown marker $marker"
      ;;
  esac

  case "$seen" in
    *" $marker "*) fail "duplicate marker $marker" ;;
  esac
  seen="$seen$marker "

  if [ "$mode" = "digest" ]; then
    valid_digest "$digest" || fail "$marker has a missing or malformed build digest"
    source="$registry/$repo@$digest"
  else
    source="$registry/$repo:$release_from"
  fi
  sources+=("$source")
  targets+=("$registry/$repo:$version")
done

# All inputs are validated before the first registry mutation. A bad second image can
# therefore never leave a release half-tagged.
for index in "${!sources[@]}"; do
  docker buildx imagetools create -t "${targets[$index]}" "${sources[$index]}"
  echo "tagged ${sources[$index]} -> ${targets[$index]}"
done
