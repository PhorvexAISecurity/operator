#!/usr/bin/env bash
# P4b sustained-load churn driver (out-of-process; engine unchanged): toggles data-class on
# soak pods so the optimizer keeps finding positive-net moves (defeats anti-over-rotation decay).
export KUBECONFIG="$HOME/.kube/config"; k="C:/kube/kubectl.exe"
while true; do
  for p in $($k -n soak get pods -l app=soak -o name 2>/dev/null | head -3); do
    cls=$([ $((RANDOM%2)) -eq 0 ] && echo restricted || echo internal)
    $k -n soak label "$p" data-class=$cls --overwrite >/dev/null 2>&1
  done
  sleep 3
done
