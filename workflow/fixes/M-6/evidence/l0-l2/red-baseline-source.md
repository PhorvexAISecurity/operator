# RED baseline — source at 5a0fd3f (pre-M6): the insecure state the head closes

## 1. actuator handler emitted a MUTABLE tag, joined command, and NO securityContext
```
func (debuggerHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return injectEphemeral(ctx, ec, req, "phorvex-debugger", "busybox:1.36", nil)
}
func (customInjectHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return injectEphemeral(ctx, ec, req, "phorvex-custom", "busybox:1.36", []string{"sh", "-c", "echo phorvex-custom-action; sleep 1"})
}
--- injectEphemeral container construction (baseline) ---
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: name, Image: image, Command: cmd, TTY: false, Stdin: false},
```

## 2. capability gate had NO code-exec admission leg (debugger/custom-inject offered with zero admission verification)
```
(no code-exec / admission reference in baseline gate.go)
```

## 3. internal/codeexec did not exist at baseline
```
fatal: path 'phorvex/internal/codeexec/verifier.go' exists on disk, but not in '5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9'
```
