package crm

import _ "embed"

// These are exact fixture bytes embedded into the harness binary. Their hashes
// are checked by the scenario before any sandbox mutation.
//
//go:embed app.py
var AppSource []byte

//go:embed probe.py
var ProbeSource []byte

//go:embed dependencies.lock.json
var DependencyLock []byte
