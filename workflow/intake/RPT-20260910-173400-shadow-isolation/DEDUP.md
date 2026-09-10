# Root-cause comparison

M-140 owns policy lifecycle cleanup, M-91 native tenant registry, M-106 statistical model choices. This is counterfactual evaluation mutating valid production state. Clock and metrics facets share the non-persisting evaluation contract.

Ranked search aid:

```text
M-25	score=13	The AI stage classifier overrides — and can downgrade — real detector evidence	terms=behavior,evidence,not,raw,real,separate,stage
M-144	score=13	λ decays to its floor and is structurally trapped there — after a brief seed-decay, the cost stack becomes inert	terms=also,any,cadence,claim,evidence,exclusion,first,not,observation,observed,production,retained,separate
M-146	score=13	`omitempty` on eleven numeric audit fields erases measured zeros — the audit record cannot distinguish "0" from "not computed"	terms=any,claim,default,evidence,here,inputs,not,raw,record
M-136	score=12	The console's authentication is optional and fails OPEN — with mutation endpoints that shell out to kubectl	terms=any,default,evidence,logs,mutation,not,pods,production,real,stage
```

The ranked matches were inspected: M-146 is product audit optional-field presence, M-144 production dual economics, M-136 console authorization, M-154 audit retention, M-25 event/AI stage precedence, M-142 telemetry phase inference. Similar words do not make them the same producer, violated invariant or repair. This intake has the distinct boundary described above. Lead determination: NEW.
