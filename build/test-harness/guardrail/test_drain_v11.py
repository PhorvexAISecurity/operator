from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import httpx
import drain_v11 as drain

class FakeEngine:
    def __init__(self, boot="b"*32):
        self.boot=boot; self.source="engine-source"; self.admission="OPEN"; self.generation=0; self.operation=None; self.sequence=0
        self.snapshot={"0":{"waiting":["wait"],"running":["run"],"swapped":["swap"],"cached":[]}}
        self.queues={"0":{"waiting":[],"running":[],"swapped":[],"cached":[]}}
        self.calls=[]; self.fail_begin=False; self.omit_terminal=False
    def response(self,rid,action,nonce=None):
        terminal=({rid:"aborted" for q in self.snapshot.values() for n in ("waiting","running","swapped","cached") for rid in q[n]} if self.operation and not self.omit_terminal else {})
        return {"request_id":rid,"action":action,"supported":True,"engine_boot_id":self.boot,
          "admission":self.admission,"admission_generation":str(self.generation),
          "operation_id":self.operation[0] if self.operation else None,
          "operation_generation":self.operation[1] if self.operation else None,
          "observation_nonce":nonce,"observation_sequence":str(self.sequence),"virtual_engine_ids":[0],
          "snapshot":self.snapshot if self.operation else {},
          "queues":self.queues,
          "terminal_dispositions":terminal,"error":None}
    async def capability(self): self.calls.append("capability"); return self.response("cap","capability")
    async def begin(self,operation_id,generation):
        self.calls.append(("begin",operation_id,generation)); self.admission="CLOSED"; self.generation=int(generation); self.operation=(operation_id,generation)
        if self.fail_begin: raise TimeoutError("lost begin response")
        return self.response("begin","begin")
    async def observe(self,operation_id,generation,nonce):
        self.calls.append(("observe",operation_id,generation,nonce)); self.sequence+=1; return self.response("obs","observe",nonce)
    async def reopen(self,operation_id,generation):
        self.calls.append(("reopen",operation_id,generation)); self.admission="OPEN"; result=self.response("reopen","reopen"); self.operation=None; return result

class DrainLedgerTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/"ledger"; self.pod_uid="pod-uid"
        drain.initialize_ledger(self.root,self.pod_uid,"a"*32)
    def ledger(self): return drain.Ledger(self.root,self.pod_uid)
    async def coordinator(self,engine=None,events=None):
        engine=engine or FakeEngine(); events=events if events is not None else []
        async def snapshot(): events.append("proxy-snapshot"); return {"active":3}
        async def terminate(): events.append("proxy-terminate"); return {"cancelled":3,"remaining":0}
        c=drain.Coordinator(self.ledger(),engine,pod_uid=self.pod_uid,proxy_source="proxy-source",model_digest="model-digest",snapshot_proxy=snapshot,terminate_proxy=terminate)
        await c.initialize(); return c,engine
    def startup_coordinator(self, engine, *, timeout=0.3, retry=0.005):
        async def snapshot(): return {"active": 0}
        async def terminate(): return {"cancelled": 0, "remaining": 0}
        return drain.Coordinator(self.ledger(), engine, pod_uid=self.pod_uid,
            proxy_source="proxy-source", model_digest="model-digest",
            snapshot_proxy=snapshot, terminate_proxy=terminate,
            engine_startup_timeout=timeout, engine_startup_retry=retry)

    async def test_startup_waits_for_real_refused_connection_then_valid_capability(self):
        engine = FakeEngine()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        client = drain.EngineHTTPClient(f"http://127.0.0.1:{port}", "test-token", "engine-source")
        coordinator = self.startup_coordinator(client, timeout=1.0)
        before = (self.root / "ledger.json").read_bytes()
        requests = []
        async def handle(reader, writer):
            request = await reader.readuntil(b"\r\n\r\n")
            requests.append(request)
            body = json.dumps(engine.response("cap", "capability")).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        pending = asyncio.create_task(coordinator.initialize())
        await asyncio.sleep(0.05)
        self.assertFalse(pending.done())
        self.assertEqual((self.root / "ledger.json").read_bytes(), before)
        server = await asyncio.start_server(handle, "127.0.0.1", port)
        try:
            await pending
        finally:
            server.close()
            await server.wait_closed()
        self.assertTrue(coordinator.admission_open)
        self.assertEqual(len(requests), 1)
        self.assertIn(b"GET /phorvex/drain/capability HTTP/1.1", requests[0])
        self.assertIn(b"Authorization: Bearer test-token", requests[0])

    async def test_startup_connection_timeout_keeps_prior_ledger_unchanged(self):
        class Refused:
            def __init__(self, error): self.error = error
            async def capability(self):
                raise self.error
        first, _ = await self.coordinator()
        await first.create(await self.payload(first))
        before = (self.root / "ledger.json").read_bytes()
        for error in (httpx.ConnectError("connection refused"),
                      httpx.ConnectTimeout("engine still starting")):
            with self.subTest(error=type(error).__name__):
                coordinator = self.startup_coordinator(Refused(error), timeout=0.025,
                                                       retry=0.001)
                with self.assertRaisesRegex(drain.DrainError, "engine_startup_timeout"):
                    await coordinator.initialize()
                self.assertFalse(coordinator.admission_open)
                self.assertEqual((self.root / "ledger.json").read_bytes(), before)

    async def test_startup_refusal_and_invalid_capability_fail_without_retry(self):
        class Refused:
            def __init__(self, error): self.error=error; self.calls=0
            async def capability(self):
                self.calls += 1
                if isinstance(self.error, Exception): raise self.error
                return self.error
        bad = FakeEngine().response("cap", "capability")
        bad["engine_boot_id"] = "invalid-engine-boot-id"
        for value in (drain.DrainError(502, "engine_control_refused"), bad):
            with self.subTest(value=value):
                engine = Refused(value)
                coordinator = self.startup_coordinator(engine)
                before = (self.root / "ledger.json").read_bytes()
                with self.assertRaises(drain.DrainError):
                    await coordinator.initialize()
                self.assertEqual(engine.calls, 1)
                self.assertEqual((self.root / "ledger.json").read_bytes(), before)

    async def test_startup_real_http_auth_and_invalid_capability_fail_immediately(self):
        valid = FakeEngine().response("cap", "capability")
        wrong = dict(valid, engine_boot_id="invalid-engine-boot-id")
        for status, body, code in ((401, b'{"error":"unauthorized"}', "engine_control_refused"),
                                   (200, json.dumps(wrong).encode(), "unsupported_engine")):
            with self.subTest(status=status):
                requests = []
                async def handle(reader, writer):
                    requests.append(await reader.readuntil(b"\r\n\r\n"))
                    writer.write(f"HTTP/1.1 {status} test\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                server = await asyncio.start_server(handle, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                engine = drain.EngineHTTPClient(f"http://127.0.0.1:{port}", "test-token", "engine-source")
                coordinator = self.startup_coordinator(engine)
                before = (self.root / "ledger.json").read_bytes()
                try:
                    with self.assertRaisesRegex(drain.DrainError, code):
                        await coordinator.initialize()
                finally:
                    server.close()
                    await server.wait_closed()
                self.assertEqual(len(requests), 1)
                self.assertEqual((self.root / "ledger.json").read_bytes(), before)
    async def payload(self,c,generation="1",operation_id="1"*32,**extra):
        cap=await c.capability(); value={"schema":drain.SCHEMA,"operation_id":operation_id,"operation_generation":generation,"attempt":1,
          "owner":{"tenant":"t","namespace_uid":"n","policy_uid":"p","pod_uid":self.pod_uid,"service_uid":"s"},
          "expected_incarnation_digest":cap["incarnation_digest"],
          "deadline":(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat().replace("+00:00","Z"),"mode":"abort-and-quiesce"}
        value.update(extra); return value
    async def test_ordered_create_observe_reopen_and_new_tuple(self):
        events=[]; c,e=await self.coordinator(events=events); payload=await self.payload(c)
        code,created=await c.create(payload); self.assertEqual((code,created["state"]),(201,"DRAINING")); self.assertEqual(events,["proxy-snapshot","proxy-terminate"]); self.assertIsNone(created["query_nonce"])
        with self.assertRaisesRegex(drain.DrainError,"admission_closed"): c.admit_generation()
        code,duplicate=await c.create(payload); self.assertEqual(code,200); self.assertEqual(duplicate["receipt_sha256"],created["receipt_sha256"])
        self.assertEqual(sum(isinstance(x,tuple) and x[0]=="begin" for x in e.calls),1)
        first=await c.status("1","1"*32,"2"*32); second=await c.status("1","1"*32,"3"*32)
        self.assertEqual((first["state"],second["state"]),("DRAINING","QUIESCENT")); self.assertEqual([x["sequence"] for x in second["observations"]],["1","2"])
        self.assertEqual((first["query_nonce"],second["query_nonce"]),("2"*32,"3"*32))
        terminal=await c.status("1","1"*32,"9"*32); self.assertEqual(terminal["query_nonce"],"9"*32); self.assertNotEqual(terminal["receipt_sha256"],second["receipt_sha256"])
        opened=await c.reopen("1","1"*32,second["owner_digest"],second["backend_incarnation_digest"],second["revision"])
        self.assertEqual((opened["state"],opened["admission"]),("OPENED","OPEN")); c.admit_generation()
        code,new=await c.create(await self.payload(c,generation="2",operation_id="1"*32)); self.assertEqual((code,new["operation_generation"]),(201,"2"))
    async def test_terminal_status_rechecks_engine_incarnation_and_operation(self):
        for drift in ("boot", "admission", "operation", "generation"):
            with self.subTest(drift=drift):
                root=Path(self.temp.name)/drift; drain.initialize_ledger(root,self.pod_uid,("d" if drift=="boot" else "e" if drift=="admission" else "f" if drift=="operation" else "8")*32)
                old=self.root; self.root=root
                try:
                    c,e=await self.coordinator(); await c.create(await self.payload(c))
                    await c.status("1","1"*32,"2"*32)
                    terminal=await c.status("1","1"*32,"3"*32)
                    self.assertEqual(terminal["state"],"QUIESCENT")
                    same=await c.status("1","1"*32,"4"*32)
                    self.assertEqual(same["state"],"QUIESCENT")
                    if drift=="boot": e.boot="9"*32; e.admission="OPEN"; e.operation=None
                    elif drift=="admission": e.admission="OPEN"; e.operation=None
                    else: e.operation=("8"*32,"1")
                    if drift=="generation": e.operation=("1"*32,"1"); e.generation=2
                    changed=await c.status("1","1"*32,"5"*32)
                    self.assertEqual(changed["state"],"STALE" if drift=="boot" else "FAILED")
                    self.assertEqual((changed["admission"],c.admission_open),("CLOSED",False))
                finally:self.root=old
    async def test_reopening_lost_response_resolves_once_without_replay(self):
        for effect in ("opened", "changed-generation", "closed"):
            with self.subTest(effect=effect):
                root=Path(self.temp.name)/("reopen-"+effect); drain.initialize_ledger(root,self.pod_uid,("6" if effect=="opened" else "7" if effect=="closed" else "8")*32)
                old=self.root; self.root=root
                try:
                    c,e=await self.coordinator(); await c.create(await self.payload(c))
                    await c.status("1","1"*32,"2"*32); quiet=await c.status("1","1"*32,"3"*32)
                    real_reopen=e.reopen
                    async def lost(operation_id,generation):
                        if effect!="closed":
                            await real_reopen(operation_id,generation)
                            if effect=="changed-generation": e.generation+=1
                        raise TimeoutError("lost reopen response")
                    e.reopen=lost
                    with self.assertRaises(TimeoutError):
                        await c.reopen("1","1"*32,quiet["owner_digest"],quiet["backend_incarnation_digest"],quiet["revision"])
                    self.assertEqual(self.ledger().data["current"]["state"],"REOPENING")
                    recovered=await c.status("1","1"*32,"4"*32)
                    self.assertEqual(recovered["state"],"OPENED" if effect=="opened" else "FAILED")
                    self.assertEqual(recovered["admission"],"OPEN" if effect=="opened" else "CLOSED")
                    self.assertEqual(sum(isinstance(call,tuple) and call[0]=="reopen" for call in e.calls),0 if effect=="closed" else 1)
                finally:self.root=old
    async def test_lost_begin_failed_closed_and_restart_supersession(self):
        c,e=await self.coordinator(); payload=await self.payload(c); e.fail_begin=True
        with self.assertRaises(TimeoutError): await c.create(payload)
        persisted=self.ledger().data; self.assertEqual((persisted["admission"],persisted["current"]["state"]),("CLOSED","FAILED"))
        code,dup=await c.create(payload); self.assertEqual((code,dup["state"]),(200,"FAILED"))
        self.root=Path(self.temp.name)/"restart"; drain.initialize_ledger(self.root,self.pod_uid,"c"*32)
        first,_=await self.coordinator(FakeEngine("d"*32)); original=await self.payload(first); await first.create(original)
        replacement_engine=FakeEngine("e"*32); replacement_engine.admission="CLOSED"; replacement_engine.generation=1
        replacement,_=await self.coordinator(replacement_engine); stale=replacement.ledger.data["current"]; self.assertEqual(stale["state"],"STALE")
        stale_capability=await replacement.capability()
        self.assertEqual((stale_capability["admission"],stale_capability["next_operation_generation"]),("CLOSED","2"))
        sup={"operation_generation":stale["operation_generation"],"operation_id":stale["operation_id"],"revision":stale["revision"]}
        code,result=await replacement.create(await self.payload(replacement,generation="2",operation_id="4"*32,attempt=2,supersedes=sup))
        self.assertEqual((code,result["state"]),(201,"DRAINING")); self.assertEqual(replacement.ledger.data["history"][0]["state"],"STALE")
    async def test_attempt_and_supersession_are_exact(self):
        c,_=await self.coordinator()
        stale={"operation_generation":"1","operation_id":"2"*32,"revision":"1"}
        for candidate in (
                await self.payload(c,attempt=2),
                await self.payload(c,supersedes=stale)):
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                    drain.DrainError,"invalid_attempt_supersession"):
                drain.validate_create(candidate)
    async def test_cancel_stays_closed_until_two_observations(self):
        c,_=await self.coordinator(); _,created=await c.create(await self.payload(c))
        cancelled=await c.cancel("1","1"*32,created["owner_digest"],created["backend_incarnation_digest"],created["revision"]); self.assertEqual(cancelled["state"],"CANCEL_REQUESTED")
        one=await c.status("1","1"*32,"5"*32); two=await c.status("1","1"*32,"6"*32)
        self.assertEqual((one["state"],two["state"]),("CANCEL_REQUESTED","CANCELLED")); self.assertFalse(c.admission_open)
    async def test_duplicate_cancel_does_not_slide_boundary_or_revision(self):
        c,_=await self.coordinator(); _,created=await c.create(await self.payload(c))
        args=("1","1"*32,created["owner_digest"],created["backend_incarnation_digest"],created["revision"])
        first=await c.cancel(*args); second=await c.cancel(*args)
        self.assertEqual(first["state"],"CANCEL_REQUESTED")
        for field in ("revision","cancellation_grace_deadline","transition_reason","cancel_boundary_revision","last_transition"):
            self.assertEqual(second[field],first[field],field)
    async def test_cancel_needs_zero_queues_and_complete_dispositions(self):
        for mode in ("active","missing-terminal"):
            with self.subTest(mode=mode):
                root=Path(self.temp.name)/mode; drain.initialize_ledger(root,self.pod_uid,("b" if mode=="active" else "c")*32)
                old=self.root; self.root=root
                try:
                    c,e=await self.coordinator()
                    if mode=="missing-terminal": e.omit_terminal=True
                    _,created=await c.create(await self.payload(c))
                    await c.cancel("1","1"*32,created["owner_digest"],created["backend_incarnation_digest"],created["revision"])
                    if mode=="active": e.queues={"0":{"waiting":[],"running":["late"],"swapped":[],"cached":[]}}
                    one=await c.status("1","1"*32,"a"*32); two=await c.status("1","1"*32,"b"*32)
                    self.assertEqual((one["state"],two["state"]),("CANCEL_REQUESTED","CANCEL_REQUESTED"))
                    self.assertFalse(c.admission_open)
                finally:self.root=old
    async def test_grace_expiry_fails_closed_without_observation(self):
        c,e=await self.coordinator(); _,created=await c.create(await self.payload(c))
        record=c.ledger.data["current"]
        deadline=datetime.now(timezone.utc)-timedelta(seconds=31)
        record["deadline"]=deadline.isoformat().replace("+00:00","Z")
        record["cancellation_grace_deadline"]=drain.deadline_text(deadline+timedelta(seconds=30))
        record["canonical_create"]["deadline"]=record["deadline"]
        c.ledger.write(); before=len([x for x in e.calls if isinstance(x,tuple) and x[0]=="observe"])
        failed=await c.status("1","1"*32,"c"*32)
        self.assertEqual((failed["state"],failed["admission"]),("FAILED","CLOSED"))
        self.assertEqual(failed["transition_reason"],"deadline-expired")
        self.assertEqual(len([x for x in e.calls if isinstance(x,tuple) and x[0]=="observe"]),before)
    async def test_normal_deadline_enters_fixed_cancel_grace_and_never_grants_success(self):
        c,_=await self.coordinator()
        deadline=(datetime.now(timezone.utc)+timedelta(milliseconds=50)).isoformat().replace("+00:00","Z")
        _,created=await c.create(await self.payload(c,deadline=deadline))
        await __import__("asyncio").sleep(0.06)
        one=await c.status("1","1"*32,"7"*32)
        self.assertEqual((one["state"],one["admission"]),("CANCEL_REQUESTED","CLOSED"))
        self.assertFalse(c.admission_open)
        two=await c.status("1","1"*32,"8"*32)
        self.assertEqual((two["state"],two["admission"]),("CANCELLED","CLOSED"))
        opened=await c.reopen("1","1"*32,two["owner_digest"],two["backend_incarnation_digest"],two["revision"])
        self.assertEqual((opened["state"],opened["admission"]),("OPENED","OPEN"))
    async def test_generation_conflict_expiry_capacity_and_engine_drift(self):
        c,e=await self.coordinator(); payload=await self.payload(c)
        _,created=await c.create(payload)
        conflict=dict(payload); conflict["operation_id"]="2"*32
        with self.assertRaisesRegex(drain.DrainError,"generation_conflict"):
            await c.create(conflict)
        e.boot="c"*32
        with self.assertRaisesRegex(drain.DrainError,"engine_incarnation_changed"):
            await c.status("1","1"*32,"7"*32)
        self.assertEqual(self.ledger().data["current"]["state"],"STALE")

        # A retained generation conflicts; an evicted generation is expired.
        ledger=self.ledger(); data=ledger.data; stale=data["current"]
        stale["state"]="OPENED"; stale["last_transition"]="2000-01-01T00:00:00Z"
        data["history"]=[]
        for i in range(1,65):
            retained=dict(stale,operation_generation=str(i),operation_id=f"{i:032x}")
            retained["canonical_create"]=dict(
                stale["canonical_create"], operation_generation=str(i),
                operation_id=f"{i:032x}")
            data["history"].append(retained)
        data["current"]=None; data["generation_high_water"]="64"; data["admission"]="OPEN"
        ledger.write()
        fresh,_=await self.coordinator(FakeEngine("d"*32))
        with self.assertRaisesRegex(drain.DrainError,"generation_conflict"):
            await fresh.create(await self.payload(fresh,generation="64",operation_id="f"*32))
        code,_=await fresh.create(await self.payload(fresh,generation="65",operation_id="e"*32))
        self.assertEqual(code,201)
        self.assertEqual(len(fresh.ledger.data["history"]),63)
        with self.assertRaisesRegex(drain.DrainError,"expired_generation"):
            await fresh.status("1","1"*32,"8"*32)

    async def test_64_real_operations_capacity_preflight_and_http_refusal_preserve_all_proofs(self):
        c,e=await self.coordinator()
        for generation in range(1,65):
            operation_id=f"{generation:032x}"
            code,_=await c.create(await self.payload(c,str(generation),operation_id))
            self.assertEqual(code,201)
            await c.status(str(generation),operation_id,"a"*32)
            terminal=await c.status(str(generation),operation_id,"b"*32)
            opened=await c.reopen(str(generation),operation_id,terminal["owner_digest"],
                                  terminal["backend_incarnation_digest"],terminal["revision"])
            self.assertEqual(opened["state"],"OPENED")
        before=(self.root/"ledger.json").read_bytes()
        capability=await c.capability()
        self.assertEqual((capability["admission"],capability["generation_high_water"]),("OPEN","64"))
        self.assertNotIn("next_operation_generation",capability)
        self.assertEqual((self.root/"ledger.json").read_bytes(),before)
        payload=await self.payload(c,"65","e"*32)
        calls=list(e.calls)
        # Actual FastAPI wrapper + actual Coordinator/ledger producer, with only
        # the GPU scheduler's RPC boundary represented by FakeEngine.
        app=guardrail_proxy.create_app(runtime=None,load_models=False,
                                      admin_api_key="admin",drain_coordinator=c)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
            response=await client.post("/v1/drain/operations",json=payload,
                                       headers={"Authorization":"Bearer admin"})
            self.assertEqual((response.status_code,response.json()),(503,{"error":"ledger_capacity"}))
            self.assertTrue(response.headers["content-type"].startswith("application/json"))
            missing=await client.get("/v1/drain/operations/65/"+"e"*32+"?observation_nonce="+"c"*32,
                                    headers={"Authorization":"Bearer admin"})
            self.assertEqual((missing.status_code,missing.json()),(404,{"error":"unknown_operation"}))
        self.assertEqual(e.calls,calls)  # no engine capability/begin/abort RPC after rejection
        self.assertEqual((self.root/"ledger.json").read_bytes(),before)
        self.assertEqual((len(c.ledger.data["history"]),c.ledger.data["current"],e.admission,e.generation),
                         (64,None,"OPEN",64))

    async def test_capacity_admission_slot_and_exact_retention_boundary(self):
        c,_=await self.coordinator()
        fixed=datetime(2026,9,28,12,tzinfo=timezone.utc)
        class FrozenDateTime(datetime):
            @classmethod
            def now(cls,tz=None): return fixed
        recent={"state":"OPENED","last_transition":drain.deadline_text(fixed)}
        eligible={"state":"OPENED","last_transition":drain.deadline_text(fixed-timedelta(hours=24))}
        too_recent={"state":"OPENED","last_transition":drain.deadline_text(fixed-timedelta(hours=24)+timedelta(microseconds=1))}
        with patch.object(drain,"datetime",FrozenDateTime):
            c.ledger.data["history"]=[dict(recent) for _ in range(63)]
            self.assertEqual(c._capacity_evictions(None),[])
            self.assertIsNone(c._capacity_evictions({"state":"STALE"}))
            c.ledger.data["history"][0]=eligible
            self.assertEqual(c._capacity_evictions({"state":"STALE"}),[0])
            c.ledger.data["history"].append(dict(recent))
            self.assertEqual(c._capacity_evictions(None),[0])
            c.ledger.data["history"][0]=too_recent
            self.assertIsNone(c._capacity_evictions(None))
            c.ledger.data["history"][0]=dict(eligible,state="STALE")
            self.assertIsNone(c._capacity_evictions(None))
    def test_decimal_strict_json_corruption_and_new_domain(self):
        for v in ("0",str(2**53-1),str(2**53),str(2**64-1)): self.assertEqual(drain.u64(v,"x"),int(v))
        for v in (0,-1,"-1","01",str(2**64),1.0):
            with self.assertRaises(drain.DrainError): drain.u64(v,"x")
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}'):
            with self.assertRaises(drain.DrainError): drain.strict_loads(raw,max_bytes=100)
        other=Path(self.temp.name)/"other"; drain.initialize_ledger(other,"new-pod","e"*32)
        self.assertNotEqual(self.ledger().ledger_id,drain.Ledger(other,"new-pod").ledger_id)
        with self.assertRaises(RuntimeError): drain.Ledger(other,self.pod_uid)
        with self.assertRaises(RuntimeError): drain.initialize_ledger(self.root,self.pod_uid,"d"*32)
        (self.root/"ledger.json").write_text("{}")
        with self.assertRaises((RuntimeError,drain.DrainError)): self.ledger()
    def test_transaction_residue_refuses_restart(self):
        (self.root/"ledger-write-interrupted.tmp").write_text("partial")
        with self.assertRaisesRegex(RuntimeError,"transaction residue"):
            self.ledger()
    def test_canonical_unicode_html_and_integer_boundaries(self):
        value={"a":"<tag>&\u2028\u2029\x01","b":r"literal\u2028"}
        self.assertEqual(drain.canonical_bytes(value).hex(),"7b2261223a223c7461673e26e280a8e280a95c7530303031222c2262223a226c69746572616c5c5c7532303238227d")
        self.assertEqual(drain.domain_digest("phorvex-test-v1",value),"8110fa35f0f6250d8b1b6421e8d959b0259f13ba8d25c90ac5d254e6618b1189")
        self.assertEqual(drain.canonical_bytes({"n":drain.MAX_SAFE_JSON_INTEGER}),b'{"n":9007199254740991}')
        for invalid in (drain.MAX_SAFE_JSON_INTEGER+1,-1,1.0,float("inf")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError): drain.canonical_bytes({"n":invalid})
        self.assertEqual(drain.u64("18446744073709551615","n"),drain.MAX_U64)
        for invalid in ("01","-1","18446744073709551616",9007199254740992):
            with self.subTest(invalid=invalid), self.assertRaises(drain.DrainError): drain.u64(invalid,"n")

# Deliberately defined after the direct ledger tests: this imports the actual
# FastAPI producer but does not load model dependencies.
import json
import httpx
import guardrail_proxy

class FakeCoordinator:
    def __init__(self): self.calls=[]; self.open=True
    async def initialize(self): self.calls.append("initialize")
    async def capability(self): self.calls.append("capability"); return {"schema":drain.SCHEMA}
    async def create(self,body): self.calls.append(("create",body)); return 201,{"state":"DRAINING"}
    async def status(self,generation,operation_id,nonce): self.calls.append(("status",generation,operation_id,nonce)); return {"state":"QUIESCENT"}
    async def cancel(self,*args): self.calls.append(("cancel",)+args); return {"state":"CANCEL_REQUESTED"}
    async def reopen(self,*args): self.calls.append(("reopen",)+args); return {"state":"OPENED"}
    def admit_generation(self):
        self.calls.append("admit")
        if not self.open: raise drain.DrainError(503,"admission_closed")

class DrainHTTPProducerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.coordinator=FakeCoordinator()
        class ReadyRuntime:
            def snapshot(self): return "pgv2","enforce",0.5,True,0
            def score(self,_variant,_text): return 0.1
            def public_state(self): return {"ready":True}
        runtime=ReadyRuntime()
        self.app=guardrail_proxy.create_app(runtime=runtime,load_models=False,
          admin_api_key="admin",drain_coordinator=self.coordinator)
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),base_url="http://test")
    async def asyncTearDown(self): await self.client.aclose()
    async def test_auth_exact_body_and_routes(self):
        self.assertEqual((await self.client.get("/v1/drain/capability")).status_code,401)
        auth={"Authorization":"Bearer admin"}
        response=await self.client.get("/v1/drain/capability",headers=auth); self.assertEqual((response.status_code,response.json()),(200,{"schema":drain.SCHEMA}))
        body={"schema":drain.SCHEMA,"operation_id":"1"*32,"operation_generation":"1","attempt":1,
          "owner":{"tenant":"t","namespace_uid":"n","policy_uid":"p","pod_uid":"u","service_uid":"s"},
          "expected_incarnation_digest":"2"*64,"deadline":"x","mode":"abort-and-quiesce"}
        response=await self.client.post("/v1/drain/operations",headers={**auth,"Content-Type":"application/json"},content=json.dumps(body)); self.assertEqual(response.status_code,201)
        response=await self.client.post("/v1/drain/operations",headers={**auth,"Content-Type":"application/json"},content=b'{"x":1,"x":2}'); self.assertEqual(response.status_code,400)
        response=await self.client.get("/v1/drain/operations/1/"+"1"*32+"?observation_nonce="+"3"*32,headers=auth); self.assertEqual(response.json()["state"],"QUIESCENT")
        intent={"owner_digest":"4"*64,"expected_incarnation_digest":"5"*64,"expected_revision":"2"}
        for suffix,state in (("cancel","CANCEL_REQUESTED"),("reopen","OPENED")):
            response=await self.client.post("/v1/drain/operations/1/"+"1"*32+"/"+suffix,headers={**auth,"Content-Type":"application/json"},content=json.dumps(intent)); self.assertEqual(response.json()["state"],state)
        response=await self.client.post("/v1/drain",headers={"Content-Type":"application/json"},content=b'{}'); self.assertEqual(response.status_code,410)
    async def test_http_refuses_ambiguous_or_oversized_admin_bodies(self):
        auth={"Authorization":"Bearer admin"}
        cases=(
          ({**auth,"Content-Type":"text/plain"},b"{}",415),
          ({**auth,"Content-Type":"application/json"},b'{"x":NaN}',400),
          ({**auth,"Content-Type":"application/json"},b'{"x":1,"x":2}',400),
          ({**auth,"Content-Type":"application/json"},b'{"unknown":1}',400),
          ({**auth,"Content-Type":"application/json"},b'{' + b'"x":"' + b'a'*17000 + b'"}',413),
        )
        for headers,body,want in cases:
            with self.subTest(want=want,body=body[:32]):
                response=await self.client.post("/v1/drain/operations",headers=headers,content=body)
                self.assertEqual(response.status_code,want)
    async def test_closed_gate_refuses_before_upstream(self):
        self.coordinator.open=False
        response=await self.client.post("/v1/completions",headers={"Content-Type":"application/json"},content=b'{"prompt":"benign"}')
        self.assertEqual(response.status_code,503)
        self.assertEqual(response.json(),{"error":"admission_closed"})
        self.assertIn("admit",self.coordinator.calls)

if __name__=="__main__": unittest.main()
