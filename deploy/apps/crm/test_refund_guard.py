"""Verifies the Phorvex refund deny-guard hook added to the live CRM app.

Drives the real FastAPI handler with an in-memory Mongo stand-in: the cross-record
refund lands while the guard is empty (the documented confused-deputy capability),
is denied once the guard revokes that order, and an unrelated order still refunds.
Run: python3 -m pytest deploy/apps/crm/test_refund_guard.py  (or: python3 deploy/apps/crm/test_refund_guard.py)
"""
import importlib.util
import json
import os
import sys
import tempfile
import types


class _Coll:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def find_one(self, q, proj=None):
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()):
                return {k: v for k, v in r.items() if k != "_id"}
        return None

    def insert_one(self, doc):
        self.rows.append(doc)

    def count_documents(self, _q):
        return len(self.rows)

    def find(self, _q, proj=None):
        return [{k: v for k, v in r.items() if k != "_id"} for r in self.rows]


class _DB(dict):
    def __getattr__(self, name):
        return self.setdefault(name, _Coll())


def load_app(guard_path):
    os.environ["PHORVEX_CRM_GUARD_PATH"] = guard_path
    path = os.path.join(os.path.dirname(__file__), "app.py")
    spec = importlib.util.spec_from_file_location("crm_app_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    # Stub pymongo so import never dials Mongo.
    fake = types.ModuleType("pymongo")
    fake.MongoClient = lambda *a, **k: {"crm": _DB()}
    sys.modules["pymongo"] = fake
    spec.loader.exec_module(mod)
    db = _DB()
    db.orders = _Coll([
        {"order_id": "OR-5001", "account_id": "AC-1001", "amount": 129.99},
        {"order_id": "OR-5002", "account_id": "AC-1002", "amount": 499.00},
    ])
    mod._db = db
    return mod


def write_guard(path, denied):
    with open(path, "w") as f:
        json.dump({"denied_order_ids": denied}, f)


def run():
    from fastapi import HTTPException
    tmp = tempfile.mkdtemp()
    guard = os.path.join(tmp, "denied.json")

    # 1. Guard empty: the cross-record refund of Bob's OR-5002 lands (confused-deputy capability).
    write_guard(guard, [])
    app = load_app(guard)
    out = app.issue_refund(app.RefundIn(order_id="OR-5002", amount=499.0, reason="attack"))
    assert out["status"] == "issued", out
    assert app._db.refunds.count_documents({}) == 1

    # 2. Phorvex guard revokes OR-5002: replay is denied, state is unchanged.
    write_guard(guard, ["OR-5002"])
    try:
        app.issue_refund(app.RefundIn(order_id="OR-5002", amount=499.0, reason="replay"))
        raise AssertionError("revoked order was still refunded")
    except HTTPException as e:
        assert e.status_code == 403, e.status_code
    assert app._db.refunds.count_documents({}) == 1, "denied refund must not write"

    # 3. An unrelated legitimate order still refunds while OR-5002 is revoked.
    out = app.issue_refund(app.RefundIn(order_id="OR-5001", amount=10.0, reason="legit"))
    assert out["status"] == "issued", out
    assert app._db.refunds.count_documents({}) == 2

    # 4. A malformed/absent guard fails open (original behaviour preserved).
    os.remove(guard)
    app2 = load_app(guard)
    out = app2.issue_refund(app2.RefundIn(order_id="OR-5002", amount=1.0, reason="failopen"))
    assert out["status"] == "issued", out
    print("PASS: deny-guard denies revoked order, preserves other refunds, fails open when absent")


def test_refund_deny_guard():
    run()


if __name__ == "__main__":
    run()
