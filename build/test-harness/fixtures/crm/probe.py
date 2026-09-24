"""Synthetic, isolated CRM fixture driver. Never points at the installed CRM/Mongo."""
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from pymongo import MongoClient


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def key(name, run):
    return f"CAT-{run}-{name}"


def record_hash(record):
    clean = {k: v for k, v in record.items() if k != "_id"}
    raw = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def request(method, path, body=None):
    url = "http://127.0.0.1:8080" + path
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with OPENER.open(req, timeout=5) as response:
            raw = response.read(16385)
            if len(raw) > 16384:
                raise RuntimeError("response too large")
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as error:
        return error.code, {}


def require_success(result):
    status, body = result
    if status != 200 or not isinstance(body, dict):
        raise RuntimeError(f"unexpected CRM status {status}")
    return body


def main(argv):
    if len(argv) < 4 or argv[1] not in ("seed", "execute", "observe") or argv[2] not in ("refund", "reset"):
        raise RuntimeError("invalid fixture invocation")
    phase, case, run = argv[1:4]
    if not re.fullmatch(r"[a-z0-9]{8,24}", run):
        raise RuntimeError("invalid synthetic run ID")
    # This process can only use the Mongo sidecar in the same isolated Pod.
    db = MongoClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=3000)["crm"]
    account_a, account_b = key("account-a", run), key("account-b", run)
    order_a, order_b = key("order-a", run), key("order-b", run)
    phone_a, phone_b = "+15550000101", "+15550000102"
    if phase == "seed":
        if db.accounts.count_documents({"account_id": {"$in": [account_a, account_b]}}) or db.orders.count_documents({"order_id": {"$in": [order_a, order_b]}}):
            raise RuntimeError("synthetic run IDs already present")
        accounts = [
            {"account_id": account_a, "phone": phone_a, "name": "Fixture A", "tier": "standard"},
            {"account_id": account_b, "phone": phone_b, "name": "Fixture B", "tier": "standard"},
        ]
        orders = [
            {"order_id": order_a, "account_id": account_a, "item": "synthetic-a", "amount": 1.0, "status": "delivered"},
            {"order_id": order_b, "account_id": account_b, "item": "synthetic-b", "amount": 1.0, "status": "delivered"},
        ]
        db.accounts.insert_many(accounts)
        db.orders.insert_many(orders)
        emit({"schema": 1, "phase": phase, "case": case, "run": run,
              "account_ids": [account_a, account_b], "order_ids": [order_a, order_b],
              "baseline_hashes": {"account_a": record_hash(accounts[0]), "account_b": record_hash(accounts[1]),
                                  "order_a": record_hash(orders[0]), "order_b": record_hash(orders[1])}})
        return
    if phase == "execute":
        a = require_success(request("GET", "/accounts/by-phone/" + urllib.parse.quote(phone_a, safe="")))
        orders = require_success(request("GET", "/orders/by-phone/" + urllib.parse.quote(phone_a, safe="")))
        if a.get("account_id") != account_a or orders.get("account_id") != account_a or [x.get("order_id") for x in orders.get("orders", [])] != [order_a]:
            raise RuntimeError("legitimate A read control failed")
        result = {"schema": 1, "phase": phase, "case": case, "run": run, "legitimate_read": True}
        if case == "refund":
            appt = require_success(request("POST", "/appointments", {"phone": phone_a, "date": "2030-01-01"}))
            own = require_success(request("POST", "/refunds", {"order_id": order_a, "amount": 1.0, "reason": "synthetic-own-control"}))
            cross_status, cross = request("POST", "/refunds", {"order_id": order_b, "amount": 1.0, "reason": "synthetic-cross-control"})
            if cross_status not in (200, 401, 403):
                raise RuntimeError(f"unexpected cross-record status {cross_status}")
            result.update({"appointment_id": appt.get("appointment_id"), "own_refund_id": own.get("refund_id"),
                           "cross_status": cross_status, "cross_refund_id": cross.get("refund_id"), "own_order_id": own.get("order_id"),
                           "cross_order_id": cross.get("order_id")})
        else:
            own = require_success(request("POST", "/password-resets", {"phone": phone_a}))
            cross_status, cross = request("POST", "/password-resets", {"phone": phone_b})
            if cross_status not in (200, 401, 403):
                raise RuntimeError(f"unexpected cross-record status {cross_status}")
            result.update({"own_reset_account_id": own.get("account_id"),
                           "cross_status": cross_status, "cross_reset_account_id": cross.get("account_id")})
        emit(result)
        return
    if len(argv) != 6:
        raise RuntimeError("observe requires two exact created IDs")
    own_id, cross_id = argv[4:6]
    docs = [db.accounts.find_one({"account_id": account_a}), db.accounts.find_one({"account_id": account_b}),
            db.orders.find_one({"order_id": order_a}), db.orders.find_one({"order_id": order_b})]
    if any(x is None for x in docs):
        raise RuntimeError("synthetic baseline record missing")
    hashes = {k: record_hash(v) for k, v in zip(("account_a", "account_b", "order_a", "order_b"), docs)}
    result = {"schema": 1, "phase": phase, "case": case, "run": run, "baseline_hashes": hashes}
    if case == "refund":
        # The two order IDs were created only for this run. Discover writes by
        # independent Mongo readback even when the HTTP response omitted an ID.
        own = list(db.refunds.find({"order_id": order_a}))
        cross = list(db.refunds.find({"order_id": order_b}))
        if len(own) != 1 or len(cross) > 1:
            raise RuntimeError("refund write cardinality is inconclusive")
        if own[0].get("refund_id") != own_id or own[0].get("reason") != "synthetic-own-control" or own[0].get("amount") != 1.0:
            raise RuntimeError("legitimate refund does not match exact request")
        if cross:
            if cross[0].get("reason") != "synthetic-cross-control" or cross[0].get("amount") != 1.0 or not cross[0].get("refund_id"):
                raise RuntimeError("cross refund does not match exact request")
            if cross_id != "-" and cross[0]["refund_id"] != cross_id:
                raise RuntimeError("cross refund response ID differs from Mongo")
        elif cross_id != "-":
            raise RuntimeError("cross refund response ID lacks Mongo record")
        result.update({"own_exact_count": len(own), "cross_exact_count": len(cross),
                       "own_created_id": own[0]["refund_id"],
                       "cross_created_id": cross[0]["refund_id"] if cross else "",
                       "own_order_id": own[0]["order_id"],
                       "cross_order_id": cross[0]["order_id"] if cross else None,
                       "appointment_exact_count": db.appointments.count_documents({"phone": phone_a, "date": "2030-01-01"})})
    else:
        own = list(db.resets.find({"phone": phone_a}))
        cross = list(db.resets.find({"phone": phone_b}))
        result.update({"own_exact_count": len(own), "cross_exact_count": len(cross),
                       "own_created_id": str(own[0]["_id"]) if len(own) == 1 else "",
                       "cross_created_id": str(cross[0]["_id"]) if len(cross) == 1 else "",
                       "own_account_id": own[0].get("account_id") if len(own) == 1 else None,
                       "cross_account_id": cross[0].get("account_id") if len(cross) == 1 else None})
    emit(result)


if __name__ == "__main__":
    main(sys.argv)
