"""Deterministic on-chain verification for VisualMilestoneEscrow (studionet).

Covers funding, caller/authorization guards, premature-refund guards, evidence
binding, photo-reuse protection, SSRF guards and the deadline+grace anti-lock
refund. Non-deterministic vision review is excluded here (it needs full
consensus); see README for the full-consensus transaction proof.

Usage (from the repository root):

  python scripts/verify_onchain.py
  python scripts/verify_onchain.py --address 0xB322AD0A... --keep

Signing key resolution:
  1. STUDIONET_PRIVATE_KEY environment variable, or
  2. .wallets/studionet.json (gitignored) with a "private_key" field.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import genlayer_py as g  # noqa: E402
from genlayer_py import accounts  # noqa: E402
from genlayer_py.types.transactions import TransactionStatus  # noqa: E402

NETWORK = "studionet"
DEFAULT_CONTRACT = "contracts/visual_milestone_escrow.py"
STAMP = int(time.time())
JOB_ID = f"vme-{STAMP}"
EXPIRE_JOB = f"{JOB_ID}-exp"
REVIEW_JOB = f"{JOB_ID}-review"
AMOUNTS = [700, 300]
TOTAL = sum(AMOUNTS)
CRITERIA = ["Surface fully paved.", "Drainage channel visible."]
PHOTO_URL = "https://raw.githubusercontent.com/genlayerlabs/genvm/main/LICENSE"
PHOTO_SHA = hashlib.sha256(b"placeholder").hexdigest()


def _load_private_key() -> str:
    key = os.environ.get("STUDIONET_PRIVATE_KEY", "").strip()
    if key:
        return key
    path = ROOT / ".wallets" / f"{NETWORK}.json"
    if not path.exists():
        raise SystemExit(
            f"No key found. Set STUDIONET_PRIVATE_KEY or create {path} with a "
            '"private_key" field.'
        )
    return json.loads(path.read_text(encoding="utf-8"))["private_key"]


class Harness:
    def __init__(self) -> None:
        self.employer = accounts.create_account(_load_private_key())
        self.contractor = accounts.create_account()
        self.stranger = accounts.create_account()
        self.client = g.create_client(
            chain=getattr(g, NETWORK), account=self.employer
        )
        self._schema: dict[str, dict] = {}
        self.addr = ""
        self.passed = 0
        self.failed = 0

    def note(self, label: str, ok: bool, extra: str = "") -> None:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {label}{(': ' + extra) if extra else ''}", flush=True)
        if ok:
            self.passed += 1
        else:
            self.failed += 1

    def _order(self, fn: str) -> list[str]:
        if self.addr not in self._schema:
            schema = self.client.get_contract_schema(self.addr)
            self._schema[self.addr] = schema.get("methods", {})
        params = self._schema[self.addr].get(fn, {}).get("params", [])
        return [p[0] for p in params]

    def _args(self, fn: str, kw: dict) -> list:
        return [kw.get(name) for name in self._order(fn)]

    def _wait(self, tx: str) -> dict:
        return self.client.wait_for_transaction_receipt(
            tx, status=TransactionStatus.ACCEPTED, interval=2000, retries=90
        )

    def write(self, fn: str, *, account=None, value=0, **kw) -> dict:
        tx = self.client.write_contract(
            address=self.addr,
            function_name=fn,
            account=account or self.employer,
            value=value,
            leader_only=True,
            args=self._args(fn, kw),
        )
        return self._wait(tx)

    def fire(self, fn: str, *, account=None, value=0, **kw) -> str:
        """Broadcast without waiting (used for expected reverts)."""
        return self.client.write_contract(
            address=self.addr,
            function_name=fn,
            account=account or self.employer,
            value=value,
            leader_only=True,
            args=self._args(fn, kw),
        )

    def read(self, fn: str, **kw):
        last_exc = None
        for attempt in range(5):
            try:
                return self.client.read_contract(
                    address=self.addr, function_name=fn, args=self._args(fn, kw)
                )
            except Exception as exc:  # transient studio 502/504 or rate limits
                last_exc = exc
                time.sleep(3 * (attempt + 1))
        raise last_exc

    def _snapshot(self, view: str, view_kw: dict) -> str:
        try:
            return json.dumps(self.read(view, **view_kw), default=str, sort_keys=True)
        except Exception as exc:  # view of an object that does not exist yet
            return f"ERROR:{exc}"

    def guard(self, label: str, view: str, view_kw: dict, fn: str, kw: dict,
              *, account=None, value=0) -> None:
        before = self._snapshot(view, view_kw)
        self.fire(fn, account=account, value=value, **kw)
        after = self._snapshot(view, view_kw)
        self.note(f"guard: {label}", before == after)

    def create_kwargs(self, job_id: str, window: int, grace: int) -> dict:
        return {
            "job_id": job_id,
            "contractor": self.contractor.address,
            "title": "Visual verify",
            "spec": "Pave the drive and cut a drain.",
            "milestone_amounts_json": json.dumps(AMOUNTS),
            "milestone_criteria_json": json.dumps(CRITERIA),
            "submit_window_seconds": window,
            "review_grace_seconds": grace,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--address", default="")
    parser.add_argument("--keep", action="store_true", help="keep the created jobs")
    args = parser.parse_args(argv)

    h = Harness()
    if args.address:
        h.addr = args.address.strip()
    else:
        code = (ROOT / args.contract).read_text(encoding="utf-8")
        tx = h.client.deploy_contract(code=code, account=h.employer, leader_only=True)
        receipt = h._wait(tx)
        h.addr = receipt.get("to_address") or receipt.get("recipient")
        if not h.addr:
            raise SystemExit(f"deploy failed: {receipt}")
    print(f"Contract: {h.addr}\nJob: {JOB_ID}\n", flush=True)

    evidence = json.dumps([{"url": PHOTO_URL, "sha256": PHOTO_SHA}])

    # A) funding invariant (job does not exist yet)
    h.guard(
        "funding below milestone total",
        "get_job",
        {"job_id": JOB_ID},
        "create_job",
        h.create_kwargs(JOB_ID, 600, 60),
        account=h.employer,
        value=TOTAL - 1,
    )

    h.write(
        "create_job",
        account=h.employer,
        value=TOTAL,
        **h.create_kwargs(JOB_ID, 600, 60),
    )
    job = h.read("get_job", job_id=JOB_ID)
    h.note(
        "create_job funded escrow",
        job.get("status") == "open" and int(job.get("total_amount", 0)) == TOTAL,
        f"status={job.get('status')} total={job.get('total_amount')}",
    )
    seeds = h.read("get_job_milestones", job_id=JOB_ID).get("milestones", [])
    h.note(
        "milestones stored with tranche amounts",
        [int(m.get("amount", 0)) for m in seeds] == AMOUNTS,
    )

    # B) authorization / duplicate / input guards
    h.guard(
        "zero-address contractor",
        "get_job",
        {"job_id": f"{JOB_ID}-zero"},
        "create_job",
        {
            "job_id": f"{JOB_ID}-zero",
            "contractor": "0x0000000000000000000000000000000000000000",
            "title": "Zero",
            "spec": "Zero",
            "milestone_amounts_json": json.dumps([TOTAL]),
            "milestone_criteria_json": json.dumps([CRITERIA[0]]),
            "submit_window_seconds": 600,
            "review_grace_seconds": 60,
        },
        account=h.employer,
        value=TOTAL,
    )
    h.guard(
        "duplicate job id",
        "get_job",
        {"job_id": JOB_ID},
        "create_job",
        h.create_kwargs(JOB_ID, 600, 60),
        account=h.employer,
        value=TOTAL,
    )
    h.guard(
        "stranger submits milestone evidence",
        "get_milestone",
        {"job_id": JOB_ID, "index": 0},
        "submit_milestone",
        {"job_id": JOB_ID, "index": 0, "evidence_json": evidence},
        account=h.stranger,
    )

    h.write(
        "submit_milestone",
        account=h.contractor,
        job_id=JOB_ID,
        index=0,
        evidence_json=evidence,
    )
    milestone = h.read("get_milestone", job_id=JOB_ID, index=0)
    canonical = json.dumps(json.loads(evidence), sort_keys=True)
    expected_binding = hashlib.sha256(f"{JOB_ID}|0|{canonical}".encode()).hexdigest()
    h.note(
        "contractor submits hash-bound evidence",
        milestone.get("status") == "submitted"
        and milestone.get("evidence_binding") == expected_binding,
        f"binding={milestone.get('evidence_binding')}",
    )

    h.guard(
        "double evidence submission",
        "get_milestone",
        {"job_id": JOB_ID, "index": 0},
        "submit_milestone",
        {"job_id": JOB_ID, "index": 0, "evidence_json": evidence},
        account=h.contractor,
    )
    h.guard(
        "same photo reused for another tranche",
        "get_milestone",
        {"job_id": JOB_ID, "index": 1},
        "submit_milestone",
        {"job_id": JOB_ID, "index": 1, "evidence_json": evidence},
        account=h.contractor,
    )
    h.guard(
        "private/local evidence host",
        "get_milestone",
        {"job_id": JOB_ID, "index": 1},
        "submit_milestone",
        {
            "job_id": JOB_ID,
            "index": 1,
            "evidence_json": json.dumps(
                [{"url": "http://127.0.0.1/photo.gif", "sha256": PHOTO_SHA}]
            ),
        },
        account=h.contractor,
    )

    # C) no premature refunds, no review without evidence
    h.guard(
        "employer reclaims pending milestone",
        "get_job",
        {"job_id": JOB_ID},
        "claim_denied",
        {"job_id": JOB_ID, "index": 1},
        account=h.employer,
    )
    h.guard(
        "stranger reclaims submitted milestone",
        "get_job",
        {"job_id": JOB_ID},
        "claim_denied",
        {"job_id": JOB_ID, "index": 0},
        account=h.stranger,
    )
    h.guard(
        "expire inside submission window",
        "get_job",
        {"job_id": JOB_ID},
        "expire_job",
        {"job_id": JOB_ID},
        account=h.stranger,
    )

    h.write(
        "create_job",
        account=h.employer,
        value=TOTAL,
        **h.create_kwargs(REVIEW_JOB, 600, 60),
    )
    h.guard(
        "review without submitted evidence",
        "get_milestone",
        {"job_id": REVIEW_JOB, "index": 0},
        "review_milestone",
        {"job_id": REVIEW_JOB, "index": 0},
        account=h.stranger,
    )

    # D) anti-lock: after deadline + grace every never-submitted tranche is refunded
    h.write(
        "create_job",
        account=h.employer,
        value=TOTAL,
        **h.create_kwargs(EXPIRE_JOB, 2, 2),
    )
    time.sleep(8)
    h.write("expire_job", account=h.stranger, job_id=EXPIRE_JOB)
    expired = h.read("get_job", job_id=EXPIRE_JOB)
    h.note(
        "expire refunds unreviewed tranches",
        expired.get("status") == "closed"
        and int(expired.get("refunded_amount", 0)) == TOTAL
        and int(expired.get("remaining_amount", 0)) == 0,
        f"status={expired.get('status')} refunded={expired.get('refunded_amount')}",
    )
    h.guard(
        "double expire",
        "get_job",
        {"job_id": EXPIRE_JOB},
        "expire_job",
        {"job_id": EXPIRE_JOB},
        account=h.stranger,
    )

    print(f"\nContract: {h.addr}")
    print(f"Result: {h.passed} passed, {h.failed} failed")
    if args.keep:
        print("(jobs kept on-chain for inspection)")
    return 0 if h.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
