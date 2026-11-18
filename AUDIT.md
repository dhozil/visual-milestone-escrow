# Security Audit — VisualMilestoneEscrow

**Scope:** `contracts/visual_milestone_escrow.py` (studionet deployment
`0xB322AD0ACB842E4c94d71917B156c3dF4305C2EA`), its lifecycle, its consensus path, and
every public entry point.
**Method:** adversarial review of the lifecycle and caller model, targeted regression
tests in direct mode, deterministic on-chain verification, and a full AI-consensus
vision review on studionet. Plus a line-by-line mapping of the GenLayer staff review
feedback received on this author's earlier submissions.

---

## 1. Findings summary

| ID | Severity | Issue | Status |
|---|---|---|---|
| H-1 | **High** | Deadline-race expiry: an employer could set a 1-second review grace and reclaim a tranche seconds after the contractor submitted evidence — work delivered, no payment | **Fixed** (7-day submitted-tranche protection, two-phase `expire_job`) |
| H-2 | **High** | One delivered photo could be claimed against several tranches of the same job (double-dip) | **Fixed** (`photo_usage` index + distinct-photo check) |
| M-1 | Medium | SSRF: the contract fetched any caller-supplied URL, including `localhost`, private ranges, link-local/metadata and credential-bearing URLs | **Fixed** (public-host validation at submission and again before fetch) |
| M-2 | Medium | Non-image bytes were handed to the vision model as “photos” | **Fixed** (PNG/JPEG/GIF/WebP magic-byte check after hash verification) |
| M-3 | Medium | Unbounded JSON strings were parsed before any size validation (VM memory DoS) | **Fixed** (pre-parse length caps for amounts, criteria, evidence) |
| M-4 | Medium | Free-form `job_id` could collide/confuse storage keys and UIs | **Fixed** (explicit character allowlist, no `#`) |
| M-5 | Medium | Zero-address contractor would burn the escrow on payout | **Fixed** (zero-address rejected) |
| M-6 | Medium | External transfer happened before the last state write in two paths | **Fixed** (all state transitions before `emit_transfer`) |
| M-7 | Medium | `review_milestone` had no job-status guard; `expire_job` had ambiguous re-entry semantics | **Fixed** (explicit `closed`/`expired` handling) |
| M-8 | Medium | No per-transaction verification id tying an agreement and a verdict to what was judged | **Fixed** (`terms_binding`, `evidence_binding`, `verdict_binding`) |
| L-1 | Low | Stored `reasoning` is unverified natural-language text | **Accepted, constrained** (never read by any later computation) |
| L-2 | Low | Validators may store adjacent score buckets (approval must still match exactly) | **Accepted, bounded** (score is audit-only, pays nothing) |
| L-3 | Low | Bytes cannot prove *when/where* a photo was taken; cross-job photo reuse is not detectable | **Accepted, documented** (per-job code pattern) |
| L-4 | Low | If the validator set cannot process images, review stays undetermined | **Accepted** (bounded refund path) |
| L-5 | Low | Runner pin warning (“newer runner available”) | **Accepted** (pin is resolvable and repo/docs standard) |

Each fixed item below has a regression test in
`tests/test_visual_milestone_escrow.py` (18 tests total).

---

## 2. Detailed findings

### H-1 — Deadline-race expiry (free work) — FIXED

Original logic refunded every `submitted` tranche once
`submit_deadline + review_grace` had passed. Because submission is allowed *until*
that deadline, an employer could create a job with `review_grace_seconds = 1`, wait for
the contractor to deliver near the deadline, call `expire_job`, and get the money back
before any review could land. The contractor did the work and was paid nothing; the
“evidence” was refunded away.

**Fix.** `expire_job` is now two-phase:

- `pending` and `denied` tranches are refundable at `submit_deadline + review_grace`;
- a `submitted` tranche is protected until **7 days after its own `submitted_at`**, and
  only then becomes refundable (a second `expire_job` call finishes the job);
- `review_milestone` still works while the job is `expired`, so evidence delivered near
  the deadline can be judged and paid after the employer's refund crank ran.

**Tests:** `test_expire_protects_submitted_tranche_and_refunds_pending`,
`test_review_still_works_after_expiry_of_other_tranches`.

### H-2 — Same photo paying multiple tranches — FIXED

Each milestone’s evidence binding includes the milestone index, so the *binding* alone
did not stop a contractor from reusing one photo for tranche 2 after tranche 1 was
paid (the bytes are identical; only the index differs).

**Fix.** A `photo_usage` index maps `job_id|sha256 -> index`; a photo already committed
in the job cannot be submitted again, and duplicate photos inside one submission are
rejected.

**Tests:** `test_same_photo_cannot_pay_two_tranches`.

### M-1 — SSRF / internal fetch — FIXED

`gl.nondet.web.get(url)` accepted any `http(s)` string: localhost, `127.0.0.1`,
`10/8`, `192.168/16`, `172.16/12`, `169.254/16` (cloud metadata), `.local` /
`.internal`, IPv6 literals, and `user:pass@host` URLs. Validators run inside
infrastructure, so those are network-probing primitives.

**Fix.** `_validate_public_host` requires a dotted public hostname, rejects
credentials, IPv6 literals, single-label hosts and the private/link-local ranges.
Validation runs at submission (deterministic revert) and again inside `_fetch_image`
(defense in depth; failures become recorded denials, not reverts).

**Tests:** private/local/credential URL guards in
`test_submit_milestone_contractor_only_and_binds_evidence`; on-chain guard
`private/local evidence host`.

### M-2 — Non-image payloads reaching the vision model — FIXED

A committed “photo” could be HTML, a 4 KB text prompt, or a script. The model would
then be asked to “inspect” attacker-chosen text.

**Fix.** After the hash check, the bytes must carry a PNG, JPEG, GIF or WebP signature;
otherwise the tranche is denied deterministically. Hash verification runs first so a
substituted GIF is reported as substitution, not as a format error.

**Tests:** `test_review_rejects_non_image_content`.

### M-3 — Pre-parse input bombs — FIXED

`json.loads` ran on caller-controlled strings of unbounded length. A 100 MB argument
would be parsed before any field validation.

**Fix.** `MAX_AMOUNTS_JSON_CHARS` (2 000), `MAX_CRITERIA_JSON_CHARS` (12 000) and
`MAX_EVIDENCE_JSON_CHARS` (4 000) are enforced before parsing.

**Tests:** `Milestone amounts payload is too large`, `Evidence payload is too large`.

### M-4 — Job id keyspace — FIXED

`job_id` allowed `#`, the milestone-key separator. Keys are never parsed, so a
collision required contrived ids, but free-form ids also invite UI/log confusion.

**Fix.** `[A-Za-z0-9-_.]` only, max 64 chars.

**Tests:** `Job id may only contain letters, digits, dash, underscore or dot`.

### M-5 — Zero-address payout — FIXED

A job could name `0x000…0` as contractor; every approval would send the tranche to the
burn address. Zero address is now rejected for the contractor (and any address input).

**Tests:** `Address must not be the zero address`; on-chain guard
`zero-address contractor`.

### M-6 — Effects/interaction ordering — FIXED

`claim_denied` and the approval branch of `review_milestone` emitted the transfer
before writing the final job status. GenVM messages are queued (no synchronous
re-entrancy), but the ordering was still wrong for auditability and for any future
message semantics.

**Fix.** Status, accounting counters, `closed_at` and the verdict binding are all
written before `emit_transfer`.

### M-7 — Status guards — FIXED

- `review_milestone` now rejects a `closed` job and keeps working for `expired` jobs
  (needed by H-1).
- `claim_denied` rejects a `closed` job.
- `expire_job` is explicitly idempotent while tranches are protected (returns
  `refunded_amount = 0`, `protected_milestones > 0`) and reverts once the job is closed.

**Tests:** `test_review_still_works_after_expiry_of_other_tranches`,
`test_denial_after_expiry_still_allows_employer_refund`,
`test_claim_denied_requires_open_or_expired_job`.

### M-8 — Verification ids — FIXED

Staff feedback on earlier contracts asked for each transaction’s returned verification
id. Now:

| Call | Returns | Binding |
|---|---|---|
| `create_job` | `terms_binding` | `sha256(job_id, parties, title, spec, amounts, criteria, windows)` |
| `submit_milestone` | `evidence_binding` | `sha256(job_id \| index \| canonical evidence JSON)` |
| `review_milestone` | `verdict_binding` | `sha256(terms_binding \| evidence_binding \| criteria \| score \| decision)` |

`verdict_binding` is stored on the milestone, so an auditor can reconstruct exactly
which agreement and which evidence bytes produced a payout.

**Tests:** `test_verdict_binding_and_evidence_binding_are_distinct`, binding assertions
in `test_create_job_validates_and_funds` and `test_submit_milestone_contractor_only_and_binds_evidence`.

---

## 3. Double-submit and replay matrix

| Attempt | Result | Test |
|---|---|---|
| `create_job` with an existing id | revert `Job already exists` | `test_create_job_validates_and_funds` |
| `submit_milestone` for an already-submitted tranche | revert `Milestone evidence was already submitted` | `test_submit_milestone_contractor_only_and_binds_evidence` |
| `submit_milestone` for another tranche with a used photo | revert `Evidence photo already used…` | `test_same_photo_cannot_pay_two_tranches` |
| `submit_milestone` with the same photo twice | revert `…must be distinct` | `test_same_photo_cannot_pay_two_tranches` |
| `review_milestone` twice | revert `Milestone is not awaiting review` | `test_review_approved_releases_tranche` |
| `claim_denied` twice | revert `Milestone is not in a denied state` | `test_review_denied_records_denial_then_employer_refund` |
| `claim_denied` on a pending/submitted tranche | revert `Milestone is not in a denied state` | same |
| `expire_job` twice after closure | revert `Job is closed` | `test_expire_protects_submitted_tranche_and_refunds_pending` |
| `expire_job` before `deadline + grace` | revert `Review grace period has not passed` | same |
| Payout twice for one tranche | impossible: `approved`, `refunded`, `expired` are terminal; closure requires `released + refunded == total` | `test_denied_refund_closes_single_milestone_job`, `test_approved_release_closes_single_milestone_job` |

---

## 4. Caller / authorization matrix

| Actor | Can | Cannot |
|---|---|---|
| Employer (funder) | `create_job`; `claim_denied` after a recorded denial; `expire_job` after the time gates; `review_milestone` | submit evidence; reclaim a pending tranche; reclaim a submitted tranche inside its 7-day protection; change criteria after funding; mark a tranche approved without consensus |
| Contractor | `submit_milestone` once per tranche before the deadline; `review_milestone` (own crank) | refund the employer; influence the verdict beyond the committed photos; resubmit a denied tranche; reuse a photo in the job |
| Stranger | `review_milestone` and `expire_job` (cranks only) | submit evidence; claim a refund; alter terms; choose an outcome — both cranks are time-gated or consensus-gated and only ever pay the pre-agreed party |
| Anyone | views (`get_job`, `get_milestone`, `get_job_milestones`) | write state |

An external caller cannot create a job in someone else’s name (`employer` is always
`gl.message.sender_address`), cannot submit for another contractor (hex-compared sender
check), and cannot redirect funds (recipient is fixed at creation).

---

## 5. Consensus-path audit

**Consequential-field budget.** Only these fields can move value or block a refund:
`job_id`, parties, tranche amounts, criteria, deadlines, committed evidence
(`url` + `sha256`), the approval decision, and recorded timestamps. Everything else
stored (`score`, `reasoning`, bindings) is audit data.

**Validator obligations.** `validator_fn` requires the leader result to be a `Return`
with:

- an `int` score on a 20-point bucket in `[0, 100]` (bool and out-of-range rejected),
- a non-empty `str` reasoning,

then re-fetches and re-judges independently and rejects when the **approval decision**
differs. Only the stored score may differ, by at most one bucket, and the score never
gates money or any later computation — so two accepted runs cannot produce different
future payouts, refunds or expiries.

**Why the decision is exact.** `score >= 60` releases a fixed tranche. A one-bucket
tolerance across that boundary would let a leader pay on 60 while a validator judged 40,
so the boundary is compared exactly.

**Error classification.**

| Failure | Behaviour |
|---|---|
| Photo unreachable / HTTP != 200 / oversized / not an image / hash mismatch | deterministic recorded denial (`score 0`), never a revert, so state stays auditable and the refund path opens |
| Model returns no usable score | recorded denial with reasoning |
| Model/leader raises | leader result is an error → validator returns `False` → consensus rotates rather than locking a bad verdict |
| Validators disagree on the decision | rotation; nothing is stored |

**Prompt-injection controls.** Scope and criteria are delimited and labelled untrusted,
the photos are labelled untrusted data, and the prompt states that claims are not
evidence. The only output consumed is the score; the model cannot name a recipient,
an amount, or a state transition.

**Not reused later.** `reasoning` is stored for audit and is never fed to another
prompt, comparison or payout calculation. This is the mitigation the staff recommended
as an alternative to validating free-text reasoning.

---

## 6. Staff feedback mapping

Grouped by theme (several messages repeat the same requirement).

| # | Staff feedback (paraphrased) | Verdict for this contract |
|---|---|---|
| 1 | Validators cannot verify a precedent-departure reason without prior precedent facts | **N/A** — no precedent mechanism. Policy applied: stored reasoning is audit-only. |
| 2 | Validator must independently verify the distinguishing reason | **N/A** as above; validator additionally requires non-empty reasoning and never reuses it. |
| 3 | Validators can accept different raw readings that create different later behaviour | **Applied** — approval is exact, tranche amounts are fixed at creation, stored scores are never consequential. |
| 4 | Undetermined challenge has no timeout → deposits locked | **Applied** — two-phase `expire_job`, including a 7-day protection window for submitted evidence. |
| 5 | Funded escrow can lock if adjudication is inconclusive | **Applied** — every non-approved tranche has a time-bounded refund path. |
| 6 | Validators must agree on every mandatory criterion; bind source claims to URLs actually fetched; use returned verification ids | **Applied in substance** — criteria come from storage, URLs/hashes are fetched and enforced, `terms/evidence/verdict_binding` are returned and stored. Per-criterion votes are replaced by a hard-rule rubric + exact approval because vision models do not agree item-by-item (trade-off documented in §7). |
| 7 | Bind verification to stored criteria and committed evidence; each party submits its own case; validators agree on the verdict category; winner settles atomically | **Applied** — contractor submits its own committed evidence, validators agree on the approval category, and the winning tranche is paid in the same transaction. |
| 8 | Anyone can resolve someone else’s commitment; stored owner never checked; resolution time not enforced | **Applied** — permissionless calls are cranks that cannot choose an outcome; submission is contractor-only; refunds are employer-only; all deadlines enforced (§4). |
| 9 | Fetched content discarded; unverified reasoning reused later | **Avoided** — fetched bytes go straight into the model, and reasoning is never consequential. |
| 10 | Fee reason/market summary unverified and later reused | **N/A** — no descriptive field feeds a later computation. |
| 11 | Performance-analysis fields not independently bound | **N/A** — no multi-field analysis output is consumed. |
| 12 | Adaptive fee used only owner-supplied text; validators accept different exact stored values | **Avoided** — evidence is acquired contract-side, and the exact consequential value (decision + fixed tranche) is bound. |
| 13 | Evidence not authenticated; claimant hash checked against claimant hash | **Avoided** — hashes are checked against contract-side fetched bytes, plus image-signature validation. |
| 14 | Stored reasoning unverified and then used in appeal review | **N/A** — there is no appeal path and no reuse of reasoning. |
| 15 | Partial release percentage unverified; URLs passed without fetching | **Avoided** — tranche amounts are fixed per milestone and contents are fetched before judging. |
| 16 | Prohibited float division must be replaced by integer division | **Compliant** — no `/` division anywhere; scores use `//` on integers, and decimals are truncated without float math. |
| 17 | Repin the dependency to a resolvable version; correlate receipts to the just-submitted intent; fund-conservation tests | **Compliant** — pinned `py-genlayer:1jb45aa8…` (resolves; lint passes), per-call binding ids, and explicit released/refunded/remaining conservation tests. |
| 18 | Sealed commit call still receives plaintext entry + salt | **N/A** — this contract has no sealed bids; hashes are an integrity commitment over public photo evidence, not a secrecy mechanism. |

---

## 7. Residual risks (accepted, and why)

1. **Photo authenticity is not cryptographically provable.** A photo can be old, staged,
   or taken elsewhere. Bytes prove *which* image was judged, not *when/where*. Mitigation
   guidance: put a per-job code (e.g. “a handwritten sign reading `DRIVE-7Q2` must be
   visible”) in the criteria — the same consensus path then enforces it. Cross-*job*
   reuse is not detectable on-chain.
2. **Per-criterion agreement is delegated to the rubric.** The model must score 0–100 and
   any unproven criterion caps the score at 40; validators must agree on approve/deny.
   Requiring exact agreement per criterion would make vision consensus fragile without
   adding payout safety, because the payout is a fixed tranche.
3. **Contradictory analysis text in the reasoning is not compared.** It is audit-only by
   construction; no later prompt or calculation reads it.
4. **Vision-model availability.** If no validator model accepts images, the review stays
   undetermined and the tranches are refundable after the protection window — degraded
   availability, not lost funds.
5. **Evidence URL mutability.** The hash commitment makes the image immutable, so a URL
   whose bytes change (CDN transform, moving branch) denies deterministically. Use
   content-addressed or commit-pinned URLs.
6. **Host allowlist excludes local testing servers.** `localhost` evidence is rejected by
   design (SSRF); local integration tests must use a public or tunneled host.
7. **Single-shot review per tranche.** A denied tranche cannot be resubmitted; this
   prevents “audition until approval” gambling on model variance. Contractors should
   commit their best evidence.
8. **Runner pin.** `genvm-lint` reports a newer runner exists; the pinned hash is
   resolvable, is what the GenLayer docs and this repository use, and the deployed code
   runs on studionet.

---

## 8. Verification evidence

| Check | Result |
|---|---|
| `genvm-lint check` | pass — 8 methods (3 view, 5 write) |
| Direct-mode tests | **18/18 passed** |
| Deterministic on-chain (`leader_only=True`) | **16/16 PASS** — funding, zero address, duplicate id, stranger submit, hash binding, double submit, photo reuse, private host, premature `claim_denied` (pending + stranger), expire before window, review without evidence, expire → refund, double expire |
| Full AI consensus vision review | tx `0x6a4721ca…a653` — 3 validators `agree`, `stderr` empty, score `100`, approved, `verdict_binding` returned, job `closed` |
| Source ↔ deployment | on-chain code byte-identical to `contracts/visual_milestone_escrow.py` |
| Deployment | `0xB322AD0ACB842E4c94d71917B156c3dF4305C2EA`, deploy tx `0x083d3479…c4f9` |
