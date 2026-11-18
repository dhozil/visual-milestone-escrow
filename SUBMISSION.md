# Submission: VisualMilestoneEscrow

## Category
Intelligent Contracts

## Contract Name
VisualMilestoneEscrow

## Summary
Photo-proof milestone escrow. The employer funds every milestone tranche up front and
writes the acceptance criteria; the contractor submits 1-2 hash-committed photographs;
GenLayer validators fetch those exact images on-chain and independently judge them
against the criteria. An approval releases that tranche, a denial is recorded on-chain
(and only then can the employer reclaim it), and anything still unreviewed is refunded
after the deadline plus a review grace period — with submitted evidence protected for
seven further days.

## What Makes This Unique
- **True multi-modal consensus**: validators fetch the committed photo bytes and pass
  them to the model with `exec_prompt(images=[...])`; the judgment is about what is
  visible, not about a URL string
- **Content-bound, format-checked evidence**: each photo's `sha256` is re-derived from the
  fetched bytes before the model runs (substitution → deterministic denial) and the bytes
  must be a real PNG/JPEG/GIF/WebP image
- **No photo double-dip**: a per-job `photo_usage` index makes one delivered photo
  unusable for a second tranche, and duplicate photos in one submission are rejected
- **Decision-exact, score-tolerant validator**: approval (score >= 60) must match exactly
  because it moves money, while the stored score may differ by at most one 20-point bucket
  (the score is never reused by any later computation)
- **Explicit recorded denial** instead of a revert, which is what gates the employer refund
- **Two-phase anti-lock expiry**: pending/denied tranches are refundable at deadline +
  grace; a submitted tranche is protected for 7 days after submission, which closes the
  "expire the evidence seconds after delivery" free-work path, and it remains reviewable
  while the job is `expired`
- **Atomic milestone accounting**: `released + refunded == total` closes the job; each
  tranche terminates exactly once and all state writes precede the external transfer
- **Verification ids**: `terms_binding` (agreement), `evidence_binding` (exact photos),
  `verdict_binding` (terms + evidence + score + decision) are returned and stored
- **SSRF-hardened acquisition**: public dotted hosts only; credentials, IPv6 literals,
  localhost, private and link-local/metadata ranges are rejected

## How Consensus Is Used
`review_milestone` runs `gl.vm.run_nondet_unsafe(judge, validator_fn)`.

- `judge` fetches each committed photo, rejects unreachable / oversized / hash-mismatched /
  non-image bytes with a deterministic score of 0 (recorded denial), otherwise calls
  `gl.nondet.exec_prompt(prompt, images=[...], response_format="json")` and quantizes the
  result to 0/20/40/60/80/100 using integer math only.
- `validator_fn` requires the leader result to be a `Return` carrying an int score on a
  20-point bucket and a non-empty string reasoning, then independently re-fetches and
  re-judges. It rejects any approval/denial flip and any score gap larger than one bucket.
- No storage is read inside the nondet blocks; job/tranche fields are snapshotted into
  plain values before consensus, and payouts happen afterwards in deterministic code.

## Technical Details
- Python GenLayer Intelligent Contract, pinned runner
  `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`
- Storage: `Job` and `Milestone` dataclasses under `TreeMap[str, ...]`, plus a
  `photo_usage` index; `u256` amounts/counters; ISO-string time gates via `datetime`
- 1-8 milestones per job, `total_amount == sum(tranches)`, 1 MB per photo, 2 photos max,
  pre-parse caps on every JSON argument, zero-address and job-id allowlist validation
- Methods: 8 (5 write, 3 view), no constructor params
- `genvm-lint check`: passed

## Use Case
Physical or field work that is verified from photographs and paid in tranches:
construction and renovation milestones, field service and installation sign-off, delivery
or handover proof, repair/damage documentation, retrofit and inspection programs.

## Security Review
Full report: `AUDIT.md`. Findings closed before this submission:

| ID | Severity | Issue | Fix |
|---|---|---|---|
| H-1 | High | Deadline-race expiry could reclaim freshly submitted evidence (free work) | 7-day submitted-tranche protection + two-phase `expire_job` |
| H-2 | High | One photo could pay several tranches | Per-job `photo_usage` index + distinct-photo check |
| M-1 | Medium | SSRF/private-host fetching | Public-host validation at submission and before fetch |
| M-2 | Medium | Non-image bytes sent to the vision model | PNG/JPEG/GIF/WebP signature check |
| M-3 | Medium | Pre-parse JSON size bombs | Length caps before `json.loads` |
| M-4 | Medium | Free-form job ids | `[A-Za-z0-9-_.]` allowlist |
| M-5 | Medium | Zero-address payout | Zero address rejected |
| M-6 | Medium | Transfer before final state write | Effects before interaction |
| M-7 | Medium | Missing status/re-entry guards | Explicit closed/expired semantics |
| M-8 | Medium | No verification ids | `terms/evidence/verdict_binding` |

The audit also documents the double-submit matrix, the caller-authorization matrix, the
consequential-field budget, and the mapping of the GenLayer staff review feedback received
on earlier submissions (applied / avoided by design / not applicable).

## Verification
- 18/18 direct-mode tests (`gltest tests/ -q`): funding/input guards, contractor-only
  deadline-bounded submission, hash binding, photo reuse + duplicate photo, private-host
  and credential URL rejection, approval payout, denial → employer refund, substituted
  evidence, unreachable evidence, non-image content, unusable LLM output, validator
  approval-flip rejection and one-bucket tolerance, two-phase expiry with submitted
  protection, review after expiry, denial after expiry, closure on every terminal path
- Deterministic on-chain verification on studionet
  (`scripts/verify_visual_milestone_escrow_onchain.py`): **16/16 PASS**
- Full AI-consensus vision review on studionet: `review_milestone` tx
  `0x6a4721caa4975ac612524464d7065185d49b4e8597135022c5346b717e16a653` — 3 validators
  `agree`, `stderr` empty, score `100`, approved, 1000 released, `verdict_binding` returned,
  job `closed`
- Anti-lock path proven on-chain: job `vme-1794994952` → `status="closed"`,
  `refunded_amount=1000`
- On-chain code byte-identical to `contracts/visual_milestone_escrow.py`

## Live Deployment
Deployed on GenLayer studionet (chain `61999`):
[`0xB322AD0ACB842E4c94d71917B156c3dF4305C2EA`](https://explorer-studio.genlayer.com/address/0xB322AD0ACB842E4c94d71917B156c3dF4305C2EA)
Deploy tx: `0x083d3479ee0287c31d2144a18f7d1c80be860e0dd151e647329d050147e3c4f9`

## Source Code
See `contracts/visual_milestone_escrow.py`
