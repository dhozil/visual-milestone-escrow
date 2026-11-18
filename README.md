<div align="center">

# VisualMilestoneEscrow

**Photo-proof milestone escrow: the employer funds every tranche up front, the contractor submits hash-committed photographs, and GenLayer validators fetch and inspect the images themselves before releasing money.**

![GenLayer](https://img.shields.io/badge/GenLayer-Intelligent%20Contract-6a4cff)
![Python](https://img.shields.io/badge/Python-3.12-3776AB)
![Status](https://img.shields.io/badge/status-live%20on%20studionet-2ea44f)
![Tests](https://img.shields.io/badge/tests-18%20passed-2ea44f)
![Audit](https://img.shields.io/badge/security%20audit-18%20findings%20closed-2ea44f)

[Live Contract](https://explorer-studio.genlayer.com/address/0xB322AD0ACB842E4c94d71917B156c3dF4305C2EA) ·
[Security Audit](AUDIT.md) ·
[GenLayer Docs](https://docs.genlayer.com)

</div>

---

## Why

Physical work is still settled by whoever holds the money. A homeowner, a property
manager, or a procurement desk looks at a photo, decides "close enough", and pays. The
contractor has no neutral record of why a tranche was released or denied, and a dispute
becomes a he-said-she-said over a chat thread.

VisualMilestoneEscrow replaces that reviewer with a written agreement plus validator
consensus over the photographs themselves:

- the employer writes the acceptance criteria **before** any work starts;
- the employer funds **every** milestone up front, so the contractor is not exposed to a
  payer who changes their mind mid-job;
- the contractor commits the exact photos (URL + SHA-256) they want judged;
- GenLayer validators fetch those photos on-chain, look at them, and independently judge
  them against the criteria;
- an approval releases that tranche; a denial is **recorded on-chain** and only then can
  the employer reclaim it; anything unreviewed is refunded after the deadline — while a
  submitted tranche stays protected for seven more days.

Reference: [GenLayer Use Cases — Performance and milestone decisions / Multi-modal
use cases](https://docs.genlayer.com/understand-genlayer-protocol/typical-use-cases) and
[Image Processing](https://docs.genlayer.com/developers/intelligent-contracts/features/image-processing).

## Live Deployment

| | |
|---|---|
| **Contract** | [VisualMilestoneEscrow](https://explorer-studio.genlayer.com/address/0xB322AD0ACB842E4c94d71917B156c3dF4305C2EA) |
| **Address** | `0xB322AD0ACB842E4c94d71917B156c3dF4305C2EA` |
| **Network** | GenLayer studionet (chain `61999`) |
| **Deploy tx** | `0x083d3479ee0287c31d2144a18f7d1c80be860e0dd151e647329d050147e3c4f9` |
| **Vision review tx** | `0x6a4721caa4975ac612524464d7065185d49b4e8597135022c5346b717e16a653` — 3 validators `agree`, `stderr` empty, score `100`, approved, `verdict_binding` returned, job `closed` |
| **Constructor args** | none |

Source and deployed code are byte-identical (verified via `gen_getContractCode`).

## Highlights

- 📸 **Real multi-modal evidence** — validators fetch the committed photo bytes and pass
  them to the model with `exec_prompt(images=[...])`; nothing is judged from a URL string
- 🔒 **Content-bound evidence** — each photo's `sha256` is enforced against the fetched
  bytes, so the image cannot be swapped at the same URL; PNG/JPEG/GIF/WebP signature
  required before the model sees it
- 🧾 **No photo double-dip** — one delivered photo cannot pay two tranches of the same job
- 🗳️ **Decision-exact consensus** — validators re-fetch and re-judge; the approval decision
  (the part that moves money) must match exactly, and the stored score may differ by at
  most one bucket because it is never reused
- 🛡️ **No premature refunds** — pending/submitted tranches cannot be reclaimed; the
  employer can only refund a **recorded denial**, and a tranche submitted near the
  deadline stays protected for 7 days
- ⏱️ **No fund locks** — after `submit_deadline + review_grace` every unapproved tranche is
  refundable; submitted ones become refundable once their protection window ends
- 🧮 **Atomic accounting** — `released_amount + refunded_amount == total_amount` closes the
  job; every tranche terminates exactly once
- 🧷 **Verification ids** — `terms_binding`, `evidence_binding` and `verdict_binding` make
  any payout reconstructable from the agreement, the evidence and the decision
- 🌐 **SSRF-hardened** — evidence hosts must be public dotted hostnames; credentials,
  IPv6 literals, localhost, private and link-local/metadata ranges are rejected
- 🧱 **Reusable primitive** — construction milestones, field service, delivery proof,
  repair/damage documentation, retrofits, agricultural or inspection work

## How It Works

```
create_job (payable; employer, contractor, scope, amounts[], criteria[], window, grace)
      |  returns terms_binding
      v
submit_milestone (contractor; 1-2 photos {url,sha256} -> evidence_binding stored)
      |  same photo cannot be used twice in the job
      v
review_milestone (permissionless; fetch photos, verify hashes+format, judge vs criteria)
      |                         |
   score >= 60             score < 60
      |                         |
      v                         v
approved -> tranche paid   denied (recorded) -> employer may claim_denied
      |  returns verdict_binding
      +-----------+-------------+
                  |
                  v
expire_job (after deadline + grace: pending/denied refunded; submitted tranches
            protected for 7 days after their own submission, then refundable)
```

## Methods

| Role | Method | Guard |
|---|---|---|
| Employer (funder) | `create_job` | payable; `value == sum(milestone amounts)`; valid non-zero contractor address; 1-8 milestones; criteria per milestone; job id `[A-Za-z0-9-_.]` |
| Contractor | `submit_milestone` | contractor-only; before `submit_deadline`; tranche `pending`; 1-2 distinct public http(s) photos with 64-hex SHA-256 |
| Any (crank) | `review_milestone` | tranche `submitted`; job not closed; consensus over fetched photos |
| Employer | `claim_denied` | employer-only; tranche must be `denied` (recorded on-chain) |
| Any (crank) | `expire_job` | after `submit_deadline + review_grace`; refunds unapproved tranches once their protection window ends |
| Any | `get_job`, `get_milestone`, `get_job_milestones` | read-only |

## Consensus Design

`review_milestone` uses `gl.vm.run_nondet_unsafe()` with a custom validator:

```
leader_fn:
  for each committed photo:
    fetch bytes (public host only)
    unreachable / HTTP != 200 / > 1MB / sha256 mismatch / not an image
        -> score 0, deterministic recorded denial
  exec_prompt(prompt, images=[...], response_format="json")
  quantize score to 0/20/40/60/80/100  (integer only, no float math)

validator_fn:
  require leader Return + dict + int score on a 20-point bucket + non-empty str reasoning
  re-run the whole leader path independently
  reject if the approval decision (score >= 60) differs at all
  accept only if |leader_score - own_score| <= 20
```

Why this shape:

- **Approval is the consequential field.** Two vision models can reasonably differ by one
  bucket, but they must not disagree on *pay or deny*, so the approval gate is exact and
  only the stored score has a one-bucket tolerance.
- **Hashes are checked before the model runs.** Substituted, unreachable or non-image
  evidence is a deterministic denial, not a consensus puzzle.
- **Unusable model output becomes a recorded denial**, never a silent revert, so the
  employer's refund path stays available and the state remains auditable.
- **Reasoning is audit-only.** It is required to be a non-empty string and stored, but no
  later computation reads it.
- **Nothing is read from storage inside a nondet block**: job/tranche fields are
  snapshotted into plain values before consensus, and payouts run afterwards.

## Evidence Integrity

| Risk | Mitigation |
|---|---|
| Same URL, different photo before payout | Per-photo `sha256` recomputed from the fetched bytes; mismatch → score 0 denial |
| Swapping which URLs were judged | `sha256(job_id \| index \| canonical evidence JSON)` stored as `evidence_binding` |
| One photo paying several tranches | `photo_usage` index per job + distinct-photo check |
| Text/HTML submitted as a "photo" | PNG/JPEG/GIF/WebP signature required |
| SSRF / metadata probing | Public dotted host required; credentials, IPv6 literals, localhost, private, link-local rejected |
| Prompt injection inside the photo | Untrusted-data delimiters, explicit "claims are not evidence" rule, hard cap on the score when a criterion is unproven |
| Contractor evidence spam | Max 2 photos, 1 MB per photo, bounded URL/JSON lengths |
| Model never returns a score | Recorded denial with reasoning, refund path open |

## Fund Safety

- Funding invariant: `gl.message.value` must equal the sum of the milestone tranches.
- `submit_milestone` is contractor-only and deadline-bounded; a tranche can be submitted once.
- `claim_denied` is employer-only and requires a **recorded denial** — no refund while a
  tranche is pending or under review.
- `review_milestone` is permissionless: the contractor can trigger their own review, so a
  passive employer cannot stall an earned tranche.
- `expire_job` is the bounded escape hatch, in two phases:
  pending/denied tranches are refundable at deadline + grace, while a submitted tranche is
  protected for **7 days after submission** (this closes the "expire the evidence seconds
  after delivery" griefing path) and is still reviewable while the job is `expired`.
- Payouts happen exactly once per terminal tranche (`approved`, `refunded`, `expired`), all
  state writes precede the external transfer, and the job closes when
  `released + refunded == total`.

## Security Audit

Full report: [`AUDIT.md`](AUDIT.md). Summary of what was found and closed:

| ID | Issue | Status |
|---|---|---|
| H-1 | Deadline-race expiry could reclaim freshly submitted evidence (free work) | Fixed — 7-day submitted-tranche protection |
| H-2 | One photo could be claimed for several tranches | Fixed — per-job photo usage index |
| M-1 | SSRF/private-host fetching | Fixed — public-host validation |
| M-2 | Non-image bytes sent to the vision model | Fixed — image signature check |
| M-3 | Pre-parse JSON size bombs | Fixed — length caps |
| M-4 | Free-form job ids | Fixed — character allowlist |
| M-5 | Zero-address payout | Fixed — zero address rejected |
| M-6 | Transfer before final state write | Fixed — effects before interaction |
| M-7 | Missing status/re-entry guards | Fixed — closed/expired semantics |
| M-8 | No verification ids | Fixed — terms/evidence/verdict bindings |

The report also contains the double-submit matrix, the caller-authorization matrix, the
consensus-path review, and a line-by-line mapping of the GenLayer staff feedback received
on earlier submissions (which requirements apply here, which are avoided by design, and
which are not applicable).

## Limitations (read before using with real money)

- **Use immutable evidence URLs.** The hash commitment makes a photo immutable, so a URL
  whose bytes change between submission and review (CDN transforms, mutable `main`
  branches) will deterministically score 0. Prefer content-addressed storage.
- **No localhost evidence hosts.** Public dotted hostnames only (SSRF protection); use a
  public or tunneled host for integration testing.
- **Vision-capable validator set required.** If validators cannot accept images, review
  stays undetermined and funds are returned after the protection window — availability,
  not safety, degrades.
- **Photos prove only what is visible.** Criteria such as "meets code" or "structurally
  sound" are not visually verifiable; write criteria a photograph can actually show. A
  per-job code in the criteria ("a sign reading `DRIVE-7Q2` must be visible") is the
  recommended anti-reuse recipe.
- **Cross-job photo reuse is not detectable on-chain**, and a denied tranche cannot be
  resubmitted (no auditioning until approval).
- **Not a court.** This is an agreed, evidence-based settlement workflow — not legal
  adjudication or a warranty of workmanship.

## Usage Sketch

```text
# 1. employer funds both tranches (amounts must sum to msg.value)
create_job(
  job_id="driveway-1",
  contractor="0x...",
  title="Driveway rebuild",
  spec="Replace the drive, edge it, add a drain along the low side.",
  milestone_amounts_json="[600, 400]",
  milestone_criteria_json='["Surface fully paved and edged.", "Drainage channel visible."]',
  submit_window_seconds=2592000,
  review_grace_seconds=604800,
)  # value = 1000, returns terms_binding

# 2. contractor commits exact photos (public https URL + sha256)
submit_milestone(
  job_id="driveway-1",
  index=0,
  evidence_json='[{"url": "https://cdn.example.com/after.gif", "sha256": "<64 hex>"}]',
)  # returns evidence_binding

# 3. anyone cranks the vision review
review_milestone(job_id="driveway-1", index=0)  # returns verdict_binding

# 4. only if the judgment denied the tranche
claim_denied(job_id="driveway-1", index=0)   # employer

# 5. or, after deadline + grace (submitted tranches after their protection window)
expire_job(job_id="driveway-1")
```

## Test

```bash
gltest tests/ -q      # 18 passed (direct mode)
```

Coverage: funding/input guards (including zero address, job-id charset, oversized
payloads), contractor-only and deadline-bounded submission, hash binding, photo-reuse and
duplicate-photo rejection, private-host/credential URL rejection, approval payout,
recorded denial → employer refund, substituted evidence, unreachable evidence, non-image
content, unusable LLM output, validator approval-flip rejection and one-bucket tolerance,
two-phase expiry with submitted-tranche protection, review after expiry, denial after
expiry, and job closure on every terminal path.

## Lint

```bash
genvm-lint check contracts/visual_milestone_escrow.py
```

`check` passes: 8 methods (3 view, 5 write), 0 constructor params.

## On-Chain Verification

Deterministic studionet run (`leader_only=True`), script
[`scripts/verify_onchain.py`](scripts/verify_onchain.py) —
**16/16 PASS**:

| Step | Result |
|---|---|
| Funding below milestone total | reverted (expected) |
| `create_job` funded escrow (1000 wei, 2 tranches) | accepted, `status=open` |
| Milestone tranches stored | `[700, 300]` |
| Zero-address contractor | reverted (expected) |
| Duplicate job id | reverted (expected) |
| Stranger submits evidence | reverted (expected) |
| Contractor submits hash-bound evidence | accepted; binding matches `sha256(job\|index\|evidence)` |
| Double evidence submission | reverted (expected) |
| Same photo reused for another tranche | reverted (expected) |
| Private/local evidence host | reverted (expected) |
| Employer reclaims pending tranche | reverted (expected) |
| Stranger reclaims submitted tranche | reverted (expected) |
| `expire_job` inside submission window | reverted (expected) |
| `review_milestone` without evidence | reverted (expected) |
| `expire_job` after deadline + grace | accepted; `status=closed`, refunded `1000`, remaining `0` |
| Double `expire_job` | reverted (expected) |

Full AI consensus (`leader_only=False`) on the deployed contract:

| Tx | Scenario | Exec | Notes |
|---|---|---|---|
| `0x0bf29a0f…89ea` | `create_job` (photo-proof test) | SUCCESS | funded 1000 |
| `0x98feca0a…b173` | `submit_milestone` (Python logo PNG, committed SHA-256) | SUCCESS | `evidence_binding` stored |
| `0x6a4721ca…a653` | `review_milestone` | SUCCESS | 3 validators `agree`, `stderr` empty, score `100`, approved, 1000 released, `verdict_binding` returned, job `closed` |

Live state read from the contract:

- `get_milestone("vision-1794995319", 0)` → `status="approved"`, `score=100`,
  `verdict_binding="e15eea44…"`, `reasoning`: "The single photograph clearly and
  unambiguously displays the official Python logo…"
- `get_job("vision-1794995319")` → `status="closed"`, `released_amount=1000`,
  `refunded_amount=0`, `remaining_amount=0`
- `get_job("vme-1794994952")` → `status="closed"`, `refunded_amount=1000` (anti-lock path)
