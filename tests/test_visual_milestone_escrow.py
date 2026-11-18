"""Direct-mode tests for the VisualMilestoneEscrow contract."""

import hashlib
import json
import re
from datetime import datetime, timedelta

from gltest.direct import create_address

JOB_ID = "driveway-1"
EMPLOYER_ADDR = create_address("vme-employer")
CONTRACTOR_ADDR = create_address("vme-contractor")
STRANGER_ADDR = create_address("vme-stranger")
EMPLOYER = "0x" + EMPLOYER_ADDR.hex()
CONTRACTOR = "0x" + CONTRACTOR_ADDR.hex()

PHOTO_A = "https://evidence.example.com/milestone-1-after.jpg"
PHOTO_B = "https://evidence.example.com/milestone-1-drain.jpg"
PHOTO_A_BODY = "GIF89a-milestone-1-after"
PHOTO_B_BODY = "RIFF0000WEBPmilestone-1-drain"

AMOUNTS = [600, 400]
CRITERIA = [
    "The driveway surface is fully paved and edged.",
    "A drainage channel is visible along the low side.",
]
TOTAL = sum(AMOUNTS)

APPROVED_JSON = json.dumps({"score": 80, "reasoning": "Paving and edging are visible."})
DENIED_JSON = json.dumps({"score": 20, "reasoning": "Only bare ground is visible."})
NO_SCORE_JSON = json.dumps({"verdict": "looks fine to me"})


def _sha(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()


def _evidence(entries=None) -> str:
    if entries is None:
        entries = [{"url": PHOTO_A, "sha256": _sha(PHOTO_A_BODY)}]
    return json.dumps(entries)


def _mock_photo(direct_vm, url=PHOTO_A, body=PHOTO_A_BODY, status=200):
    direct_vm.mock_web(re.escape(url), {"status": status, "body": body})


def _mock_verdict(direct_vm, payload):
    direct_vm.mock_llm(r"strict visual milestone inspector", payload)


def _create_job(
    direct_vm,
    contract,
    job_id=JOB_ID,
    contractor=CONTRACTOR,
    amounts=None,
    criteria=None,
    amounts_json=None,
    window=3600,
    grace=600,
    value=None,
):
    amounts = AMOUNTS if amounts is None else amounts
    criteria = CRITERIA if criteria is None else criteria
    if value is None:
        value = sum(amounts)
    direct_vm.sender = EMPLOYER_ADDR
    direct_vm.value = value
    return contract.create_job(
        job_id=job_id,
        contractor=contractor,
        title="Driveway rebuild",
        spec="Replace the driveway, edge it, and add a drainage channel.",
        milestone_amounts_json=(
            json.dumps(amounts) if amounts_json is None else amounts_json
        ),
        milestone_criteria_json=json.dumps(criteria),
        submit_window_seconds=window,
        review_grace_seconds=grace,
    )


def _submit(direct_vm, contract, index=0, evidence=None, job_id=JOB_ID):
    direct_vm.sender = CONTRACTOR_ADDR
    return contract.submit_milestone(
        job_id=job_id,
        index=index,
        evidence_json=_evidence() if evidence is None else evidence,
    )


def _review(direct_vm, contract, index=0, job_id=JOB_ID):
    return contract.review_milestone(job_id=job_id, index=index)


def test_create_job_validates_and_funds(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    direct_vm.check_pickling = True

    direct_vm.sender = EMPLOYER_ADDR
    direct_vm.value = TOTAL
    with direct_vm.expect_revert("Job id is required"):
        _create_job(direct_vm, contract, job_id="")
    with direct_vm.expect_revert("Invalid Ethereum address"):
        _create_job(direct_vm, contract, contractor="0x123")
    with direct_vm.expect_revert("Employer and contractor must differ"):
        contract.create_job(
            job_id=JOB_ID,
            contractor=EMPLOYER,
            title="Driveway rebuild",
            spec="Replace the driveway.",
            milestone_amounts_json=json.dumps([TOTAL]),
            milestone_criteria_json=json.dumps(["Paved."]),
            submit_window_seconds=3600,
            review_grace_seconds=600,
        )
    with direct_vm.expect_revert("Job title is required"):
        contract.create_job(
            job_id=JOB_ID,
            contractor=CONTRACTOR,
            title="",
            spec="Replace the driveway.",
            milestone_amounts_json=json.dumps([TOTAL]),
            milestone_criteria_json=json.dumps(["Paved."]),
            submit_window_seconds=3600,
            review_grace_seconds=600,
        )
    with direct_vm.expect_revert("Job scope is required"):
        contract.create_job(
            job_id=JOB_ID,
            contractor=CONTRACTOR,
            title="Driveway rebuild",
            spec="",
            milestone_amounts_json=json.dumps([TOTAL]),
            milestone_criteria_json=json.dumps(["Paved."]),
            submit_window_seconds=3600,
            review_grace_seconds=600,
        )
    with direct_vm.expect_revert("Submission window must be at least 1 second"):
        _create_job(direct_vm, contract, window=0)
    with direct_vm.expect_revert("Submission window cannot exceed 90 days"):
        _create_job(direct_vm, contract, window=7776001)
    with direct_vm.expect_revert("Review grace period must be at least 1 second"):
        _create_job(direct_vm, contract, grace=0)
    with direct_vm.expect_revert("Review grace period cannot exceed 30 days"):
        _create_job(direct_vm, contract, grace=2592001)
    with direct_vm.expect_revert(
        "Job id may only contain letters, digits, dash, underscore or dot"
    ):
        _create_job(direct_vm, contract, job_id="bad id!#0")
    with direct_vm.expect_revert("Address must not be the zero address"):
        _create_job(
            direct_vm,
            contract,
            contractor="0x0000000000000000000000000000000000000000",
        )
    with direct_vm.expect_revert("Milestone amounts payload is too large"):
        _create_job(
            direct_vm, contract, amounts_json="[" + "1" * 2000, value=TOTAL
        )
    with direct_vm.expect_revert("Milestone amounts must be valid JSON"):
        _create_job(direct_vm, contract, amounts_json="{oops")
    with direct_vm.expect_revert("Milestone amounts and criteria must have equal length"):
        _create_job(direct_vm, contract, amounts=[TOTAL], criteria=["a", "b"])
    with direct_vm.expect_revert("Milestone amounts must be > 0"):
        _create_job(direct_vm, contract, amounts=[0], criteria=["Paved."], value=0)
    with direct_vm.expect_revert("Milestone amounts must be integers"):
        _create_job(direct_vm, contract, amounts=["600"], criteria=["Paved."], value=TOTAL)
    with direct_vm.expect_revert("Milestone criteria are required"):
        _create_job(direct_vm, contract, amounts=[TOTAL], criteria=["   "])
    direct_vm.value = 0
    with direct_vm.expect_revert("Escrow funding must be > 0"):
        contract.create_job(
            job_id=JOB_ID,
            contractor=CONTRACTOR,
            title="Driveway rebuild",
            spec="Replace the driveway.",
            milestone_amounts_json=json.dumps([TOTAL]),
            milestone_criteria_json=json.dumps(["Paved."]),
            submit_window_seconds=3600,
            review_grace_seconds=600,
        )
    with direct_vm.expect_revert("Escrow funding must equal the milestone total"):
        _create_job(direct_vm, contract, value=TOTAL - 1)
    with direct_vm.expect_revert("Job must have between 1 and 8 milestones"):
        _create_job(direct_vm, contract, amounts=[], criteria=[])

    created = _create_job(direct_vm, contract)
    assert created["job_id"] == JOB_ID
    assert int(created["milestone_count"]) == 2
    assert int(created["total_amount"]) == TOTAL

    job = contract.get_job(JOB_ID)
    assert job["status"] == "open"
    assert job["employer"].lower() == EMPLOYER.lower()
    assert job["contractor"].lower() == CONTRACTOR.lower()
    assert job["released_amount"] == 0
    assert job["refunded_amount"] == 0
    assert job["remaining_amount"] == TOTAL

    milestones = contract.get_job_milestones(JOB_ID)["milestones"]
    assert [m["status"] for m in milestones] == ["pending", "pending"]
    assert [m["amount"] for m in milestones] == AMOUNTS

    assert len(created["terms_binding"]) == 64
    assert job["terms_binding"] == created["terms_binding"]

    with direct_vm.expect_revert("Job already exists"):
        _create_job(direct_vm, contract)
    with direct_vm.expect_revert("Job not found"):
        contract.get_job("missing")
    with direct_vm.expect_revert("Milestone not found"):
        contract.get_milestone(JOB_ID, 9)


def test_submit_milestone_contractor_only_and_binds_evidence(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)

    direct_vm.sender = STRANGER_ADDR
    with direct_vm.expect_revert("Only the contractor can submit milestone evidence"):
        contract.submit_milestone(JOB_ID, 0, _evidence())

    direct_vm.sender = EMPLOYER_ADDR
    with direct_vm.expect_revert("Only the contractor can submit milestone evidence"):
        contract.submit_milestone(JOB_ID, 0, _evidence())

    direct_vm.sender = CONTRACTOR_ADDR
    with direct_vm.expect_revert("Milestone index is out of range"):
        contract.submit_milestone(JOB_ID, 5, _evidence())
    with direct_vm.expect_revert("Evidence must be valid JSON"):
        contract.submit_milestone(JOB_ID, 0, "not json")
    with direct_vm.expect_revert("Evidence must contain 1 or 2 photos"):
        contract.submit_milestone(JOB_ID, 0, "[]")
    with direct_vm.expect_revert("Evidence must contain 1 or 2 photos"):
        contract.submit_milestone(
            JOB_ID,
            0,
            _evidence(
                [
                    {"url": PHOTO_A, "sha256": _sha(PHOTO_A_BODY)},
                    {"url": PHOTO_B, "sha256": _sha(PHOTO_B_BODY)},
                    {"url": PHOTO_A, "sha256": _sha(PHOTO_A_BODY)},
                ]
            ),
        )
    with direct_vm.expect_revert("Evidence photo URL must be http(s)"):
        contract.submit_milestone(
            JOB_ID, 0, _evidence([{"url": "ftp://x/y.jpg", "sha256": _sha("x")}])
        )
    with direct_vm.expect_revert("Evidence photo sha256 must be 64 hex characters"):
        contract.submit_milestone(
            JOB_ID, 0, _evidence([{"url": PHOTO_A, "sha256": "abc"}])
        )
    with direct_vm.expect_revert("Evidence URL must use a public hostname"):
        contract.submit_milestone(
            JOB_ID, 0, _evidence([{"url": "http://127.0.0.1/photo.gif", "sha256": _sha("x")}])
        )
    with direct_vm.expect_revert("Evidence URL must use a public hostname"):
        contract.submit_milestone(
            JOB_ID, 0, _evidence([{"url": "http://localhost/photo.gif", "sha256": _sha("x")}])
        )
    with direct_vm.expect_revert("Evidence URL must use a public hostname"):
        contract.submit_milestone(
            JOB_ID, 0, _evidence([{"url": "http://169.254.169.254/latest/meta", "sha256": _sha("x")}])
        )
    with direct_vm.expect_revert("Evidence URL must not contain credentials"):
        contract.submit_milestone(
            JOB_ID, 0, _evidence([{"url": "https://user:pass@example.com/a.gif", "sha256": _sha("x")}])
        )
    with direct_vm.expect_revert("Evidence payload is too large"):
        contract.submit_milestone(
            JOB_ID, 0, _evidence([{"url": PHOTO_A, "sha256": _sha("x"), "pad": "a" * 4000}])
        )

    submitted = contract.submit_milestone(JOB_ID, 0, _evidence())
    canonical = json.dumps(
        [{"url": PHOTO_A, "sha256": _sha(PHOTO_A_BODY)}], sort_keys=True
    )
    expected_binding = hashlib.sha256(
        f"{JOB_ID}|0|{canonical}".encode()
    ).hexdigest()
    assert submitted["evidence_binding"] == expected_binding

    milestone = contract.get_milestone(JOB_ID, 0)
    assert milestone["status"] == "submitted"
    assert milestone["evidence_binding"] == expected_binding
    assert milestone["evidence"][0]["url"] == PHOTO_A

    with direct_vm.expect_revert("Milestone evidence was already submitted"):
        contract.submit_milestone(JOB_ID, 0, _evidence())

    direct_vm.warp((datetime.now() + timedelta(seconds=7200)).isoformat())
    with direct_vm.expect_revert("Submission deadline has passed"):
        contract.submit_milestone(JOB_ID, 1, _evidence())


def test_same_photo_cannot_pay_two_tranches(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(direct_vm, contract, index=0)

    with direct_vm.expect_revert(
        "Evidence photo already used for another milestone in this job"
    ):
        _submit(direct_vm, contract, index=1)

    _submit(
        direct_vm,
        contract,
        index=1,
        evidence=_evidence([{"url": PHOTO_B, "sha256": _sha(PHOTO_B_BODY)}]),
    )
    assert contract.get_milestone(JOB_ID, 1)["status"] == "submitted"

    _create_job(
        direct_vm,
        contract,
        job_id="dup-photo",
        amounts=[TOTAL],
        criteria=[CRITERIA[0]],
    )
    direct_vm.sender = CONTRACTOR_ADDR
    with direct_vm.expect_revert(
        "Evidence photos in one submission must be distinct"
    ):
        contract.submit_milestone(
            "dup-photo",
            0,
            _evidence(
                [
                    {"url": PHOTO_A, "sha256": _sha(PHOTO_A_BODY)},
                    {"url": PHOTO_B, "sha256": _sha(PHOTO_A_BODY)},
                ]
            ),
        )


def test_review_approved_releases_tranche(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(
        direct_vm,
        contract,
        evidence=_evidence(
            [
                {"url": PHOTO_A, "sha256": _sha(PHOTO_A_BODY)},
                {"url": PHOTO_B, "sha256": _sha(PHOTO_B_BODY)},
            ]
        ),
    )

    _mock_photo(direct_vm, PHOTO_A, PHOTO_A_BODY)
    _mock_photo(direct_vm, PHOTO_B, PHOTO_B_BODY)
    _mock_verdict(direct_vm, APPROVED_JSON)

    result = _review(direct_vm, contract)
    assert result["approved"] is True
    assert result["score"] == 80
    assert result["released_amount"] == AMOUNTS[0]

    milestone = contract.get_milestone(JOB_ID, 0)
    assert milestone["status"] == "approved"
    assert milestone["score"] == 80
    assert "Paving" in milestone["reasoning"]

    job = contract.get_job(JOB_ID)
    assert job["released_amount"] == AMOUNTS[0]
    assert job["remaining_amount"] == AMOUNTS[1]

    with direct_vm.expect_revert("Milestone is not awaiting review"):
        _review(direct_vm, contract)


def test_review_denied_records_denial_then_employer_refund(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(direct_vm, contract)

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, DENIED_JSON)

    result = _review(direct_vm, contract)
    assert result["approved"] is False
    assert result["score"] == 20
    assert result["released_amount"] == 0

    milestone = contract.get_milestone(JOB_ID, 0)
    assert milestone["status"] == "denied"
    assert contract.get_job(JOB_ID)["refunded_amount"] == 0

    direct_vm.sender = STRANGER_ADDR
    with direct_vm.expect_revert("Only the employer can reclaim a denied milestone"):
        contract.claim_denied(JOB_ID, 0)

    direct_vm.sender = EMPLOYER_ADDR
    refund = contract.claim_denied(JOB_ID, 0)
    assert refund["refunded_amount"] == AMOUNTS[0]
    assert contract.get_milestone(JOB_ID, 0)["status"] == "refunded"
    assert contract.get_job(JOB_ID)["refunded_amount"] == AMOUNTS[0]
    assert contract.get_job(JOB_ID)["remaining_amount"] == AMOUNTS[1]

    with direct_vm.expect_revert("Milestone is not in a denied state"):
        contract.claim_denied(JOB_ID, 0)

    # A pending milestone still belongs to the escrow: no premature refund path.
    with direct_vm.expect_revert("Milestone is not in a denied state"):
        contract.claim_denied(JOB_ID, 1)


def test_review_rejects_substituted_evidence(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(direct_vm, contract)

    # Same URL, different bytes: committed hash no longer matches.
    _mock_photo(direct_vm, PHOTO_A, "GIF89a-swapped-image-bytes")
    result = _review(direct_vm, contract)
    assert result["approved"] is False
    assert result["score"] == 0
    assert "substituted" in result["reasoning"]

    milestone = contract.get_milestone(JOB_ID, 0)
    assert milestone["status"] == "denied"


def test_review_unreachable_evidence_denies(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(direct_vm, contract)

    _mock_photo(direct_vm, PHOTO_A, "gone", status=404)
    result = _review(direct_vm, contract)
    assert result["approved"] is False
    assert result["score"] == 0
    assert "HTTP 404" in result["reasoning"]


def test_review_unusable_llm_output_denies_safely(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(direct_vm, contract)

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, NO_SCORE_JSON)
    result = _review(direct_vm, contract)
    assert result["approved"] is False
    assert result["score"] == 0
    assert "no usable score" in result["reasoning"]
    assert contract.get_milestone(JOB_ID, 0)["status"] == "denied"


def test_validator_requires_exact_approval_decision(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(direct_vm, contract)

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, APPROVED_JSON)
    _review(direct_vm, contract)

    # Validator sees a denial for the same evidence -> approval flips -> reject.
    direct_vm.clear_mocks()
    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, DENIED_JSON)
    assert direct_vm.run_validator() is False

    # Validator agrees on the same approval bucket.
    direct_vm.clear_mocks()
    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, APPROVED_JSON)
    assert direct_vm.run_validator() is True

    # Validator accepts a neighbouring bucket but never a malformed score.
    direct_vm.clear_mocks()
    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, json.dumps({"score": 60, "reasoning": "Mostly done."}))
    assert direct_vm.run_validator() is True
    assert direct_vm.run_validator(leader_result={"score": 30, "reasoning": "x"}) is False
    assert (
        direct_vm.run_validator(
            leader_result={"score": 80, "reasoning": "only reasoning missing?"}
        )
        is True
    )
    assert direct_vm.run_validator(leader_result={"score": 80}) is False


def test_expire_protects_submitted_tranche_and_refunds_pending(direct_vm, direct_deploy):
    """Regression: an employer must not expire evidence submitted seconds before
    the deadline. Pending tranches are refunded; the submitted one is protected."""
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract, window=60, grace=1)
    _submit(direct_vm, contract, index=0)

    with direct_vm.expect_revert("Review grace period has not passed"):
        contract.expire_job(JOB_ID)

    # Past deadline + grace, but less than 7 days after submission.
    direct_vm.warp((datetime.now() + timedelta(seconds=120)).isoformat())
    result = contract.expire_job(JOB_ID)
    assert result["refunded_amount"] == AMOUNTS[1]
    assert result["protected_milestones"] == 1
    assert result["expired_milestones"] == 1
    assert result["status"] == "expired"

    assert contract.get_milestone(JOB_ID, 0)["status"] == "submitted"
    assert contract.get_milestone(JOB_ID, 1)["status"] == "expired"
    job = contract.get_job(JOB_ID)
    assert job["refunded_amount"] == AMOUNTS[1]
    assert job["remaining_amount"] == AMOUNTS[0]

    # After the protection window the remaining tranche is refundable.
    direct_vm.warp((datetime.now() + timedelta(days=8)).isoformat())
    result = contract.expire_job(JOB_ID)
    assert result["refunded_amount"] == AMOUNTS[0]
    assert result["status"] == "closed"

    job = contract.get_job(JOB_ID)
    assert job["refunded_amount"] == TOTAL
    assert job["remaining_amount"] == 0
    assert job["status"] == "closed"

    with direct_vm.expect_revert("Job is closed"):
        contract.expire_job(JOB_ID)


def test_review_still_works_after_expiry_of_other_tranches(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract, window=60, grace=1)
    _submit(direct_vm, contract, index=0)

    direct_vm.warp((datetime.now() + timedelta(seconds=120)).isoformat())
    contract.expire_job(JOB_ID)
    assert contract.get_job(JOB_ID)["status"] == "expired"

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, APPROVED_JSON)
    result = _review(direct_vm, contract, index=0)
    assert result["approved"] is True

    job = contract.get_job(JOB_ID)
    assert job["released_amount"] == AMOUNTS[0]
    assert job["refunded_amount"] == AMOUNTS[1]
    assert job["status"] == "closed"


def test_review_rejects_non_image_content(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(
        direct_vm,
        contract,
        evidence=_evidence([{"url": PHOTO_A, "sha256": _sha("plain text, not an image")}]),
    )

    _mock_photo(direct_vm, PHOTO_A, "plain text, not an image")
    result = _review(direct_vm, contract)
    assert result["approved"] is False
    assert "not a PNG" in result["reasoning"]
    assert contract.get_milestone(JOB_ID, 0)["status"] == "denied"


def test_verdict_binding_and_evidence_binding_are_distinct(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract)
    _submit(direct_vm, contract)

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, APPROVED_JSON)
    result = _review(direct_vm, contract)

    milestone = contract.get_milestone(JOB_ID, 0)
    assert len(result["verdict_binding"]) == 64
    assert result["verdict_binding"] == milestone["verdict_binding"]
    assert milestone["verdict_binding"] != milestone["evidence_binding"]


def test_denial_after_expiry_still_allows_employer_refund(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract, window=60, grace=1)
    _submit(direct_vm, contract, index=0)

    direct_vm.warp((datetime.now() + timedelta(seconds=120)).isoformat())
    contract.expire_job(JOB_ID)
    assert contract.get_job(JOB_ID)["status"] == "expired"

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, DENIED_JSON)
    _review(direct_vm, contract, index=0)

    direct_vm.sender = EMPLOYER_ADDR
    contract.claim_denied(JOB_ID, 0)
    job = contract.get_job(JOB_ID)
    assert job["refunded_amount"] == TOTAL
    assert job["status"] == "closed"


def test_claim_denied_requires_open_or_expired_job(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract, amounts=[TOTAL], criteria=[CRITERIA[0]])
    _submit(direct_vm, contract)
    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, DENIED_JSON)
    _review(direct_vm, contract)

    direct_vm.sender = EMPLOYER_ADDR
    contract.claim_denied(JOB_ID, 0)
    assert contract.get_job(JOB_ID)["status"] == "closed"
    with direct_vm.expect_revert("Job is closed"):
        contract.claim_denied(JOB_ID, 0)


def test_expire_keeps_approved_and_refunds_the_rest(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract, window=60, grace=60)
    _submit(direct_vm, contract, index=0)

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, APPROVED_JSON)
    _review(direct_vm, contract)

    direct_vm.warp((datetime.now() + timedelta(seconds=180)).isoformat())
    result = contract.expire_job(JOB_ID)
    assert result["expired_milestones"] == 1
    assert result["refunded_amount"] == AMOUNTS[1]

    job = contract.get_job(JOB_ID)
    assert job["released_amount"] == AMOUNTS[0]
    assert job["refunded_amount"] == AMOUNTS[1]
    assert job["status"] == "closed"


def test_approved_release_closes_single_milestone_job(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract, amounts=[TOTAL], criteria=[CRITERIA[0]])
    _submit(direct_vm, contract)

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, APPROVED_JSON)
    _review(direct_vm, contract)

    job = contract.get_job(JOB_ID)
    assert job["released_amount"] == TOTAL
    assert job["remaining_amount"] == 0
    assert job["status"] == "closed"


def test_denied_refund_closes_single_milestone_job(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/visual_milestone_escrow.py")
    _create_job(direct_vm, contract, amounts=[TOTAL], criteria=[CRITERIA[0]])
    _submit(direct_vm, contract)

    _mock_photo(direct_vm)
    _mock_verdict(direct_vm, DENIED_JSON)
    _review(direct_vm, contract)

    direct_vm.sender = EMPLOYER_ADDR
    contract.claim_denied(JOB_ID, 0)
    job = contract.get_job(JOB_ID)
    assert job["status"] == "closed"
    assert job["remaining_amount"] == 0
