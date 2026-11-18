"""KX108-K1 — contrat RED : liaison des tickets souverains aux décisions KX108 vérifiées.

Un ticket souverain ne doit être émis et consommé qu'à partir d'une décision réellement produite par le rail canonique
(sigma.protocols.run_tooling_build_pipeline → GuardX108), persistée et vérifiée par scripts/obsidia_kx108_decision_store.py.
Une signature HMAC valide prouve la détention de la clé, pas l'existence d'une décision.

Les décisions utilisées ici sont réelles : run_and_persist_kx108_decision invoque le pipeline une fois et persiste
l'enregistrement. Aucun test n'écrit dans le dépôt : clé, magasins de décisions et de nonces, worktree cible sont en
tmp_path.

API K1 attendue (absente au HEAD 95cdc3af1 : ces tests sont RED) :
- sovereign_ticket.issue_sovereign_ticket_from_decision_record(decision_record_id, *, action_id, scope, input_hash,
  decision_store_dir, ttl_seconds=...) : charge et vérifie l'enregistrement dans le magasin canonique ; x108_gate,
  decision_id, domaine et liaison viennent de l'enregistrement, jamais de l'appelant ; le ticket porte
  decision_record_id et decision_record_hash ;
- issue_sovereign_ticket(x108_gate="ALLOW", ...) sans enregistrement : refusé (HOLD/BLOCK restent émissibles) ;
- ticket_store.verify_and_consume_sovereign_ticket(..., decision_store_dir=...) : recharge et revérifie la décision liée
  AVANT de réserver le nonce ; échec fermé si le magasin est indisponible ;
- l'enregistrement est authentifié à sa création par le rail canonique : un enregistrement forgé dont le hash
  structurel a été recalculé est refusé.
Aucune décision de remplacement n'est fabriquée lorsqu'un enregistrement manque.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (_REPO_ROOT / "scripts", _REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import obsidia_kx108_decision_store as S  # noqa: E402
from periphery.world_calls import sovereign_ticket as T  # noqa: E402
from periphery.world_calls import ticket_store as TS  # noqa: E402

SCOPE = "bounded_apply"
ACTION_ID = "prop-c2-001"
PAYLOAD = [{"path": "periphery/xdomain/c2_target_v0.py", "content": "# governed remediation content C2\nVALUE = 108\n", "type": "WRITE"}]


def _sha_json(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


INPUT_HASH = _sha_json(PAYLOAD)


def _state_kwargs(**overrides) -> dict:
    kwargs = {
        "session_id": "k1-session", "objective": "k1 objective",
        "base_sha": "e" * 40, "manifest_hash": "f" * 64, "diff_hash": "0" * 64,
        "approved_scope": ["synthetic/file.py"], "actual_touched_files": ["synthetic/file.py"],
        "new_files": [], "deleted_files": [],
        "protected_scope_status": "CLEAN", "human_approval_status": "APPROVED", "obsidure_status": "CLEAN",
        "worktree_isolated": True, "branch_isolated": True,
        "auto_commit_disabled": True, "auto_push_disabled": True, "auto_merge_disabled": True,
        "tests_results": "PASS", "gates_results": "PASS", "first_failure": None,
        "commit_status": "NOT_COMMITTED", "push_status": "NOT_PUSHED", "merge_status": "NOT_MERGED",
        "unknowns": [], "contradictions": [], "risk_flags": [], "decision_authority": "KX108_ONLY",
    }
    kwargs.update(overrides)
    return kwargs


def _binding(label: str) -> dict:
    return {
        "batch_execution_id": f"k1-batch-{label}", "child_execution_id": f"k1-child-{label}",
        "execution_authority_hash": "a" * 64, "approval_id": f"k1-approval-{label}",
        "test_contract_hash": "b" * 64, "test_result_id": f"tcr-k1-{label}",
        "test_result_record_hash": "c" * 64, "kx108_input_translation_hash": "d" * 64,
    }


@pytest.fixture(autouse=True)
def kernel_key():
    T.reset_kernel_keys()
    T.register_kernel_key(T._DEFAULT_KEY_ID, b"kx108-k1-contract-test-key-0123456789abcdef")
    yield
    T.reset_kernel_keys()


@pytest.fixture
def stores(tmp_path, monkeypatch):
    decisions = tmp_path / "dc"
    nonces = tmp_path / "consumed_nonces.jsonl"
    monkeypatch.setattr(TS, "_DEFAULT_CONSUMED_STORE", str(nonces))
    monkeypatch.setattr(S, "KX108_DECISION_DIR", decisions)
    return {"decisions": decisions, "nonces": str(nonces), "root": tmp_path}



def _approved_world(stores):
    if "approved_world" not in stores:
        import runpy
        helpers = runpy.run_path(
            "tests/cli/test_k1_pre_action_binding_positive_v1.py"
        )
        w, target, proposal, kw = helpers["_fixture"](stores["root"])
        assert w["dc"] == stores["decisions"]
        assert proposal.proposal_id == ACTION_ID
        assert proposal.raw_payload == PAYLOAD
        stores["approved_world"] = (w, target, proposal, kw)
    return stores["approved_world"]


def _decide(stores, **overrides) -> dict:
    # POST retained exclusively for negative HOLD/refusal tests.
    if overrides:
        result = S.run_and_persist_kx108_decision(
            _state_kwargs(**overrides),
            _binding(uuid.uuid4().hex[:8]),
            stores["decisions"],
        )
        assert result["verify_ok"], result
        return result["record"]

    # Positive path: genuine canonical PRE evidence and real KX108.
    w, _, _, _ = _approved_world(stores)

    import obsidia_kx108_pre_execution_evidence_adapter_v0 as PRE

    tr = PRE.translate_pre_execution_evidence_to_tooling_build_state(
        w["env"]["batch_execution_id"],
        w["child"]["child_execution_id"],
        w["approval_id"],
        execution_dir=w["ex"],
        pre_execution_context_dir=w["cx"],
    )
    assert tr["status"] == PRE.STATUS_READY, tr

    result = S.run_and_persist_kx108_pre_execution_decision(
        tr["pre_tooling_build_state_kwargs"],
        tr["pre_binding_context"],
        store_dir=stores["decisions"],
        execution_dir=w["ex"],
        pre_execution_context_dir=w["cx"],
    )
    assert result["verify_ok"], result
    assert result["record"]["x108_gate"] == "ALLOW", result
    return result["record"]



def _k1_issue(record_id: str, stores, **overrides):
    issue = getattr(T, "issue_sovereign_ticket_from_decision_record", None)
    if issue is None:
        pytest.fail("K1_NOT_IMPLEMENTED")

    _, _, _, canonical = _approved_world(stores)

    fields = (
        "action_id", "scope", "input_hash", "action_hash",
        "action_payload", "target_worktree", "base_sha",
        "approved_scope", "execution_dir",
        "pre_execution_context_dir", "repo_root",
        "world_call_class",
    )
    params = {key: canonical[key] for key in fields}
    params["decision_store_dir"] = stores["decisions"]
    params.update(overrides)

    return issue(record_id, **params)



def _consume(ticket, stores, *, payload=PAYLOAD, scope=SCOPE, decision_store_dir=None):
    kwargs = {
        "required_scope": scope,
        "expected_action_id": ACTION_ID,
        "action_payload": payload,
        "consumed_store_path": stores["nonces"],
    }

    if "decision_store_dir" in inspect.signature(
        TS.verify_and_consume_sovereign_ticket
    ).parameters:
        kwargs["decision_store_dir"] = decision_store_dir or stores["decisions"]

    if getattr(ticket, "version", None) == T.TICKET_VERSION_V2:
        _, _, _, canonical = _approved_world(stores)
        for key in (
            "target_worktree", "base_sha", "approved_scope",
            "execution_dir", "pre_execution_context_dir", "repo_root",
        ):
            kwargs[key] = canonical[key]

    return TS.verify_and_consume_sovereign_ticket(ticket, **kwargs)



def _mint_signed_allow(**fields):
    """Ticket ALLOW cryptographiquement valide, signé avec la clé, sans passer par aucun émetteur souverain
    (détenteur de clé ou code hérité) : modèle de l'autorité fabriquée par signature seule."""
    now = datetime.now(timezone.utc)
    base = {
        "version": T.TICKET_VERSION_V1, "ticket_id": uuid.uuid4().hex, "decision_id": "dec-fabricated",
        "action_id": ACTION_ID, "os3_ticket_id": "os3-fabricated", "scope": SCOPE, "x108_gate": "ALLOW",
        "autonomy_level": 1, "world_call_class": "GOVERNED_WRITE", "dry_run_only": True, "input_hash": INPUT_HASH,
        "action_hash": hashlib.sha256(ACTION_ID.encode("utf-8")).hexdigest(),
        "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=300)).isoformat(),
        "nonce": uuid.uuid4().hex, "key_id": T._DEFAULT_KEY_ID,
    }
    base.update(fields)
    raw = T.canonical_ticket_bytes(**{k: base.get(k, "") for k in inspect.signature(T.canonical_ticket_bytes).parameters})
    ticket_fields = {k: v for k, v in base.items() if k in T.SovereignTicket.__dataclass_fields__}
    return T.SovereignTicket(**ticket_fields, hash="", authenticator=T.compute_authenticator(raw, key_id=base["key_id"]))


def _nonce_consumed(stores, nonce: str) -> bool:
    return nonce in TS.load_consumed_nonces(stores["nonces"])


# ── refus : provenance souveraine absente ou fausse ────────────────────────────────────────────────────────────────

def test_signed_allow_without_any_decision_record_is_refused_before_nonce(stores):
    ticket = _mint_signed_allow()
    with pytest.raises(AssertionError):
        _consume(ticket, stores)
    assert not _nonce_consumed(stores, ticket.nonce)          # la décision est contrôlée avant le nonce


def test_fabricated_decision_identifiers_are_refused(stores):
    ticket = _mint_signed_allow(decision_id="dec-fabricated-001", decision_record_id="kxd-" + "0" * 32,
                                decision_record_hash="0" * 64)
    with pytest.raises(AssertionError):
        _consume(ticket, stores)
    assert not _nonce_consumed(stores, ticket.nonce)


def test_caller_supplied_allow_verdict_cannot_be_issued():
    with pytest.raises(AssertionError):
        T.issue_sovereign_ticket(action_id=ACTION_ID, os3_ticket_id="os3-caller", x108_gate="ALLOW", scope=SCOPE,
                                 autonomy_level=1, world_call_class="GOVERNED_WRITE", input_hash=INPUT_HASH)


def test_non_allow_tickets_remain_issuable_for_refusal_paths():
    ticket = T.issue_sovereign_ticket(action_id=ACTION_ID, os3_ticket_id="os3-refusal", x108_gate="HOLD",
                                      scope="world_bus", autonomy_level=1, world_call_class="NO_WORLD_CALL")
    assert ticket.x108_gate == "HOLD"


def test_signed_allow_bound_to_a_hold_decision_is_refused(stores):
    hold = _decide(stores, human_approval_status="PENDING")
    assert hold["x108_gate"] == "HOLD"
    ticket = _mint_signed_allow(decision_id=hold["decision_id"], decision_record_id=hold["decision_record_id"],
                                decision_record_hash=hold["decision_record_hash"])
    with pytest.raises(AssertionError):
        _consume(ticket, stores)
    assert not _nonce_consumed(stores, ticket.nonce)


def test_record_altered_after_issuance_is_refused(stores):
    record = _decide(stores)
    ticket = _k1_issue(record["decision_record_id"], stores)
    path = stores["decisions"] / f"{record['decision_record_id']}.json"
    altered = json.loads(path.read_text(encoding="utf-8"))
    altered["reason_code"] = "ALTERED_AFTER_DECISION"
    path.write_text(json.dumps(altered, ensure_ascii=False, indent=2), encoding="utf-8")
    with pytest.raises(AssertionError):
        _consume(ticket, stores)
    assert not _nonce_consumed(stores, ticket.nonce)


def test_forged_record_with_recomputed_structural_hash_is_refused(stores):
    genuine = _decide(stores)
    forged = dict(genuine)
    forged["decision_id"] = "forged-" + genuine["decision_id"]
    forged["decision_record_id"] = "kxd-forged" + uuid.uuid4().hex[:16]
    forged["decision_record_hash"] = S.compute_kx108_decision_record_hash(forged)
    assert S.verify_kx108_decision_record(forged)[0]          # l'intégrité structurelle seule l'accepte : c'est la faille
    assert S.store_kx108_decision_record(forged, stores["decisions"])["status"] == S.STATUS_STORED
    with pytest.raises(AssertionError):
        _k1_issue(forged["decision_record_id"], stores)


def test_input_binding_mismatch_is_refused(stores):
    record = _decide(stores)
    ticket = _k1_issue(record["decision_record_id"], stores)
    with pytest.raises(AssertionError):
        _consume(ticket, stores, payload=[{"path": "synthetic/file.py", "content": "x = 2\n", "type": "WRITE"}])


def test_scope_outside_the_decision_domain_is_refused(stores):
    record = _decide(stores)
    assert record["domain"] == "tooling_build"
    with pytest.raises(AssertionError):
        _k1_issue(record["decision_record_id"], stores, scope="world_bus")
    ticket = _k1_issue(record["decision_record_id"], stores)
    with pytest.raises(AssertionError):
        _consume(ticket, stores, scope="world_bus")


def test_verified_non_allow_decision_cannot_authorize(stores):
    hold = _decide(stores, human_approval_status="PENDING")
    try:
        ticket = _k1_issue(hold["decision_record_id"], stores)
    except AssertionError:
        return                                                  # émission refusée : conforme
    assert ticket.x108_gate == "HOLD"                           # verdict copié de l'enregistrement, jamais promu
    with pytest.raises(AssertionError):
        _consume(ticket, stores)


def test_expired_ticket_is_refused(stores):
    record = _decide(stores)
    ticket = _k1_issue(record["decision_record_id"], stores, ttl_seconds=-1)
    with pytest.raises(AssertionError):
        _consume(ticket, stores)


def test_consumed_nonce_is_refused(stores):
    record = _decide(stores)
    ticket = _k1_issue(record["decision_record_id"], stores)
    _consume(ticket, stores)
    with pytest.raises(AssertionError):
        _consume(ticket, stores)


def test_a_decision_backs_a_single_execution(stores):
    record = _decide(stores)
    _consume(_k1_issue(record["decision_record_id"], stores), stores)
    second = _k1_issue(record["decision_record_id"], stores)     # nouveau ticket, nouveau nonce, même décision
    with pytest.raises(AssertionError):
        _consume(second, stores)


def test_unauthenticated_legacy_record_is_refused(stores):
    record = _decide(stores)
    legacy = {k: v for k, v in record.items() if not k.startswith("decision_record_auth")
              and k not in ("decision_record_authenticator", "decision_record_key_id", "decision_record_producer")}
    legacy["decision_record_id"] = "kxd-legacy" + uuid.uuid4().hex[:16]
    legacy["decision_record_hash"] = S.compute_kx108_decision_record_hash(legacy)
    assert S.verify_kx108_decision_record(legacy)[0]
    assert S.store_kx108_decision_record(legacy, stores["decisions"])["status"] == S.STATUS_STORED
    with pytest.raises(AssertionError):
        _k1_issue(legacy["decision_record_id"], stores)


def test_unavailable_decision_store_fails_closed(stores, tmp_path):
    record = _decide(stores)
    ticket = _k1_issue(record["decision_record_id"], stores)
    with pytest.raises(AssertionError):
        _consume(ticket, stores, decision_store_dir=tmp_path / "decision_store_absent")
    assert not _nonce_consumed(stores, ticket.nonce)


def test_production_without_kernel_secret_authenticates_nothing(stores, monkeypatch):
    record = _decide(stores)                                    # authentifié avec la clé de test
    T.reset_kernel_keys()
    monkeypatch.setenv("OBSIDIA_ENV", "production")
    monkeypatch.delenv("OBSIDIA_KX108_SECRET_KEY", raising=False)
    monkeypatch.delenv("OBSIDIA_KEY_KX108_K1", raising=False)
    # K1: production can legitimately use the provisioned DPAPI key.
    # This negative test explicitly removes BOTH key sources:
    # environment and DPAPI. No fallback is allowed.
    from periphery.world_calls import k1_dpapi_bootstrap as dpapi
    monkeypatch.setattr(
        dpapi,
        "load_k1_dpapi_key_text",
        lambda: None,
    )
    with pytest.raises(Exception):                              # aucune clé de repli en production
        _decide(stores)
    with pytest.raises(AssertionError):                         # rien ne s'authentifie sans le secret du noyau
        _k1_issue(record["decision_record_id"], stores)


# ── usage conforme d'une décision réelle ────────────────────────────────────────────────────────────────────────────

def test_verified_allow_decision_is_usable_once_with_its_provenance(stores):
    record = _decide(stores)
    assert record["x108_gate"] == "ALLOW"
    assert S.verify_kx108_decision_record_authenticity(record) == (True, None)
    ticket = _k1_issue(record["decision_record_id"], stores)
    consumed = _consume(ticket, stores)
    assert consumed.x108_gate == "ALLOW" and consumed.decision_id == record["decision_id"]
    assert consumed.decision_record_id == record["decision_record_id"]
    assert consumed.decision_record_hash == record["decision_record_hash"]
    assert _nonce_consumed(stores, ticket.nonce)


# ── consommateur gouverné : un ticket injecté sans décision n'écrit rien ───────────────────────────────────────────

def test_governed_apply_injected_ticket_without_decision_writes_nothing(stores, tmp_path):
    from sigma.tooling.governed_bounded_apply import GovernedBoundedApply, PatchOperation, PatchProposal

    target = tmp_path / "target_worktree"
    target.mkdir()
    proposal = PatchProposal(proposal_id="k1-injected", base_sha="k1-base", target_worktree=str(target),
                             approved_scope=["note.txt"], operations=[PatchOperation(path="note.txt", content="x",
                                                                                     op_type="WRITE")])
    ticket = _mint_signed_allow(action_id="k1-injected", input_hash=proposal.patch_hash)
    result = GovernedBoundedApply(worktree_head_provider=lambda _path: "k1-base").apply_proposal_governed(
        proposal, injected_ticket=ticket)
    assert result.disk_written is False and not (target / "note.txt").exists()
    assert result.status.startswith("REFUSED")


def test_governed_apply_without_verified_decision_writes_nothing_and_invents_no_verdict(stores, tmp_path):
    from sigma.tooling.governed_bounded_apply import GovernedBoundedApply, PatchOperation, PatchProposal

    target = tmp_path / "target_worktree"
    target.mkdir()
    proposal = PatchProposal(proposal_id="k1-no-decision", base_sha="k1-base", target_worktree=str(target),
                             approved_scope=["note.txt"], operations=[PatchOperation(path="note.txt", content="x",
                                                                                     op_type="WRITE")])
    engine = GovernedBoundedApply(worktree_head_provider=lambda _path: "k1-base")
    for record_id in (None, "kxd-" + "0" * 32):                  # absente, puis fabriquée
        result = engine.apply_proposal_governed(proposal, decision_record_id=record_id,
                                                decision_store_dir=stores["decisions"])
        assert result.status == "REFUSED_PRE_DECISION" and result.disk_written is False
        assert result.kx108_pre_gate == "NO_VERIFIED_DECISION"   # ni HOLD ni BLOCK attribués au noyau
        assert not (target / "note.txt").exists()
