"""KX108 K1 approved canonical PRE child / exact proposal ticket binding."""
import hashlib
import runpy
from pathlib import Path

import pytest

from periphery.world_calls.sovereign_ticket import (
    issue_sovereign_ticket_from_decision_record,
)
from periphery.world_calls.ticket_store import verify_and_consume_sovereign_ticket
from sigma.tooling.governed_bounded_apply import PatchProposal, PatchOperation


def _fixture(tmp_path):
    c2 = runpy.run_path('tests/cli/test_governed_content_apply_c2_v0.py')
    w = c2['_world'](tmp_path)
    wt = w['repo'] / 'wt'
    rel = w['child']['target_path']
    target = wt / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(c2['_OLD'])
    proposal = PatchProposal(
        proposal_id=w['mk']['proposal_id'],
        base_sha='a'*40,
        target_worktree=str(wt),
        approved_scope=[rel],
        operations=[PatchOperation(rel, c2['_SRC'].decode('utf-8'), 'WRITE')],
    )
    kw = dict(
        action_id=proposal.proposal_id,
        scope='bounded_apply',
        input_hash=proposal.patch_hash,
        action_hash=hashlib.sha256(
            f'{proposal.target_worktree}:{proposal.base_sha}'.encode('utf-8')
        ).hexdigest(),
        action_payload=proposal.raw_payload,
        target_worktree=proposal.target_worktree,
        base_sha=proposal.base_sha,
        approved_scope=proposal.approved_scope,
        execution_dir=w['ex'],
        pre_execution_context_dir=w['cx'],
        decision_store_dir=w['dc'],
        repo_root=w['repo'],
        world_call_class='GOVERNED_WRITE',
    )
    return w, target, proposal, kw


def test_exact_pre_approved_action_can_issue_and_consume_once(tmp_path):
    w, target, proposal, kw = _fixture(tmp_path)
    ticket = issue_sovereign_ticket_from_decision_record(w['pre_id'], **kw)
    consume = dict(
        required_scope='bounded_apply',
        expected_action_id=proposal.proposal_id,
        action_payload=proposal.raw_payload,
        decision_store_dir=w['dc'],
        consumed_store_path=str(tmp_path / 'private_nonces.jsonl'),
        target_worktree=proposal.target_worktree,
        base_sha=proposal.base_sha,
        approved_scope=proposal.approved_scope,
        execution_dir=w['ex'],
        pre_execution_context_dir=w['cx'],
        repo_root=w['repo'],
    )
    assert verify_and_consume_sovereign_ticket(ticket, **consume).ticket_id == ticket.ticket_id
    with pytest.raises(AssertionError):
        verify_and_consume_sovereign_ticket(ticket, **consume)
    assert target.read_bytes() == runpy.run_path('tests/cli/test_governed_content_apply_c2_v0.py')['_OLD']


@pytest.mark.parametrize('mutation', [
    'action_id','content','path','scope','base_sha','worktree','type','multi','missing_evidence',
])
def test_unapproved_action_is_never_issued(tmp_path, mutation):
    w, target, proposal, kw = _fixture(tmp_path)
    kw = dict(kw)
    if mutation == 'action_id':
        kw['action_id'] = 'unrelated-proposal'
    elif mutation == 'content':
        kw['action_payload'] = [{'path':kw['action_payload'][0]['path'], 'content':'DIFFERENT', 'type':'WRITE'}]
        kw['input_hash'] = hashlib.sha256(__import__('json').dumps(kw['action_payload'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    elif mutation == 'path':
        kw['action_payload'] = [{'path':'src/not_approved.py','content':kw['action_payload'][0]['content'],'type':'WRITE'}]
        kw['input_hash'] = hashlib.sha256(__import__('json').dumps(kw['action_payload'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    elif mutation == 'scope':
        kw['approved_scope'] = ['extra.py', *kw['approved_scope']]
    elif mutation == 'base_sha':
        kw['base_sha'] = 'f' * 40
        kw['action_hash'] = hashlib.sha256(f"{kw['target_worktree']}:{kw['base_sha']}".encode()).hexdigest()
    elif mutation == 'worktree':
        kw['target_worktree'] = str(tmp_path / 'other_wt')
        kw['action_hash'] = hashlib.sha256(f"{kw['target_worktree']}:{kw['base_sha']}".encode()).hexdigest()
    elif mutation == 'type':
        kw['action_payload'] = [{**kw['action_payload'][0], 'type':'DELETE'}]
        kw['input_hash'] = hashlib.sha256(__import__('json').dumps(kw['action_payload'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    elif mutation == 'multi':
        kw['action_payload'] = kw['action_payload'] + kw['action_payload']
        kw['input_hash'] = hashlib.sha256(__import__('json').dumps(kw['action_payload'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    elif mutation == 'missing_evidence':
        kw['execution_dir'] = None
    with pytest.raises(AssertionError, match='SOVEREIGN_TICKET_PRE_ACTION_BINDING'):
        issue_sovereign_ticket_from_decision_record(w['pre_id'], **kw)


def test_consumption_revalidates_changed_precondition_before_nonce(tmp_path):
    w, target, proposal, kw = _fixture(tmp_path)
    ticket = issue_sovereign_ticket_from_decision_record(w['pre_id'], **kw)
    target.write_text('DRIFT', encoding='utf-8')
    ledger = tmp_path / 'consumed_private.jsonl'
    with pytest.raises(AssertionError, match='TARGET_PRECONDITION_DRIFT'):
        verify_and_consume_sovereign_ticket(
            ticket, required_scope='bounded_apply',
            expected_action_id=proposal.proposal_id,
            action_payload=proposal.raw_payload,
            decision_store_dir=w['dc'], consumed_store_path=str(ledger),
            target_worktree=proposal.target_worktree,
            base_sha=proposal.base_sha, approved_scope=proposal.approved_scope,
            execution_dir=w['ex'], pre_execution_context_dir=w['cx'],repo_root=w['repo'],
        )
    assert not ledger.exists()
