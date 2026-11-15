"""Cancellation evidence must unlock maintenance only with its private proof."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ordinary_cancel_setup', HERE / 'setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
CORE = HERE.parents[1] / 'kura/kura/distrib/src/main/resources/variants/linux/unfiltered/deb/control'

def core_guard(name):
    text = (CORE / name).read_text().split("<<'PYGUARD'\n", 1)[1].split('\nPYGUARD', 1)[0]
    tree = ast.parse(text)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'guard_cancelled_handoff')
    source = ast.get_source_segment(text, node)
    ns = dict(os=os, stat=stat, hashlib=hashlib, json=json, uuid=uuid)
    exec(source, ns)
    return source, ns['guard_cancelled_handoff']

class OrdinaryCancellationGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ordinary-cancel-guard-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'recovery'
        self.root.mkdir(mode=0o700)
        self.functions = [setup.guard_cancelled_handoff, *[core_guard(n)[1] for n in ['preinst', 'postinst']]]

    def put(self, path, value):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
        path.chmod(0o600)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def fixture(self):
        ident = 'handoff-' + str(uuid.uuid4())
        source = dict(schema_version=2, id='rec-' + str(uuid.uuid4()), state='COMPLETED_APPROVED_CHECKS', ordinary=None, completion={'completed': True})
        f = lambda suffix: self.root / 'receipts' / (ident + suffix)
        source_sha = self.put(f('.ordinary-source.json'), source)
        grant = dict(schema=1, unit='kura-ordinary.service', profileId='profile-' + str(uuid.uuid4()), profileFiles=[dict(path='/fixed/input', sha256='a'*64)])
        grant_sha = self.put(f('.ordinary-grant.json'), grant)
        profile_sha = hashlib.sha256((grant_sha+'\n'+'a'*64).encode()).hexdigest()
        result = dict(id=ident, unit=grant['unit'], profileId=grant['profileId'], state='ORDINARY_CANCELLED', cancelled=True, issued=False, ordinaryUnitHandedOff=False, scope='administrator-selected-checks', kuraRecoveryVerified=False, normalBootVerified=False)
        binding = dict(commandId=str(uuid.uuid4()), operation=29, requestSha256='b'*64)
        decision = dict(schema=1, binding=binding, recoveryId=source['id'], handoffId=ident, result=result)
        command_path = self.root / 'commands' / (binding['commandId'] + '.json')
        command_sha = self.put(command_path, decision)
        receipt = dict(schema='yofc.agent.ordinary-cancel.v1', result=result, sourceJournalSha256=source_sha, grantSha256=grant_sha, profileDigest=profile_sha, cancellationCommand=binding)
        receipt_sha = self.put(f('.ordinary-cancel.json'), receipt)
        p = dict(id=ident, unit=grant['unit'], profile_id=grant['profileId'], source_sha256=source_sha, grant_sha256=grant_sha, profile_digest=profile_sha, cancelled=True, issued=False, verified=False, observation=None, cancel_command=binding, command_decisions={binding['commandId']:command_sha}, receipt_sha256=receipt_sha)
        j = {**source, 'state':'ORDINARY_CANCELLED', 'ordinary':p}
        self.put(self.root / 'transaction.json', j)
        return j, f, command_path

    def test_shipped_guards_are_exact_and_read_only(self):
        import inspect
        self.assertEqual(core_guard('preinst')[0], inspect.getsource(setup.guard_cancelled_handoff).strip())
        self.assertEqual(core_guard('preinst')[0], core_guard('postinst')[0])
        self.fixture()
        before = {str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        for call in self.functions:
            call(self.root)
        self.assertEqual(before, {str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_issued_and_unlinked_or_tampered_evidence_never_unlocks(self):
        j, f, command = self.fixture()
        original = (self.root / 'transaction.json').read_bytes()
        for field, value in [('issued',True),('verified',True),('receipt_sha256','c'*64),('command_decisions',{})]:
            bad = json.loads(original);bad['ordinary'][field]=value;self.put(self.root/'transaction.json',bad)
            for call in self.functions:
                with self.assertRaises((RuntimeError, ValueError, KeyError)):
                    call(self.root)
        (self.root/'transaction.json').write_bytes(original)
        saved = command.read_bytes();command.write_bytes(b'changed')
        for call in self.functions:
            with self.assertRaises((RuntimeError, ValueError)):
                call(self.root)
        command.write_bytes(saved)
        f('.ordinary-cancel.json').chmod(0o644)
        for call in self.functions:
            with self.assertRaises(RuntimeError):
                call(self.root)

    def test_parent_identity_and_archived_grant_are_required(self):
        j, f, _ = self.fixture()
        for path in [f('.ordinary-source.json'), f('.ordinary-grant.json')]:
            raw=path.read_bytes();path.write_bytes(b'{}')
            for call in self.functions:
                with self.assertRaises(RuntimeError):
                    call(self.root)
            path.write_bytes(raw)

    @unittest.skipUnless(os.environ.get('YOFC_ORDINARY_CANCEL_GUARD_FIXTURE'), 'explicit exported native contract fixture')
    def test_exported_native_cancelled_journal_is_accepted_without_mutation(self):
        f=Path(os.environ['YOFC_ORDINARY_CANCEL_GUARD_FIXTURE'])
        root=Path(json.loads((f/'fixture.json').read_text())['state'])
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
        for call in self.functions:
            call(root)
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()})

    @unittest.skipUnless(os.environ.get('YOFC_ORDINARY_CANCEL_GUARD_FIXTURE'), 'explicit exported native contract fixture')
    def test_native_original_prepare_token_cannot_drift_after_cancellation(self):
        import shutil
        f=Path(os.environ['YOFC_ORDINARY_CANCEL_GUARD_FIXTURE'])
        source=Path(json.loads((f/'fixture.json').read_text())['state'])
        clone=self.root/'native-copy';shutil.copytree(source,clone)
        j=json.loads((clone/'transaction.json').read_text());j['ordinary']['confirm_token']=str(uuid.uuid4());self.put(clone/'transaction.json',j)
        for call in self.functions:
            with self.assertRaises(RuntimeError):
                call(clone)
