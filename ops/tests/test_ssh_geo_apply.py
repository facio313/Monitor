import contextlib
import io
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error

from ops import ssh_geo_apply
from ops.ssh_geo_apply import make_transaction


class TransactionTests(unittest.TestCase):
    def test_replaces_only_dedicated_table_in_one_batch(self):
        policy = '# pinned policy\ntable inet monitor_ssh_geo {\n}\n'
        result = make_transaction(policy)
        self.assertEqual(result, 'add table inet monitor_ssh_geo\ndelete table inet monitor_ssh_geo\n' + policy)

    def test_rejects_out_of_scope_commands(self):
        bad = [
            'flush ruleset\ntable inet monitor_ssh_geo {}',
            'table inet another_table {}',
            'table inet monitor_ssh_geo {}\ntable inet another_table {}',
            'table inet monitor_ssh_geo { include "/etc/anything"; }',
            'table inet monitor_ssh_geo {}\ndelete table inet something',
            'table inet monitor_ssh_geo {}\nreset counters\n{}',
        ]
        for policy in bad:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                make_transaction(policy)

    def test_rejects_oversized_policy(self):
        with self.assertRaises(ValueError):
            make_transaction('table inet monitor_ssh_geo {\n#' + 'x' * (2 * 1024 * 1024) + '\n}')


class PolicyUpdateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.policy = Path(temporary.name) / 'ssh-kr-only.nft'
        self.previous = self.policy.with_name(self.policy.name + '.previous')
        self.original = '# original\ntable inet monitor_ssh_geo {\n}\n'
        self.candidate = '# candidate\ntable inet monitor_ssh_geo {\n counter github {}\n}\n'
        self.policy.write_text(self.original, encoding='ascii')
        self.active = make_transaction(self.original)
        patcher = mock.patch.object(ssh_geo_apply, 'POLICY', self.policy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def nft(self, transaction, *, check=False):
        if not check:
            self.active = transaction

    def assert_original_retained(self):
        self.assertEqual(self.policy.read_text(encoding='ascii'), self.original)
        self.assertEqual(self.active, make_transaction(self.original))
        self.assertEqual(list(self.policy.parent.glob('.*')), [])

    def test_success_persists_and_activates_with_recovery_copy(self):
        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=self.nft) as nft:
            self.assertTrue(ssh_geo_apply.update_policy(self.original, self.candidate))
        self.assertEqual(self.policy.read_text(encoding='ascii'), self.candidate)
        self.assertEqual(self.previous.read_text(encoding='ascii'), self.original)
        self.assertEqual(self.active, make_transaction(self.candidate))
        self.assertEqual(stat.S_IMODE(self.policy.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.previous.stat().st_mode), 0o600)
        self.assertEqual(nft.call_args_list, [
            mock.call(make_transaction(self.candidate), check=True),
            mock.call(make_transaction(self.candidate)),
        ])

    def test_check_failure_leaves_disk_and_running_policy_untouched(self):
        failure = subprocess.CalledProcessError(1, ['nft', '--check'])
        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=failure) as nft:
            with self.assertRaises(subprocess.CalledProcessError):
                ssh_geo_apply.update_policy(self.original, self.candidate)
        self.assert_original_retained()
        self.assertFalse(self.previous.exists())
        nft.assert_called_once_with(make_transaction(self.candidate), check=True)

    def test_check_only_does_not_persist_or_activate(self):
        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=self.nft) as nft:
            self.assertFalse(ssh_geo_apply.update_policy(self.original, self.candidate, check=True))
        self.assert_original_retained()
        self.assertFalse(self.previous.exists())
        nft.assert_called_once_with(make_transaction(self.candidate), check=True)

    def test_unchanged_input_checks_without_rewriting_or_replacing_table(self):
        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=self.nft) as nft:
            with mock.patch.object(ssh_geo_apply, 'write_atomic') as write:
                self.assertFalse(ssh_geo_apply.update_policy(self.original, self.original))
        self.assert_original_retained()
        write.assert_not_called()
        nft.assert_called_once_with(make_transaction(self.original), check=True)

    def test_apply_failure_restores_original_disk_and_running_table(self):
        candidate_transaction = make_transaction(self.candidate)

        def nft_failure(transaction, *, check=False):
            if not check and transaction == candidate_transaction:
                raise subprocess.CalledProcessError(1, ['nft'])
            self.nft(transaction, check=check)

        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=nft_failure) as nft:
            with self.assertRaises(subprocess.CalledProcessError):
                ssh_geo_apply.update_policy(self.original, self.candidate)
        self.assert_original_retained()
        self.assertEqual(self.previous.read_text(encoding='ascii'), self.original)
        self.assertEqual(nft.call_args_list[-1], mock.call(make_transaction(self.original)))

    def test_timeout_after_nft_commit_restores_original_disk_and_table(self):
        candidate_transaction = make_transaction(self.candidate)

        def nft_timeout(transaction, *, check=False):
            self.nft(transaction, check=check)
            if not check and transaction == candidate_transaction:
                raise subprocess.TimeoutExpired(['nft'], 20)

        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=nft_timeout):
            with self.assertRaises(subprocess.TimeoutExpired):
                ssh_geo_apply.update_policy(self.original, self.candidate)
        self.assert_original_retained()
        self.assertEqual(self.previous.read_text(encoding='ascii'), self.original)

    def test_persistence_failure_before_or_after_replace_restores_original(self):
        real_write = ssh_geo_apply.write_atomic
        for fail_after_replace in (False, True):
            with self.subTest(fail_after_replace=fail_after_replace):
                def fail_candidate_write(path, content):
                    if path == self.policy and content == self.candidate:
                        if fail_after_replace:
                            real_write(path, content)
                        raise OSError('simulated persistence failure')
                    real_write(path, content)

                with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=self.nft) as nft:
                    with mock.patch.object(ssh_geo_apply, 'write_atomic', side_effect=fail_candidate_write):
                        with self.assertRaisesRegex(OSError, 'persistence failure'):
                            ssh_geo_apply.update_policy(self.original, self.candidate)
                self.assert_original_retained()
                self.assertEqual(self.previous.read_text(encoding='ascii'), self.original)
                self.assertNotIn(mock.call(make_transaction(self.candidate)), nft.call_args_list)

    def test_backup_failure_does_not_change_original_or_running_policy(self):
        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=self.nft) as nft:
            with mock.patch.object(ssh_geo_apply, 'write_atomic', side_effect=OSError('backup failure')):
                with self.assertRaisesRegex(OSError, 'backup failure'):
                    ssh_geo_apply.update_policy(self.original, self.candidate)
        self.assert_original_retained()
        self.assertFalse(self.previous.exists())
        nft.assert_called_once_with(make_transaction(self.candidate), check=True)

    def test_disk_recovery_failure_still_attempts_running_table_recovery(self):
        real_write = ssh_geo_apply.write_atomic

        def fail_disk_recovery(path, content):
            if path == self.policy and content == self.original:
                raise OSError('disk recovery failure')
            real_write(path, content)

        def nft_timeout(transaction, *, check=False):
            self.nft(transaction, check=check)
            if not check and transaction == make_transaction(self.candidate):
                raise subprocess.TimeoutExpired(['nft'], 20)

        with mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=nft_timeout):
            with mock.patch.object(ssh_geo_apply, 'write_atomic', side_effect=fail_disk_recovery):
                with self.assertRaisesRegex(RuntimeError, 'recovery failed'):
                    ssh_geo_apply.update_policy(self.original, self.candidate)
        self.assertEqual(self.active, make_transaction(self.original))
        self.assertEqual(self.previous.read_text(encoding='ascii'), self.original)

    def test_fetch_or_metadata_failure_retains_original_before_any_nft_operation(self):
        runtime = mock.Mock()
        runtime.lstat.return_value = mock.Mock(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
        runtime.__truediv__ = mock.Mock(return_value=self.policy.parent / 'apply.lock')
        for failure in ('fetch', 'parse'):
            with self.subTest(failure=failure), contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(ssh_geo_apply, 'RUNTIME', runtime))
                stack.enter_context(mock.patch.object(ssh_geo_apply.os, 'geteuid', return_value=0))
                stack.enter_context(mock.patch.object(ssh_geo_apply.os, 'fstat', return_value=mock.Mock(
                    st_uid=0, st_mode=stat.S_IFREG | 0o600, st_nlink=1)))
                stack.enter_context(mock.patch.object(ssh_geo_apply, 'read_policy', return_value=self.original))
                parser = mock.Mock(side_effect=ValueError('invalid metadata') if failure == 'parse' else None)
                renderer = mock.Mock()
                stack.enter_context(mock.patch.object(ssh_geo_apply, 'github_helpers', return_value=(parser, renderer)))
                stack.enter_context(mock.patch.object(ssh_geo_apply, 'fetch_github_meta',
                    side_effect=urllib.error.URLError('network unavailable') if failure == 'fetch' else None,
                    return_value=b'{}'))
                nft = stack.enter_context(mock.patch.object(ssh_geo_apply, 'run_nft', side_effect=self.nft))
                writer = stack.enter_context(mock.patch.object(ssh_geo_apply, 'write_atomic'))
                stack.enter_context(mock.patch.object(ssh_geo_apply.sys, 'argv', ['ssh-geo-apply', '--update-github']))
                stderr = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                self.assertEqual(ssh_geo_apply.main(), 1)
                self.assertIn('existing rules retained', stderr.getvalue())
                self.assert_original_retained()
                nft.assert_not_called()
                writer.assert_not_called()
                renderer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
