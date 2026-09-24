"""Regression cases for duplicate tail probes, real loss, and degraded evidence."""
import datetime as dt
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import linux_telemetry, notification_reports as reports
from ops import security_signals as signals, notification_visuals as visuals
from ops.tests import test_notification_visuals as visual_fixtures
from ops.tests import test_notification_reports as report_fixtures

NOW = report_fixtures.NOW


def ssh_observation(index):
    counters = {"totalRetrans": 100 + index * 60, "dsackDuplicates": 100 + index * 60}
    return {"status": "supported", "socketId": "c" * 64, "before": dict(counters), "after": dict(counters)}


def current(index, **overrides):
    result = visual_fixtures.snapshot()
    stamp = (NOW + dt.timedelta(minutes=index)).isoformat().replace('+00:00', 'Z')
    result.update(generatedAt=stamp, identity={"bootId": "a" * 32})
    result['latest']['timestamp'] = stamp
    result['syntheticProbeCollection']['observedAt'] = stamp
    result['system']['reboot']['observedAt'] = stamp
    for probe in result['syntheticProbes']:
        probe['checkedAt'] = stamp
    counters = {key: 100 for key in signals.TCP_PROBE_COUNTERS}
    counters.update(OutSegs=10000 + index * 1000, RetransSegs=100 + index * 60,
                    TCPLossProbes=100 + index * 60, TCPDSACKRecv=100 + index * 60)
    counters.update(overrides)
    result['linux'].update(collectedAt=stamp)
    result['linux']['tcp'] = {"status": "supported", "rateStatus": "ok", "retransmissionPercent": 6,
                              "counters": counters, "verifiedSsh": ssh_observation(index)}
    return result


def window(mutator=lambda _row, _index: None):
    state = None
    for index in range(4):
        row = current(index)
        mutator(row, index)
        projected, state = signals.prepare_notification_current(row, NOW + dt.timedelta(minutes=index), state)
    return row, projected, state


class TcpProbePolicyTests(unittest.TestCase):
    def test_spurious_tail_probes_keep_raw_evidence_without_tcp_warning(self):
        raw, projected, _ = window()
        tcp = projected['linux']['tcp']
        self.assertEqual(raw['linux']['tcp']['retransmissionPercent'], 6)
        self.assertEqual(tcp['retransmissionPercent'], 0)
        self.assertEqual(tcp['notificationWindow']['rawRetransmittedSegmentsDelta'], 180)
        self.assertEqual(tcp['notificationWindow']['rawRetransmissionPercent'], 6)
        self.assertEqual(tcp['notificationWindow']['duplicateProbeSegmentsEstimate'], 180)
        self.assertEqual(tcp['notificationWindow']['duplicateProbeScope'], 'verified_ssh_socket')
        self.assertFalse(any(row['key'] == 'tcp:retransmission' for row in signals.operational_signals(projected)))

    def test_host_totals_alone_and_legacy_samples_never_authorize_a_discount(self):
        for unavailable in (None, {'status': 'unavailable'}):
            _, projected, _ = window(lambda row, _index: row['linux']['tcp'].update(verifiedSsh=unavailable))
            self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 6)
            self.assertEqual(projected['linux']['tcp']['notificationWindow']['duplicateProbeSegmentsEstimate'], 0)
        raw, _, state = window()
        for sample in state['samples']:
            sample.pop('verifiedSshDelta')
        projected, _ = signals.prepare_notification_current(raw, NOW + dt.timedelta(minutes=3), state)
        self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 6)

    def test_other_connections_remain_counted_even_without_host_loss_indicators(self):
        def mixed(row, index):
            row['linux']['tcp']['counters'].update(RetransSegs=100 + 100 * index,
                TCPLossProbes=100 + 100 * index, TCPDSACKRecv=100 + 100 * index)
        _, projected, _ = window(mixed)
        window_data = projected['linux']['tcp']['notificationWindow']
        self.assertEqual(window_data['rawRetransmittedSegmentsDelta'], 300)
        self.assertEqual(window_data['duplicateProbeSegmentsEstimate'], 180)
        self.assertEqual(window_data['retransmittedSegmentsDelta'], 120)
        self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 4)
        self.assertTrue(any(row['key'] == 'tcp:retransmission' for row in signals.operational_signals(projected)))

    def test_socket_reconnect_missing_fields_and_resets_disable_discount(self):
        def reconnect(row, index):
            if index >= 2:
                row['linux']['tcp']['verifiedSsh']['socketId'] = 'd' * 64
        def missing(row, index):
            if index == 2:
                row['linux']['tcp']['verifiedSsh']['before'].pop('dsackDuplicates')
        def reset(row, index):
            if index >= 2:
                row['linux']['tcp']['verifiedSsh']['before']['totalRetrans'] = index
                row['linux']['tcp']['verifiedSsh']['after']['totalRetrans'] = index
        for mutator in (reconnect, missing, reset):
            with self.subTest(mutator=mutator.__name__):
                _, projected, _ = window(mutator)
                self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 6)

    def test_socket_brackets_exclude_sampling_boundary_retransmissions(self):
        def boundary(row, _index):
            ssh = row['linux']['tcp']['verifiedSsh']
            for key in ('totalRetrans', 'dsackDuplicates'):
                ssh['after'][key] += 2
        _, projected, _ = window(boundary)
        self.assertEqual(projected['linux']['tcp']['notificationWindow']['duplicateProbeSegmentsEstimate'], 174)
        self.assertEqual(projected['linux']['tcp']['notificationWindow']['retransmittedSegmentsDelta'], 6)

    def test_dsack_from_a_different_interval_cannot_discount_current_retransmissions(self):
        def shifted(row, index):
            ssh = row['linux']['tcp']['verifiedSsh']
            count = (100, 100, 220, 280)[index]
            ssh['before']['dsackDuplicates'] = ssh['after']['dsackDuplicates'] = count
        _, projected, _ = window(shifted)
        self.assertEqual(projected['linux']['tcp']['notificationWindow']['duplicateProbeSegmentsEstimate'], 120)
        self.assertEqual(projected['linux']['tcp']['notificationWindow']['retransmittedSegmentsDelta'], 60)

    def test_socket_delta_exceeding_host_delta_is_not_clamped_into_a_discount(self):
        def inconsistent(row, index):
            row['linux']['tcp']['verifiedSsh']['before']['totalRetrans'] = 100 + index * 70
            row['linux']['tcp']['verifiedSsh']['after']['totalRetrans'] = 100 + index * 70
        _, projected, _ = window(inconsistent)
        self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 6)

    def test_discount_never_exceeds_either_probes_or_duplicate_reports(self):
        for counter in ('TCPLossProbes', 'TCPDSACKRecv'):
            raw, projected, _ = window(lambda row, index: row['linux']['tcp']['counters'].update({counter: 100 + index * 50}))
            self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 1)
            self.assertEqual(projected['linux']['tcp']['notificationWindow']['duplicateProbeSegmentsEstimate'], 150)
            self.assertEqual(next(row['severity'] for row in signals.operational_signals(projected) if row['key'] == 'tcp:retransmission'), 'warning')

    def test_any_actual_loss_indicator_preserves_full_warning_for_mixed_traffic(self):
        for counter in signals.TCP_LOSS_COUNTERS:
            with self.subTest(counter=counter):
                _, projected, _ = window(lambda row, index: row['linux']['tcp']['counters'].update({counter: 100 + index}))
                self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 6)
                self.assertEqual(projected['linux']['tcp']['notificationWindow']['duplicateProbeSegmentsEstimate'], 0)
                self.assertEqual(next(row['severity'] for row in signals.operational_signals(projected) if row['key'] == 'tcp:retransmission'), 'critical')

    def test_missing_invalid_or_reset_evidence_keeps_raw_assessment(self):
        def missing(row, index):
            if index == 2:
                row['linux']['tcp']['counters'].pop('TCPDSACKRecv')
        def reset(row, index):
            row['linux']['tcp']['counters']['TCPDSACKRecv'] = 100 if index >= 2 else 200
        def invalid(row, _index):
            row['linux']['tcp']['counters']['TCPLossProbes'] = True
        for mutator in (missing, reset, invalid):
            _, projected, _ = window(mutator)
            self.assertEqual(projected['linux']['tcp']['retransmissionPercent'], 6)

    def test_cached_snapshot_does_not_advance_or_reuse_changed_probe_counters(self):
        raw, projected, state = window()
        now = NOW + dt.timedelta(minutes=3, seconds=1)
        same, same_state = signals.prepare_notification_current(raw, now, state)
        self.assertEqual(same['linux']['tcp']['notificationWindow'], projected['linux']['tcp']['notificationWindow'])
        self.assertEqual(same_state['samples'], state['samples'])
        raw['linux']['tcp']['counters']['TCPTimeouts'] += 1
        changed, _ = signals.prepare_notification_current(raw, now, state)
        self.assertEqual(changed['linux']['tcp']['rateStatus'], 'insufficient_samples')
        raw['linux']['tcp']['counters']['TCPTimeouts'] -= 1
        raw['linux']['tcp']['verifiedSsh']['after']['dsackDuplicates'] += 1
        changed, _ = signals.prepare_notification_current(raw, now, state)
        self.assertEqual(changed['linux']['tcp']['rateStatus'], 'insufficient_samples')

    def test_stale_samples_and_boot_changes_never_claim_recovery(self):
        raw, _, state = window()
        stale, _ = signals.prepare_notification_current(raw, NOW + dt.timedelta(minutes=7), state)
        self.assertIsNone(stale['linux']['tcp']['retransmissionPercent'])
        raw['identity']['bootId'] = 'b' * 32
        raw['generatedAt'] = raw['linux']['collectedAt'] = (NOW + dt.timedelta(minutes=4)).isoformat()
        reboot, _ = signals.prepare_notification_current(raw, NOW + dt.timedelta(minutes=4), state)
        self.assertIsNone(reboot['linux']['tcp']['retransmissionPercent'])

    def test_collector_exports_real_probe_counters_without_inventing_missing_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'net').mkdir()
            (root / 'net/snmp').write_text('Tcp: OutSegs RetransSegs\nTcp: 10000 600\n')
            keys = signals.TCP_PROBE_COUNTERS[:-1]
            (root / 'net/netstat').write_text('TcpExt: ' + ' '.join(keys) + '\nTcpExt: ' + ' '.join('10' for _ in keys) + '\n')
            observed, _ = linux_telemetry.collect_tcp(root, {}, 60)
            for key in keys:
                self.assertEqual(observed['counters'][key], 10)
            self.assertNotIn('TCPRetransFail', observed['counters'])

    def test_hourly_mail_and_immediate_outbox_agree_without_turning_explanation_into_warning(self):
        fixture = report_fixtures.NotificationReportsTests('test_ssh_episode_and_source_loss_do_not_false_recover')
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        for index in range(4):
            now = NOW + dt.timedelta(minutes=index)
            fixture.refresh(now)
            fixture.current.update(identity=current(index)['identity'], linux=current(index)['linux'])
            produced = fixture.run_producer(now)
            self.assertEqual(produced['status'], 'ok')
            self.assertFalse(any('TCP' in row['evidence'] for row in produced['detections']))
        self.assertEqual(produced['immediate']['enqueued'], 0)
        _, projected, _ = window()
        visual = visuals.assess_hourly(projected, fixture.evaluation, produced['sourceHealth'], {}, now)
        self.assertEqual(visual['status'], 'ok')
        self.assertTrue(any('원시 합산 6.000%' in text for text in visual['highlights']))
        self.assertTrue(any('확인된 관리 SSH 소켓' in text for text in visual['highlights']))
        self.assertEqual(next(card['value'] for card in visual['cards'] if card['label'].startswith('TCP 경고 판정')), '0')

    def test_real_timeout_alongside_duplicate_probes_remains_rule_owned(self):
        fixture = report_fixtures.NotificationReportsTests('test_ssh_episode_and_source_loss_do_not_false_recover')
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        for index in range(4):
            now = NOW + dt.timedelta(minutes=index)
            fixture.refresh(now)
            snapshot = current(index, TCPTimeouts=100 + index)
            fixture.current.update(identity=snapshot['identity'], linux=snapshot['linux'])
            produced = fixture.run_producer(now)
        self.assertEqual(produced['immediate']['enqueued'], 0)
        self.assertFalse(any('TCP 재전송률' in row['evidence'] for row in produced['detections']))
        self.assertIn('TcpRetransmissionHigh', reports._retired_signal_reason('tcp:retransmission'))
        self.assertEqual(fixture.run_producer(now)['immediate']['enqueued'], 0)


class VerifiedSshCollectionTests(unittest.TestCase):
    BOOT = '01234567-89ab-cdef-0123-456789abcdef'
    LINE = ('0 0 10.0.0.1:22022 10.0.0.2:51111 uid:0 ino:123 sk:abcd '
            'cubic wscale:7,7 rtt:1/0.5 retrans:0/60 dsack_dups:59')

    def policy(self):
        identity = hashlib.sha256(f'{self.BOOT}|abcd|10.0.0.1:22022|10.0.0.2:51111'.encode()).hexdigest()
        return self.BOOT, identity, 22022

    def test_exact_cookie_endpoints_and_boot_are_required_without_exposing_addresses(self):
        result = linux_telemetry.parse_verified_ssh_socket(self.LINE, self.policy())
        self.assertEqual(result, {'socketId': self.policy()[1], 'totalRetrans': 60, 'dsackDuplicates': 59})
        self.assertNotIn('10.0.0.', json.dumps(result))
        for changed in (self.LINE.replace('sk:abcd', 'sk:abce'),
                        self.LINE.replace(':51111', ':51112'),
                        self.LINE.replace('dsack_dups:59', ''),
                        self.LINE.replace('10.0.0.2', '203.0.113.2'),
                        self.LINE + '\n' + self.LINE):
            self.assertIsNone(linux_telemetry.parse_verified_ssh_socket(changed, self.policy()))
        self.assertIsNone(linux_telemetry.parse_verified_ssh_socket(self.LINE, ('a' * 36, *self.policy()[1:])))

    def test_query_is_bounded_port_filtered_and_fails_closed(self):
        with mock.patch.object(linux_telemetry.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, self.LINE, '')
            self.assertIsNotNone(linux_telemetry.collect_verified_ssh_socket(self.policy()))
            self.assertEqual(run.call_args.args[0][-1], '( sport = :22022 )')
            self.assertEqual(run.call_args.kwargs['timeout'], 1.0)
            run.return_value = subprocess.CompletedProcess([], 1, self.LINE, 'permission denied')
            self.assertIsNone(linux_telemetry.collect_verified_ssh_socket(self.policy()))
            run.side_effect = subprocess.TimeoutExpired('ss', 1)
            self.assertIsNone(linux_telemetry.collect_verified_ssh_socket(self.policy()))
        with mock.patch.object(linux_telemetry.subprocess, 'run') as run:
            self.assertIsNone(linux_telemetry.collect_verified_ssh_socket(None))
            run.assert_not_called()
        self.assertIsNone(linux_telemetry.verified_ssh_policy(Path('/test/proc')))

    def test_collector_brackets_the_global_counter_read(self):
        calls = []
        def socket_read(_policy):
            calls.append('socket')
            return {'socketId': 'c' * 64, 'totalRetrans': len(calls), 'dsackDuplicates': len(calls)}
        original_read = linux_telemetry.read_limited
        def read(path, *args):
            if str(path).endswith(('/net/snmp', '/net/netstat')):
                calls.append(path.name)
            return original_read(path, *args)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(linux_telemetry, 'collect_verified_ssh_socket', side_effect=socket_read), \
                mock.patch.object(linux_telemetry, 'read_limited', side_effect=read):
            root = Path(temporary)
            observed, _ = linux_telemetry.collect_tcp(root, {}, 60)
        self.assertEqual(calls, ['socket', 'snmp', 'netstat', 'socket'])
        self.assertEqual(observed['verifiedSsh']['before']['totalRetrans'], 1)
        self.assertEqual(observed['verifiedSsh']['after']['totalRetrans'], 4)
