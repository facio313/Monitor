import datetime as dt
import json
import unittest

from ops.log_pipeline import (
    PipelineLimits,
    LogSource,
    SourceBatch,
    normalize_record,
    normalize_quota_state,
    process_batches,
    redact_text,
)


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)
HOST_ID = "b7410c1a-e265-4bd7-8a8e-7411d3744961"


class LogPipelineTests(unittest.TestCase):
    def test_source_contract_rejects_unbounded_or_sensitive_dimensions(self):
        with self.assertRaises(ValueError):
            LogSource(source_id="a" * 64, kind="docker")
        with self.assertRaises(ValueError):
            LogSource(source_id="app", kind="socket")
        with self.assertRaises(ValueError):
            LogSource(source_id="app", kind="file", field_allowlist=("password",))
        with self.assertRaises(ValueError):
            LogSource(source_id="app", kind="file", field_allowlist=("db_password",))
        with self.assertRaises(ValueError):
            LogSource(source_id="app", kind="file", host_id="not-a-uuid")
        with self.assertRaises(ValueError):
            LogSource(source_id="app", kind="file", container_name="token=value")
        with self.assertRaises(ValueError):
            SourceBatch(LogSource(source_id="app", kind="file"), "not-a-sequence-of-lines")

    def test_redaction_removes_secrets_and_common_personal_identifiers(self):
        raw = (
            "Authorization: Bearer super-secret\n"
            "token=also-secret\n"
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue "
            "person@example.com 192.168.1.20 4111 1111 1111 1111\n"
            "2001:db8::1 +82-10-1234-5678 AKIAIOSFODNN7EXAMPLE "
            "postgres://monitor:database-password@db.internal/app\n"
            "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"
        )
        redacted = redact_text(raw)
        for forbidden in (
            "super-secret",
            "also-secret",
            "eyJhbGci",
            "person@example.com",
            "192.168.1.20",
            "4111 1111 1111 1111",
            "2001:db8::1",
            "+82-10-1234-5678",
            "AKIAIOSFODNN7EXAMPLE",
            "database-password",
            "private-material",
        ):
            self.assertNotIn(forbidden, redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn("[REDACTED_JWT]", redacted)
        self.assertIn("[REDACTED_EMAIL]", redacted)
        self.assertIn("[REDACTED_IP]", redacted)
        self.assertIn("[REDACTED_CARD]", redacted)
        self.assertIn("[REDACTED_PHONE]", redacted)
        self.assertIn("[REDACTED_TOKEN]", redacted)
        self.assertIn("[REDACTED_PRIVATE_KEY]", redacted)

    def test_redaction_consumes_basic_auth_and_quoted_multiword_secrets(self):
        raw = (
            'Authorization: Basic dXNlcjpwYXNzd29yZA== request=discarded\n'
            'password="very secret phrase" trailing=discarded\n'
            'secret=\'two words\' trailing=discarded\n'
            'Proxy-Authorization=Negotiate c3VwZXItc2VjcmV0 trailing=discarded'
        )

        redacted = redact_text(raw)

        for forbidden in (
            "dXNlcjpwYXNzd29yZA==",
            "very secret phrase",
            "two words",
            "c3VwZXItc2VjcmV0",
        ):
            self.assertNotIn(forbidden, redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED]"), 4)

    def test_redaction_fails_closed_for_malformed_and_unknown_secret_syntax(self):
        raw = (
            'password="very secret phrase\n'
            'password=[REDACTED] secret phrase]\n'
            'Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260831, '
            'SignedHeaders=host, Signature=abcdef\n'
            'Authorization: ApiKey opaque secret material'
        )

        redacted = redact_text(raw)

        for forbidden in (
            "very secret phrase",
            "secret phrase]",
            "Credential=",
            "Signature=",
            "opaque secret material",
        ):
            self.assertNotIn(forbidden, redacted)
        self.assertEqual(redacted.count("[REDACTED]"), 4)

    def test_redaction_covers_prefixed_and_suffixed_credential_labels(self):
        raw = (
            "AWS_SECRET_ACCESS_KEY=supersecret123 trailing=discarded\n"
            "db_password=hunter2 trailing=discarded\n"
            "OpenAI_Api_Key=opaque-value trailing=discarded\n"
            '{"message":"failed","MYSQL_ROOT_PASSWORD":"database-secret"}\n'
            "https://example.test/?service_access_token_value=query-secret"
        )

        redacted = redact_text(raw)

        for forbidden in (
            "supersecret123", "hunter2", "opaque-value", "database-secret",
            "query-secret", "trailing=discarded",
        ):
            self.assertNotIn(forbidden, redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED]"), 5)

    def test_json_logfmt_syslog_and_plain_are_normalized_to_one_schema(self):
        json_source = LogSource(
            source_id="docker:monitor",
            kind="docker",
            host_id=HOST_ID,
            container_name="monitor",
            compose_project="monitor",
            compose_service="monitor",
            stream="stdout",
            field_allowlist=("request.method", "status", "user"),
        )
        logfmt_source = LogSource(
            source_id="file:worker", kind="file", parser="logfmt",
            process_name="worker", field_allowlist=("job",),
        )
        journal_source = LogSource(
            source_id="journal:sshd", kind="journald", parser="syslog",
            systemd_unit="sshd.service", priority="security",
        )
        plain_source = LogSource(source_id="file:plain", kind="file", parser="plain")
        result = process_batches(
            [
                SourceBatch(json_source, [json.dumps({
                    "timestamp": "2026-08-30T11:59:58+00:00",
                    "level": "warn",
                    "message": "request from person@example.com token=hidden",
                    "request": {"method": "GET"},
                    "status": 503,
                    "user": "person@example.com",
                    "password": "must-never-escape",
                })]),
                SourceBatch(logfmt_source, [
                    'time=2026-08-30T11:59:59Z level=error msg="worker failed" job=backup api_key=hidden'
                ]),
                SourceBatch(journal_source, [
                    "<3>1 2026-08-30T12:00:00Z host sshd 9 ID47 - login failed from 10.0.0.4"
                ]),
                SourceBatch(plain_source, ["plain cookie=session-secret"]),
            ],
            NOW,
        )
        self.assertEqual(result["admittedTotal"], 4)
        records = result["records"]
        self.assertEqual([row["parser"] for row in records], ["json", "logfmt", "syslog", "plain"])
        self.assertEqual(records[0]["severity"], "warning")
        self.assertEqual(records[0]["timestamp"], "2026-08-30T11:59:58.000Z")
        self.assertEqual(records[0]["timestampSource"], "event")
        self.assertEqual(records[0]["fields"], {
            "request.method": "GET", "status": 503, "user": "[REDACTED_EMAIL]",
        })
        self.assertEqual(records[1]["fields"], {"job": "backup"})
        self.assertEqual(records[2]["severity"], "error")
        self.assertEqual(records[2]["systemdUnit"], "sshd.service")
        serialized = json.dumps(result, ensure_ascii=False)
        for forbidden in (
            "person@example.com", "must-never-escape", "session-secret", "10.0.0.4",
            "api_key=hidden",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_multiline_stack_trace_is_joined_and_bounded(self):
        source = LogSource(source_id="file:app", kind="file", multiline="auto")
        limits = PipelineLimits(
            max_multiline_lines=3,
            max_event_bytes=1024,
            max_line_bytes=1024,
            max_input_bytes_per_source=4096,
        )
        result = process_batches([SourceBatch(source, [
            "2026-08-30T11:59:58Z ERROR request failed",
            "  at first(frame)",
            "Caused by: broken",
            "  at dropped(frame)",
            "2026-08-30T11:59:59Z INFO recovered",
        ])], NOW, limits=limits)
        self.assertEqual(result["admittedTotal"], 2)
        first = result["records"][0]
        self.assertEqual(first["parser"], "syslog")
        self.assertEqual(first["multilineLineCount"], 4)
        self.assertTrue(first["truncated"])
        self.assertIn("at first(frame)", first["message"])
        self.assertNotIn("dropped(frame)", first["message"])
        self.assertEqual(result["sources"][0]["dropped"]["multilineLineLimit"], 1)

    def test_private_pem_physical_lines_are_suppressed_for_all_supported_labels(self):
        source = LogSource(source_id="file:pem", kind="file", multiline="off")
        labels = (
            "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
            "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "APPLICATION SECRET",
        )
        lines: list[str] = []
        forbidden: list[str] = []
        for index, label in enumerate(labels):
            body = f"TUlJRXZRSUJBREFOQmdraGtpRzl3MEJBUUVGQUFTQ{index}="
            lines.extend((f"-----BEGIN {label}-----", body, f"-----END {label}-----"))
            forbidden.extend((f"BEGIN {label}", body, f"END {label}"))
        lines.append("service recovered")

        result = process_batches([SourceBatch(source, lines)], NOW)

        self.assertEqual(
            [row["message"] for row in result["records"]],
            ["[REDACTED_PRIVATE_KEY]"] * len(labels) + ["service recovered"],
        )
        serialized = json.dumps(result, ensure_ascii=False)
        for value in forbidden:
            self.assertNotIn(value, serialized)
        self.assertEqual(result["quotaState"]["pemSuppressionBySource"], {})

    def test_private_pem_suppression_is_source_local_and_survives_collection_runs(self):
        pem_source = LogSource(source_id="file:pem", kind="file", multiline="off")
        peer_source = LogSource(source_id="file:peer", kind="file", multiline="off")
        first = process_batches([
            SourceBatch(pem_source, [
                "-----BEGIN RSA PRIVATE KEY-----", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
            ]),
            SourceBatch(peer_source, ["peer remains visible"]),
        ], NOW)
        self.assertEqual([row["message"] for row in first["records"]], [
            "[REDACTED_PRIVATE_KEY]", "peer remains visible",
        ])
        self.assertEqual(
            first["quotaState"]["pemSuppressionBySource"]["file:pem"]["label"],
            "RSA PRIVATE KEY",
        )

        second = process_batches([
            SourceBatch(pem_source, [
                "RkZHSElKS0w=", "-----END RSA PRIVATE KEY-----", "pem source recovered",
            ]),
            SourceBatch(peer_source, ["peer next"]),
        ], NOW + dt.timedelta(seconds=61), prior_state=first["quotaState"])

        self.assertEqual([row["message"] for row in second["records"]], [
            "pem source recovered", "peer next",
        ])
        self.assertNotIn("RkZHSElKS0w=", json.dumps(second))
        self.assertEqual(second["quotaState"]["pemSuppressionBySource"], {})

    def test_unterminated_pem_recovers_after_bounded_fail_closed_overflow(self):
        source = LogSource(source_id="file:pem", kind="file", multiline="off")
        limits = PipelineLimits(
            max_multiline_lines=2,
            max_event_bytes=256,
            max_line_bytes=256,
            max_input_bytes_per_source=1024,
        )
        first = process_batches([SourceBatch(source, [
            "-----BEGIN OPENSSH PRIVATE KEY-----", "QUJDRA==",
        ])], NOW, limits=limits)
        second = process_batches([SourceBatch(source, [
            "RkZHSA==", "SUpLTE1O", "service recovered", "later event",
        ])], NOW + dt.timedelta(seconds=1), limits=limits, prior_state=first["quotaState"])

        self.assertEqual([row["message"] for row in second["records"]], [
            "service recovered", "later event",
        ])
        self.assertNotIn("RkZHSA==", json.dumps(second))
        self.assertNotIn("SUpLTE1O", json.dumps(second))
        self.assertEqual(second["quotaState"]["pemSuppressionBySource"], {})

    def test_v1_quota_state_enters_conservative_cursor_recovery(self):
        source = LogSource(source_id="file:pem", kind="file", multiline="off")
        legacy_state = {
            "schemaVersion": 1,
            "windowStartedAt": int(NOW.timestamp()),
            "admittedGlobal": 0,
            "admittedBySource": {},
        }
        result = process_batches([SourceBatch(source, [
            "QUJDRA==", "-----END ENCRYPTED PRIVATE KEY-----", "ordinary event",
        ])], NOW, prior_state=legacy_state)

        self.assertEqual([row["message"] for row in result["records"]], ["ordinary event"])
        self.assertNotIn("QUJDRA==", json.dumps(result))
        self.assertEqual(result["quotaState"]["schemaVersion"], 2)
        self.assertEqual(result["quotaState"]["redactionVersion"], "monitor-log-redaction-v2")
        self.assertFalse(result["quotaState"]["pemRecoveryRequired"])

    def test_acquisition_recovery_suppresses_body_when_begin_was_skipped(self):
        source = LogSource(source_id="file:pem", kind="file", multiline="off")
        result = process_batches(
            [SourceBatch(source, [
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
                "-----END RSA PRIVATE KEY-----",
                "ordinary event",
            ])],
            NOW,
            pem_recovery_sources=(source.source_id,),
        )

        self.assertEqual([row["message"] for row in result["records"]], ["ordinary event"])
        self.assertNotIn("MIIEvQIB", json.dumps(result))
        wrapped = LogSource(
            source_id="file:wrapped-pem", kind="file", parser="logfmt", multiline="off"
        )
        wrapped_result = process_batches(
            [SourceBatch(wrapped, [
                'msg="MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"',
                'msg="-----END OPENSSH PRIVATE KEY-----"',
                'msg="wrapped recovery succeeded"',
            ])],
            NOW,
            pem_recovery_sources=(wrapped.source_id,),
        )
        self.assertEqual(
            [row["message"] for row in wrapped_result["records"]],
            ["wrapped recovery succeeded"],
        )
        self.assertNotIn("MIIEvQIB", json.dumps(wrapped_result))
        with self.assertRaises(ValueError):
            process_batches(
                [SourceBatch(source, ["line"])], NOW,
                pem_recovery_sources=("file:not-configured",),
            )

    def test_priority_and_persistent_quotas_bound_bursts(self):
        debug = LogSource(source_id="file:debug", kind="file", priority="debug")
        security = LogSource(source_id="journal:audit", kind="journald", priority="security")
        limits = PipelineLimits(
            max_events_per_source_per_window=2,
            max_events_global_per_window=2,
        )
        first = process_batches([
            SourceBatch(debug, ["debug one", "debug two"]),
            SourceBatch(security, ["security one", "security two"]),
        ], NOW, limits=limits)
        self.assertEqual([row["message"] for row in first["records"]], [
            "security one", "security two",
        ])
        self.assertEqual(first["sources"][0]["dropped"]["globalQuota"], 2)
        self.assertEqual(first["quotaState"]["admittedBySource"], {"journal:audit": 2})

        second = process_batches([
            SourceBatch(security, ["security three"]),
            SourceBatch(debug, ["debug three"]),
        ], NOW + dt.timedelta(seconds=10), limits=limits, prior_state=first["quotaState"])
        self.assertEqual(second["records"], [])
        self.assertEqual(second["sources"][0]["dropped"]["sourceQuota"], 1)
        self.assertEqual(second["sources"][1]["dropped"]["globalQuota"], 1)

        reset = process_batches(
            [SourceBatch(debug, ["next window"])],
            NOW + dt.timedelta(seconds=61), limits=limits, prior_state=second["quotaState"],
        )
        self.assertEqual(reset["admittedTotal"], 1)
        self.assertEqual(reset["quotaState"]["admittedBySource"], {"file:debug": 1})

    def test_aggregate_input_share_and_run_event_cap_are_priority_safe(self):
        normal = LogSource(source_id="file:normal", kind="file", priority="normal")
        security = LogSource(
            source_id="journal:security", kind="journald", priority="security"
        )
        limits = PipelineLimits(
            max_sources=2,
            max_input_bytes_per_source=1024 * 1024,
            max_input_bytes_global=1024 * 1024,
            max_line_bytes=512 * 1024,
            max_event_bytes=512 * 1024,
            max_events_per_source_per_window=10,
            max_events_global_per_window=10,
            max_events_per_run=2,
            max_record_bytes_per_run=1024 * 1024,
        )
        large = "x" * (300 * 1024)
        result = process_batches([
            SourceBatch(normal, [large, large, "normal not reached"]),
            SourceBatch(security, ["security one", "security two"]),
        ], NOW, limits=limits)

        self.assertEqual([row["message"] for row in result["records"]], [
            "security one", "security two",
        ])
        normal_stats, security_stats = result["sources"]
        self.assertEqual(normal_stats["seenBytes"], 300 * 1024)
        self.assertEqual(normal_stats["dropped"]["inputByteLimit"], 2)
        self.assertEqual(normal_stats["dropped"]["globalQuota"], 1)
        self.assertEqual(security_stats["admittedEvents"], 2)
        self.assertLessEqual(
            sum(item["seenBytes"] for item in result["sources"]),
            limits.max_input_bytes_global,
        )

    def test_aggregate_record_byte_ceiling_drops_without_retaining_candidates(self):
        source = LogSource(source_id="file:large", kind="file", multiline="off")
        limits = PipelineLimits(
            max_sources=1,
            max_input_bytes_per_source=2 * 1024 * 1024,
            max_input_bytes_global=2 * 1024 * 1024,
            max_line_bytes=700 * 1024,
            max_event_bytes=700 * 1024,
            max_events_per_source_per_window=10,
            max_events_global_per_window=10,
            max_events_per_run=10,
            max_record_bytes_per_run=1024 * 1024,
        )
        message = "z" * (600 * 1024)
        result = process_batches(
            [SourceBatch(source, [message, message])], NOW, limits=limits
        )

        self.assertEqual(result["admittedTotal"], 1)
        self.assertEqual(result["sources"][0]["dropped"]["globalQuota"], 1)
        encoded = sum(len(json.dumps(
            row, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode()) + 1 for row in result["records"])
        self.assertLessEqual(encoded, limits.max_record_bytes_per_run)

    def test_input_bounds_and_invalid_timestamps_are_explicit(self):
        source = LogSource(source_id="file:bounded", kind="file")
        limits = PipelineLimits(
            max_input_lines_per_source=2,
            max_input_bytes_per_source=1024,
            max_line_bytes=64,
            max_event_bytes=512,
        )
        result = process_batches([SourceBatch(source, [
            "2040-01-01T00:00:00Z future",
            "x" * 65,
            "not-read-because-line-cap",
        ])], NOW, limits=limits)
        self.assertEqual(result["admittedTotal"], 1)
        self.assertEqual(result["records"][0]["timestamp"], "2026-08-30T12:00:00.000Z")
        self.assertEqual(result["records"][0]["timestampSource"], "observed")
        stats = result["sources"][0]
        self.assertEqual(stats["invalidTimestamps"], 1)
        self.assertEqual(stats["dropped"]["oversizedLine"], 1)
        self.assertEqual(stats["dropped"]["inputLineLimit"], 1)

    def test_prior_state_is_strict_and_output_never_contains_nan(self):
        source = LogSource(
            source_id="file:json", kind="file", field_allowlist=("value",),
        )
        result = process_batches([
            SourceBatch(source, ['{"message":"ok","value":NaN}'])
        ], NOW)
        self.assertEqual(result["records"][0]["fields"], {})
        json.dumps(result, allow_nan=False)
        with self.assertRaises(ValueError):
            process_batches(
                [SourceBatch(source, ["line"])], NOW,
                prior_state={"schemaVersion": 1, "windowStartedAt": 1},
            )

    def test_public_record_contract_rejects_extra_fields_and_unredacted_content(self):
        source = LogSource(source_id="file:public", kind="file")
        record = process_batches(
            [SourceBatch(source, ["safe message"])], NOW
        )["records"][0]
        self.assertEqual(normalize_record(record), record)
        self.assertIsNone(normalize_record({**record, "extra": True}))
        self.assertIsNone(normalize_record({**record, "message": "token=raw-secret"}))
        self.assertIsNone(normalize_record({**record, "fields": {"password": "hidden"}}))
        self.assertIsNone(normalize_record({**record, "timestamp": "2026-08-30T12:00:00Z"}))
        state = process_batches(
            [SourceBatch(source, ["safe message"])], NOW
        )["quotaState"]
        self.assertEqual(normalize_quota_state(state), state)
        self.assertIsNone(normalize_quota_state({
            **state, "admittedGlobal": state["admittedGlobal"] + 1,
        }))


if __name__ == "__main__":
    unittest.main()
