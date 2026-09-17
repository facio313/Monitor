import json
import math
import struct
import unittest
import zlib
from html.parser import HTMLParser
from unittest import mock

from ops import email_visuals as visuals


def visual():
    return {
        "schemaVersion": 1, "kind": "hourly", "theme": "light", "status": "warning",
        "title": "서버 상태를 한눈에", "subtitle": "2026년 9월 13일 · 정시 운영 보고서",
        "cards": [
            {"label": "CPU 최대", "value": "42.5", "unit": "%", "tone": "ok"},
            {"label": "메모리 최대", "value": "81", "unit": "%", "tone": "warning"},
        ],
        "highlights": ["재부팅 필요 여부를 확인하세요.", "외부 서비스 연결 상태를 확인하세요."],
        "sources": [{"label": "서버 지표", "status": "fresh"}, {"label": "네트워크", "status": "partial"}],
        "trend": {
            "from": "2026-09-13T08:00:00Z", "to": "2026-09-13T09:00:00Z",
            "cpu": [None, 0, 20, 40, 80] * 6,
            "memory": [52, 60, None, 80, 81] * 6,
            "tcp": [0, None, 0.2, 1.3, 5.7] * 6,
        },
    }


def payload(model=None):
    return {
        "schemaVersion": 1, "purpose": "transition", "test": False,
        "event": {
            "ruleId": "SystemRebootPending", "target": "host/server", "severity": "warning",
            "transition": "firing", "observedAt": "2026-09-13T09:00:00Z", "description": "점검이 필요합니다.",
        },
        "presentation": {"subject": "Monitor report", "body": "Complete plain-text report.", "visual": visual() if model is None else model},
    }


class ParsedHTML(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.tables = []
        self.images = []
        self.links = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if tag == "table":
            self.tables.append(attrs)
        if tag == "img":
            self.images.append(attrs)
        if tag == "a":
            self.links.append(attrs)


def decode_png(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise AssertionError("PNG signature is invalid")
    position = 8
    parts = []
    compressed = []
    while position < len(data):
        length = struct.unpack("!I", data[position:position + 4])[0]
        kind = data[position + 4:position + 8]
        chunk = data[position + 8:position + 8 + length]
        checksum = struct.unpack("!I", data[position + 8 + length:position + 12 + length])[0]
        if checksum != zlib.crc32(kind + chunk) & 0xFFFFFFFF:
            raise AssertionError("PNG checksum mismatch")
        parts.append(kind)
        if kind == b"IHDR":
            header = struct.unpack("!IIBBBBB", chunk)
        if kind == b"IDAT":
            compressed.append(chunk)
        position += 12 + length
    return header, parts, zlib.decompress(b"".join(compressed))


class NormalizeVisualTests(unittest.TestCase):
    def test_valid_model_is_a_deep_copy_and_canonicalizes_timezones(self):
        model = visual()
        model["trend"]["from"] = "2026-09-13T17:00:00+09:00"
        model["trend"]["to"] = "2026-09-13T18:00:00+09:00"
        result = visuals.normalize_visual(model)
        self.assertEqual(result["trend"]["from"], "2026-09-13T08:00:00Z")
        self.assertEqual(result["trend"]["to"], "2026-09-13T09:00:00Z")
        result["trend"]["cpu"][0] = 99
        result["cards"][0]["value"] = "0"
        self.assertIsNone(model["trend"]["cpu"][0])
        self.assertEqual(model["cards"][0]["value"], "42.5")

    def test_null_trend_and_empty_units_are_supported_without_fake_metrics(self):
        model = visual()
        model["trend"] = None
        model["cards"] = [{"label": "재부팅", "value": "필요", "unit": "", "tone": "warning"}]
        self.assertIsNone(visuals.normalize_visual(model)["trend"])

    def test_neutral_is_only_valid_as_a_card_tone(self):
        model = visual()
        model["cards"][0].update(label="처음 관측", value="09/13 17:10", unit="KST", tone="neutral")
        self.assertEqual(visuals.normalize_visual(model)["cards"][0]["tone"], "neutral")
        model["status"] = "neutral"
        with self.assertRaises(ValueError):
            visuals.normalize_visual(model)

    def test_unknown_missing_fields_and_wrong_schema_are_rejected(self):
        changes = [{"arbitrary": "data"}, {"schemaVersion": True}, {"schemaVersion": 2}, {"theme": "auto"}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                visuals.normalize_visual(visual() | change)
        for name in visual():
            model = visual()
            del model[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                visuals.normalize_visual(model)
        for value in (None, [], "html", 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                visuals.normalize_visual(value)

    def test_invalid_nested_fields_types_and_limits_are_rejected(self):
        mutations = [
            lambda m: m.update(cards=[m["cards"][0]] * 7),
            lambda m: m.update(highlights=["item"] * 5),
            lambda m: m.update(sources=[m["sources"][0]] * 5),
            lambda m: m.update(cards="cards"),
            lambda m: m["cards"][0].update(url="https://example.invalid"),
            lambda m: m["cards"][0].update(value=45),
            lambda m: m["cards"][0].update(unit="x" * 9),
            lambda m: m["cards"][0].update(label="x" * 25),
            lambda m: m["cards"][0].update(value="x" * 25),
            lambda m: m["cards"][0].update(tone="fresh"),
            lambda m: m["sources"][0].update(status="ok"),
            lambda m: m["sources"][0].update(label="x" * 25),
            lambda m: m.update(title="x" * 81),
            lambda m: m.update(subtitle="x" * 121),
            lambda m: m.update(highlights=["x" * 161]),
            lambda m: m["trend"].update(extra=True),
        ]
        for index, change in enumerate(mutations):
            model = visual()
            change(model)
            with self.subTest(index=index), self.assertRaises(ValueError):
                visuals.normalize_visual(model)

    def test_rejects_controls_markup_urls_and_excluded_workload_tokens(self):
        for text in (
            "bad\x00text", "bad\ntext", "bad\x7ftext", "bad\u202etext", "bad\ud800text",
            "<img src=x>", "<script>alert(1)</script>", "https://example.invalid", "ftp://example.invalid",
            "javascript:alert(1)", "data:image/png,aaa", "www.example.invalid", "secret-WGANG-target", " ",
        ):
            with self.subTest(text=repr(text)), self.assertRaises(ValueError):
                visuals.normalize_visual(visual() | {"title": text})
        result = visuals.normalize_visual(visual() | {"title": 'CPU & RAM "peak"'})
        self.assertEqual(result["title"], 'CPU & RAM "peak"')

    def test_rejects_invalid_array_lengths_boolean_nan_infinity_and_ranges(self):
        for name, maximum in (("cpu", 100), ("memory", 100), ("tcp", 1_000_000)):
            for wrong in ([], [None] * 29, [None] * 31, "values"):
                model = visual()
                model["trend"][name] = wrong
                with self.subTest(name=name, wrong=wrong), self.assertRaises(ValueError):
                    visuals.normalize_visual(model)
            for wrong in (True, False, math.nan, math.inf, -math.inf, -1, maximum + 0.1, "10", {}, 10 ** 10000):
                model = visual()
                model["trend"][name][0] = wrong
                with self.subTest(name=name, wrong_type=type(wrong).__name__), self.assertRaises(ValueError):
                    visuals.normalize_visual(model)
            model = visual()
            model["trend"][name] = [None, 0, maximum] * 10
            self.assertEqual(visuals.normalize_visual(model)["trend"][name], model["trend"][name])

    def test_requires_timezone_and_exact_chronological_hour(self):
        for start, end in (
            ("2026-09-13T08:00:00", "2026-09-13T09:00:00Z"),
            ("2026-09-13", "2026-09-13T09:00:00Z"),
            ("2026-13-13T08:00:00Z", "2026-09-13T09:00:00Z"),
            ("2026-09-13T09:00:00Z", "2026-09-13T08:00:00Z"),
            ("2026-09-13T08:00:00Z", "2026-09-13T09:00:01Z"),
            ("2026-09-13T08:00:00Z", "2026-09-13T08:59:59Z"),
            ("2026-09-13T08:00:00+99:00", "2026-09-13T09:00:00Z"),
        ):
            model = visual()
            model["trend"].update({"from": start, "to": end})
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                visuals.normalize_visual(model)

    def test_total_utf8_budget_applies_in_addition_to_per_field_limits(self):
        model = visual()
        model.update(title="가" * 80, subtitle="나" * 120, highlights=["다" * 160] * 4)
        model["cards"] = [{"label": "라" * 24, "value": "마" * 24, "unit": "바" * 8, "tone": "ok"}] * 6
        self.assertGreater(len(json.dumps(model, ensure_ascii=False).encode()), visuals.MAX_VISUAL_BYTES)
        with self.assertRaises(ValueError):
            visuals.normalize_visual(model)


class RenderEmailTests(unittest.TestCase):
    def test_rich_email_has_two_inline_pngs_table_layout_mobile_rules_and_fixed_link(self):
        document, images = visuals.render_email(payload(), "delivery-key-001")
        parsed = ParsedHTML(document)
        self.assertLess(len(document.encode()), 60 * 1024)
        self.assertEqual(len(images), 2)
        self.assertEqual(len(parsed.images), 2)
        self.assertTrue(all(table.get("role") == "presentation" for table in parsed.tables))
        self.assertGreater(len(parsed.tables), 4)
        self.assertEqual([link["href"] for link in parsed.links], [visuals.MONITOR_URL])
        self.assertIn("max-width:480px", document)
        self.assertIn("max-width:340px", document)
        self.assertIn("display:block!important;width:100%!important", document)
        mobile_css = document.split("max-width:480px)", 1)[1].split("@media", 1)[0]
        self.assertNotIn("display:block!important", mobile_css)
        self.assertIn("font-size:24px!important", mobile_css)
        self.assertIn("2026-09-13 17:00 – 2026-09-13 18:00 KST", document)
        self.assertIn("최근 1시간 · 2분 구간 최대값", document)
        self.assertIn("전송량 가중 비율", document)
        self.assertIn("CPU 실선", document)
        self.assertIn("RAM 점선", document)
        self.assertIn("최저 0% / 최고 80%", document)
        self.assertIn("24/30 구간", document)
        self.assertIn("세로축 0–5.7%", document)
        self.assertIn('align="left">17:00 KST</td>', document)
        self.assertIn('align="right">18:00 KST</td>', document)
        self.assertIn("WARNING", document)
        self.assertIn("일부 확인", document)
        for (cid, png), tag in zip(images, parsed.images):
            self.assertEqual(tag["src"], f"cid:{cid}")
            self.assertEqual(tag["width"], "600")
            self.assertEqual(tag["height"], "140")
            self.assertNotIn("<", cid)
            self.assertLess(len(png), 200 * 1024)
            header, parts, raw = decode_png(png)
            self.assertEqual(header, (1200, 280, 8, 2, 0, 0, 0))
            self.assertEqual(parts, [b"IHDR", b"IDAT", b"IEND"])
            self.assertEqual(len(raw), (1200 * 3 + 1) * 280)
            self.assertTrue(all(raw[row * 3601] == 0 for row in range(280)))
        self.assertFalse({"script", "svg", "iframe", "object", "link", "form"}.intersection(parsed.tags))
        self.assertNotIn("url(", document)
        self.assertNotIn("base64", document)

    def test_text_is_escaped_in_every_visual_field(self):
        model = visual()
        model.update(title='A & B "title"', subtitle="A & B's subtitle", highlights=['"a" & \'b\''])
        model["cards"][0].update(label="CPU & RAM", value='"42"', unit="&")
        model["sources"][0]["label"] = "Host & network"
        document, _ = visuals.render_email(payload(model), "key")
        for escaped in ("A &amp; B &quot;title&quot;", "B&#x27;s subtitle", "CPU &amp; RAM", "&quot;42&quot;", "Host &amp; network"):
            self.assertIn(escaped, document)

    def test_no_visual_legacy_and_test_cards_escape_body_without_fabricated_metrics(self):
        model = payload()
        del model["presentation"]["visual"]
        model["presentation"].update(subject='<b>"Report"</b>', body='<script>bad()</script>\nCPU & RAM')
        document, images = visuals.render_email(model, "key")
        self.assertEqual(images, [])
        self.assertIn("&lt;b&gt;&quot;Report&quot;&lt;/b&gt;", document)
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt;<br>CPU &amp; RAM", document)
        self.assertNotIn("<script>", document)
        self.assertNotIn("최저", document)
        self.assertIn("WARNING", document)
        model.update(test=True, purpose="test")
        model.pop("presentation")
        document, images = visuals.render_email(model, "key")
        self.assertIn("TEST", document)
        self.assertIn("테스트 알림", document)
        self.assertEqual(images, [])
        model.update(test=False, purpose="transition")
        model["event"]["transition"] = "resolved"
        self.assertIn("RESOLVED", visuals.render_email(model, "key")[0])

    def test_null_trend_never_fabricates_graphs_and_dark_theme_is_supported(self):
        model = visual()
        model.update(theme="dark", trend=None, cards=[model["cards"][0]])
        document, images = visuals.render_email(payload(model), "key")
        self.assertEqual(images, [])
        self.assertIn('content="dark"', document)
        self.assertIn("#10151d", document)
        self.assertIn('class="metric-empty"', document)
        self.assertNotIn("最近", document)

    def test_neutral_metadata_has_no_misleading_status_badge(self):
        model = visual()
        model.update(trend=None, cards=[{"label": "처음 관측", "value": "09/13 17:10", "unit": "KST", "tone": "neutral"}])
        document, images = visuals.render_email(payload(model), "key")
        self.assertIn("처음 관측", document)
        self.assertIn("09/13 17:10", document)
        self.assertNotIn('class="metric-tone"', document)
        self.assertNotIn("UNKNOWN", document)
        self.assertIn("WARNING", document)
        self.assertEqual(images, [])

    def test_visual_test_preview_is_marked_without_overriding_real_status(self):
        for marker in ({"test": True}, {"purpose": "test"}):
            item = payload()
            item.update(marker)
            document, _ = visuals.render_email(item, "key")
            self.assertIn("디자인 미리보기 · TEST", document)
            self.assertLess(document.index("디자인 미리보기 · TEST"), document.index("<h1"))
            self.assertIn("주의 · WARNING", document)
            self.assertIn("42.5", document)
        document, _ = visuals.render_email(payload(), "key")
        self.assertNotIn("디자인 미리보기 · TEST", document)

    def test_tcp_scale_has_five_percent_floor(self):
        model = visual()
        model["trend"]["tcp"] = [0, 0.05, 2.15] * 10
        document, _ = visuals.render_email(payload(model), "key")
        self.assertIn("세로축 0–5%", document)
        self.assertIn("최고 2.15%", document)
        self.assertNotIn("세로축 0–2.15%", document)

    def test_missing_data_is_explicit_and_zero_is_a_valid_observation(self):
        model = visual()
        for name in ("cpu", "memory", "tcp"):
            model["trend"][name] = [None] * 30
        document, images = visuals.render_email(payload(model), "key")
        self.assertEqual(len(images), 2)
        self.assertEqual(document.count("관측 없음 (0/30 구간)"), 3)
        self.assertIn("빈 구간은 정상 값이 아닙니다", document)
        self.assertNotIn("최저 0%", document)
        self.assertEqual(visuals._segments([None] * 30, 100), [])
        for name in ("cpu", "memory", "tcp"):
            model["trend"][name] = [0] * 30
        document, images = visuals.render_email(payload(model), "key")
        self.assertEqual(document.count("최저 0% / 최고 0% · 30/30 구간"), 3)
        self.assertNotIn("관측 없음", document)
        self.assertEqual(len(images), 2)

    def test_null_buckets_break_line_paths_and_single_points_remain_visible(self):
        values = [None] * 30
        values[:5] = [10, 20, None, 80, 90]
        runs = visuals._segments(values, 100)
        self.assertEqual([len(run) for run in runs], [2, 2])
        self.assertLess(runs[0][-1][0], runs[1][0][0])
        values = [None] * 30
        values[14] = 50
        runs = visuals._segments(values, 100)
        self.assertEqual([len(run) for run in runs], [1])
        blank = visuals._graph([([None] * 30, "#2563eb", False)], 100, visuals._PALETTES["light"])
        single = visuals._graph([(values, "#2563eb", False)], 100, visuals._PALETTES["light"])
        self.assertNotEqual(blank, single)
        # Inspect the PNG itself: the unknown bucket must contain no CPU pixels.
        values = [50] * 30
        values[14] = None
        png = visuals._graph([(values, "#2563eb", False)], 100, visuals._PALETTES["light"])
        _, _, raw = decode_png(png)
        missing_x = round(40 + 14 * 1120 / 29)
        for y in range(280):
            offset = y * 3601 + 1 + missing_x * 3
            self.assertNotEqual(raw[offset:offset + 3], bytes.fromhex("2563eb"))

    def test_pngs_and_content_ids_are_deterministic_and_delivery_scoped(self):
        first = visuals.render_email(payload(), "key-a")
        second = visuals.render_email(payload(), "key-a")
        other = visuals.render_email(payload(), 'key-b\r\n"<unsafe>')
        self.assertEqual(first, second)
        self.assertNotEqual(first[1][0][0], other[1][0][0])
        self.assertEqual(first[1][0][1], other[1][0][1])
        self.assertRegex(other[1][0][0], r"^monitor-[a-f0-9]{32}-resources@localhost$")

    def test_maximum_complexity_graphs_are_bounded_in_both_themes(self):
        for theme in ("light", "dark"):
            model = visual()
            model["theme"] = theme
            model["trend"]["cpu"] = [0, 100] * 15
            model["trend"]["memory"] = [100, 0] * 15
            model["trend"]["tcp"] = [0, 1_000_000] * 15
            document, images = visuals.render_email(payload(model), "key")
            self.assertLess(len(document.encode()), visuals.MAX_HTML_BYTES)
            self.assertTrue(all(len(png) < visuals.MAX_PNG_BYTES for _, png in images))
            self.assertIn("1,000,000%", document)

    def test_legacy_unusually_large_escaped_body_is_bounded(self):
        item = payload()
        item["presentation"] = {"subject": "Large report", "body": "&" * 10000}
        document, images = visuals.render_email(item, "key")
        self.assertLess(len(document.encode()), visuals.MAX_HTML_BYTES)
        self.assertIn("…", document)
        self.assertEqual(images, [])

    def test_invalid_visual_does_not_silently_become_a_healthy_report(self):
        item = payload()
        item["presentation"]["visual"]["trend"]["cpu"][0] = math.nan
        with self.assertRaises(ValueError):
            visuals.render_email(item, "key")
        for wrong in (None, "", "k" * 257):
            with self.subTest(key=wrong), self.assertRaises(ValueError):
                visuals.render_email(payload(), wrong)
        item = payload()
        item["presentation"] = {"subject": "Excluded", "body": "WGANG excluded fixture"}
        with self.assertRaises(ValueError):
            visuals.render_email(item, "key")

    def test_render_has_no_network_or_file_access(self):
        with mock.patch("builtins.open", side_effect=AssertionError("file I/O")), mock.patch(
            "socket.socket", side_effect=AssertionError("network I/O"),
        ):
            document, images = visuals.render_email(payload(), "key")
        self.assertTrue(document)
        self.assertEqual(len(images), 2)


if __name__ == "__main__":
    unittest.main()
