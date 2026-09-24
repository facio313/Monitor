import unittest

from ops import email_visuals as visuals


def _visual():
    return {
        "schemaVersion": 1,
        "kind": "hourly",
        "theme": "light",
        "status": "warning",
        "title": "서버 일일 보고",
        "subtitle": "확인 시각 09:00 KST",
        "cards": [],
        "highlights": [],
        "sources": [],
        "trend": None,
    }


class EmailVisualDetailTests(unittest.TestCase):
    def test_visual_email_keeps_escaped_bounded_plain_report(self):
        body = (
            "확인된 활성 규칙 2건\n"
            "탐지 입력 상태: 일부 확인 필요\n"
            '<script>alert("unsafe")</script> & 원문\x00'
        )
        payload = {
            "schemaVersion": 1,
            "purpose": "report",
            "test": False,
            "presentation": {
                "subject": "Monitor report",
                "body": body,
                "visual": _visual(),
            },
        }

        document, images = visuals.render_email(payload, "daily-report-20260924")

        self.assertEqual(images, [])
        self.assertIn("상세 보고", document)
        self.assertIn("확인된 활성 규칙 2건<br>탐지 입력 상태", document)
        self.assertIn("&lt;script&gt;alert(&quot;unsafe&quot;)&lt;/script&gt; &amp; 원문", document)
        self.assertNotIn("<script>alert", document)
        self.assertNotIn("\x00", document)
        self.assertLess(len(document.encode("utf-8")), visuals.MAX_HTML_BYTES)

    def test_visual_email_truncates_plain_report_at_the_render_boundary(self):
        payload = {
            "presentation": {
                "body": "가" * 6001,
                "visual": _visual(),
            },
        }

        document, _ = visuals.render_email(payload, "bounded-detail")

        self.assertIn("가" * 6000 + "…", document)
        self.assertNotIn("가" * 6001, document)
        self.assertLess(len(document.encode("utf-8")), visuals.MAX_HTML_BYTES)


if __name__ == "__main__":
    unittest.main()
