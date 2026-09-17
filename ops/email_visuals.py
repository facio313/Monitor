"""Bounded, dependency-free HTML email and inline PNG presentation.

Only a small validated data model is persisted in the outbox.  Rendering uses
memory alone: no fonts, image services, files, subprocesses, or network access.
The SMTP adapter remains responsible for the complete plain-text alternative.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import math
import re
import struct
import unicodedata
import zlib
from typing import Any, Mapping


MAX_VISUAL_BYTES = 4096
MAX_HTML_BYTES = 60 * 1024
MAX_PNG_BYTES = 200 * 1024
GRAPH_WIDTH = 1200
GRAPH_HEIGHT = 280
POINT_COUNT = 30
MONITOR_URL = "https://bonifacio.work/monitor"
_STATUSES = frozenset({"ok", "warning", "critical", "resolved", "unknown", "test"})
_CARD_TONES = _STATUSES | {"neutral"}
_SOURCE_STATUSES = frozenset({"fresh", "stale", "unavailable", "partial"})
_VISUAL_FIELDS = frozenset({
    "schemaVersion", "kind", "theme", "status", "title", "subtitle",
    "cards", "highlights", "sources", "trend",
})
_HTML_OR_URL = re.compile(
    r"<[^>]*>|(?:[a-z][a-z0-9+.-]*://|\bwww\.|\b(?:data|javascript|mailto|cid):)",
    re.IGNORECASE,
)
_STATUS_LABELS = {
    "ok": "정상 · OK", "warning": "주의 · WARNING", "critical": "위험 · CRITICAL",
    "resolved": "해결 · RESOLVED", "unknown": "확인 필요 · UNKNOWN", "test": "테스트 · TEST",
}
_SOURCE_LABELS = {
    "fresh": "최신", "stale": "오래됨", "unavailable": "확인 불가", "partial": "일부 확인",
}
_PALETTES = {
    "light": {
        "page": "#f2f4f8", "surface": "#ffffff", "card": "#f6f8fb",
        "ink": "#182231", "muted": "#5d697b", "border": "#e1e6ed",
        "grid": "#e6eaf0", "cpu": "#2563eb", "memory": "#7c3aed", "tcp": "#087f8c",
        "ok": "#117343", "warning": "#916000", "critical": "#bc2433",
        "resolved": "#117343", "unknown": "#586579", "test": "#3157ba",
    },
    "dark": {
        "page": "#10151d", "surface": "#18202c", "card": "#222d3d",
        "ink": "#f1f5fb", "muted": "#b2bed0", "border": "#354258",
        "grid": "#344154", "cpu": "#78a9ff", "memory": "#c0a0ff", "tcp": "#61d5dd",
        "ok": "#7ae0ac", "warning": "#f3ca6c", "critical": "#ff939d",
        "resolved": "#7ae0ac", "unknown": "#c3cedd", "test": "#a5baff",
    },
}


def _fields(value: Any, names: set[str] | frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != names:
        raise ValueError("email visual fields are invalid")
    return value


def _text(value: Any, maximum: int) -> str:
    if (
        not isinstance(value, str) or not value.strip() or len(value) > maximum
        or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)
        or "wgang" in value.casefold() or _HTML_OR_URL.search(value)
    ):
        raise ValueError("email visual text is invalid")
    return value


def _enum(value: Any, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValueError("email visual status is invalid")
    return value


def _array(value: Any, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("email visual list is invalid")
    return value


def _timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value,
    ):
        raise ValueError("email visual timestamp is invalid")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValueError("email visual timestamp is invalid") from error


def _series(value: Any, maximum: float) -> list[float | int | None]:
    if not isinstance(value, list) or len(value) != POINT_COUNT:
        raise ValueError("email visual trend must contain 30 buckets")
    result = []
    for item in value:
        if item is not None and (
            isinstance(item, bool) or not isinstance(item, (int, float))
            or not 0 <= item <= maximum or not math.isfinite(item)
        ):
            raise ValueError("email visual trend value is invalid")
        result.append(item)
    return result


def normalize_visual(value: Any) -> dict[str, Any]:
    """Validate/copy the versioned data-only model; reject unknown fields."""
    item = _fields(value, _VISUAL_FIELDS)
    if type(item["schemaVersion"]) is not int or item["schemaVersion"] != 1:
        raise ValueError("email visual schema is invalid")
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": _enum(item["kind"], frozenset({"hourly", "incident"})),
        "theme": _enum(item["theme"], frozenset({"light", "dark"})),
        "status": _enum(item["status"], _STATUSES),
        "title": _text(item["title"], 80),
        "subtitle": _text(item["subtitle"], 120),
        "cards": [], "highlights": [], "sources": [], "trend": None,
    }
    for raw in _array(item["cards"], 6):
        card = _fields(raw, {"label", "value", "unit", "tone"})
        # An empty unit is meaningful for count/status cards.
        unit = "" if card["unit"] == "" else _text(card["unit"], 8)
        result["cards"].append({
            "label": _text(card["label"], 24), "value": _text(card["value"], 24),
            "unit": unit, "tone": _enum(card["tone"], _CARD_TONES),
        })
    result["highlights"] = [_text(raw, 160) for raw in _array(item["highlights"], 4)]
    for raw in _array(item["sources"], 4):
        source = _fields(raw, {"label", "status"})
        result["sources"].append({
            "label": _text(source["label"], 24),
            "status": _enum(source["status"], _SOURCE_STATUSES),
        })
    if item["trend"] is not None:
        trend = _fields(item["trend"], {"from", "to", "cpu", "memory", "tcp"})
        start, end = _timestamp(trend["from"]), _timestamp(trend["to"])
        if end - start != dt.timedelta(hours=1):
            raise ValueError("email visual trend must span exactly one hour")
        result["trend"] = {
            "from": start.isoformat().replace("+00:00", "Z"),
            "to": end.isoformat().replace("+00:00", "Z"),
            "cpu": _series(trend["cpu"], 100), "memory": _series(trend["memory"], 100),
            "tcp": _series(trend["tcp"], 1_000_000),
        }
    try:
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("email visual encoding is invalid") from error
    if len(encoded) > MAX_VISUAL_BYTES:
        raise ValueError("email visual exceeds byte limit")
    return result


def _rgb(color: str) -> bytes:
    return bytes.fromhex(color[1:])


class _Canvas:
    def __init__(self, background: str):
        self.pixels = bytearray(_rgb(background) * (GRAPH_WIDTH * GRAPH_HEIGHT))

    def dot(self, x: int, y: int, color: bytes, radius: int = 1) -> None:
        for dy in range(-radius, radius + 1):
            for dx in range(-radius, radius + 1):
                px, py = x + dx, y + dy
                if dx * dx + dy * dy <= radius * radius and 0 <= px < GRAPH_WIDTH and 0 <= py < GRAPH_HEIGHT:
                    offset = (py * GRAPH_WIDTH + px) * 3
                    self.pixels[offset:offset + 3] = color

    def line(self, start: tuple[int, int], end: tuple[int, int], color: bytes, *, radius: int = 1, dashed: bool = False) -> None:
        x, y = start
        x2, y2 = end
        dx, dy = abs(x2 - x), -abs(y2 - y)
        sx, sy = (1 if x < x2 else -1), (1 if y < y2 else -1)
        error, step = dx + dy, 0
        while True:
            if not dashed or step % 16 < 10:
                self.dot(x, y, color, radius)
            if x == x2 and y == y2:
                break
            twice = 2 * error
            if twice >= dy:
                error += dy
                x += sx
            if twice <= dx:
                error += dx
                y += sy
            step += 1

    def png(self) -> bytes:
        row_size = GRAPH_WIDTH * 3
        raw = b"".join(b"\x00" + self.pixels[row * row_size:(row + 1) * row_size] for row in range(GRAPH_HEIGHT))

        def chunk(kind: bytes, data: bytes) -> bytes:
            return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)

        result = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack("!IIBBBBB", GRAPH_WIDTH, GRAPH_HEIGHT, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")
        )
        if len(result) >= MAX_PNG_BYTES:
            raise ValueError("email graph exceeds byte limit")
        return result


def _segments(values: list[float | int | None], maximum: float) -> list[list[tuple[int, int]]]:
    """Map each known run separately: unknown buckets never become zero/lines."""
    runs: list[list[tuple[int, int]]] = []
    current: list[tuple[int, int]] = []
    for index, value in enumerate(values):
        if value is None:
            if current:
                runs.append(current)
                current = []
            continue
        current.append((round(40 + index * 1120 / (POINT_COUNT - 1)), round(240 - value / maximum * 208)))
    if current:
        runs.append(current)
    return runs


def _graph(series: list[tuple[list[float | int | None], str, bool]], maximum: float, palette: Mapping[str, str]) -> bytes:
    canvas = _Canvas(palette["surface"])
    for fraction in range(5):
        y = round(240 - fraction * 208 / 4)
        canvas.line((40, y), (1160, y), _rgb(palette["grid"]), radius=0)
    for values, color, dashed in series:
        for run in _segments(values, maximum):
            for start, end in zip(run, run[1:]):
                canvas.line(start, end, _rgb(color), radius=2, dashed=dashed)
            for x, y in run:
                canvas.dot(x, y, _rgb(color), radius=3)
    return canvas.png()


def _number(value: float | int) -> str:
    return f"{value:,.2f}".rstrip("0").rstrip(".") if value % 1 else f"{value:,.0f}"


def _summary(name: str, values: list[float | int | None], unit: str, line: str) -> str:
    known = [value for value in values if value is not None]
    if not known:
        return f"{name} {line} · 관측 없음 (0/30 구간)"
    return f"{name} {line} · 최저 {_number(min(known))}{unit} / 최고 {_number(max(known))}{unit} · {len(known)}/30 구간"


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _legacy_text(value: Any, maximum: int, *, multiline: bool = False) -> str:
    if not isinstance(value, str):
        return ""
    if "wgang" in value.casefold():
        raise ValueError("email visual target is excluded")
    result = "".join(
        char for char in value[:maximum]
        if unicodedata.category(char) not in {"Cc", "Cf", "Cs"} or (multiline and char in "\n\t")
    )
    return result + ("…" if len(value) > maximum else "")


def _legacy_model(payload: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    event = payload.get("event") if isinstance(payload.get("event"), Mapping) else {}
    presentation = payload.get("presentation") if isinstance(payload.get("presentation"), Mapping) else {}
    is_test = payload.get("test") is True or payload.get("purpose") == "test"
    status = "test" if is_test else "resolved" if event.get("transition") == "resolved" else event.get("severity", "unknown")
    if status not in _STATUSES:
        status = "ok" if status == "info" else "unknown"
    title = _legacy_text(presentation.get("subject"), 180) or ("Monitor 테스트 알림" if is_test else "Monitor 서버 알림")
    subtitle = _legacy_text(event.get("ruleId"), 120) or "서버 상태 알림"
    target = _legacy_text(event.get("target"), 160)
    observed = _legacy_text(event.get("observedAt"), 64)
    body = _legacy_text(presentation.get("body"), 4000, multiline=True) or _legacy_text(event.get("description"), 4000, multiline=True)
    return {
        "kind": "incident", "theme": "light", "status": status, "title": title, "subtitle": subtitle,
        "cards": [], "sources": [], "trend": None,
        "highlights": [text for text in (target, observed) if text],
    }, body


def _time_window(trend: Mapping[str, Any]) -> str:
    korea = dt.timezone(dt.timedelta(hours=9))
    start, end = (_timestamp(trend[key]).astimezone(korea) for key in ("from", "to"))
    return f"{start:%Y-%m-%d %H:%M} – {end:%Y-%m-%d %H:%M} KST"


def render_email(payload: Mapping[str, Any], delivery_key: str) -> tuple[str, list[tuple[str, bytes]]]:
    """Return escaped HTML and at most two (bare content-ID, PNG) attachments."""
    if not isinstance(payload, Mapping) or not isinstance(delivery_key, str) or not 1 <= len(delivery_key) <= 256:
        raise ValueError("email render input is invalid")
    presentation = payload.get("presentation")
    has_visual = isinstance(presentation, Mapping) and "visual" in presentation
    if has_visual:
        model, body = normalize_visual(presentation["visual"]), ""
    else:
        model, body = _legacy_model(payload)
    palette = _PALETTES[model["theme"]]
    status = model["status"]
    escaped = _escape
    sections: list[str] = []
    images: list[tuple[str, bytes]] = []
    border = palette["border"]
    muted = palette["muted"]
    ink = palette["ink"]
    preview_banner = (
        f'<div style="margin-top:16px;padding:9px 12px;border:1px solid {palette["test"]};'
        f'border-radius:8px;color:{palette["test"]};font-size:12px;font-weight:700;">디자인 미리보기 · TEST</div>'
        if has_visual and (payload.get("test") is True or payload.get("purpose") == "test") else ""
    )
    sections.append(
        f'<tr><td class="pad" style="padding:36px 24px 26px;">'
        f'<div style="font-size:12px;font-weight:700;letter-spacing:2px;color:{muted};">MONITOR / '
        + ("HOURLY BRIEF" if model["kind"] == "hourly" else "INCIDENT UPDATE")
        + f'</div><div style="padding-top:22px;"><span style="display:inline-block;padding:7px 12px;'
        f'border:1px solid {palette[status]};border-radius:24px;color:{palette[status]};font-size:12px;'
        f'font-weight:700;">{escaped(_STATUS_LABELS[status])}</span></div>'
        f'{preview_banner}'
        f'<h1 style="margin:18px 0 12px;font-size:34px;line-height:1.22;letter-spacing:-1px;color:{ink};'
        f'overflow-wrap:anywhere;">{escaped(model["title"])}</h1>'
        f'<p style="margin:0;font-size:15px;line-height:1.7;color:{muted};overflow-wrap:anywhere;">'
        f'{escaped(model["subtitle"])}</p></td></tr>'
    )
    if model["cards"]:
        rows = []
        for offset in range(0, len(model["cards"]), 2):
            cells = []
            for card in model["cards"][offset:offset + 2]:
                badge = "" if card["tone"] == "neutral" else (
                    f'<div class="metric-tone" style="padding-top:12px;font-size:11px;color:{palette[card["tone"]]};">'
                    f'{escaped(_STATUS_LABELS[card["tone"]])}</div>'
                )
                cells.append(
                    f'<td class="metric" width="50%" valign="top" style="width:50%;padding:6px;">'
                    f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
                    f'style="background:{palette["card"]};border:1px solid {border};border-radius:16px;"><tr>'
                    f'<td class="metric-pad" style="padding:20px;"><div class="metric-label" style="font-size:13px;color:{muted};">{escaped(card["label"])}</div>'
                    f'<div class="metric-value" style="padding-top:12px;font-size:31px;line-height:1.2;letter-spacing:-1px;font-weight:700;'
                    f'color:{ink};overflow-wrap:anywhere;">{escaped(card["value"])} '
                    f'<span class="metric-unit" style="font-size:15px;font-weight:400;letter-spacing:0;">{escaped(card["unit"])}</span></div>'
                    f'{badge}</td></tr></table></td>'
                )
            if len(cells) == 1:
                cells.append('<td class="metric-empty" width="50%" style="width:50%;"></td>')
            rows.append("<tr>" + "".join(cells) + "</tr>")
        sections.append('<tr><td style="padding:0 18px 22px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0">' + "".join(rows) + "</table></td></tr>")
    if model["highlights"]:
        highlights = "".join(
            f'<tr><td width="22" valign="top" style="padding:8px 0;color:{muted};">{index + 1}.</td>'
            f'<td style="padding:8px 0;font-size:14px;line-height:1.7;overflow-wrap:anywhere;">{escaped(text)}</td></tr>'
            for index, text in enumerate(model["highlights"])
        )
        sections.append(
            f'<tr><td class="pad" style="padding:8px 24px 26px;"><h2 style="margin:0 0 8px;'
            f'font-size:17px;color:{ink};">확인할 사항</h2><table role="presentation" width="100%" '
            f'cellspacing="0" cellpadding="0">{highlights}</table></td></tr>'
        )
    if body:
        escaped_body = escaped(body).replace("\n", "<br>")
        sections.append(
            f'<tr><td class="pad" style="padding:0 24px 28px;font-size:14px;line-height:1.8;'
            f'overflow-wrap:anywhere;">{escaped_body}</td></tr>'
        )
    trend = model["trend"]
    if trend is not None:
        identity = hashlib.sha256(delivery_key.encode("utf-8")).hexdigest()[:32]
        known_tcp = [value for value in trend["tcp"] if value is not None]
        tcp_max = max(5.0, max(known_tcp, default=0))
        korea = dt.timezone(dt.timedelta(hours=9))
        start_label = _timestamp(trend["from"]).astimezone(korea).strftime("%H:%M KST")
        end_label = _timestamp(trend["to"]).astimezone(korea).strftime("%H:%M KST")
        charts = [
            (
                "resources", "CPU & 메모리", "최근 1시간 · 2분 구간 최대값", 100.0,
                [(trend["cpu"], palette["cpu"], False), (trend["memory"], palette["memory"], True)],
                [_summary("CPU", trend["cpu"], "%", "실선"), _summary("RAM", trend["memory"], "%", "점선")],
                "세로축 0–100%", any(value is not None for value in trend["cpu"] + trend["memory"]),
            ),
            (
                "tcp", "TCP 재전송", "최근 1시간 · 2분 구간 전송량 가중 비율", tcp_max,
                [(trend["tcp"], palette["tcp"], False)], [_summary("TCP", trend["tcp"], "%", "실선")],
                f"세로축 0–{_number(tcp_max)}% · 구간별 재전송 합 / 전송 합 × 100", bool(known_tcp),
            ),
        ]
        for graph_id, title, subtitle, maximum, series, summaries, scale, has_data in charts:
            cid = f"monitor-{identity}-{graph_id}@localhost"
            images.append((cid, _graph(series, maximum, palette)))
            summary_html = "".join(f'<div style="padding-top:5px;">{escaped(summary)}</div>' for summary in summaries)
            sections.append(
                f'<tr><td class="pad" style="padding:8px 24px 28px;"><h2 style="margin:0 0 7px;'
                f'font-size:19px;">{escaped(title)}</h2><div style="font-size:12px;line-height:1.7;color:{muted};">'
                f'{escaped(subtitle)}<br>{escaped(_time_window(trend))}</div>'
                f'<img src="cid:{cid}" width="600" height="140" alt="{escaped(title)}: '
                + ("추이 그래프. 수치는 아래 요약 참조." if has_data else "관측 데이터 없음. 빈 구간은 정상 값이 아닙니다.")
                + f'" style="display:block;width:100%;max-width:600px;height:auto;border:0;margin-top:14px;">'
                f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
                f'style="margin-bottom:10px;font-size:11px;color:{muted};"><tr>'
                f'<td align="left">{escaped(start_label)}</td><td align="right">{escaped(end_label)}</td></tr></table>'
                f'<div style="font-size:12px;line-height:1.7;color:{muted};">{escaped(scale)}{summary_html}'
                '<div style="padding-top:7px;">빈 구간은 미수집 데이터이며 선으로 연결하지 않습니다.</div></div></td></tr>'
            )
    if model["sources"]:
        chips = "".join(
            f'<span style="display:inline-block;margin:4px 6px 4px 0;padding:7px 10px;'
            f'border:1px solid {border};border-radius:20px;font-size:12px;">'
            f'{escaped(source["label"])} · {escaped(_SOURCE_LABELS[source["status"]])}</span>'
            for source in model["sources"]
        )
        sections.append(
            f'<tr><td class="pad" style="padding:0 24px 26px;"><div style="font-size:12px;color:{muted};'
            f'padding-bottom:6px;">관측 소스 상태</div>{chips}</td></tr>'
        )
    sections.append(
        f'<tr><td class="pad" style="padding:24px;border-top:1px solid {border};">'
        f'<table role="presentation" cellspacing="0" cellpadding="0"><tr><td style="border-radius:10px;'
        f'background:{palette["cpu"]};"><a href="{MONITOR_URL}" style="display:inline-block;padding:13px 19px;'
        f'color:{palette["surface"]};text-decoration:none;font-size:14px;font-weight:700;">Monitor에서 자세히 보기 →</a>'
        f'</td></tr></table><p style="margin:18px 0 0;font-size:11px;line-height:1.7;color:{muted};">'
        '이 메일은 생성 시점의 상태를 담고 있습니다. 현재 상태는 Monitor에서 확인하세요.<br>'
        '이미지를 표시하지 않아도 위 수치 요약과 메일의 텍스트 버전에서 내용을 확인할 수 있습니다.</p></td></tr>'
    )
    document = (
        '<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="color-scheme" content="{model["theme"]}"><title>Monitor</title>'
        '<style>@media only screen and (max-width:480px){.metric{padding:4px!important;'
        'box-sizing:border-box!important}.metric-pad{padding:13px!important}.metric-label{font-size:12px!important}'
        '.metric-value{font-size:24px!important;letter-spacing:-.6px!important}.metric-unit{font-size:12px!important}'
        '.metric-tone{font-size:10px!important}.pad{padding-left:18px!important;padding-right:18px!important}'
        'h1{font-size:29px!important}}@media only screen and (max-width:340px){'
        '.metric{display:block!important;width:100%!important}.metric-empty{display:none!important}}</style></head>'
        f'<body style="margin:0;padding:0;background:{palette["page"]};color:{ink};font-family:-apple-system,BlinkMacSystemFont,'
        '\'Segoe UI\',\'Apple SD Gothic Neo\',Arial,sans-serif;">'
        f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:{palette["page"]};">'
        '<tr><td align="center" style="padding:28px 10px;">'
        f'<table role="presentation" class="shell" width="648" cellspacing="0" cellpadding="0" '
        f'style="width:100%;max-width:648px;background:{palette["surface"]};border:1px solid {border};border-radius:22px;">'
        + "".join(sections) + '</table></td></tr></table></body></html>'
    )
    if len(document.encode("utf-8")) >= MAX_HTML_BYTES:
        raise ValueError("email HTML exceeds byte limit")
    return document, images
