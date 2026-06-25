from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import random
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("VOLUNTEER_DB", DATA_DIR / "volunteer_system.db"))
SCHEMA_PATH = BASE_DIR / "schema.sql"
DEFAULT_THRESHOLD = int(os.environ.get("VOLUNTEER_MATCH_THRESHOLD", "80"))
MANUAL_REVIEW_MARGIN = int(os.environ.get("VOLUNTEER_MANUAL_REVIEW_MARGIN", "30"))
SECUGEN_MATCH_ENDPOINT = os.environ.get(
    "VOLUNTEER_SECUGEN_MATCH_ENDPOINT",
    "https://localhost:8443/SGIMatchScore",
)
SECUGEN_CAPTURE_ENDPOINT = os.environ.get(
    "VOLUNTEER_SECUGEN_CAPTURE_ENDPOINT",
    "https://localhost:8443/SGIFPCapture",
)
SECUGEN_LICENSE = os.environ.get("SECUGEN_LICENSE", "")
SECUGEN_LICENSE_FILE = os.environ.get(
    "SECUGEN_LICENSE_FILE",
    r"C:\Program Files\SecuGen\SgiBioSrv\sgiwebsrv.lic",
)
SECUGEN_ORIGIN = os.environ.get("VOLUNTEER_SECUGEN_ORIGIN", "https://webapi.secugen.com")
PREFERRED_APP_HOST = os.environ.get("VOLUNTEER_APP_HOST", "localhost")


def now_text() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_template(template: str) -> str:
    return "".join(str(template or "").split())


def template_hash(template: str) -> str:
    return hashlib.sha256(normalize_template(template).encode("utf-8")).hexdigest()


def image_hash(image_base64: str | None) -> str | None:
    if not image_base64:
        return None
    return hashlib.sha256(image_base64.encode("utf-8")).hexdigest()


def fingerprint_features_from_bmp_base64(image_base64: str | None, size: int = 32) -> str | None:
    if not image_base64:
        return None
    try:
        data = base64.b64decode(image_base64)
        if len(data) < 54 or data[:2] != b"BM":
            return None
        pixel_offset = int.from_bytes(data[10:14], "little")
        width = abs(int.from_bytes(data[18:22], "little", signed=True))
        height_raw = int.from_bytes(data[22:26], "little", signed=True)
        height = abs(height_raw)
        bpp = int.from_bytes(data[28:30], "little")
        if width <= 0 or height <= 0 or bpp not in (8, 24):
            return None

        row_stride = ((width * bpp + 31) // 32) * 4
        bottom_up = height_raw > 0
        pixels: list[list[int]] = []
        for y in range(height):
            source_y = height - 1 - y if bottom_up else y
            start = pixel_offset + source_y * row_stride
            row = data[start : start + row_stride]
            if bpp == 8:
                pixels.append([255 - row[x] for x in range(min(width, len(row)))])
            else:
                values = []
                for x in range(width):
                    i = x * 3
                    if i + 2 >= len(row):
                        values.append(0)
                    else:
                        b, g, r = row[i], row[i + 1], row[i + 2]
                        values.append(255 - int((int(r) + int(g) + int(b)) / 3))
                pixels.append(values)

        dark_points = [
            (x, y)
            for y, row in enumerate(pixels)
            for x, value in enumerate(row)
            if value > 20
        ]
        if dark_points:
            xs = [point[0] for point in dark_points]
            ys = [point[1] for point in dark_points]
            pad_x = max(4, int((max(xs) - min(xs) + 1) * 0.08))
            pad_y = max(4, int((max(ys) - min(ys) + 1) * 0.08))
            left = max(0, min(xs) - pad_x)
            right = min(width, max(xs) + pad_x + 1)
            top = max(0, min(ys) - pad_y)
            bottom = min(height, max(ys) + pad_y + 1)
        else:
            left, top, right, bottom = 0, 0, width, height

        crop_w = max(1, right - left)
        crop_h = max(1, bottom - top)
        output = bytearray()
        for oy in range(size):
            y0 = top + int(oy * crop_h / size)
            y1 = top + max(int((oy + 1) * crop_h / size), int(oy * crop_h / size) + 1)
            for ox in range(size):
                x0 = left + int(ox * crop_w / size)
                x1 = left + max(int((ox + 1) * crop_w / size), int(ox * crop_w / size) + 1)
                total = 0
                count = 0
                for yy in range(y0, min(y1, bottom)):
                    row = pixels[yy]
                    for xx in range(x0, min(x1, right, len(row))):
                        total += row[xx]
                        count += 1
                output.append(int(total / count) if count else 0)

        return base64.b64encode(bytes(output)).decode("ascii")
    except Exception:
        return None


def compare_fingerprint_features(first: str | None, second: str | None, size: int = 32) -> int | None:
    if not first or not second:
        return None
    try:
        a = list(base64.b64decode(first))
        b = list(base64.b64decode(second))
    except Exception:
        return None
    if len(a) != size * size or len(b) != size * size:
        return None

    def corr_for_shift(dx: int, dy: int) -> float | None:
        av: list[float] = []
        bv: list[float] = []
        for y in range(size):
            yy = y + dy
            if yy < 0 or yy >= size:
                continue
            for x in range(size):
                xx = x + dx
                if xx < 0 or xx >= size:
                    continue
                av.append(float(a[y * size + x]))
                bv.append(float(b[yy * size + xx]))
        if len(av) < 100:
            return None
        mean_a = sum(av) / len(av)
        mean_b = sum(bv) / len(bv)
        numerator = sum((x - mean_a) * (y - mean_b) for x, y in zip(av, bv))
        denom_a = math.sqrt(sum((x - mean_a) ** 2 for x in av))
        denom_b = math.sqrt(sum((y - mean_b) ** 2 for y in bv))
        if denom_a == 0 or denom_b == 0:
            return None
        return numerator / (denom_a * denom_b)

    best = max(
        (
            score
            for dy in range(-4, 5)
            for dx in range(-4, 5)
            if (score := corr_for_shift(dx, dy)) is not None
        ),
        default=None,
    )
    if best is None:
        return None
    return max(0, min(100, int(round(best * 100))))


def json_response(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
    payload = json.dumps(body, ensure_ascii=True).encode("utf-8")
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
        pass


def text_response(handler: BaseHTTPRequestHandler, status: int, body: str, content_type: str) -> None:
    payload = body.encode("utf-8")
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
        pass


def redirect_response(handler: BaseHTTPRequestHandler, location: str) -> None:
    try:
        handler.send_response(HTTPStatus.FOUND)
        handler.send_header("Location", location)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
        pass


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        ensure_column(conn, "fingerprint_templates", "image_sha256", "TEXT")
        ensure_column(conn, "fingerprint_templates", "image_features", "TEXT")


def ensure_column(conn: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


def donor_code() -> str:
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"DNR-{stamp}-{random.randint(1000, 9999)}"


def parse_score(body: str) -> int | None:
    clean = body.strip()
    if not clean:
        return None
    if clean.lstrip("-").isdigit():
        return int(clean)
    try:
        parsed = json.loads(clean)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, int):
        return parsed
    if isinstance(parsed, str) and parsed.lstrip("-").isdigit():
        return int(parsed)
    if isinstance(parsed, dict):
        for key in (
            "MatchingScore",
            "matchingScore",
            "matchScore",
            "score",
            "Score",
            "MatchingResult",
            "matchingResult",
        ):
            value = parsed.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.lstrip("-").isdigit():
                return int(value)
    return None


def parse_json_body(body: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def secugen_license() -> str:
    if SECUGEN_LICENSE:
        return SECUGEN_LICENSE.strip()
    try:
        return Path(SECUGEN_LICENSE_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def secugen_post(
    endpoint: str,
    payload: dict[str, Any],
    timeout_seconds: int = 8,
    *,
    origin: str | None = None,
) -> tuple[dict[str, Any] | None, str]:
    active_origin = origin or SECUGEN_ORIGIN
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Origin": active_origin,
            "Referer": f"{active_origin}/",
        },
        method="POST",
    )
    return _secugen_request(request, timeout_seconds)


def secugen_post_form(
    endpoint: str,
    payload: dict[str, Any],
    timeout_seconds: int = 8,
    *,
    origin: str | None = None,
) -> tuple[dict[str, Any] | None, str]:
    active_origin = origin or SECUGEN_ORIGIN
    form_data = urllib.parse.urlencode(
        {key: str(value) for key, value in payload.items() if value not in (None, "")},
        quote_via=urllib.parse.quote,
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=form_data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Origin": active_origin,
            "Referer": f"{active_origin}/",
        },
        method="POST",
    )
    return _secugen_request(request, timeout_seconds)


def _secugen_request(request: urllib.request.Request, timeout_seconds: int) -> tuple[dict[str, Any] | None, str]:
    context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        return None, f"secugen_unavailable: {exc.reason}"
    except TimeoutError:
        return None, "secugen_unavailable: timeout"
    except Exception as exc:
        return None, f"secugen_error: {exc}"

    parsed = parse_json_body(body)
    if parsed is None:
        return None, f"secugen_error: invalid_response {body[:120]}"
    return parsed, "secugen_webapi"


def secugen_error_message(code: Any) -> str:
    if code in (None, "", 0, "0"):
        return ""
    if str(code) == "10004":
        return (
            "SecuGen rejected the request because the browser origin was missing or not accepted. "
            "The app now sends an Origin header; refresh the page and try again."
        )
    if str(code) == "10002":
        return (
            "SecuGen rejected this page URL (error 10002: invalid domain). "
            "Your SecuGen license is tied to a specific address — open the app using "
            "http://localhost:8000, "
            "then refresh and scan again."
        )
    if str(code) == "10003":
        return (
            "SecuGen license has expired (error 10003). "
            "Request a new license key from SecuGen for this domain."
        )
    if str(code) == "54":
        return (
            "Fingerprint capture timed out. Place your finger firmly on the scanner "
            "before clicking Scan, and keep it still until capture completes."
        )
    if str(code) == "100":
        return (
            "SecuGen rejected one of the fingerprint templates (error 100). "
            "Scan the finger again. If this keeps happening, re-register affected donors."
        )
    return (
        f"SecuGen returned ErrorCode {code}. Check that the WebAPI license is valid, "
        "the scanner is connected, and no other biometric program is holding the device."
    )


def secugen_capture(
    timeout_ms: int,
    quality: int,
    template_format: str,
    *,
    origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    active_origin = origin or SECUGEN_ORIGIN
    attempts: list[tuple[Any, dict[str, Any]]] = [
        (
            secugen_post,
            {
                "licstr": secugen_license(),
                "timeout": int(timeout_ms),
                "quality": int(quality),
                "templateFormat": template_format or "ISO",
                "imageWSQRate": 0.75,
                "fakeDetection": 0,
            },
        ),
        (
            secugen_post_form,
            {
                "licstr": secugen_license(),
                "Timeout": int(timeout_ms),
                "Quality": int(quality),
                "templateFormat": template_format or "ISO",
                "imageWSQRate": 0.75,
                "fakeDetection": 0,
            },
        ),
    ]

    result: dict[str, Any] | None = None
    status = "secugen_not_called"
    for post_fn, payload in attempts:
        result, status = post_fn(
            SECUGEN_CAPTURE_ENDPOINT,
            payload,
            timeout_seconds=max(5, int(timeout_ms / 1000) + 4),
            origin=active_origin,
        )
        if result is None:
            continue
        error_code = str(result.get("ErrorCode", 0))
        if error_code in ("0", ""):
            break
        if error_code not in ("10002", "10004"):
            break
    if result is None:
        return HTTPStatus.SERVICE_UNAVAILABLE, {
            "ok": False,
            "message": "SecuGen WebAPI is not reachable.",
            "matcherStatus": status,
        }

    error_code = result.get("ErrorCode", 0)
    if str(error_code) not in ("0", ""):
        return HTTPStatus.BAD_GATEWAY, {
            "ok": False,
            "message": secugen_error_message(error_code),
            "secugen": result,
            "matcherStatus": status,
        }

    if (template_format or "ISO").upper() == "ISO":
        template = (
            result.get("TemplateBase64")
            or result.get("ISOTemplateBase64")
            or result.get("Template")
            or result.get("template")
            or result.get("FingerprintTemplate")
            or ""
        )
    else:
        template = (
            result.get("TemplateBase64")
            or result.get("ANSITemplateBase64")
            or result.get("Template")
            or result.get("template")
            or result.get("FingerprintTemplate")
            or ""
        )
    if not template:
        return HTTPStatus.BAD_GATEWAY, {
            "ok": False,
            "message": "SecuGen captured data but did not return a fingerprint template.",
            "secugen": result,
            "matcherStatus": status,
        }

    bmp_base64 = result.get("BMPBase64")
    image_features = fingerprint_features_from_bmp_base64(bmp_base64)

    return HTTPStatus.OK, {
        "ok": True,
        "template": template,
        "templateFormat": template_format or "ISO",
        "imageHash": image_hash(bmp_base64),
        "imageFeatures": image_features,
        "quality": result.get("ImageQuality") or result.get("Quality"),
        "deviceName": result.get("DeviceName") or "SecuGen Hamster",
        "imageWidth": result.get("ImageWidth"),
        "imageHeight": result.get("ImageHeight"),
        "matcherStatus": status,
    }


def secugen_match_score(
    probe_template: str,
    stored_template: str,
    template_format: str,
    *,
    origin: str | None = None,
) -> tuple[int | None, str, int | None]:
    normalized_probe = normalize_template(probe_template)
    normalized_stored = normalize_template(stored_template)
    active_format = template_format or "ISO"
    license_key = secugen_license()
    payload = {
        "licstr": license_key,
        "template1": normalized_probe,
        "template2": normalized_stored,
        "templateFormat": active_format,
    }

    result: dict[str, Any] | None = None
    status = "secugen_not_called"
    last_error_code: int | None = None
    result, status = secugen_post_form(
        SECUGEN_MATCH_ENDPOINT,
        payload,
        timeout_seconds=5,
        origin=origin or SECUGEN_ORIGIN,
    )
    if result is not None:
        error_code = str(result.get("ErrorCode", 0))
        if error_code not in ("0", ""):
            try:
                last_error_code = int(error_code)
            except ValueError:
                last_error_code = None

    if result is None:
        return None, status, last_error_code
    error_code = result.get("ErrorCode", 0)
    if str(error_code) not in ("0", ""):
        try:
            last_error_code = int(error_code)
        except (TypeError, ValueError):
            last_error_code = None
        return None, f"secugen_error: code {error_code}", last_error_code

    score = parse_score(json.dumps(result))
    if score is None:
        return None, "secugen_error: could_not_parse_score", last_error_code
    return score, status, last_error_code


def fetch_donor(conn: sqlite3.Connection, donor_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, donor_code, full_name, phone, age, blood_group, id_document,
               address, notes, created_at, updated_at
        FROM donors
        WHERE id = ?
        """,
        (donor_id,),
    ).fetchone()
    return row_to_dict(row)


def donor_recent_visits(conn: sqlite3.Connection, donor_id: int, limit: int = 5) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, visit_date, status, match_score, operator_name, notes, created_at
        FROM donation_visits
        WHERE donor_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (donor_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def active_template_count(conn: sqlite3.Connection) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) FROM fingerprint_templates WHERE is_active = 1"
        ).fetchone()[0]
    )


def find_donor_without_active_fingerprint(
    conn: sqlite3.Connection,
    full_name: str,
    phone: str | None,
) -> sqlite3.Row | None:
    if phone:
        row = conn.execute(
            """
            SELECT d.*
            FROM donors d
            WHERE d.phone = ?
              AND NOT EXISTS (
                  SELECT 1 FROM fingerprint_templates ft
                  WHERE ft.donor_id = d.id AND ft.is_active = 1
              )
            ORDER BY d.updated_at DESC
            LIMIT 1
            """,
            (phone,),
        ).fetchone()
        if row is not None:
            return row

    return conn.execute(
        """
        SELECT d.*
        FROM donors d
        WHERE lower(d.full_name) = lower(?)
          AND NOT EXISTS (
              SELECT 1 FROM fingerprint_templates ft
              WHERE ft.donor_id = d.id AND ft.is_active = 1
          )
        ORDER BY d.updated_at DESC
        LIMIT 1
        """,
        (full_name,),
    ).fetchone()


def review_floor(threshold: int) -> int:
    return max(0, int(threshold) - MANUAL_REVIEW_MARGIN)


def find_fingerprint_match(
    conn: sqlite3.Connection,
    probe_template: str,
    probe_image_features: str | None,
    threshold: int,
    template_format: str,
    *,
    origin: str | None = None,
    browser_match: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized = normalize_template(probe_template)
    probe_hash = template_hash(normalized)
    exact_row = conn.execute(
        """
        SELECT ft.id AS template_id, ft.donor_id, ft.template_format,
               d.full_name, d.donor_code
        FROM fingerprint_templates ft
        JOIN donors d ON d.id = ft.donor_id
        WHERE ft.template_sha256 = ? AND ft.is_active = 1
        """,
        (probe_hash,),
    ).fetchone()
    if exact_row is not None:
        return {
            "matched": True,
            "score": 100,
            "template_id": exact_row["template_id"],
            "donor_id": exact_row["donor_id"],
            "matcher_status": "exact_hash",
            "probe_hash": probe_hash,
        }

    rows = conn.execute(
        """
        SELECT id, donor_id, template_format, template_data, image_features
        FROM fingerprint_templates
        WHERE is_active = 1
        ORDER BY captured_at DESC
        """
    ).fetchall()

    if not rows:
        return {
            "matched": False,
            "score": None,
            "template_id": None,
            "donor_id": None,
            "matcher_status": "empty_database",
            "probe_hash": probe_hash,
        }

    best_score: int | None = None
    best_row: sqlite3.Row | None = None
    matcher_status = "secugen_not_called"
    secugen_license_error = False
    invalid_template_row: sqlite3.Row | None = None

    for row in rows:
        score, status, error_code = secugen_match_score(
            normalized,
            row["template_data"],
            template_format or row["template_format"] or "ISO",
            origin=origin,
        )
        matcher_status = status
        if score is None:
            if error_code == 100 or "code 100" in status:
                invalid_template_row = row
                continue
            if status.startswith("secugen_unavailable"):
                return {
                    "matched": False,
                    "score": best_score,
                    "template_id": best_row["id"] if best_row else None,
                    "donor_id": best_row["donor_id"] if best_row else None,
                    "matcher_status": status,
                    "probe_hash": probe_hash,
                    "needs_review": True,
                }
            if "code 10002" in status or "code 10004" in status:
                secugen_license_error = True
            continue
        if best_score is None or score > best_score:
            best_score = score
            best_row = row

    if invalid_template_row is not None and best_score is None:
        return {
            "matched": False,
            "needs_review": True,
            "score": None,
            "template_id": invalid_template_row["id"],
            "donor_id": invalid_template_row["donor_id"],
            "matcher_status": "secugen_invalid_stored_template",
            "probe_hash": probe_hash,
        }

    if secugen_license_error and best_score is None:
        return {
            "matched": False,
            "score": None,
            "template_id": None,
            "donor_id": None,
            "matcher_status": "secugen_license_browser_required",
            "probe_hash": probe_hash,
            "needs_review": True,
        }

    if best_row is not None and best_score is not None and best_score >= threshold:
        return {
            "matched": True,
            "score": best_score,
            "template_id": best_row["id"],
            "donor_id": best_row["donor_id"],
            "matcher_status": matcher_status,
            "probe_hash": probe_hash,
        }

    if best_row is not None and best_score is not None and best_score >= review_floor(threshold):
        return {
            "matched": False,
            "needs_review": True,
            "score": best_score,
            "template_id": best_row["id"],
            "donor_id": best_row["donor_id"],
            "matcher_status": f"{matcher_status}_review",
            "probe_hash": probe_hash,
        }

    return {
        "matched": False,
        "score": best_score,
        "template_id": best_row["id"] if best_row else None,
        "donor_id": best_row["donor_id"] if best_row else None,
        "matcher_status": matcher_status,
        "probe_hash": probe_hash,
    }


def insert_candidate_check(
    conn: sqlite3.Connection,
    *,
    probe_hash: str,
    outcome: str,
    threshold: int,
    matcher_status: str,
    quality: int | None,
    device_name: str | None,
    operator_name: str | None,
    notes: str | None,
    matched_donor_id: int | None = None,
    matched_template_id: int | None = None,
    match_score: int | None = None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO candidate_checks (
            probe_template_sha256, outcome, matched_donor_id, matched_template_id,
            match_score, threshold_used, matcher_status, quality, device_name,
            operator_name, notes, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            probe_hash,
            outcome,
            matched_donor_id,
            matched_template_id,
            match_score,
            threshold,
            matcher_status,
            quality,
            device_name,
            operator_name,
            notes,
            now_text(),
        ),
    )
    return int(cursor.lastrowid)


def handle_identify(
    data: dict[str, Any],
    *,
    request_origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    template = normalize_template(data.get("template", ""))
    if not template:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Fingerprint template is required."}

    threshold = int(data.get("threshold") or DEFAULT_THRESHOLD)
    template_format = str(data.get("templateFormat") or "ISO").upper()
    image_features = data.get("imageFeatures")
    browser_match = None
    quality = data.get("quality")
    device_name = data.get("deviceName")
    operator_name = data.get("operatorName")
    notes = data.get("notes")

    with get_db() as conn:
        match = find_fingerprint_match(
            conn,
            template,
            image_features,
            threshold,
            template_format,
            origin=SECUGEN_ORIGIN,
            browser_match=browser_match if isinstance(browser_match, dict) else None,
        )
        matcher_status = str(match["matcher_status"])
        matcher_failed = matcher_status.startswith("secugen_unavailable") or (
            matcher_status.startswith("secugen_error")
            and browser_match is None
        )

        if match.get("needs_review"):
            review_message = "Fingerprint result requires manual review. Do not register this candidate yet."
            if matcher_status == "secugen_invalid_stored_template":
                review_message = (
                    "A stored fingerprint template could not be compared by SecuGen. "
                    "Delete and re-register the affected donor before accepting more candidates."
                )
            check_id = insert_candidate_check(
                conn,
                probe_hash=match["probe_hash"],
                outcome="matcher_unavailable",
                matched_donor_id=match["donor_id"],
                matched_template_id=match["template_id"],
                match_score=match["score"],
                threshold=threshold,
                matcher_status=matcher_status,
                quality=quality,
                device_name=device_name,
                operator_name=operator_name,
                notes=notes,
            )
            conn.execute(
                """
                INSERT INTO alerts (check_id, donor_id, severity, message, created_at)
                VALUES (?, ?, 'warning', ?, ?)
                """,
                (
                    check_id,
                    match["donor_id"],
                    review_message,
                    now_text(),
                ),
            )
            conn.commit()
            return HTTPStatus.OK, {
                "ok": True,
                "matched": False,
                "needsReview": True,
                "message": review_message,
                "score": match["score"],
                "threshold": threshold,
                "matcherStatus": matcher_status,
                "checkId": check_id,
            }

        if match["matched"]:
            donor = fetch_donor(conn, int(match["donor_id"]))
            check_id = insert_candidate_check(
                conn,
                probe_hash=match["probe_hash"],
                outcome="duplicate_alert",
                matched_donor_id=match["donor_id"],
                matched_template_id=match["template_id"],
                match_score=match["score"],
                threshold=threshold,
                matcher_status=matcher_status,
                quality=quality,
                device_name=device_name,
                operator_name=operator_name,
                notes=notes,
            )
            conn.execute(
                """
                INSERT INTO donation_visits (
                    donor_id, visit_date, status, check_id, matched_template_id,
                    match_score, threshold_used, operator_name, notes, created_at
                )
                VALUES (?, ?, 'blocked_duplicate', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    match["donor_id"],
                    now_text(),
                    check_id,
                    match["template_id"],
                    match["score"],
                    threshold,
                    operator_name,
                    notes,
                    now_text(),
                ),
            )
            message = f"Duplicate donor detected: {donor['full_name']} already exists as {donor['donor_code']}."
            conn.execute(
                """
                INSERT INTO alerts (check_id, donor_id, severity, message, created_at)
                VALUES (?, ?, 'danger', ?, ?)
                """,
                (check_id, match["donor_id"], message, now_text()),
            )
            conn.commit()
            return HTTPStatus.OK, {
                "ok": True,
                "matched": True,
                "needsReview": False,
                "message": message,
                "score": match["score"],
                "threshold": threshold,
                "matcherStatus": matcher_status,
                "donor": donor,
                "recentVisits": donor_recent_visits(conn, int(match["donor_id"])),
            }

        if matcher_failed:
            check_id = insert_candidate_check(
                conn,
                probe_hash=match["probe_hash"],
                outcome="matcher_unavailable",
                matched_donor_id=match["donor_id"],
                matched_template_id=match["template_id"],
                match_score=match["score"],
                threshold=threshold,
                matcher_status=matcher_status,
                quality=quality,
                device_name=device_name,
                operator_name=operator_name,
                notes=notes,
            )
            conn.execute(
                """
                INSERT INTO alerts (check_id, donor_id, severity, message, created_at)
                VALUES (?, ?, 'warning', ?, ?)
                """,
                (
                    check_id,
                    match["donor_id"],
                    "Fingerprint matcher is unavailable. Do not clear this candidate until SecuGen matching is running.",
                    now_text(),
                ),
            )
            conn.commit()
            return HTTPStatus.SERVICE_UNAVAILABLE, {
                "ok": False,
                "matched": False,
                "needsReview": True,
                "message": "Matcher unavailable. Start the SecuGen WebAPI service and scan again.",
                "score": match["score"],
                "threshold": threshold,
                "matcherStatus": matcher_status,
            }

        check_id = insert_candidate_check(
            conn,
            probe_hash=match["probe_hash"],
            outcome="screened_clear",
            matched_donor_id=match["donor_id"],
            matched_template_id=match["template_id"],
            match_score=match["score"],
            threshold=threshold,
            matcher_status=matcher_status,
            quality=quality,
            device_name=device_name,
            operator_name=operator_name,
            notes=notes,
        )
        conn.commit()
        return HTTPStatus.OK, {
            "ok": True,
            "matched": False,
            "needsReview": False,
            "message": "No matching donor found.",
            "score": match["score"],
            "threshold": threshold,
            "matcherStatus": matcher_status,
            "checkId": check_id,
        }


def handle_register(
    data: dict[str, Any],
    *,
    request_origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    full_name = str(data.get("fullName") or "").strip()
    template = normalize_template(data.get("template", ""))
    if not full_name:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Full name is required."}
    if not template:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Fingerprint template is required."}

    threshold = int(data.get("threshold") or DEFAULT_THRESHOLD)
    template_format = str(data.get("templateFormat") or "ISO").upper()
    image_features = data.get("imageFeatures")
    image_sha256 = data.get("imageHash")
    quality = data.get("quality")
    device_name = data.get("deviceName")
    operator_name = data.get("operatorName")
    phone = str(data.get("phone") or "").strip() or None
    age = data.get("age") or None
    blood_group = str(data.get("bloodGroup") or "").strip() or None
    id_document = str(data.get("idDocument") or "").strip() or None
    address = str(data.get("address") or "").strip() or None
    notes = str(data.get("notes") or "").strip() or None

    browser_match = None

    with get_db() as conn:
        match = find_fingerprint_match(
            conn,
            template,
            image_features,
            threshold,
            template_format,
            origin=SECUGEN_ORIGIN,
            browser_match=browser_match if isinstance(browser_match, dict) else None,
        )
        matcher_status = str(match["matcher_status"])
        matcher_failed = matcher_status.startswith("secugen_unavailable") or (
            matcher_status.startswith("secugen_error")
            and browser_match is None
        )

        if match.get("needs_review"):
            review_message = "Cannot register because the fingerprint result needs manual review."
            if matcher_status == "secugen_invalid_stored_template":
                review_message = (
                    "Cannot register because a stored fingerprint template is incompatible with SecuGen matching. "
                    "Delete and re-register the affected donor first."
                )
            return HTTPStatus.CONFLICT, {
                "ok": False,
                "matched": False,
                "needsReview": True,
                "message": review_message,
                "score": match["score"],
                "threshold": threshold,
                "matcherStatus": matcher_status,
            }

        if match["matched"]:
            donor = fetch_donor(conn, int(match["donor_id"]))
            return HTTPStatus.CONFLICT, {
                "ok": False,
                "matched": True,
                "message": "This fingerprint already belongs to a registered donor.",
                "score": match["score"],
                "threshold": threshold,
                "matcherStatus": matcher_status,
                "donor": donor,
                "recentVisits": donor_recent_visits(conn, int(match["donor_id"])),
            }

        if matcher_failed and active_template_count(conn) > 0:
            return HTTPStatus.SERVICE_UNAVAILABLE, {
                "ok": False,
                "matched": False,
                "needsReview": True,
                "message": "Cannot register safely while the SecuGen matcher is unavailable.",
                "matcherStatus": matcher_status,
            }

        timestamp = now_text()
        existing = find_donor_without_active_fingerprint(conn, full_name, phone)
        if existing is not None:
            donor_id = int(existing["id"])
            conn.execute(
                """
                UPDATE donors
                SET full_name = ?, phone = ?, age = ?, blood_group = ?, id_document = ?,
                    address = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    full_name,
                    phone,
                    age,
                    blood_group,
                    id_document,
                    address,
                    notes,
                    timestamp,
                    donor_id,
                ),
            )
        else:
            code = donor_code()
            cursor = conn.execute(
                """
                INSERT INTO donors (
                    donor_code, full_name, phone, age, blood_group, id_document,
                    address, notes, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    code,
                    full_name,
                    phone,
                    age,
                    blood_group,
                    id_document,
                    address,
                    notes,
                    timestamp,
                    timestamp,
                ),
            )
            donor_id = int(cursor.lastrowid)
        fingerprint_cursor = conn.execute(
            """
            INSERT INTO fingerprint_templates (
                donor_id, finger_position, template_format, template_data,
                template_sha256, image_sha256, image_features, quality, device_name, captured_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                donor_id,
                str(data.get("fingerPosition") or "right_thumb").strip(),
                template_format,
                template,
                match["probe_hash"],
                image_sha256,
                image_features,
                quality,
                device_name,
                timestamp,
            ),
        )
        template_id = int(fingerprint_cursor.lastrowid)
        check_id = insert_candidate_check(
            conn,
            probe_hash=match["probe_hash"],
            outcome="registered",
            matched_donor_id=donor_id,
            matched_template_id=template_id,
            match_score=match["score"],
            threshold=threshold,
            matcher_status=matcher_status,
            quality=quality,
            device_name=device_name,
            operator_name=operator_name,
            notes=notes,
        )
        conn.execute(
            """
            INSERT INTO donation_visits (
                donor_id, visit_date, status, check_id, matched_template_id,
                match_score, threshold_used, operator_name, notes, created_at
            )
            VALUES (?, ?, 'accepted', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                donor_id,
                timestamp,
                check_id,
                template_id,
                match["score"],
                threshold,
                operator_name,
                str(data.get("visitNotes") or "").strip() or None,
                timestamp,
            ),
        )
        conn.commit()
        return HTTPStatus.CREATED, {
            "ok": True,
            "message": "Donor registered and first visit recorded.",
            "donor": fetch_donor(conn, donor_id),
        }


def handle_capture(data: dict[str, Any], request_origin: str | None = None) -> tuple[int, dict[str, Any]]:
    timeout_ms = int(data.get("timeout") or 15000)
    quality = int(data.get("quality") or 50)
    template_format = str(data.get("templateFormat") or "ISO").upper()
    return secugen_capture(timeout_ms, quality, template_format, origin=SECUGEN_ORIGIN)


def handle_secugen_config(request_origin: str | None = None) -> tuple[int, dict[str, Any]]:
    return HTTPStatus.OK, {
        "ok": True,
        "configuredOrigin": SECUGEN_ORIGIN,
        "timeout": 15000,
        "quality": 50,
    }


def handle_match_score(
    data: dict[str, Any],
    *,
    request_origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    template1 = normalize_template(data.get("template1") or data.get("Template1") or "")
    template2 = normalize_template(data.get("template2") or data.get("Template2") or "")
    if not template1 or not template2:
        return HTTPStatus.BAD_REQUEST, {
            "ok": False,
            "error": "Both fingerprint templates are required.",
        }

    template_format = str(data.get("templateFormat") or data.get("TemplateFormat") or "ISO").upper()
    score, matcher_status, error_code = secugen_match_score(
        template1,
        template2,
        template_format,
        origin=SECUGEN_ORIGIN,
    )
    if score is None:
        message = secugen_error_message(error_code) if error_code is not None else "SecuGen match failed."
        if error_code in (10002, 10004):
            message = (
                f"{message} Matching must run from the browser at "
                "http://localhost:8000, or through this app's server proxy."
            )
        return HTTPStatus.OK, {
            "ok": False,
            "score": None,
            "errorCode": error_code,
            "message": message,
            "matcherStatus": matcher_status,
        }

    return HTTPStatus.OK, {
        "ok": True,
        "score": score,
        "errorCode": 0,
        "matcherStatus": matcher_status,
    }


def handle_match_templates() -> tuple[int, dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT ft.id, ft.donor_id, ft.template_format, ft.template_data,
                   d.full_name, d.donor_code
            FROM fingerprint_templates ft
            JOIN donors d ON d.id = ft.donor_id
            WHERE ft.is_active = 1
            ORDER BY ft.captured_at DESC
            """
        ).fetchall()
    return HTTPStatus.OK, {
        "ok": True,
        "templates": [
            {
                "id": int(row["id"]),
                "donorId": int(row["donor_id"]),
                "donorName": row["full_name"],
                "donorCode": row["donor_code"],
                "templateFormat": row["template_format"] or "ISO",
                "templateData": row["template_data"],
            }
            for row in rows
        ],
    }


def handle_fingerprint_features(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    bmp_base64 = str(data.get("bmpBase64") or "")
    features = fingerprint_features_from_bmp_base64(bmp_base64)
    return HTTPStatus.OK, {
        "ok": True,
        "imageFeatures": features or "",
        "imageHash": image_hash(bmp_base64) or "",
    }


def handle_donors(query: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
    search = (query.get("search") or [""])[0].strip()
    with get_db() as conn:
        if search:
            like = f"%{search}%"
            rows = conn.execute(
                """
                SELECT d.id, d.donor_code, d.full_name, d.phone, d.age, d.blood_group,
                       d.created_at,
                       MAX(v.visit_date) AS last_visit,
                       COUNT(v.id) AS visit_count
                FROM donors d
                LEFT JOIN donation_visits v ON v.donor_id = d.id
                WHERE d.full_name LIKE ? OR d.phone LIKE ? OR d.donor_code LIKE ?
                GROUP BY d.id
                ORDER BY d.created_at DESC
                LIMIT 50
                """,
                (like, like, like),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT d.id, d.donor_code, d.full_name, d.phone, d.age, d.blood_group,
                       d.created_at,
                       MAX(v.visit_date) AS last_visit,
                       COUNT(v.id) AS visit_count
                FROM donors d
                LEFT JOIN donation_visits v ON v.donor_id = d.id
                GROUP BY d.id
                ORDER BY d.created_at DESC
                LIMIT 50
                """
            ).fetchall()
    return HTTPStatus.OK, {"ok": True, "donors": [dict(row) for row in rows]}


def handle_delete_donor(donor_id: int) -> tuple[int, dict[str, Any]]:
    with get_db() as conn:
        donor = fetch_donor(conn, donor_id)
        if donor is None:
            return HTTPStatus.NOT_FOUND, {
                "ok": False,
                "error": "Donor not found.",
            }
        conn.execute("DELETE FROM donors WHERE id = ?", (donor_id,))
        conn.commit()
    return HTTPStatus.OK, {
        "ok": True,
        "message": "Donor deleted.",
        "donor": donor,
    }


def handle_recent() -> tuple[int, dict[str, Any]]:
    with get_db() as conn:
        checks = conn.execute(
            """
            SELECT c.id, c.outcome, c.match_score, c.threshold_used, c.matcher_status,
                   c.quality, c.device_name, c.created_at,
                   d.donor_code, d.full_name
            FROM candidate_checks c
            LEFT JOIN donors d ON d.id = c.matched_donor_id
            ORDER BY c.created_at DESC
            LIMIT 20
            """
        ).fetchall()
        alerts = conn.execute(
            """
            SELECT a.id, a.severity, a.message, a.is_resolved, a.created_at,
                   d.donor_code, d.full_name
            FROM alerts a
            LEFT JOIN donors d ON d.id = a.donor_id
            ORDER BY a.created_at DESC
            LIMIT 20
            """
        ).fetchall()
    return HTTPStatus.OK, {
        "ok": True,
        "checks": [dict(row) for row in checks],
        "alerts": [dict(row) for row in alerts],
    }


def handle_stats() -> tuple[int, dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM donors) AS donor_count,
                (SELECT COUNT(*) FROM fingerprint_templates WHERE is_active = 1) AS fingerprint_count,
                (SELECT COUNT(*) FROM donation_visits WHERE status = 'accepted') AS accepted_visits,
                (SELECT COUNT(*) FROM alerts WHERE is_resolved = 0) AS open_alerts
            """
        ).fetchone()
    return HTTPStatus.OK, {"ok": True, "stats": dict(row)}


class VolunteerHandler(BaseHTTPRequestHandler):
    server_version = "VolunteerFingerprintServer/1.0"

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        host = self.headers.get("Host", "").split(":", 1)[0].lower()

        if path == "/api/health":
            return json_response(self, HTTPStatus.OK, {"ok": True, "db": str(DB_PATH)})
        if path == "/api/secugen-config":
            return self.respond_api(handle_secugen_config(self.get_request_origin()))
        if path == "/api/donors":
            return self.respond_api(handle_donors(query))
        if path == "/api/recent":
            return self.respond_api(handle_recent())
        if path == "/api/stats":
            return self.respond_api(handle_stats())
        if path == "/api/match-templates":
            return self.respond_api(handle_match_templates())

        if host in ("127.0.0.1", "::1") and PREFERRED_APP_HOST:
            target = f"http://{PREFERRED_APP_HOST}:{self.server.server_port}{self.path}"
            return redirect_response(self, target)

        if path == "/":
            path = "/index.html"
        self.serve_static(path)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid JSON."})

        if parsed.path == "/api/identify":
            return self.respond_api(handle_identify(data, request_origin=self.get_request_origin()))
        if parsed.path == "/api/register":
            return self.respond_api(handle_register(data, request_origin=self.get_request_origin()))
        if parsed.path == "/api/capture":
            return self.respond_api(handle_capture(data, request_origin=self.get_request_origin()))
        if parsed.path == "/api/match-score":
            return self.respond_api(handle_match_score(data, request_origin=self.get_request_origin()))
        if parsed.path == "/api/fingerprint-features":
            return self.respond_api(handle_fingerprint_features(data))
        return json_response(self, HTTPStatus.NOT_FOUND, {"ok": False, "error": "Route not found."})

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "donors":
            try:
                donor_id = int(parts[2])
            except ValueError:
                return json_response(self, HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid donor id."})
            return self.respond_api(handle_delete_donor(donor_id))
        return json_response(self, HTTPStatus.NOT_FOUND, {"ok": False, "error": "Route not found."})

    def get_request_origin(self) -> str | None:
        origin = self.headers.get("Origin")
        if origin:
            return origin
        app_origin = self.headers.get("X-App-Origin")
        if app_origin:
            return app_origin
        referer = self.headers.get("Referer", "")
        if referer:
            parsed = urllib.parse.urlparse(referer)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        return None

    def log_message(self, fmt: str, *args: Any) -> None:
        try:
            sys.stderr.write("[%s] %s\n" % (now_text(), fmt % args))
        except OSError:
            pass

    def respond_api(self, result: tuple[int, dict[str, Any]]) -> None:
        status, body = result
        json_response(self, status, body)

    def serve_static(self, path: str) -> None:
        relative = path.lstrip("/")
        target = (STATIC_DIR / relative).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.exists() or target.is_dir():
            return text_response(self, HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")

        suffix = target.suffix.lower()
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(suffix, "application/octet-stream")

        payload = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass


def run() -> None:
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")
    httpd = ThreadingHTTPServer((host, port), VolunteerHandler)
    try:
        print(f"Volunteer identification system running at http://{host}:{port}")
        print(f"Database: {DB_PATH}")
    except OSError:
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run()
