from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import sqlite3
import time
import urllib.request
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from common import paths
from common.tls import client_context

_IMAGE_AWE_TYPES = {"2702", "2703", "2704"}
_BROWSER_NATIVE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif"}
_HEIF_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs", b"mif1", b"msf1"}
_AVIF_BRANDS = {b"avif", b"avis"}
_VIDEO_BRANDS = {b"mp42", b"mp41", b"isom", b"iso2", b"iso4", b"iso5", b"iso6", b"avc1", b"M4V ", b"qt  "}

original_images_router = APIRouter(prefix="/panel")

_state: dict[str, Any] = {
    "status": "idle", "total": 0, "done": 0, "recovered": 0,
    "raw_saved": 0, "applied": 0, "raw_only": 0, "failed": 0,
    "skipped": 0, "message": "", "backup_path": None,
    "report_path": None, "started_at": None, "finished_at": None,
    "cancel_requested": False,
}


class RecoverOriginalImagesRequest(BaseModel):
    force: bool = True


@dataclass
class RecoveredAsset:
    raw_path: str
    display_path: str | None
    width: int
    height: int
    size: int
    sha256: str
    ext: str

    @property
    def score(self) -> tuple[int, int]:
        return (self.width * self.height, self.size)


@dataclass
class RecoverOutcome:
    assets: list[RecoveredAsset]
    errors: list[str]

    @property
    def best(self) -> RecoveredAsset | None:
        items = [asset for asset in self.assets if asset.display_path]
        return max(items, key=lambda asset: asset.score) if items else None


def _as_object(value: Any) -> dict:
    current = value
    for _ in range(3):
        if isinstance(current, dict):
            return current
        if not isinstance(current, str) or not current.strip():
            return {}
        try:
            current = json.loads(current)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    return current if isinstance(current, dict) else {}


def _content_json(row: Any) -> dict:
    raw_value = row["raw_data"] if isinstance(row, sqlite3.Row) else row.get("raw_data")
    raw = _as_object(raw_value)
    parsed = _as_object(raw.get("content_json"))
    if parsed:
        return parsed
    content = row["content"] if isinstance(row, sqlite3.Row) else row.get("content")
    return _as_object(content)


def _is_image_payload(msg_type: int, cj: dict) -> bool:
    if int(msg_type or 0) == 3 or str(cj.get("aweType", "")) in _IMAGE_AWE_TYPES:
        return True
    return bool(cj.get("inline_pic") and (cj.get("check_pics") or "is_long_pic" in cj or "create_type" in cj))


def _flatten_urls(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.startswith(("http://", "https://")) else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_flatten_urls(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for key in ("url", "uri", "url_list", "origin_url_list"):
            if key in value:
                out.extend(_flatten_urls(value[key]))
        return out
    return []


def _resource_candidates(cj: dict) -> list[dict[str, Any]]:
    """Return only true origin resources; never accept large/medium/thumb fallbacks."""
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            urls = _flatten_urls(value.get("origin_url_list"))
            if urls:
                skey = str(value.get("skey") or "")
                identity = (skey, tuple(urls))
                if identity not in seen:
                    seen.add(identity)
                    found.append({"skey": skey, "urls": urls})
            for child in value.values():
                if isinstance(child, (dict, list)):
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, (dict, list)):
                    walk(child)

    walk(cj)
    return found


def _fetch_bytes(url: str, timeout: int = 30) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Referer": "https://www.douyin.com/"})
    with urllib.request.urlopen(request, timeout=timeout, context=client_context()) as response:
        return response.read()


def _iso_brands(data: bytes) -> set[bytes]:
    if len(data) < 12 or data[4:8] != b"ftyp":
        return set()
    size = int.from_bytes(data[:4], "big", signed=False)
    end = min(len(data), size if 16 <= size <= len(data) else 64)
    brands = {data[8:12]}
    brands.update(data[offset:offset + 4] for offset in range(16, end - 3, 4))
    return brands


def _detect_format(data: bytes) -> tuple[str, str] | None:
    if data[:3] == b"\xff\xd8\xff": return ("image", ".jpg")
    if data[:8] == b"\x89PNG\r\n\x1a\n": return ("image", ".png")
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP": return ("image", ".webp")
    if data[:6] in (b"GIF87a", b"GIF89a"): return ("image", ".gif")
    if data[:2] == b"BM": return ("image", ".bmp")
    if data[:4] in (b"II*\x00", b"MM\x00*"): return ("image", ".tiff")
    brands = _iso_brands(data)
    if brands & _AVIF_BRANDS: return ("image", ".avif")
    if brands & _HEIF_BRANDS: return ("image", ".heic")
    if brands & _VIDEO_BRANDS: return ("video", ".mp4")
    return None


def _decode_resource(downloaded: bytes, skey: str) -> tuple[bytes, str, str]:
    detected = _detect_format(downloaded)
    if detected:
        return downloaded, *detected
    if not skey:
        raise ValueError("origin URL did not return a recognized image and no skey is available")
    if len(downloaded) < 28:
        raise ValueError("encrypted payload is too short")
    try:
        key = bytes.fromhex(skey)
    except ValueError as exc:
        raise ValueError("skey is not valid hex") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError(f"unexpected AES key length: {len(key)}")
    plain = AESGCM(key).decrypt(downloaded[:12], downloaded[12:], None)
    detected = _detect_format(plain)
    if not detected:
        raise ValueError("decrypted payload has an unknown format")
    return plain, *detected


def _image_size(data: bytes, ext: str) -> tuple[int, int]:
    try:
        from PIL import Image
        if ext == ".heic":
            import pillow_heif
            pillow_heif.register_heif_opener()
        with Image.open(io.BytesIO(data)) as image:
            return int(image.width), int(image.height)
    except Exception:
        return (0, 0)


def _safe_message_id(msg_id: str) -> str:
    value = re.sub(r"[^0-9A-Za-z._-]+", "_", str(msg_id or "unknown")).strip("._")
    return value[:160] or "unknown"


def _atomic_write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = f"{path}.tmp-{os.getpid()}-{time.time_ns()}"
    try:
        with open(temp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            try: os.remove(temp)
            except OSError: pass


def _render_for_browser(data: bytes, ext: str, target: str) -> bool:
    try:
        from PIL import Image, ImageOps
        if ext == ".heic":
            import pillow_heif
            pillow_heif.register_heif_opener()
        with Image.open(io.BytesIO(data)) as image:
            image = ImageOps.exif_transpose(image)
            if image.mode not in ("RGB", "RGBA", "L", "LA"):
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            output = io.BytesIO()
            image.save(output, "PNG", optimize=False)
        _atomic_write(target, output.getvalue())
        return True
    except Exception:
        return False


def _recover_one_message(msg_id: str, cj: dict) -> RecoverOutcome:
    originals_dir = os.path.join(paths.MEDIA_DIR, "originals")
    rendered_dir = os.path.join(paths.MEDIA_DIR, "originals_rendered")
    os.makedirs(originals_dir, exist_ok=True)
    os.makedirs(rendered_dir, exist_ok=True)
    resources = _resource_candidates(cj)
    if not resources:
        return RecoverOutcome([], ["no origin_url_list found"])

    assets: list[RecoveredAsset] = []
    errors: list[str] = []
    hashes: set[str] = set()
    safe_id = _safe_message_id(msg_id)

    for index, resource in enumerate(resources, 1):
        payload = None
        kind = ext = ""
        last_error = ""
        for url in resource["urls"]:
            try:
                downloaded = _fetch_bytes(url)
                payload, kind, ext = _decode_resource(downloaded, resource["skey"])
                break
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
        if payload is None:
            errors.append(f"resource {index}: {last_error or 'all origin URLs failed'}")
            continue
        if kind != "image":
            errors.append(f"resource {index}: origin payload is {kind}, not an image")
            continue

        digest = hashlib.sha256(payload).hexdigest()
        if digest in hashes:
            continue
        hashes.add(digest)
        width, height = _image_size(payload, ext)
        filename = f"{safe_id}-{digest[:12]}{ext}"
        raw_rel = f"originals/{filename}"
        _atomic_write(os.path.join(originals_dir, filename), payload)

        if ext in _BROWSER_NATIVE_EXTS:
            display_rel = raw_rel
        else:
            preview_name = f"{safe_id}-{digest[:12]}.png"
            preview_path = os.path.join(rendered_dir, preview_name)
            display_rel = f"originals_rendered/{preview_name}" if _render_for_browser(payload, ext, preview_path) else None

        assets.append(RecoveredAsset(raw_rel, display_rel, width, height, len(payload), digest, ext))

    return RecoverOutcome(assets, errors)


def _backup_database(conn: sqlite3.Connection) -> str:
    backup_dir = os.path.join(paths.DATA_DIR, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"chat-before-original-image-recovery-{stamp}.db"
    target = os.path.join(backup_dir, name)
    suffix = 1
    while os.path.exists(target):
        name = f"chat-before-original-image-recovery-{stamp}-{suffix}.db"
        target = os.path.join(backup_dir, name)
        suffix += 1
    destination = sqlite3.connect(target)
    try:
        conn.backup(destination)
    finally:
        destination.close()
    return f"backups/{name}"


def _eligible_rows(conn: sqlite3.Connection) -> list[tuple[sqlite3.Row, dict]]:
    rows = conn.execute(
        "SELECT msg_id, msg_type, content, raw_data, media_local_path, timestamp, seq "
        "FROM messages ORDER BY timestamp, seq"
    ).fetchall()
    result = []
    for row in rows:
        cj = _content_json(row)
        if cj and _is_image_payload(row["msg_type"], cj):
            result.append((row, cj))
    return result


def _pending_summary() -> dict[str, int]:
    from backend.database import get_db
    conn = get_db()
    try:
        rows = _eligible_rows(conn)
        recovered = sum(
            1 for row, _ in rows
            if str(row["media_local_path"] or "").startswith(("originals/", "originals_rendered/"))
        )
        return {"eligible": len(rows), "recovered": recovered, "pending": max(0, len(rows) - recovered)}
    finally:
        conn.close()


def _write_report(report: dict[str, Any]) -> str:
    name = "original_image_recovery_last.json"
    _atomic_write(os.path.join(paths.DATA_DIR, name), json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
    return name


async def _run_recovery(force: bool) -> None:
    from backend.database import get_db
    _state.update({
        "status": "running", "total": 0, "done": 0, "recovered": 0,
        "raw_saved": 0, "applied": 0, "raw_only": 0, "failed": 0,
        "skipped": 0, "message": "扫描数据库中的图片消息...",
        "backup_path": None, "report_path": None, "started_at": time.time(),
        "finished_at": None, "cancel_requested": False,
    })
    conn = None
    report_items: list[dict[str, Any]] = []
    try:
        conn = get_db()
        rows = _eligible_rows(conn)
        _state["total"] = len(rows)
        _state["message"] = f"发现 {len(rows)} 条图片消息"
        backup_created = False

        for row, cj in rows:
            if _state["cancel_requested"]:
                _state["status"] = "completed"
                _state["message"] = "已停止；已完成的原图保留不变"
                break

            msg_id = str(row["msg_id"])
            old_path = str(row["media_local_path"] or "")
            if not force and old_path.startswith(("originals/", "originals_rendered/")):
                _state["skipped"] += 1
                _state["done"] += 1
                continue

            item: dict[str, Any] = {"msg_id": msg_id, "old_path": old_path}
            try:
                outcome = await asyncio.to_thread(_recover_one_message, msg_id, cj)
                item["errors"] = outcome.errors
                item["assets"] = [asset.__dict__ for asset in outcome.assets]
                if outcome.assets:
                    _state["recovered"] += 1
                    _state["raw_saved"] += len(outcome.assets)
                best = outcome.best
                if best:
                    if not backup_created:
                        _state["backup_path"] = _backup_database(conn)
                        backup_created = True
                    conn.execute("UPDATE messages SET media_local_path = ? WHERE msg_id = ?", (best.display_path, msg_id))
                    conn.commit()
                    item["new_path"] = best.display_path
                    _state["applied"] += 1
                elif outcome.assets:
                    item["new_path"] = old_path
                    _state["raw_only"] += 1
                else:
                    item["new_path"] = old_path
                    _state["failed"] += 1
            except Exception as exc:
                item["errors"] = [f"{type(exc).__name__}: {exc}"]
                item["new_path"] = old_path
                _state["failed"] += 1

            report_items.append(item)
            _state["done"] += 1
            _state["message"] = (
                f"处理中 {_state['done']}/{_state['total']} · 恢复 {_state['recovered']} · "
                f"应用 {_state['applied']} · 失败 {_state['failed']}"
            )
        else:
            _state["status"] = "completed"

        if _state["status"] == "running":
            _state["status"] = "completed"
        report = {
            "generated_at": int(time.time()), "force": force,
            "summary": {key: value for key, value in _state.items() if key != "cancel_requested"},
            "items": report_items,
        }
        _state["report_path"] = _write_report(report)
        if not _state["message"].startswith("已停止"):
            _state["message"] = (
                f"完成：恢复 {_state['recovered']} 条，保存原件 {_state['raw_saved']} 个，"
                f"查看器已切换 {_state['applied']} 条，失败 {_state['failed']} 条"
            )
    except Exception as exc:
        _state["status"] = "failed"
        _state["message"] = f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            conn.close()
        _state["finished_at"] = time.time()
        _state["cancel_requested"] = False


def _status_payload() -> dict[str, Any]:
    return {key: value for key, value in _state.items() if key != "cancel_requested"}


@original_images_router.get("/api/media/originals/status")
async def original_images_status():
    return _status_payload()


@original_images_router.get("/api/media/originals/pending")
async def original_images_pending():
    try:
        return await asyncio.to_thread(_pending_summary)
    except Exception as exc:
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=500)


@original_images_router.post("/api/media/originals/recover")
async def original_images_recover(req: RecoverOriginalImagesRequest):
    if _state["status"] == "running":
        return JSONResponse({"error": "original image recovery already running"}, status_code=409)
    _state["status"] = "running"
    _state["cancel_requested"] = False
    asyncio.create_task(_run_recovery(req.force))
    return {"status": "started", "force": req.force}


@original_images_router.post("/api/media/originals/cancel")
async def original_images_cancel():
    if _state["status"] != "running":
        return {"status": _state["status"], "message": "no recovery task is running"}
    _state["cancel_requested"] = True
    return {"status": "stopping"}


_PANEL_SECTION = r"""
  <div class="section" id="originalImageRecoverySection">
    <h2>聊天图片原图恢复 <span class="status status-idle" id="originalImageStatus">闲置</span></h2>
    <div class="meta" style="margin-bottom:10px">
      只下载消息中的 <code>origin_url_list</code> 并解密保存，不会用 large/medium/inline_pic 缩略图冒充原图。
      原件保存在 <code>data/media/originals/</code>；HEIC 等浏览器不直接支持的格式会额外生成全尺寸预览，原件仍完整保留。
    </div>
    <div class="row">
      <button class="btn btn-primary" id="originalImageRecoverBtn" onclick="startOriginalImageRecovery()">恢复 / 重新检查原图</button>
      <button class="btn btn-danger" id="originalImageStopBtn" onclick="stopOriginalImageRecovery()" style="display:none">停止</button>
      <span class="meta" id="originalImagePending"></span>
    </div>
    <div class="meta" id="originalImageMsg" style="margin-top:8px"></div>
    <div class="meta" id="originalImagePaths" style="margin-top:6px"></div>
  </div>
"""

_PANEL_SCRIPT = r"""
<script id="originalImageRecoveryController">
(function() {
  let originalImagePollTimer = null;

  function setOriginalStatus(status) {
    const el = document.getElementById('originalImageStatus');
    if (!el) return;
    if (typeof setStatusEl === 'function' && ['idle','running','completed','failed'].includes(status)) {
      setStatusEl(el, status);
    } else {
      el.textContent = status || 'idle';
      el.className = 'status status-' + (status || 'idle');
    }
  }

  async function loadOriginalImagePending() {
    try {
      const response = await fetch('/panel/api/media/originals/pending');
      const data = await response.json();
      const el = document.getElementById('originalImagePending');
      if (el && response.ok) {
        el.textContent = `可检查 ${data.eligible} 条 · 已切换原图 ${data.recovered} 条 · 待处理 ${data.pending} 条`;
      }
    } catch {}
  }

  async function pollOriginalImageRecovery() {
    try {
      const response = await fetch('/panel/api/media/originals/status');
      const data = await response.json();
      if (!response.ok) return;
      const running = data.status === 'running';
      setOriginalStatus(data.status || 'idle');
      const start = document.getElementById('originalImageRecoverBtn');
      const stop = document.getElementById('originalImageStopBtn');
      if (start) start.disabled = running;
      if (stop) stop.style.display = running ? '' : 'none';
      const msg = document.getElementById('originalImageMsg');
      if (msg) msg.textContent = data.message || '';
      const paths = [];
      if (data.backup_path) paths.push('数据库备份: data/' + data.backup_path);
      if (data.report_path) paths.push('报告: data/' + data.report_path);
      const pathsEl = document.getElementById('originalImagePaths');
      if (pathsEl) pathsEl.textContent = paths.join(' · ');
      if (!running) {
        if (originalImagePollTimer) {
          clearInterval(originalImagePollTimer);
          originalImagePollTimer = null;
        }
        loadOriginalImagePending();
      }
    } catch {}
  }

  window.startOriginalImageRecovery = async function() {
    const button = document.getElementById('originalImageRecoverBtn');
    if (button) button.disabled = true;
    try {
      const response = await fetch('/panel/api/media/originals/recover', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({force: true}),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const msg = document.getElementById('originalImageMsg');
        if (msg) msg.textContent = data.error || '启动失败';
        if (button) button.disabled = false;
        return;
      }
      setOriginalStatus('running');
      await pollOriginalImageRecovery();
      if (!originalImagePollTimer) originalImagePollTimer = setInterval(pollOriginalImageRecovery, 1500);
    } catch (error) {
      const msg = document.getElementById('originalImageMsg');
      if (msg) msg.textContent = '启动失败: ' + error.message;
      if (button) button.disabled = false;
    }
  };

  window.stopOriginalImageRecovery = async function() {
    try { await fetch('/panel/api/media/originals/cancel', {method: 'POST'}); }
    finally { pollOriginalImageRecovery(); }
  };

  setTimeout(() => { loadOriginalImagePending(); pollOriginalImageRecovery(); }, 0);
})();
</script>
"""


def enhanced_panel_html() -> str:
    panel_path = os.path.join(os.path.dirname(__file__), "panel", "static", "panel.html")
    with open(panel_path, encoding="utf-8") as handle:
        html = handle.read()

    scrape_end_marker = '  </div>\n    </div>\n\n    <!-- Schedule -->'
    if 'id="originalImageRecoverySection"' not in html and scrape_end_marker in html:
        html = html.replace(
            scrape_end_marker,
            '  </div>\n' + _PANEL_SECTION + '    </div>\n\n    <!-- Schedule -->',
            1,
        )

    # Important: the section itself contains onclick="startOriginalImageRecovery()".
    # Use a dedicated script marker instead of the function name, otherwise the
    # controller script is incorrectly considered present and never injected.
    if 'id="originalImageRecoveryController"' not in html:
        html = html.replace("</body>", _PANEL_SCRIPT + "\n</body>", 1)
    return html


@original_images_router.get("", response_class=HTMLResponse, include_in_schema=False)
@original_images_router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def enhanced_panel_page():
    return HTMLResponse(content=enhanced_panel_html(), headers={"Content-Type": "text/html; charset=utf-8"})
