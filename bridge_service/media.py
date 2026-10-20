"""Bounded image decoding and public HTTPS reads; never open a supplied path.

QQ sources come only from authenticated, admitted messages. Upload sources use
OpenAI fileParams and an operator-configured exact host allowlist. URLs, rkeys,
file download tokens and original image bytes are never returned as text.
"""

import base64
import io
import re
import ssl
import threading
import time
import warnings
from urllib.parse import parse_qsl, urlsplit

from PIL import Image, ImageOps

from .webhooks import _PublicHTTPSConnection, _remaining, validate_callback_url, validate_proxy_url

MAX_IMAGE_BYTES = 4 * 1024 * 1024
MAX_PIXELS = 4_000_000
MAX_FRAMES = 64
MAX_TOTAL_PIXELS = 32_000_000
MAX_ATTACHMENTS = 4
QQ_HOSTS = frozenset({"multimedia.nt.qq.com", "gchat.qpic.cn", "c2cpicdw.qpic.cn",
                      "p.qpic.cn", "gxh.vip.qq.com"})
MIMES = {"PNG": "image/png", "JPEG": "image/jpeg", "GIF": "image/gif", "WEBP": "image/webp"}
_DECODERS = threading.BoundedSemaphore(2)


class MediaError(ValueError):
    """Fixed diagnostic only: no supplied URL, token, filename or image content."""


def file_hosts(values):
    if not isinstance(values, list) or len(values) > 8:
        raise MediaError("file_download_hosts must be a list of at most eight exact hosts")
    result = set()
    for host in values:
        if (not isinstance(host, str) or host != host.lower() or "." not in host
                or not re.fullmatch(r"[a-z0-9.-]{1,253}", host)):
            raise MediaError("file download hosts must be exact lowercase DNS names")
        validate_callback_url("https://" + host + "/")
        result.add(host)
    return frozenset(result)


def source_url(url, allowed_hosts, *, qq=False):
    if not isinstance(url, str) or len(url) > 8192:
        raise MediaError("invalid media URL")
    # Old QQ events use HTTP CDN links. Upgrade only these fixed QQ hosts;
    # there is no HTTP fetch or fallback.
    if qq and url.startswith("http://"):
        url = "https://" + url[7:]
    try:
        parts = validate_callback_url(url)
    except (ValueError, TypeError):
        raise MediaError("media requires a permitted HTTPS origin") from None
    if parts.hostname not in allowed_hosts:
        raise MediaError("media origin is not allowed")
    return url


def same_qq_resource(first, second):
    def identity(value):
        p = urlsplit(source_url(value, QQ_HOSTS, qq=True))
        query = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != "rkey")
        return p.hostname, p.path, query
    return identity(first) == identity(second)


def incoming_attachment(segment):
    """Reduce signed gateway fields to a small, private source descriptor."""
    data, kind = segment.get("data"), segment.get("type")
    if not isinstance(data, dict):
        raise MediaError("invalid attachment")
    if kind == "face":
        value = data.get("id")
        if not isinstance(value, (str, int)) or isinstance(value, bool) or not re.fullmatch(r"\d{1,6}", str(value)):
            raise MediaError("invalid system face")
        return {"kind": "face", "face_id": int(value)}
    if kind not in ("image", "mface"):
        raise MediaError("unsupported attachment")
    emoji = data.get("emoji_id")
    if kind == "mface" or emoji:
        if not isinstance(emoji, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", emoji):
            raise MediaError("invalid market face reference")
        package, key = data.get("emoji_package_id"), data.get("key")
        valid_package = type(package) is int and 0 < package <= 2**31 - 1
        valid_key = isinstance(key, str) and bool(re.fullmatch(r"[!-~]{1,256}", key))
        # Reading remains possible when upstream omitted send-only fields.
        return {"kind": "mface", "emoji_id": emoji, "emoji_package_id": package if valid_package else None,
                "key": key if valid_key else None,
                "url": f"https://gxh.vip.qq.com/club/item/parcel/item/{emoji[:2]}/{emoji}/raw300.gif"}
    url = source_url(data.get("url"), QQ_HOSTS, qq=True)
    file_id = data.get("file", "")
    if not isinstance(file_id, str) or len(file_id) > 512:
        raise MediaError("invalid image reference")
    # Only opaque QQ cache identifiers can reach get_image, never paths/URLs.
    if file_id and not re.fullmatch(r"[A-Za-z0-9_.{}-]{1,512}", file_id):
        file_id = ""
    return {"kind": "image", "file": file_id, "url": url}


def validate_file(value, hosts):
    if (not isinstance(value, dict) or not {"download_url", "file_id"} <= value.keys()
            or value.keys() - {"download_url", "file_id", "mime_type", "file_name"}):
        raise MediaError("an OpenAI fileParams file object is required")
    if not isinstance(value["file_id"], str) or not re.fullmatch(r"file[-_][A-Za-z0-9_-]{1,200}", value["file_id"]):
        raise MediaError("invalid file ID")
    if "mime_type" in value and value["mime_type"] not in MIMES.values():
        raise MediaError("unsupported declared image MIME type")
    if "file_name" in value and (not isinstance(value["file_name"], str) or len(value["file_name"]) > 255):
        raise MediaError("invalid file name")
    source_url(value["download_url"], hosts)
    return value


def inspect_image(raw, declared=None, *, preview=False):
    """Decode every permitted frame; pixel/frame limits bound decompression."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_IMAGE_BYTES:
        raise MediaError("image exceeds the four MiB limit")
    if not _DECODERS.acquire(blocking=False):
        raise MediaError("image decoder capacity reached; retry later")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw), formats=list(MIMES)) as probe:
                fmt = probe.format
                mime = MIMES[fmt]
                if declared not in (None, "", "application/octet-stream", mime):
                    raise MediaError("image content does not match MIME type")
                width, height = probe.size
                if width <= 0 or height <= 0 or width * height > MAX_PIXELS:
                    raise MediaError("image exceeds pixel limit")
                probe.verify()
            with Image.open(io.BytesIO(raw), formats=list(MIMES)) as decoded:
                first, frames, total_pixels = None, 0, 0
                # n_frames may scan the entire animation before a limit can be
                # enforced. Seek at most one frame beyond the permitted count.
                for index in range(MAX_FRAMES + 1):
                    try:
                        decoded.seek(index)
                    except EOFError:
                        break
                    pixels = decoded.width * decoded.height
                    total_pixels += pixels
                    if (index >= MAX_FRAMES or pixels > MAX_PIXELS or total_pixels > MAX_TOTAL_PIXELS
                            or (index > 0 and fmt != "GIF")):
                        raise MediaError("animation exceeds supported frame/pixel limits")
                    decoded.load()
                    frames += 1
                    if index == 0 and preview:
                        first = ImageOps.exif_transpose(decoded).convert("RGBA")
                info = {"mime_type": mime, "width": width, "height": height, "frames": frames, "bytes": len(raw)}
                if preview:
                    first.thumbnail((1024, 1024))
                    buffer = io.BytesIO()
                    first.save(buffer, format="PNG")  # Strip metadata; GIF preview is frame zero only.
                    rendered = buffer.getvalue()
                    if len(rendered) > MAX_IMAGE_BYTES:
                        raise MediaError("preview exceeds size limit")
                    return info, {"type": "image", "mimeType": "image/png", "data": base64.b64encode(rendered).decode()}
                return info
    except MediaError:
        raise
    except Exception:
        raise MediaError("invalid or unsupported image content") from None
    finally:
        _DECODERS.release()


class ImageFetcher:
    """Pinned HTTPS, no redirects/cookies/ambient proxies; two bounded readers."""
    def __init__(self, *, download_hosts=(), proxy_url=None):
        self.file_hosts = file_hosts(list(download_hosts))
        self.proxy = validate_proxy_url(proxy_url)
        self.context = ssl.create_default_context()
        self.slots = threading.BoundedSemaphore(2)

    def fetch(self, url, *, qq=False, declared=None):
        url = source_url(url, QQ_HOSTS if qq else self.file_hosts, qq=qq)
        if not self.slots.acquire(blocking=False):
            raise MediaError("media reader capacity reached; retry later")
        connection = response = None
        try:
            deadline = time.monotonic() + 10
            p = urlsplit(url)
            connection = _PublicHTTPSConnection(p.hostname, 443, timeout=10, context=self.context,
                                                deadline=deadline, proxy=self.proxy)
            target = p.path or "/"
            if p.query:
                target += "?" + p.query
            connection.request("GET", target, headers={"Accept": "image/*", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            _remaining(deadline)
            mime = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if (response.status != 200 or response.getheader("Content-Encoding", "identity").lower() != "identity"
                    or mime not in {*MIMES.values(), "application/octet-stream"}):
                raise MediaError("image download rejected")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or not 0 < int(length) <= MAX_IMAGE_BYTES):
                raise MediaError("invalid image download length")
            raw = response.read(MAX_IMAGE_BYTES + 1)
            _remaining(deadline)
            if length is not None and len(raw) != int(length):
                raise MediaError("incomplete image download")
            inspect_image(raw, mime)
            inspect_image(raw, declared) if declared else None
            return raw
        except MediaError:
            raise
        except Exception:
            raise MediaError("image download unavailable") from None
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
            self.slots.release()
