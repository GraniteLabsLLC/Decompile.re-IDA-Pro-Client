"""Signed GitHub Releases updater for the Decompile.re IDA client."""

from __future__ import annotations

import ast
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import threading
import time
from urllib.parse import urljoin, urlparse
import uuid
import zipfile

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import (
    CLIENT_USER_AGENT,
    PLUGIN_VERSION,
    PYTHON_DEPENDENCIES,
    SETTINGS_DIR,
)


GITHUB_REPOSITORY = "GraniteLabsLLC/Decompile.re-IDA-Pro-Client"
LATEST_RELEASE_URL = (
    f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest"
)
_RELEASE_DOWNLOAD_PREFIX = f"/{GITHUB_REPOSITORY.lower()}/releases/download/"
MANIFEST_ASSET_NAME = "release-manifest.json"
SIGNATURE_ASSET_NAME = "release-manifest.sig"

PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEam1bB3bVto37seGcEjM49jIW2Zmi
j8i5GwIc6JDq5VASqSlfMQsFvgq77J4ifGYBhuLbC9j9OJjSNm+eZ3mHwQ==
-----END PUBLIC KEY-----
"""

_VERSION_RE = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z"
)
_OPERATION_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_API_HOSTS = frozenset({"api.github.com"})
_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
_METADATA_LIMIT = 1024 * 1024
_ARCHIVE_LIMIT = 64 * 1024 * 1024
_EXTRACTED_LIMIT = 128 * 1024 * 1024
_FILE_LIMIT = 4096
_REDIRECT_LIMIT = 5
_CHECK_INTERVAL_SECONDS = 6 * 60 * 60
_STATE_PATH = Path(SETTINGS_DIR) / "update-state.json"
_JOURNAL_NAME = ".decompile-re-update-journal.json"
_BACKUP_DIRECTORY = ".decompile-re-backups"
_operation_lock = threading.RLock()
_activated_version: str | None = None


class UpdateError(RuntimeError):
    """An update could not be trusted, downloaded, or installed."""


class InstallerRequiredError(UpdateError):
    """The setup wizard is required to complete this update safely."""


class UpdateCancelled(UpdateError):
    """The caller cancelled an update operation."""


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    download_url: str
    size: int
    digest: str | None


@dataclass(frozen=True)
class PluginDescriptor:
    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ReleaseManifest:
    version: str
    minimum_ida_major: int
    maximum_ida_major: int
    plugin: PluginDescriptor


@dataclass(frozen=True)
class VerifiedRelease:
    tag: str
    etag: str
    manifest: ReleaseManifest
    assets: dict[str, ReleaseAsset]


@dataclass(frozen=True)
class UpdateInfo:
    version: str


@dataclass(frozen=True)
class InstallResult:
    version: str
    backup_directory: str


def _check_cancelled(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise UpdateCancelled("Update cancelled")


def _version_tuple(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not _VERSION_RE.fullmatch(value):
        raise UpdateError("Release version is not valid semantic versioning")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _is_newer(candidate: str, installed: str) -> bool:
    return _version_tuple(candidate) > _version_tuple(installed)


def _runtime_installed_version() -> str:
    if _activated_version is None:
        return PLUGIN_VERSION
    return max(
        (PLUGIN_VERSION, _activated_version),
        key=_version_tuple,
    )


def _require_dict(value, description: str) -> dict:
    if not isinstance(value, dict):
        raise UpdateError(f"{description} must be a JSON object")
    return value


def _require_string(value, description: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise UpdateError(f"{description} is invalid")
    return value


def _require_int(value, description: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise UpdateError(f"{description} is invalid")
    if value < minimum or value > maximum:
        raise UpdateError(f"{description} is outside the permitted range")
    return value


def _validate_url(url: str, allowed_hosts: frozenset[str]) -> None:
    try:
        parsed = urlparse(url)
        _ = parsed.port
    except ValueError as exc:
        raise UpdateError("Release metadata contains an invalid URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (parsed.hostname or "").lower() not in allowed_hosts
    ):
        raise UpdateError("Release metadata points to an untrusted location")


def _validate_release_download_url(url: str) -> None:
    _validate_url(url, frozenset({"github.com"}))
    path = urlparse(url).path.lower()
    if not path.startswith(_RELEASE_DOWNLOAD_PREFIX):
        raise UpdateError("Release asset is outside the configured repository")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json_file(path: Path, maximum_bytes: int) -> dict:
    try:
        if path.stat().st_size > maximum_bytes:
            raise UpdateError("Update state exceeds the permitted size")
        return _require_dict(json.loads(path.read_text("utf-8")), "Update state")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UpdateError("Update state is not valid") from exc


def _write_json_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class GitHubReleaseClient:
    """Fetch and verify the latest public release without client credentials."""

    def __init__(
        self,
        session: requests.Session | None = None,
        public_key_pem: bytes = PUBLIC_KEY_PEM,
    ):
        self._session = session or requests.Session()
        self._public_key_pem = public_key_pem

    def _request(
        self,
        url: str,
        *,
        allowed_hosts: frozenset[str],
        headers: dict[str, str] | None = None,
        cancel_event: threading.Event | None = None,
    ):
        current = url
        for _ in range(_REDIRECT_LIMIT + 1):
            _check_cancelled(cancel_event)
            _validate_url(current, allowed_hosts)
            response = self._session.get(
                current,
                headers=headers or {},
                stream=True,
                allow_redirects=False,
                timeout=(5, 20),
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("Location", "")
            response.close()
            if not location:
                raise UpdateError("GitHub returned an empty release redirect")
            current = urljoin(current, location)
        raise UpdateError("GitHub release download exceeded the redirect limit")

    @staticmethod
    def _read_response(
        response,
        *,
        maximum_bytes: int,
        expected_size: int | None = None,
        cancel_event: threading.Event | None = None,
    ) -> bytes:
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError as exc:
                raise UpdateError("GitHub returned an invalid Content-Length") from exc
            if declared < 0 or declared > maximum_bytes:
                raise UpdateError("GitHub response exceeds the permitted size")

        data = bytearray()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            _check_cancelled(cancel_event)
            if not chunk:
                continue
            data.extend(chunk)
            if len(data) > maximum_bytes:
                raise UpdateError("GitHub response exceeds the permitted size")
        if expected_size is not None and len(data) != expected_size:
            raise UpdateError("Release asset size does not match signed metadata")
        return bytes(data)

    def _download_bytes(
        self,
        asset: ReleaseAsset,
        *,
        maximum_bytes: int,
        cancel_event: threading.Event | None = None,
    ) -> bytes:
        _validate_release_download_url(asset.download_url)
        response = self._request(
            asset.download_url,
            allowed_hosts=_DOWNLOAD_HOSTS,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": CLIENT_USER_AGENT,
            },
            cancel_event=cancel_event,
        )
        try:
            if response.status_code != 200:
                raise UpdateError(
                    f"GitHub release asset returned HTTP {response.status_code}"
                )
            return self._read_response(
                response,
                maximum_bytes=maximum_bytes,
                expected_size=asset.size,
                cancel_event=cancel_event,
            )
        finally:
            response.close()

    def _latest_release_json(
        self,
        etag: str = "",
        cancel_event: threading.Event | None = None,
    ) -> tuple[dict | None, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": CLIENT_USER_AGENT,
        }
        if etag:
            headers["If-None-Match"] = etag
        response = self._request(
            LATEST_RELEASE_URL,
            allowed_hosts=_API_HOSTS,
            headers=headers,
            cancel_event=cancel_event,
        )
        try:
            response_etag = response.headers.get("ETag", etag)
            if response.status_code == 304:
                return None, response_etag
            if response.status_code == 404:
                raise UpdateError("No published client release is available")
            if response.status_code != 200:
                raise UpdateError(
                    f"GitHub release API returned HTTP {response.status_code}"
                )
            body = self._read_response(
                response,
                maximum_bytes=_METADATA_LIMIT,
                cancel_event=cancel_event,
            )
        finally:
            response.close()
        try:
            return _require_dict(json.loads(body), "GitHub release"), response_etag
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError("GitHub returned invalid release metadata") from exc

    @staticmethod
    def _assets(release: dict) -> dict[str, ReleaseAsset]:
        raw_assets = release.get("assets")
        if not isinstance(raw_assets, list) or len(raw_assets) > 256:
            raise UpdateError("GitHub release assets are invalid")
        assets: dict[str, ReleaseAsset] = {}
        for raw in raw_assets:
            item = _require_dict(raw, "GitHub release asset")
            name = _require_string(item.get("name"), "Release asset name", 255)
            if name in assets:
                raise UpdateError("GitHub release contains duplicate asset names")
            size = _require_int(
                item.get("size"),
                "Release asset size",
                1,
                _ARCHIVE_LIMIT,
            )
            download_url = _require_string(
                item.get("browser_download_url"),
                "Release asset URL",
                2048,
            )
            _validate_release_download_url(download_url)
            digest = item.get("digest")
            if digest is not None and (
                not isinstance(digest, str) or len(digest) > 128
            ):
                raise UpdateError("Release asset digest is invalid")
            assets[name] = ReleaseAsset(name, download_url, size, digest)
        return assets

    def _verify_manifest(self, manifest_bytes: bytes, signature_bytes: bytes) -> None:
        try:
            signature = base64.b64decode(signature_bytes.strip(), validate=True)
            public_key = serialization.load_pem_public_key(self._public_key_pem)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise UpdateError("Embedded release key is not an EC public key")
            if not isinstance(public_key.curve, ec.SECP256R1):
                raise UpdateError("Embedded release key is not ECDSA P-256")
            public_key.verify(
                signature,
                manifest_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature as exc:
            raise UpdateError("Release manifest signature is invalid") from exc
        except (ValueError, TypeError) as exc:
            raise UpdateError("Release manifest signature is malformed") from exc

    @staticmethod
    def _parse_manifest(
        manifest_bytes: bytes,
        *,
        tag: str,
        assets: dict[str, ReleaseAsset],
    ) -> ReleaseManifest:
        try:
            raw = _require_dict(json.loads(manifest_bytes), "Release manifest")
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError("Release manifest is not valid JSON") from exc
        if raw.get("schema_version") != 1:
            raise UpdateError("Release manifest schema is not supported")
        version = _require_string(raw.get("version"), "Release version", 64)
        _version_tuple(version)
        if tag != f"v{version}":
            raise UpdateError("Release tag does not match the signed version")
        minimum = _require_int(
            raw.get("minimum_ida_major"),
            "Minimum IDA version",
            8,
            99,
        )
        maximum = _require_int(
            raw.get("maximum_ida_major"),
            "Maximum IDA version",
            minimum,
            99,
        )
        plugin_raw = _require_dict(raw.get("plugin"), "Plugin descriptor")
        plugin_name = _require_string(
            plugin_raw.get("name"),
            "Plugin asset name",
            255,
        )
        if Path(plugin_name).name != plugin_name:
            raise UpdateError("Plugin asset name contains a path")
        sha256 = _require_string(plugin_raw.get("sha256"), "Plugin SHA-256", 64)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            raise UpdateError("Plugin SHA-256 is invalid")
        size = _require_int(
            plugin_raw.get("size"),
            "Plugin asset size",
            1,
            _ARCHIVE_LIMIT,
        )
        asset = assets.get(plugin_name)
        if asset is None:
            raise UpdateError("Release is missing the signed plugin archive")
        if asset.size != size:
            raise UpdateError("GitHub and signed plugin sizes do not match")
        if asset.digest is not None:
            expected_digest = f"sha256:{sha256.lower()}"
            if asset.digest.lower() != expected_digest:
                raise UpdateError("GitHub and signed plugin digests do not match")
        return ReleaseManifest(
            version=version,
            minimum_ida_major=minimum,
            maximum_ida_major=maximum,
            plugin=PluginDescriptor(plugin_name, sha256.lower(), size),
        )

    def fetch_latest(
        self,
        *,
        etag: str = "",
        cancel_event: threading.Event | None = None,
    ) -> VerifiedRelease | None:
        release, response_etag = self._latest_release_json(etag, cancel_event)
        if release is None:
            return None
        if release.get("draft") is not False or release.get("prerelease") is not False:
            raise UpdateError("GitHub returned a non-production release")
        tag = _require_string(release.get("tag_name"), "Release tag", 128)
        assets = self._assets(release)
        manifest_asset = assets.get(MANIFEST_ASSET_NAME)
        signature_asset = assets.get(SIGNATURE_ASSET_NAME)
        if manifest_asset is None or signature_asset is None:
            raise UpdateError("Release is missing signed metadata")
        if manifest_asset.size > _METADATA_LIMIT or signature_asset.size > 16 * 1024:
            raise UpdateError("Signed release metadata exceeds the permitted size")
        manifest_bytes = self._download_bytes(
            manifest_asset,
            maximum_bytes=_METADATA_LIMIT,
            cancel_event=cancel_event,
        )
        signature_bytes = self._download_bytes(
            signature_asset,
            maximum_bytes=16 * 1024,
            cancel_event=cancel_event,
        )
        self._verify_manifest(manifest_bytes, signature_bytes)
        manifest = self._parse_manifest(manifest_bytes, tag=tag, assets=assets)
        return VerifiedRelease(tag, response_etag, manifest, assets)

    def download_plugin(
        self,
        release: VerifiedRelease,
        destination: Path,
        cancel_event: threading.Event | None = None,
    ) -> None:
        descriptor = release.manifest.plugin
        asset = release.assets[descriptor.name]
        _validate_release_download_url(asset.download_url)
        response = self._request(
            asset.download_url,
            allowed_hosts=_DOWNLOAD_HOSTS,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": CLIENT_USER_AGENT,
            },
            cancel_event=cancel_event,
        )
        digest = hashlib.sha256()
        written = 0
        try:
            if response.status_code != 200:
                raise UpdateError(
                    f"GitHub plugin archive returned HTTP {response.status_code}"
                )
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared = int(content_length)
                except ValueError as exc:
                    raise UpdateError(
                        "GitHub returned an invalid Content-Length"
                    ) from exc
                if declared != descriptor.size:
                    raise UpdateError(
                        "Plugin download size does not match signed metadata"
                    )
            with destination.open("xb") as output:
                for chunk in response.iter_content(chunk_size=256 * 1024):
                    _check_cancelled(cancel_event)
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > descriptor.size or written > _ARCHIVE_LIMIT:
                        raise UpdateError("Plugin download exceeds signed metadata")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        finally:
            response.close()
        if written != descriptor.size:
            raise UpdateError("Plugin download ended before its signed size")
        if digest.hexdigest() != descriptor.sha256:
            raise UpdateError("Plugin archive failed SHA-256 verification")


def _read_update_state() -> dict:
    try:
        return _read_json_file(_STATE_PATH, 64 * 1024)
    except UpdateError:
        return {}


def _record_latest(version: str, etag: str) -> None:
    state = _read_update_state()
    state.update(
        {
            "schema_version": 1,
            "checked_at": int(time.time()),
            "etag": etag,
            "latest_version": version,
        }
    )
    _write_json_atomic(_STATE_PATH, state)


def _cached_update(force: bool) -> UpdateInfo | None | object:
    if force:
        return _CACHE_MISS
    state = _read_update_state()
    checked_at = state.get("checked_at")
    latest = state.get("latest_version")
    if (
        isinstance(checked_at, int)
        and time.time() - checked_at < _CHECK_INTERVAL_SECONDS
        and isinstance(latest, str)
    ):
        try:
            return (
                UpdateInfo(latest)
                if _is_newer(latest, _runtime_installed_version())
                else None
            )
        except UpdateError:
            return _CACHE_MISS
    return _CACHE_MISS


_CACHE_MISS = object()


def _current_ida_major() -> int:
    from .compat.runtime import IDA_MAJOR

    return IDA_MAJOR


def check_for_update(
    *,
    force: bool = False,
    cancel_event: threading.Event | None = None,
    client: GitHubReleaseClient | None = None,
    ida_major: int | None = None,
) -> UpdateInfo | None:
    """Return a trusted newer release, or None when this installation is current."""
    with _operation_lock:
        cached = _cached_update(force)
        if cached is not _CACHE_MISS:
            return cached  # type: ignore[return-value]
        state = _read_update_state()
        etag = "" if force else str(state.get("etag") or "")
        release_client = client or GitHubReleaseClient()
        release = release_client.fetch_latest(
            etag=etag,
            cancel_event=cancel_event,
        )
        if release is None:
            latest = state.get("latest_version")
            if isinstance(latest, str):
                _record_latest(latest, etag)
                return (
                    UpdateInfo(latest)
                    if _is_newer(latest, _runtime_installed_version())
                    else None
                )
            release = release_client.fetch_latest(cancel_event=cancel_event)
            if release is None:
                return None
        manifest = release.manifest
        _record_latest(manifest.version, release.etag)
        active_ida_major = ida_major if ida_major is not None else _current_ida_major()
        if not (
            manifest.minimum_ida_major
            <= active_ida_major
            <= manifest.maximum_ida_major
        ):
            return None
        return (
            UpdateInfo(manifest.version)
            if _is_newer(manifest.version, _runtime_installed_version())
            else None
        )


def discover_plugin_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    entry = root / "ida_ai_client.py"
    package = root / "ida_ai_client"
    if (
        root.is_symlink()
        or entry.is_symlink()
        or package.is_symlink()
        or not entry.is_file()
        or not package.is_dir()
    ):
        raise InstallerRequiredError(
            "The current plugin installation cannot be updated in place"
        )
    return root


def _ensure_writable(root: Path) -> None:
    probe = root / f".decompile-re-write-test-{uuid.uuid4().hex}"
    try:
        probe.mkdir()
        probe.rmdir()
    except OSError as exc:
        raise InstallerRequiredError(
            "This plugin directory is protected. Use the Decompile.re setup "
            "wizard to update the installation."
        ) from exc


def _safe_extract(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    total = 0
    count = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                count += 1
                if count > _FILE_LIMIT:
                    raise UpdateError("Plugin archive contains too many files")
                if info.flag_bits & 0x1:
                    raise UpdateError("Plugin archive contains encrypted files")
                path = PurePosixPath(info.filename)
                if (
                    not info.filename
                    or path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or "\\" in info.filename
                    or ":" in path.parts[0]
                ):
                    raise UpdateError("Plugin archive contains an unsafe path")
                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFLNK:
                    raise UpdateError("Plugin archive contains a symbolic link")
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise UpdateError("Plugin archive contains a special file")
                total += info.file_size
                if total > _EXTRACTED_LIMIT:
                    raise UpdateError("Plugin archive expands beyond the limit")
                target = destination.joinpath(*path.parts)
                resolved = target.resolve()
                try:
                    resolved.relative_to(destination.resolve())
                except ValueError as exc:
                    raise UpdateError("Plugin archive escapes the staging area") from exc
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while True:
                        chunk = source.read(256 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size:
                            raise UpdateError("Plugin archive entry exceeds metadata")
                        output.write(chunk)
                if written != info.file_size:
                    raise UpdateError("Plugin archive entry is truncated")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise UpdateError("Plugin archive could not be extracted") from exc

    candidates = [destination]
    children = list(destination.iterdir())
    if len(children) == 1 and children[0].is_dir():
        candidates.append(children[0])
    for candidate in candidates:
        if (
            (candidate / "ida_ai_client.py").is_file()
            and (candidate / "ida_ai_client").is_dir()
        ):
            return candidate
    raise UpdateError("Plugin archive does not contain the expected client")


def _payload_version(payload: Path) -> str:
    config_path = payload / "ida_ai_client" / "config.py"
    try:
        tree = ast.parse(config_path.read_text("utf-8"))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise UpdateError("Staged client configuration is invalid") from exc
    version = ""
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "PLUGIN_VERSION"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            version = node.value.value
            break
    _version_tuple(version)
    metadata_path = payload / "ida-plugin.json"
    if metadata_path.is_file():
        try:
            metadata = _require_dict(
                json.loads(metadata_path.read_text("utf-8")),
                "IDA plugin metadata",
            )
            plugin = _require_dict(metadata.get("plugin"), "IDA plugin descriptor")
            if plugin.get("version") != version:
                raise UpdateError("Staged client versions do not match")
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError("Staged IDA plugin metadata is invalid") from exc
    return version


def _validate_dependencies(payload: Path) -> None:
    requirements = payload / "requirements.txt"
    if not requirements.is_file():
        raise UpdateError("Plugin archive is missing requirements.txt")
    try:
        actual = {
            line.strip()
            for line in requirements.read_text("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except (OSError, UnicodeError) as exc:
        raise UpdateError("Plugin requirements could not be read") from exc
    if actual != set(PYTHON_DEPENDENCIES):
        raise InstallerRequiredError(
            "This release changes Python dependencies. Use the Decompile.re "
            "setup wizard to install it safely."
        )


def _journal_path(root: Path) -> Path:
    return root / _JOURNAL_NAME


def _rollback(root: Path, journal: dict) -> None:
    operation_id = str(journal.get("operation_id") or "")
    if not _OPERATION_ID_RE.fullmatch(operation_id):
        raise UpdateError("Update recovery journal is invalid")
    backup = root / _BACKUP_DIRECTORY / operation_id
    staging = root / f".decompile-re-staging-{operation_id}"
    target_module = root / "ida_ai_client"
    target_entry = root / "ida_ai_client.py"
    target_marker = root / "decompile-re-install.json"
    backup_module = backup / "ida_ai_client"
    backup_entry = backup / "ida_ai_client.py"
    backup_marker = backup / "decompile-re-install.json"

    if backup_module.is_dir():
        if target_module.exists():
            shutil.rmtree(target_module)
        os.replace(backup_module, target_module)
    if backup_entry.is_file():
        os.replace(backup_entry, target_entry)
    if backup_marker.is_file():
        os.replace(backup_marker, target_marker)
    elif journal.get("had_marker") is False:
        target_marker.unlink(missing_ok=True)
    shutil.rmtree(staging, ignore_errors=True)
    _journal_path(root).unlink(missing_ok=True)


def _prune_backups(root: Path, keep: int = 3) -> None:
    backups = root / _BACKUP_DIRECTORY
    if not backups.is_dir():
        return
    entries = sorted(
        (path for path in backups.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for old in entries[keep:]:
        shutil.rmtree(old, ignore_errors=True)


def _activate_payload(root: Path, payload: Path, version: str, operation_id: str) -> str:
    staging = root / f".decompile-re-staging-{operation_id}"
    backup = root / _BACKUP_DIRECTORY / operation_id
    backup.mkdir(parents=True, exist_ok=False)
    target_module = root / "ida_ai_client"
    target_entry = root / "ida_ai_client.py"
    target_marker = root / "decompile-re-install.json"
    staged_module = payload / "ida_ai_client"
    staged_entry = payload / "ida_ai_client.py"
    staged_marker = staging / "decompile-re-install.json"
    staged_marker.write_text(
        json.dumps(
            {
                "version": version,
                "installed_at": datetime.now(timezone.utc).isoformat(),
                "installation_method": "in_client_update",
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    journal = {
        "schema_version": 1,
        "operation_id": operation_id,
        "state": "backup_started",
        "had_marker": target_marker.is_file(),
    }
    _write_json_atomic(_journal_path(root), journal)

    try:
        os.replace(target_module, backup / "ida_ai_client")
        shutil.copy2(target_entry, backup / "ida_ai_client.py")
        if target_marker.is_file():
            shutil.copy2(target_marker, backup / "decompile-re-install.json")

        os.replace(staged_module, target_module)
        os.replace(staged_entry, target_entry)
        os.replace(staged_marker, target_marker)
        journal["state"] = "activated"
        journal["health_check_started"] = False
        _write_json_atomic(_journal_path(root), journal)
        shutil.rmtree(staging, ignore_errors=True)
        _prune_backups(root)
        return str(backup)
    except Exception:
        _rollback(root, journal)
        raise


def install_latest(
    *,
    cancel_event: threading.Event | None = None,
    client: GitHubReleaseClient | None = None,
    plugin_root: Path | None = None,
    ida_major: int | None = None,
) -> InstallResult:
    """Download, verify, stage, and activate the latest compatible release."""
    global _activated_version

    with _operation_lock:
        _check_cancelled(cancel_event)
        root = (plugin_root or discover_plugin_root()).resolve()
        _ensure_writable(root)
        active_ida_major = ida_major if ida_major is not None else _current_ida_major()
        release_client = client or GitHubReleaseClient()
        release = release_client.fetch_latest(cancel_event=cancel_event)
        if release is None:
            raise UpdateError("GitHub did not return a release")
        manifest = release.manifest
        if not _is_newer(manifest.version, _runtime_installed_version()):
            raise UpdateError("The installed client is already current")
        if not (
            manifest.minimum_ida_major
            <= active_ida_major
            <= manifest.maximum_ida_major
        ):
            raise UpdateError("The latest release does not support this IDA version")

        operation_id = uuid.uuid4().hex
        archive_path = root / f".decompile-re-download-{operation_id}.zip"
        staging = root / f".decompile-re-staging-{operation_id}"
        try:
            release_client.download_plugin(
                release,
                archive_path,
                cancel_event=cancel_event,
            )
            _check_cancelled(cancel_event)
            payload = _safe_extract(archive_path, staging)
            if _payload_version(payload) != manifest.version:
                raise UpdateError(
                    "Plugin archive version does not match the signed manifest"
                )
            _validate_dependencies(payload)
            _check_cancelled(cancel_event)
            backup = _activate_payload(
                root,
                payload,
                manifest.version,
                operation_id,
            )
            state = _read_update_state()
            state["installed_version"] = manifest.version
            state["installed_at"] = int(time.time())
            _write_json_atomic(_STATE_PATH, state)
            _activated_version = manifest.version
            return InstallResult(manifest.version, backup)
        finally:
            archive_path.unlink(missing_ok=True)
            shutil.rmtree(staging, ignore_errors=True)
