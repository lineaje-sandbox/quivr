#!/usr/bin/env python3
"""Lineaje AI Policy Scanner — GitHub Actions edition.

Scans already-checked-out source code against Lineaje AI security policies
and prints results as structured JSON to stdout. Designed to run on a
GitHub-managed Ubuntu runner where the repository is pre-checked-out.

Usage::

    python scripts/gha_repo_scan.py --source-path .

Output (stdout, JSON)::

    {
      "status": "violations_found | compliant | error",
      "scan_metadata": {
        "repo": "owner/repo",
        "branch": "main",
        "head_sha": "abc1234",
        "scanned_at": "2026-05-10T10:00:00Z",
        "files_scanned": 150,
        "batches": 2,
        "failed_batches": 0
      },
      "report": "...(markdown policy report)...",
      "violations": [...],
      "aibom": [...],
      "scan_errors": []
    }

Required environment variable::

    LINEAJE_PAT_TOKEN  — Lineaje refresh token (exchanged for short-lived access tokens
                          at SCIM renew-access-token). Override with
                          LINEAJE_RENEW_ACCESS_TOKEN_URL or SCIM_SERVICE_URL.

Exit codes::

    0 — scan completed (check "status" field)
    1 — runtime error
    2 — configuration error (missing LINEAJE_PAT_TOKEN, missing repo/branch)
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import base64
import fnmatch
import io
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Standalone file-collection helpers (inlined from config.py)
# ===========================================================================
# This script is deployed on its own into a target repo's
# .lineaje-scanner/scripts/ by the GitHub Action — the rest of the
# aipo_mcp_server repo (including config.py) is not present there, so it
# must not import from config.py or anywhere else in this repo. Everything
# below is a straight copy of config.py's MANIFEST_FILE_PATTERNS /
# ARCHIVE_EXCLUDE_* / list_files_for_archive() / EVIDENCE_TYPE_SCM_SCAN —
# keep both copies in sync if the source changes.

EVIDENCE_TYPE_SCM_SCAN = "scm_scan"

MANIFEST_FILE_PATTERNS: frozenset = frozenset(
    {
        # Python
        "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
        "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg",
        "poetry.lock",
        # Python — conda
        "environment.yml", "environment.yaml",
        # JavaScript/Node.js
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
        # Java
        "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
        # Scala
        "build.sbt",
        # Ruby
        "Gemfile", "Gemfile.lock",
        # Go
        "go.mod", "go.sum",
        # Rust
        "Cargo.toml", "Cargo.lock",
        # .NET
        "packages.config", "packages.lock.json", "*.csproj", "*.fsproj",
        "*.vbproj", "nuget.config", "Directory.Packages.props",
        # PHP
        "composer.json", "composer.lock",
        # Swift
        "Package.swift", "Package.resolved",
        # Dart / Flutter
        "pubspec.yaml", "pubspec.lock",
        # Elixir
        "mix.exs", "mix.lock",
        # Ruby gemspec
        "*.gemspec",
    }
)


def _is_manifest_file(name: str) -> bool:
    """True if *name* matches ``MANIFEST_FILE_PATTERNS`` (exact or glob)."""
    if name in MANIFEST_FILE_PATTERNS:
        return True
    return any(
        fnmatch.fnmatch(name, pat)
        for pat in MANIFEST_FILE_PATTERNS
        if "*" in pat or "?" in pat
    )


ARCHIVE_EXCLUDE_DIRS: frozenset = frozenset(
    {
        ".git", ".gitignore", ".gitattributes", ".gitmodules", ".hg", ".svn",
        ".env", ".env.local", ".env.development", ".env.production",
        "__pycache__", ".pytest_cache", "venv", ".venv", ".venv-scan", "env", ".tox",
        "htmlcov", ".coverage", ".mypy_cache", ".ruff_cache",
        "node_modules", ".yarn", ".pnp",
        "dist", "build", ".next", ".nuxt", "out", "coverage", ".cache",
        "target", ".gradle", ".m2",
        "Pods", ".expo",
        ".idea", ".vscode",
        ".lineaje-aiepo-security",
        ".lineaje",
        "migrations", "alembic",
    }
)

ARCHIVE_EXCLUDE_GLOBS: frozenset = frozenset(
    {
        "*.secret", "*.key", "*.pem", "*.env.*",
        "*.zip", "*.tar", "*.tar.gz", "*.jar", "*.war", "*.swp", "*.swo",
        "*.lock", "package-lock.json", "yarn.lock", "Pipfile.lock",
        "poetry.lock", "Gemfile.lock", "Cargo.lock", "composer.lock",
        "*.min.js", "*.min.css", "*.map",
        "*_pb2.py", "*.pb.go", "*.pb.cc", "*.pb.h",
        "*.snap",
    }
)

BINARY_EXTENSIONS: frozenset = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
        ".pyc", ".pyo", ".o", ".a",
        ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
        ".db", ".sqlite", ".sqlite3",
    }
)

_ARCHIVE_EXCLUDE_DIR_GLOBS: tuple = (".venv-*", "venv-*")


def _git_ls_files_archive_command(repo_path: str) -> List[str]:
    """``git ls-files`` argv that skips the same paths the upload archive tool skips.

    ``--exclude-standard`` honors ``.gitignore``. ``-x`` drops matching *untracked*
    files. ``:(exclude,glob)`` pathspecs also drop *tracked* vendor dirs, lockfiles,
    binaries, and dependency manifests so a GHA checkout does not pack them.
    """
    cmd: List[str] = [
        "git", "-C", repo_path, "ls-files", "-z", "--cached", "--others", "--exclude-standard",
    ]
    x_patterns: List[str] = [
        *sorted(ARCHIVE_EXCLUDE_DIRS),
        *sorted(ARCHIVE_EXCLUDE_GLOBS),
        *sorted(MANIFEST_FILE_PATTERNS),
        *[f"*{ext}" for ext in sorted(BINARY_EXTENSIONS)],
        *_ARCHIVE_EXCLUDE_DIR_GLOBS,
    ]
    for pattern in x_patterns:
        cmd.extend(["-x", pattern])
    cmd.extend(["--", "."])
    for name in sorted(ARCHIVE_EXCLUDE_DIRS):
        cmd.append(f":(exclude,glob){name}")
        cmd.append(f":(exclude,glob){name}/**")
        cmd.append(f":(exclude,glob)**/{name}")
        cmd.append(f":(exclude,glob)**/{name}/**")
    for pat in (*sorted(ARCHIVE_EXCLUDE_GLOBS), *sorted(MANIFEST_FILE_PATTERNS)):
        cmd.append(f":(exclude,glob){pat}")
        if not pat.startswith("**/"):
            cmd.append(f":(exclude,glob)**/{pat}")
    for ext in sorted(BINARY_EXTENSIONS):
        cmd.append(f":(exclude,glob)*{ext}")
        cmd.append(f":(exclude,glob)**/*{ext}")
    for pat in _ARCHIVE_EXCLUDE_DIR_GLOBS:
        cmd.append(f":(exclude,glob){pat}")
        cmd.append(f":(exclude,glob){pat}/**")
        cmd.append(f":(exclude,glob)**/{pat}")
        cmd.append(f":(exclude,glob)**/{pat}/**")
    return cmd


def _list_git_files_for_archive(repo_path: str) -> Optional[List[str]]:
    """Repo-relative files from ``_git_ls_files_archive_command``.

    Returns ``None`` if *repo_path* is not a git work tree or git cannot run.
    """
    try:
        proc = subprocess.run(
            _git_ls_files_archive_command(repo_path),
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    files: List[str] = []
    for chunk in proc.stdout.split(b"\0"):
        if not chunk:
            continue
        rel = chunk.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        if not rel:
            continue
        full = os.path.join(repo_path, rel)
        if os.path.isfile(full):
            files.append(rel)
    return files


def _walk_files_for_archive(root: str) -> List[str]:
    """``os.walk`` fallback using the same exclude sets as archive upload."""
    file_list: List[str] = []
    for dirpath, dirs, filenames in os.walk(root):
        dirs[:] = [
            d
            for d in dirs
            if d not in ARCHIVE_EXCLUDE_DIRS
            and not any(fnmatch.fnmatch(d, g) for g in _ARCHIVE_EXCLUDE_DIR_GLOBS)
        ]
        for fname in filenames:
            full_path = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(full_path, root).replace("\\", "/")
            ext = pathlib.Path(fname).suffix.lower()
            if ext in BINARY_EXTENSIONS:
                continue
            if _is_manifest_file(fname):
                continue
            if any(fnmatch.fnmatch(rel_path, g) for g in ARCHIVE_EXCLUDE_GLOBS):
                continue
            if any(part in ARCHIVE_EXCLUDE_DIRS for part in pathlib.Path(rel_path).parts):
                continue
            file_list.append(rel_path)
    return file_list


def list_files_for_archive(repo_path: str) -> List[str]:
    """Prefer ``git ls-files`` with upload-tool excludes; walk if git is unavailable."""
    listed = _list_git_files_for_archive(repo_path)
    if listed is not None:
        return listed
    return _walk_files_for_archive(repo_path)


def _combine_scan_reports(reports: List[str]) -> str:
    """Union per-batch markdown tables into one report (fallback: concatenate)."""
    nonempty = [r for r in reports if r]
    if not nonempty:
        return ""
    try:
        _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _root not in sys.path:
            sys.path.insert(0, _root)
        from pipeline.report.consolidate import consolidate_batch_reports
        return consolidate_batch_reports(nonempty)
    except ImportError:
        return "\n\n---\n\n".join(nonempty)


# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.commercialdev.dev.veedna.com/mcp/"
# MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

MAX_SCAN_WORKERS = 4
REMEDIATION_BRANCH_PREFIX = "remediation/unifai-gha"
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100
# GitHub rejects POST /pulls with HTTP 422 when body > 65536 chars.
GITHUB_PR_BODY_SAFE_LIMIT = 60_000
_PR_BODY_TRUNCATION_NOTE = (
    "\n\n---\n\n"
    "*…Report truncated for GitHub PR body size limit. "
    "Retrieve the full text from CI logs.*"
)

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120

# UI / GHA ``LINEAJE_PAT_TOKEN`` is a SCIM-issued refresh token. Identity-service
# ``/lineajeidentity/.../renew-access-token`` cannot decrypt it (HTTP 500
# "trying to decrypt the string"). Exchange at SCIM instead.
_SCIM_RENEW_ACCESS_TOKEN_PATH = "/scim/api/v1/auth/native/renew-access-token"
_IDENTITY_RENEW_ACCESS_TOKEN_PATH = "/lineajeidentity/api/v1/auth/native/renew-access-token"
_SCIM_SERVICE_URL_DEFAULT = "https://scim-service.commercialdev.dev.veedna.com"
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    _SCIM_SERVICE_URL_DEFAULT + _SCIM_RENEW_ACCESS_TOKEN_PATH
)

_LINEAJE_IDENTITY_SERVICE_URL_DEFAULT = (
    "https://lineaje-identity-service.commercialdev.dev.veedna.com"
)

_PAT_INTROSPECT_PATH = "/lineajeidentity/api/v1/pat/introspect"

# ===========================================================================
# Token helpers
# ===========================================================================

def _normalize_token(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().lstrip("﻿").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _normalize_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    u = str(url).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
        u = u[1:-1].strip()
    return u


def _scim_renew_url_from_identity_url(url: str) -> str:
    """Map identity-service renew URLs onto the SCIM equivalent.

    SCIM-issued refresh tokens fail at identity with HTTP 500
    ``trying to decrypt the string``.
    """
    u = (url or "").strip().rstrip("/")
    if not u or _IDENTITY_RENEW_ACCESS_TOKEN_PATH not in u:
        return u
    parsed = urllib.parse.urlparse(u)
    host = (parsed.netloc or "").replace("lineaje-identity-service", "scim-service")
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}{_SCIM_RENEW_ACCESS_TOKEN_PATH}"


def _resolve_renew_access_token_url(explicit: Optional[str] = None) -> str:
    """SCIM renew-access-token URL for a GHA/UI refresh token.

    Order: explicit arg, LINEAJE_RENEW_ACCESS_TOKEN_URL, {SCIM_SERVICE_URL}/scim/...,
    commercialdev SCIM default. Identity-service renew URLs are rewritten to SCIM.
    """
    scim_base = _normalize_url(os.environ.get("SCIM_SERVICE_URL")).rstrip("/")
    derived = f"{scim_base}{_SCIM_RENEW_ACCESS_TOKEN_PATH}" if scim_base else ""
    raw = (
        _normalize_url(explicit)
        or _normalize_url(os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL"))
        or derived
        or _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
    )
    rewritten = _scim_renew_url_from_identity_url(raw) or raw
    if rewritten != raw.rstrip("/"):
        logger.warning(
            "Auth: renew URL %s is identity-service; using SCIM %s "
            "(identity cannot decrypt SCIM refresh tokens)",
            raw, rewritten,
        )
    return rewritten.rstrip("/")


def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
    text = raw_text.strip() if raw_text else ""
    try:
        parsed: Any = json.loads(raw_text)
    except json.JSONDecodeError:
        # Some endpoints return a bare JWT string
        parts = text.split(".")
        if context == "renew-access-token" and len(parts) == 3:
            return {"access_token": text}
        raise RuntimeError(f"{context}: response is not valid JSON") from None
    for _ in range(8):
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            s = parsed.strip()
            if not s:
                raise RuntimeError(f"{context}: empty JSON string where object expected")
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parts = s.split(".")
                if context == "renew-access-token" and len(parts) == 3:
                    return {"access_token": s}
                raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
            continue
        break
    raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


class RefreshTokenTokenManager:
    """Exchange LINEAJE_PAT_TOKEN (a refresh token) for short-lived MCP bearer tokens,
    auto-renewing before expiry."""

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
        self._renew_url = _resolve_renew_access_token_url(renew_access_token_url)
        self._lock = threading.Lock()
        self._access_token = ""
        self._access_deadline = 0.0
        try:
            self._skew_sec = int(os.environ.get(
                "LINEAJE_TOKEN_REFRESH_SKEW_SEC", str(_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC)
            ))
        except ValueError:
            self._skew_sec = _DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC

    def get_access_token(self) -> str:
        with self._lock:
            return self._get_unlocked()

    def _get_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _renew(self) -> None:
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
        req = urllib.request.Request(
            url, data=b"null",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        logger.info("Auth: exchanging refresh token at %s", self._renew_url)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"renew-access-token HTTP {exc.code}: {body[:800]}") from exc
        at = (data.get("access_token") or "").strip()
        if not at:
            raise RuntimeError(f"Token response missing access_token: {data!r}")
        self._access_token = at
        rt = (data.get("refresh_token") or "").strip()
        if rt:
            self._refresh_token = rt
        exp = data.get("expires_in")
        try:
            exp_sec = int(exp) if exp is not None else 3600
        except (TypeError, ValueError):
            exp_sec = 3600
        self._access_deadline = time.time() + max(60, exp_sec)
        logger.debug("Access token renewed; expires in %ds", exp_sec)


def _looks_like_jwt_blob(value: str) -> bool:
    s = value.strip()
    if s.count(".") != 2:
        return False
    hdr, payload, sig = s.split(".")
    if len(hdr) < 10 or len(payload) < 10 or len(sig) < 10:
        return False
    seg = re.compile(r"^[A-Za-z0-9_-]+$")
    return bool(seg.match(hdr) and seg.match(payload) and seg.match(sig))


def _looks_like_already_usable_bearer(value: str) -> bool:
    """True if *value* is already a Bearer (JWT), not an opaque refresh token."""
    s = value.strip()
    if not s:
        return False
    return _looks_like_jwt_blob(s)


def _tenant_id_from_access_jwt(access_token: str) -> str:
    """Read tenant_id from the access JWT payload. No PAT introspect.

    Lineaje puts it on ``user_metadata.tenant_id`` (top-level ``tenant_id``
    is also accepted). Signature is not verified — this token was just
    minted by renew-access-token over TLS.
    """
    if not _looks_like_jwt_blob(access_token):
        return ""
    try:
        payload = access_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return ""
    if not isinstance(claims, dict):
        return ""
    meta = claims.get("user_metadata") if isinstance(claims.get("user_metadata"), dict) else {}
    for src in (claims, meta):
        tid = src.get("tenant_id")
        if isinstance(tid, str) and tid.strip():
            return tid.strip()
    return ""



def _identity_service_base_url() -> str:
    """Resolve identity service base URL.

    Resolution order:
      1. LINEAJE_IDENTITY_SERVICE_URL env var
      2. Host extracted from LINEAJE_FETCH_ACCESS_TOKEN_URL
      3. Host extracted from LINEAJE_RENEW_ACCESS_TOKEN_URL
      4. Hardcoded default (_LINEAJE_IDENTITY_SERVICE_URL_DEFAULT)
    """
    explicit = os.environ.get("LINEAJE_IDENTITY_SERVICE_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    for env_var in ("LINEAJE_FETCH_ACCESS_TOKEN_URL", "LINEAJE_RENEW_ACCESS_TOKEN_URL"):
        raw = os.environ.get(env_var, "").strip()
        if raw:
            parsed = urllib.parse.urlparse(raw)
            return f"{parsed.scheme}://{parsed.netloc}"
    return _LINEAJE_IDENTITY_SERVICE_URL_DEFAULT


def introspect_lineaje_pat(pat: str) -> Dict[str, Any]:
    """Validate a Lineaje PAT via the identity service introspect endpoint."""
    base = _identity_service_base_url()
    if not base:
        raise RuntimeError(
            "Identity service URL not configured. "
            "Set LINEAJE_IDENTITY_SERVICE_URL or LINEAJE_FETCH_ACCESS_TOKEN_URL."
        )
    url = base + _PAT_INTROSPECT_PATH
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {pat}", "Accept": "application/json"},
        method="GET",
    )
    logger.info("PAT introspect: GET %s", url)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            logger.info("PAT introspect: HTTP %s", getattr(resp, "status", None) or resp.getcode())
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode(errors="replace")
        raise RuntimeError(f"PAT introspect HTTP {exc.code}: {err_body[:400]}") from exc
    try:
        info = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PAT introspect returned non-JSON: {raw[:200]}") from exc
    logger.info(
        "PAT introspect: user_email=%s tenant_id=%s company_id=%s",
        info.get("user_email", ""), info.get("tenant_id", ""), info.get("company_id", ""),
    )
    return info


def _scan_refresh_token(args: Optional[argparse.Namespace] = None) -> str:
    """PAT / refresh token from ``--lineaje-pat`` / ``--refresh-token`` or GHA env."""
    cli = ""
    if args is not None:
        cli = _normalize_token(
            getattr(args, "lineaje_pat", None) or getattr(args, "refresh_token", None)
        )
    return cli or _normalize_token(
        os.environ.get("LINEAJE_PAT_TOKEN", "")
        or os.environ.get("LINEAJE_REFRESH_TOKEN", "")
    )


def build_bearer_getter(refresh_token: str = "") -> Callable[[], str]:
    """Return a callable that yields the MCP bearer from a refresh token.

    ``--lineaje-pat`` / ``LINEAJE_PAT_TOKEN`` is a refresh token. It is
    exchanged via renew-access-token. A JWT is used directly as Bearer.
    """
    pat = _normalize_token(refresh_token or os.environ.get("LINEAJE_PAT_TOKEN", ""))
    if not pat:
        raise RuntimeError("LINEAJE_PAT_TOKEN / --lineaje-pat is not set")
    if _looks_like_already_usable_bearer(pat):
        logger.info("LINEAJE_PAT_TOKEN is already a usable access token — using directly as bearer")
        return lambda: pat
    logger.info("Auth: treating --lineaje-pat / LINEAJE_PAT_TOKEN as refresh token")
    mgr = RefreshTokenTokenManager(pat)
    return mgr.get_access_token

# ===========================================================================
# File collection
# ===========================================================================

def collect_repo_files(local_path: str) -> List[str]:
    """List scannable files via ``git ls-files``; excludes live in the upload tool."""
    return list_files_for_archive(local_path)

# ===========================================================================
# Archive creation
# ===========================================================================

def _norm_archive_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def create_batch_archive(
    source_dir: str,
    archive_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: int = 0,
    run_id: str = "",
    manifest_files: Optional[List[str]] = None,
) -> str:
    archive_path = os.path.join(archive_dir, f"repo_scan_batch_{batch_index}.tar.gz")
    extra_manifests = [m for m in (manifest_files or []) if m not in file_subset]
    all_files = list(file_subset) + extra_manifests
    with tarfile.open(archive_path, "w:gz") as tf:
        for rel_path in all_files:
            full_path = os.path.join(source_dir, rel_path)
            if os.path.isfile(full_path):
                tf.add(full_path, arcname=rel_path, recursive=False)
        metadata = {
            "scan_source": "gha_repo_scan",
            "repo": source_code_repo,
            "branch": branch,
            "head_sha": head_sha,
            "scan_type": "full_repository",
            "evidence_type": EVIDENCE_TYPE_SCM_SCAN,
            "batch_index": batch_index,
            "batch_file_count": len(file_subset),
            "manifest_file_count": len(extra_manifests),
        }
        metadata_bytes = json.dumps(metadata, indent=2).encode("utf-8")
        metadata_info = tarfile.TarInfo(name="user_metadata.json")
        metadata_info.size = len(metadata_bytes)
        tf.addfile(metadata_info, io.BytesIO(metadata_bytes))
    size_kb = os.path.getsize(archive_path) // 1024
    logger.info(
        "Batch archive #%d: %d files + %d manifests, %d KB",
        batch_index, len(file_subset), len(extra_manifests), size_kb,
    )
    return archive_path


def _batch_size(total_files: int) -> int:
    raw = (os.environ.get("UNIFAI_FILE_BATCH_SIZE") or "").strip()
    if not raw:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    try:
        size = int(raw)
    except ValueError:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    if size <= 0:
        return max(1, total_files)
    return size

# ===========================================================================
# MCP scan (SDK path only)
# ===========================================================================

def _upload_to_s3(presigned_url: str, archive_path: str) -> None:
    size = os.path.getsize(archive_path)
    logger.info("Uploading %d KB to S3 ...", size // 1024)
    with open(archive_path, "rb") as f:
        content_type = "application/gzip" if archive_path.endswith((".tar.gz", ".tgz")) else "application/zip"
        req = urllib.request.Request(
            presigned_url, data=f.read(), method="PUT",
            headers={"Content-Type": content_type},
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"S3 upload failed: HTTP {resp.status}")
    logger.info("S3 upload complete")


def _parse_tool_result(result: Any) -> dict:
    if hasattr(result, "content") and result.content:
        raw = result.content[0].text if hasattr(result.content[0], "text") else str(result.content[0])
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"raw": raw}
    return {"raw": "empty response"}


def _run_mcp_scan_via_client(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
) -> Dict[str, Any]:
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession

    async def _scan() -> Dict[str, Any]:
        upload_args: Dict[str, Any] = {
            "source_code_repo": source_code_repo,
            "branch_or_tag": branch,
            "files_to_scan": files_to_scan,
        }
        # Only known to the SCM/CI script — a coding agent (Cursor/Claude Code) has no
        # way to set a custom transport header, so this signal cannot leak into IDE scans.
        scm_headers: Dict[str, str] = {"X-Unifai-Commit-Sha": head_sha} if head_sha else {}

        tok1 = bearer_getter()
        async with streamablehttp_client(
            server_url, headers={"Authorization": f"Bearer {tok1}", **scm_headers},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("MCP step 1/3: get_upload_url")
                upload_result = _parse_tool_result(
                    await session.call_tool("get_upload_url", arguments=upload_args)
                )
                if not upload_result.get("success"):
                    raise RuntimeError(f"get_upload_url failed: {upload_result.get('error', upload_result)}")
                archive_id = upload_result["archive_id"]
                presigned_url = upload_result["presigned_url"]

        logger.info("MCP step 2/3: upload to S3")
        _upload_to_s3(presigned_url, archive_path)

        tok2 = bearer_getter()
        sse_timeout = int(os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800"))
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}", **scm_headers},
            sse_read_timeout=sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                logger.info("MCP step 3/3: analyze_uploaded_archive (timeout=%ds)", sse_timeout)
                analyze_args = dict(upload_args)
                analyze_args["archive_id"] = archive_id
                # We already know the exact URL we used to reach this server -- more
                # reliable than any guess the server itself could make about its own
                # public address. Every other caller of this tool leaves this "" (the
                # server-side default) and gets the server's own resolution instead.
                analyze_args["mcp_server_location"] = server_url
                analyze_args["scan_type"] = EVIDENCE_TYPE_SCM_SCAN
                result = _parse_tool_result(
                    await session2.call_tool("analyze_uploaded_archive", arguments=analyze_args)
                )
                return result

    return asyncio.run(_scan())


def run_mcp_scan(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
) -> Dict[str, Any]:
    logger.info("MCP scan: %d files, repo=%s, branch=%s", len(files_to_scan), source_code_repo, branch)
    return _run_mcp_scan_via_client(
        server_url, bearer_getter, source_code_repo, branch, files_to_scan, archive_path, head_sha=head_sha,
    )

# ===========================================================================
# Guardrail stub insertion (standalone — no sibling-file / repo dependency)
# ===========================================================================
#
# analyze_uploaded_archive already computes "stub_insertions" server-side
# (adapter.py's _scan_stub_insertions_readonly, same insertion_point_scanner.py
# logic the MCP server itself uses) and returns it in each batch's JSON
# response — file, line, proposed_stub (the exact code to insert),
# import_needed (the gr_check()-family helper for that language, inlined once
# per file), safe_to_insert, skip_reason, insert_after. Applying it here needs
# nothing beyond that JSON + stdlib: no gha_stub_insertion.py, no checkout of
# the aipo_mcp_server pipeline alongside this script. That older path
# (gha_stub_insertion.py) additionally re-derived stubs locally via
# pipeline/stub/guardrail_stub_insertion.py — a much heavier, SiteDescriptor/
# companion-module design requiring this repo's full pipeline package on the
# runner, which a truly standalone script (this one, meant to be the only
# Lineaje file a customer's workflow needs) can't assume.

# Per-language marker proving the shared gr_check()-family helper this
# extension's import_needed text defines is already present in a file — skip
# re-inserting it (harmless duplicate `def`/`function` in Python/JS, but a
# real SyntaxError for a duplicate top-level `class`/`func` in Java/Go).
_GR_CHECK_MARKERS: Dict[str, str] = {
    ".py": "def gr_check(",
    ".js": "function gr_check(",
    ".jsx": "function gr_check(",
    ".ts": "function gr_check(",
    ".tsx": "function gr_check(",
    ".go": "func grCheck(",
    ".java": "class GrClient {",
}


def _module_prefix_insert_index(lines: List[str]) -> int:
    """0-indexed position to insert a new top-level block at — after any
    shebang/encoding comment AND after a leading module docstring, if
    present. Only the first statement in a Python file is its module
    docstring; inserting above it silently demotes it to a dead string-
    literal expression. Falls back to shebang/encoding-only detection for
    non-Python sources — never raises."""
    idx = 0
    for i, ln in enumerate(lines[:5]):
        if ln.startswith("#!") or ln.strip().startswith("# -*-"):
            idx = i + 1
        if ln.startswith("package "):
            idx = max(idx, i + 1)
    try:
        tree = ast.parse("".join(lines))
        first = tree.body[0] if tree.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(getattr(first, "value", None), ast.Constant)
            and isinstance(first.value.value, str)
        ):
            idx = max(idx, first.end_lineno)
    except SyntaxError:
        pass
    return idx


def safe_prefix_insert_index(lines: List[str]) -> int:
    """Like _module_prefix_insert_index(), but also walks past any leading
    `from __future__ import` line(s) — those must be the first statement(s)
    in a Python file; inserting anything above one is a real SyntaxError."""
    insert_at = _module_prefix_insert_index(lines)
    while insert_at < len(lines) and lines[insert_at].lstrip().startswith("from __future__ import"):
        insert_at += 1
    return insert_at


def validate_python_source(new_content: str, abs_path: str) -> Optional[str]:
    """Whole-file compile() check after a stub insertion. Returns None if
    still valid, else the SyntaxError message. compile(), not ast.parse() —
    ast.parse() does not enforce future-import placement."""
    try:
        compile(new_content, abs_path, "exec")
        return None
    except SyntaxError as exc:
        return str(exc)


def _stub_insertions_from_mcp_result(mcp_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Merge stub_insertions with patched_files / companion_files from the MCP response."""
    stubs = [dict(s) for s in (mcp_result.get("stub_insertions") or [])]
    by_file: Dict[str, str] = {}
    for extra in list(mcp_result.get("patched_files") or []) + list(mcp_result.get("companion_files") or []):
        if not isinstance(extra, dict):
            continue
        rel = (extra.get("file") or "").strip().replace("\\", "/")
        if rel and extra.get("content") is not None:
            by_file[rel] = extra["content"]
    if not by_file:
        return stubs
    applied: set = set()
    for s in stubs:
        rel = (s.get("file") or "").strip().replace("\\", "/")
        if rel in by_file:
            s["new_content"] = by_file[rel]
            s["status"] = "detected"
            s["safe_to_insert"] = True
            applied.add(rel)
    for rel, content in by_file.items():
        if rel not in applied:
            stubs.append({
                "file": rel,
                "status": "detected",
                "safe_to_insert": True,
                "new_content": content,
                "line": 0,
            })
    return stubs


def apply_stub_insertions_to_clone(
    stub_insertions: List[Dict[str, Any]],
    source_dir: str,
) -> Tuple[Dict[str, str], List[str]]:
    """Apply the server-computed stub_insertions to files under source_dir.

    Returns ``(validated_fixes, failed_or_skipped)`` — validated_fixes maps
    repo-relative path -> new file content, ready for _create_fix_pr.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    skipped: List[str] = []
    validated: Dict[str, str] = {}
    for s in stub_insertions:
        rel = (s.get("file") or "").strip().replace("\\", "/")
        if not rel:
            continue
        if s.get("status") != "detected":
            continue  # "already_present" — nothing to do
        if s.get("new_content"):
            # Server already instrumented the extracted archive — write the
            # whole file rather than re-applying proposed_stub line-by-line.
            validated[rel] = s["new_content"]
            continue
        if not s.get("safe_to_insert"):
            skipped.append(f"{rel}:{s.get('line', '')} {s.get('skip_reason', '') or 'unsafe'}".strip())
            continue
        by_file.setdefault(rel, []).append(s)

    for rel_path, hits in by_file.items():
        abs_path = os.path.join(source_dir, rel_path)
        if not os.path.isfile(abs_path):
            logger.warning("Stub target not found in checkout: %s — skipping", rel_path)
            skipped.append(f"{rel_path} not found in checkout")
            continue

        with open(abs_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        ext = pathlib.Path(rel_path).suffix.lower()

        # Insert bottom-up so an earlier insertion never shifts a later hit's
        # (already-captured) line number out from under it.
        sorted_hits = sorted(hits, key=lambda h: h.get("line", 0), reverse=True)
        needs_import = False
        for hit in sorted_hits:
            proposed = hit.get("proposed_stub") or ""
            if not proposed:
                continue
            line = int(hit.get("line") or 0)
            # 1-based line; insert_after=True (result/lhs patterns) must land
            # AFTER the line assigning the variable the stub references —
            # inserting before it is a NameError.
            idx = max(0, line if hit.get("insert_after") else line - 1)
            idx = min(idx, len(lines))
            lines.insert(idx, proposed + "\n")
            needs_import = True

        if needs_import:
            import_block = next(
                (h.get("import_needed") for h in hits if h.get("import_needed")), "",
            )
            marker = _GR_CHECK_MARKERS.get(ext, "def gr_check(")
            if import_block and marker not in "".join(lines):
                lines.insert(safe_prefix_insert_index(lines), import_block.rstrip("\n") + "\n")

        new_content = "".join(lines)
        if ext == ".py":
            syntax_err = validate_python_source(new_content, abs_path)
            if syntax_err:
                logger.warning(
                    "Skip %s — stub insertion would produce invalid syntax (%s); left untouched",
                    rel_path, syntax_err,
                )
                skipped.append(f"{rel_path} would be invalid Python after insertion ({syntax_err})")
                continue

        validated[rel_path] = new_content

    logger.info(
        "Stub insertions applied: %d file(s) changed, %d skipped",
        len(validated), len(skipped),
    )
    return validated, skipped


# Extensions insertion_point_scanner.scan_file() actually scans. Passing the
# full GHA file_list (lockfiles, markdown, images) is a no-op per file but
# wastes runner time; restrict to these.
_LOCAL_STUB_SCANNABLE_EXTS = frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"})
_LOCAL_STUB_MAX_FILES = 200


def _ensure_insertion_point_scanner_on_path() -> None:
    """Make ``import insertion_point_scanner`` work on a GitHub Actions runner.

    Two layouts exist:
      1. Action deploy: this script AND insertion_point_scanner.py sit together
         in ``.lineaje-scanner/scripts/`` (``python path/to/gha_repo_scan.py``
         already puts that dir on sys.path[0] — still add it explicitly).
      2. This repo: ``scripts/gha_repo_scan.py`` with the scanner at repo root.
         Running ``python scripts/gha_repo_scan.py`` puts ``scripts/`` on
         sys.path, NOT the parent, so the import fails without this.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    parent = os.path.dirname(here)
    for path in (here, parent):
        if path and path not in sys.path:
            sys.path.insert(0, path)


def _rel_candidate_file(file_path: str, source_dir: str) -> str:
    path = (file_path or "").strip().replace("\\", "/")
    if not path:
        return ""
    src = os.path.realpath(source_dir)
    abs_path = path if os.path.isabs(path) else os.path.normpath(os.path.join(src, path))
    try:
        rel = os.path.relpath(os.path.realpath(abs_path), src)
    except ValueError:
        return os.path.basename(path).replace("\\", "/")
    if rel.startswith(".."):
        return os.path.basename(path).replace("\\", "/")
    return rel.replace("\\", "/")


def _scannable_files_for_local_stubs(
    violations: List[Dict[str, Any]],
    file_list: List[str],
    source_dir: str,
) -> List[str]:
    """Prefer files named in violations; otherwise every scannable path in file_list."""
    listed = {(f or "").replace("\\", "/") for f in file_list}
    from_violations: List[str] = []
    seen: set = set()
    for v in violations or []:
        rel = _rel_candidate_file(v.get("file") or "", source_dir)
        if (
            rel
            and rel in listed
            and pathlib.Path(rel).suffix.lower() in _LOCAL_STUB_SCANNABLE_EXTS
            and rel not in seen
        ):
            seen.add(rel)
            from_violations.append(rel)
    if from_violations:
        return from_violations
    return [
        f.replace("\\", "/")
        for f in file_list
        if pathlib.Path(f).suffix.lower() in _LOCAL_STUB_SCANNABLE_EXTS
    ]


def local_stub_insertions_from_checkout(
    source_dir: str,
    file_list: List[str],
    violations: List[Dict[str, Any]],
    *,
    lineaje_pat: str = "",
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Scan the GHA checkout with insertion_point_scanner and apply stubs.

    Replaces the old ``gha_stub_insertion`` import, which required this
    repo's full ``pipeline/stub`` package — never present on a customer
    runner. Returns the same ``(validated_fixes, failed, fix_table)`` shape
    ``_execute_scan`` uses for the MCP-provided stub_insertions path.
    """
    _ensure_insertion_point_scanner_on_path()
    from insertion_point_scanner import scan_project as _scan_project_local
    from insertion_point_scanner import _import_hint as _local_import_hint

    targets = _scannable_files_for_local_stubs(violations, file_list, source_dir)
    if not targets:
        logger.info("Local insertion-point scan: no scannable files in checkout")
        return {}, [], []
    if len(targets) > _LOCAL_STUB_MAX_FILES:
        logger.warning(
            "Local insertion-point scan: capping %d scannable file(s) to %d",
            len(targets), _LOCAL_STUB_MAX_FILES,
        )
        targets = targets[:_LOCAL_STUB_MAX_FILES]

    candidates, _mw = _scan_project_local(
        project_root=source_dir,
        files_to_scan=targets,
        lineaje_pat=lineaje_pat or "",
        max_files=max(len(targets), 1),
    )
    stub_insertions: List[Dict[str, Any]] = []
    for c in candidates:
        rel = _rel_candidate_file(c.file, source_dir)
        stub_insertions.append({
            "file": rel,
            "line": c.line,
            "status": "detected",
            "proposed_stub": c.proposed_stub,
            "insert_after": c.insert_after,
            "safe_to_insert": c.safe_to_insert,
            "skip_reason": c.skip_reason,
            "description": c.description,
            "import_needed": _local_import_hint(os.path.splitext(rel)[1]),
        })
    validated, failed = apply_stub_insertions_to_clone(stub_insertions, source_dir)
    fix_table = [
        {
            "policy": "guardrail_stub",
            "description": (s.get("description") or "")[:200],
            "file": s.get("file", ""),
        }
        for s in stub_insertions
        if s.get("status") == "detected" and (s.get("file") or "") in validated
    ]
    logger.info(
        "Local insertion-point scan: %d candidate(s) found, %d file(s) applied",
        len(candidates), len(validated),
    )
    return validated, failed, fix_table


def try_local_stub_insertions_from_checkout(
    source_dir: str,
    file_list: List[str],
    violations: List[Dict[str, Any]],
    *,
    lineaje_pat: str = "",
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]], Optional[str]]:
    """Fail-open wrapper: a missing scanner must not abort the GHA scan."""
    try:
        validated, failed, table = local_stub_insertions_from_checkout(
            source_dir, file_list, violations, lineaje_pat=lineaje_pat,
        )
        return validated, failed, table, None
    except Exception as exc:
        logger.exception("Local stub insertion failed")
        return {}, [], [], f"Local stub insertion failed: {exc}"


# ===========================================================================
# Parallel batch scan
# ===========================================================================

def parallel_batch_scan(
    batches: List[List[str]],
    source_dir: str,
    temp_dir: str,
    source_code_repo: str,
    branch: str,
    head_sha: str,
    run_id: str,
    server_url: str,
    bearer_getter: Callable[[], str],
    manifest_files: Optional[List[str]] = None,
    max_workers: int = MAX_SCAN_WORKERS,
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, str]], int, List[str], str, List[Dict[str, Any]]]:
    all_violations: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    all_aibom: List[Dict[str, str]] = []
    aibom_seen: set = set()
    failed_batch_count = 0
    failure_details: List[str] = []
    enforce_service_url = ""
    all_stub_insertions: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def _scan_one(batch_idx: int, batch_files: List[str]) -> Tuple[int, Dict[str, Any]]:
        logger.info("Batch %d/%d: %d files", batch_idx, len(batches), len(batch_files))
        archive_path = create_batch_archive(
            source_dir, temp_dir, batch_files,
            source_code_repo, branch, head_sha, batch_idx, run_id=run_id,
            manifest_files=manifest_files,
        )
        result = run_mcp_scan(
            server_url, bearer_getter, source_code_repo, branch, batch_files, archive_path, head_sha=head_sha,
        )
        return batch_idx, result

    def _collect(batch_idx: int, mcp_result: Dict[str, Any]) -> None:
        nonlocal enforce_service_url
        err = (mcp_result.get("error") or "").strip()
        if mcp_result.get("success") is False or err:
            raise RuntimeError(err or f"analyze_uploaded_archive failed: {mcp_result}")
        batch_violations = list(mcp_result.get("violations") or [])
        # Older servers emptied remediations and did not yet return violations —
        # keep a file-only fallback so we can still insert stubs.
        if not batch_violations:
            batch_violations = [
                {k: v for k, v in a.items() if k != "fix_code"}
                for a in (mcp_result.get("remediation_actions") or [])
                if a.get("file")
            ]
        batch_report = mcp_result.get("report", "")
        batch_aibom = mcp_result.get("aibom", [])
        batch_enforce = (mcp_result.get("enforce_service_url") or "").strip()
        batch_stub_insertions = _stub_insertions_from_mcp_result(mcp_result)
        logger.info(
            "Batch %d/%d done: status=%s violations=%d aibom=%d enforce=%s stub_insertions=%d",
            batch_idx, len(batches), mcp_result.get("status", "unknown"),
            len(batch_violations), len(batch_aibom),
            batch_enforce or "(none)", len(batch_stub_insertions),
        )
        with lock:
            all_violations.extend(batch_violations)
            if batch_enforce:
                enforce_service_url = batch_enforce
            if batch_report:
                all_reports.append(batch_report)
            for entry in batch_aibom:
                key = (entry.get("name", ""), entry.get("source_file", ""))
                if key not in aibom_seen:
                    aibom_seen.add(key)
                    all_aibom.append(entry)
            all_stub_insertions.extend(batch_stub_insertions)

    workers = min(len(batches), max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_scan_one, idx, files): idx for idx, files in enumerate(batches, 1)}
        for future in as_completed(future_map):
            batch_idx = future_map[future]
            try:
                _, mcp_result = future.result()
                _collect(batch_idx, mcp_result)
            except BaseException as exc:
                failed_batch_count += 1
                # Unwrap ExceptionGroup / TaskGroup to surface the real cause
                cause = exc
                if hasattr(exc, "exceptions") and exc.exceptions:
                    cause = exc.exceptions[0]
                    if hasattr(cause, "exceptions") and cause.exceptions:
                        cause = cause.exceptions[0]
                detail = f"Batch {batch_idx}/{len(batches)} failed: {type(cause).__name__}: {cause}"
                logger.error("%s", detail)
                logger.debug("Full exception:", exc_info=exc)
                failure_details.append(detail)

    return all_violations, all_reports, all_aibom, failed_batch_count, failure_details, enforce_service_url, all_stub_insertions

# ===========================================================================
# JSON output
# ===========================================================================

def build_json_output(
    *,
    status: str,
    repo: str,
    branch: str,
    head_sha: str,
    source_code_repo: str,
    files_scanned: int,
    batches: int,
    failed_batches: int,
    violations: List[Dict[str, Any]],
    aibom: Optional[List[Dict[str, str]]] = None,
    report: str = "",
    remediation_pr: Optional[int] = None,
    remediation_branch: str = "",
    failed_remediation_files: Optional[List[str]] = None,
    scan_errors: Optional[List[str]] = None,
    enforce_service_url: str = "",
) -> Dict[str, Any]:
    return {
        "status": status,
        "scan_metadata": {
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "source_code_repo": source_code_repo,
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": files_scanned,
            "batches": batches,
            "failed_batches": failed_batches,
        },
        "report": report,
        "violations": violations,
        "aibom": aibom or [],
        "enforce_service_url": enforce_service_url,
        "remediation_pr": remediation_pr,
        "remediation_branch": remediation_branch,
        "failed_remediation_files": failed_remediation_files or [],
        "scan_errors": scan_errors or [],
    }


def _violation_line_display(v: Dict[str, Any]) -> str:
    """1-indexed source line(s) for a finding, or em-dash when unknown."""
    nums: List[int] = []
    seen: set = set()

    def _add(raw: Any) -> None:
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return
        if n > 0 and n not in seen:
            seen.add(n)
            nums.append(n)

    vcs = v.get("violating_code")
    if isinstance(vcs, list):
        for vc in vcs:
            if isinstance(vc, dict):
                _add(vc.get("line"))
            else:
                _add(getattr(vc, "line", 0))
    meta = v.get("metadata") if isinstance(v.get("metadata"), dict) else {}
    _add(v.get("line"))
    _add(v.get("line_number"))
    _add(meta.get("line_number"))
    if not nums:
        return "—"
    return ", ".join(str(n) for n in nums)


def _violation_file_line_and_control(v: Dict[str, Any]) -> Tuple[str, str, str]:
    vcs = v.get("violating_code") or []
    first_vc = vcs[0] if vcs and isinstance(vcs[0], dict) else {}
    file_ = v.get("file") or first_vc.get("filename") or "(unknown)"
    control = v.get("policy_name") or v.get("control") or v.get("policy_id") or "(unknown)"
    return str(file_), _violation_line_display(v), str(control)


def format_violations_markdown_table(
    violations: List[Dict[str, Any]],
    *,
    max_files: int = 0,
) -> str:
    """GitHub-flavored Markdown table: File | Line | Policy (one row per finding)."""
    rows: List[Tuple[str, str, str]] = []
    files: set = set()
    for v in violations:
        file_, line, control = _violation_file_line_and_control(v)
        files.add(file_)
        rows.append((file_, line, control))
    if not rows:
        return ""

    def _line_sort_key(line: str) -> int:
        if not line or line == "—":
            return 0
        try:
            return int(str(line).split(",", 1)[0].strip())
        except ValueError:
            return 0

    rows.sort(key=lambda r: (r[0], _line_sort_key(r[1]), r[2]))
    extra = 0
    if max_files and len(rows) > max_files:
        extra = len(rows) - max_files
        rows = rows[:max_files]
    lines = [
        f"**{len(violations)} violation(s) across {len(files)} file(s)**",
        "",
        "| File | Line | Policy |",
        "|------|------|--------|",
    ]
    for file_, line, control in rows:
        lines.append(f"| `{file_}` | {line} | {control} |")
    if extra:
        lines.append(f"| _…and {extra} more violation(s)_ | — | _see full scan report_ |")
    return "\n".join(lines)


def _extract_markdown_section(report: str, heading_substr: str) -> str:
    """Return the ``### …`` section whose heading contains *heading_substr*."""
    if not report or not heading_substr:
        return ""
    lines = report.splitlines()
    start: Optional[int] = None
    for i, line in enumerate(lines):
        if line.startswith("### ") and heading_substr in line:
            start = i
            break
    if start is None:
        return ""
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("### "):
            end = j
            break
    return "\n".join(lines[start:end]).strip()


def _clip_github_report(report: str, max_chars: int = 40_000) -> str:
    """Trim a markdown chunk to *max_chars*; close dangling fences."""
    text = (report or "").strip()
    if not text:
        return ""
    if len(text) <= max_chars:
        clipped = text
        truncated = False
    else:
        budget = max(0, max_chars - len(_PR_BODY_TRUNCATION_NOTE))
        clipped = text[:budget]
        truncated = True
    if clipped.count("```") % 2 == 1:
        clipped += "\n```\n"
    if truncated:
        clipped += _PR_BODY_TRUNCATION_NOTE
    return clipped


def _fit_github_pr_body(text: str, max_chars: int = GITHUB_PR_BODY_SAFE_LIMIT) -> str:
    """Hard-cap a PR body so GitHub's 65536-char POST /pulls does not 422."""
    text = text or ""
    if len(text) <= max_chars:
        return text
    note = _PR_BODY_TRUNCATION_NOTE
    fence = "\n```\n"
    budget = max(0, max_chars - len(note))
    clipped = text[:budget]
    if clipped.count("```") % 2 == 1:
        budget = max(0, max_chars - len(note) - len(fence))
        clipped = text[:budget] + fence
    return clipped + note


def _build_fix_pr_body(
    *,
    branch: str,
    sha_short: str,
    report: str = "",
    violations: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """PR description: UnifAI report first, full scan report folded. Stub files are
    on the branch itself — they are not listed in this body."""
    violations = violations or []
    if "## No Files Changed" in (report or ""):
        report = ""
    report_says_violations = "violations_found" in (report or "")
    status_label = "❌ Not Compliant" if (violations or report_says_violations) else "✅ Compliant"
    lines: List[str] = [
        "# UnifAI Security Report",
        "",
        f"**Status:** {status_label}",
        f"**Branch:** `{branch}`",
        f"**Commit:** `{sha_short}`",
        "",
    ]
    vtable = format_violations_markdown_table(violations, max_files=40)
    if vtable:
        lines += [vtable, ""]
    elif not violations and not report_says_violations:
        lines += ["No violations found.", ""]

    prefix_len = len("\n".join(lines))
    remaining = GITHUB_PR_BODY_SAFE_LIMIT - prefix_len - 400

    policy_section = _extract_markdown_section(report, "SECTION 2: Policy Violations")
    if policy_section and remaining > 500:
        section_budget = min(8_000, max(500, remaining // 4))
        lines += ["---", "", _clip_github_report(policy_section, max_chars=section_budget), ""]
        remaining -= section_budget

    if report and report.strip() and remaining > 500:
        lines += [
            "---",
            "",
            "<details>",
            "<summary><strong>Full scan report</strong></summary>",
            "",
            _clip_github_report(report, max_chars=remaining),
            "",
            "</details>",
        ]
    return _fit_github_pr_body("\n".join(lines))


def print_human_output(output: Dict[str, Any]) -> None:
    status = output.get("status", "unknown")
    violations = output.get("violations", [])
    scan_errors = output.get("scan_errors", [])
    metadata = output.get("scan_metadata", {})
    scanned_at = metadata.get("scanned_at", "")
    branch = metadata.get("branch", "")
    repo = metadata.get("repo") or ""
    rem_pr = output.get("remediation_pr")
    rem_branch = output.get("remediation_branch") or ""

    if status == "compliant":
        status_label = "✅ Compliant"
    elif status == "violations_found":
        status_label = "❌ Not Compliant"
    else:
        status_label = status

    print("# UnifAI Security Report")
    print()
    print(f"**Status:** {status_label}")
    if branch:
        print(f"**Branch:** `{branch}`")
    if scanned_at:
        print(f"**Scanned at:** {scanned_at}")
    if rem_pr:
        print(f"**Remediation PR:** https://github.com/{repo}/pull/{rem_pr}")
    elif rem_branch:
        print(f"**Remediation branch:** `{rem_branch}` (PR was not opened automatically)")

    if scan_errors:
        print("\n**Errors:**")
        for err in scan_errors:
            print(f"- {err}")
        print()

    if not violations:
        if status == "compliant":
            print("\nNo violations found.")
        return

    print()
    print(format_violations_markdown_table(violations, max_files=40))


# ===========================================================================
# Patch application (ported from veracode_repo_scan.py, no external deps)
# ===========================================================================

def _normalize_for_patch_match(s: str) -> str:
    return re.sub(r"[ \t]+", " ", s)


def _apply_fix_entry(content: str, original: str, replacement: str) -> Tuple[str, bool]:
    if not original:
        return content, False

    if original in content:
        return content.replace(original, replacement, 1), True

    orig_stripped = original.strip()
    if orig_stripped and orig_stripped in content:
        return content.replace(orig_stripped, replacement, 1), True

    norm_orig = _normalize_for_patch_match(orig_stripped)
    norm_content = _normalize_for_patch_match(content)
    idx = norm_content.find(norm_orig)
    if idx != -1:
        orig_len = len(orig_stripped)
        real_idx = 0
        norm_walked = 0
        for ci, ch in enumerate(content):
            if norm_walked >= idx:
                real_idx = ci
                break
            norm_walked += len(_normalize_for_patch_match(ch))
        else:
            real_idx = len(content)
        sub = content[real_idx: real_idx + orig_len + 50]
        if orig_stripped in sub:
            actual_idx = content.find(orig_stripped, real_idx)
            if actual_idx != -1:
                return content[:actual_idx] + replacement + content[actual_idx + len(orig_stripped):], True

    orig_lines = [l for l in orig_stripped.splitlines() if l.strip()]
    if orig_lines:
        anchor = orig_lines[0].strip()
        if len(anchor) > 15:
            anchor_idx = content.find(anchor)
            if anchor_idx != -1:
                end_search = content.find(orig_lines[-1].strip(), anchor_idx) if len(orig_lines) > 1 else anchor_idx
                if end_search != -1:
                    end_idx = end_search + len(orig_lines[-1].strip())
                    found_block = content[anchor_idx:end_idx]
                    if len(found_block) < len(orig_stripped) * 2:
                        return content[:anchor_idx] + replacement + content[end_idx:], True

    return content, False


def _norm_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def _resolve_source_file(source_dir: str, filepath: str, file_list: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a violation filepath to (rel_path, content) from the live checkout."""
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_rel_path(raw)
    root = pathlib.Path(source_dir)

    candidate = root / raw
    if candidate.is_file():
        return norm_fp, candidate.read_text(errors="replace")

    # Try normalised path
    candidate2 = root / norm_fp
    if candidate2.is_file():
        return norm_fp, candidate2.read_text(errors="replace")

    # Basename fallback
    base = pathlib.Path(norm_fp).name
    matches = [f for f in file_list if pathlib.Path(f).name == base]
    if len(matches) == 1:
        full = root / matches[0]
        if full.is_file():
            return _norm_rel_path(matches[0]), full.read_text(errors="replace")

    logger.warning("Cannot resolve remediation file %r in source dir", raw)
    return None, None


def apply_pipeline_fix_code_to_clone(
    remediation_actions: List[Dict[str, Any]],
    source_dir: str,
    file_list: List[str],
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Apply fix_code patches from MCP remediation_actions to checked-out files.

    Returns (validated_fixes, failed_files, fix_table_rows).
    """
    validated_fixes: Dict[str, str] = {}
    failed_files: List[str] = []
    fix_table_rows: List[Dict[str, str]] = []

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for action in remediation_actions:
        fp = (action.get("file") or "").strip()
        if fp:
            by_file.setdefault(fp, []).append(action)

    for filepath, actions in by_file.items():
        has_fix_code = any(action.get("fix_code") for action in actions)
        if not has_fix_code:
            failed_files.append(filepath)
            continue

        rel_path, original_content = _resolve_source_file(source_dir, filepath, file_list)
        if rel_path is None or original_content is None:
            failed_files.append(filepath)
            continue

        content = original_content
        patch_applied = False
        for action in actions:
            for fix_entry in (action.get("fix_code") or []):
                original = fix_entry.get("original") or ""
                replacement = fix_entry.get("replacement", "")
                if not original.strip():
                    continue
                content, applied = _apply_fix_entry(content, original, replacement)
                if applied:
                    patch_applied = True
                else:
                    logger.debug(
                        "Patch not applied for %r — original snippet (%d chars) not found",
                        filepath, len(original),
                    )

        if patch_applied and content != original_content:
            validated_fixes[rel_path] = content
            for action in actions:
                fix_table_rows.append({
                    "policy": action.get("control", ""),
                    "description": (action.get("instruction") or "")[:200],
                    "file": filepath,
                })
        else:
            logger.warning("No patch applied for %r — snippets did not match file content", filepath)
            failed_files.append(filepath)

    return validated_fixes, failed_files, fix_table_rows


# ===========================================================================
# Remediation PR creation
# ===========================================================================

def _create_fix_pr(
    github_token: str,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
    violations: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Optional[int], str, str]:
    """Commit stub + enforce-API files to a branch and open a PR.

    Returns ``(pr_number_or_None, remediation_branch, error_or_empty)``.
    """
    try:
        import sys as _sys
        import os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
        from scm_client import GitHubClient  # type: ignore
    except ImportError:
        logger.error("scm_client.py not found — cannot create remediation PR")
        return None, "", "scm_client.py not found — cannot create remediation PR"

    if not validated_fixes:
        return None, "", ""

    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)
    sha_short = head_sha[:7]
    timestamp = time.strftime("%m%d%H%M")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}-{safe_branch.replace('/', '-')}-{sha_short}-{timestamp}"

    scm = GitHubClient(token=github_token)

    # Resolve short SHA to full 40-char SHA (GitHub's /git/refs API requires it)
    if len(head_sha) < 40:
        try:
            commit_data = scm._request("GET", f"/repos/{repo}/commits/{head_sha}")
            head_sha = commit_data["sha"]
        except Exception as exc:
            logger.warning("Could not resolve short SHA %s: %s", head_sha, exc)

    try:
        logger.info("Creating remediation branch %s from %s", remediation_branch, sha_short)
        scm.create_branch(repo, remediation_branch, head_sha)
    except Exception as exc:
        logger.error("Failed to create/verify remediation branch: %s", exc)
        return None, remediation_branch, f"Failed to create remediation branch: {exc}"

    committed: List[str] = []
    for filepath, content in validated_fixes.items():
        blob_sha: Optional[str] = None
        try:
            blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
        except Exception:
            pass
        policies = ", ".join({r["policy"] for r in fix_table if r["file"] == filepath}) or "policy violations"
        message = f"fix({filepath}): remediate {policies} [unifai-gha-scan]"
        try:
            scm.commit_file(repo, remediation_branch, filepath, content.encode("utf-8"), message, sha=blob_sha)
            committed.append(filepath)
            logger.info("Committed fix: %s", filepath)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", filepath, exc)

    if not committed:
        logger.warning("No files committed — skipping PR creation")
        return None, remediation_branch, "No files committed — skipping PR creation"

    title = f"[unifai-bot] chore: insert guardrail stubs for {branch}@{sha_short}"
    pr_body = _build_fix_pr_body(
        branch=branch,
        sha_short=sha_short,
        report=report,
        violations=violations,
    )
    logger.info(
        "PR body: %d chars, report=%s, violations=%d",
        len(pr_body), "yes" if (report or "").strip() else "no", len(violations or []),
    )

    try:
        pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, pr_body)
        logger.info("Created remediation PR #%d", pr_number)
        return pr_number, remediation_branch, ""
    except Exception as exc:
        logger.error("Failed to create remediation PR (%d chars): %s", len(pr_body), exc)
        fallback = _build_fix_pr_body(
            branch=branch,
            sha_short=sha_short,
            report="",
            violations=[],
        )
        try:
            pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, fallback)
            logger.warning(
                "Created remediation PR #%d with fallback body after: %s", pr_number, exc,
            )
            return pr_number, remediation_branch, ""
        except Exception as exc2:
            logger.error("Fallback PR creation also failed: %s", exc2)
            return (
                None,
                remediation_branch,
                f"Failed to create remediation PR for `{remediation_branch}`: {exc2}",
            )


# ===========================================================================
# Main scan orchestration
# ===========================================================================

def _execute_scan(args: argparse.Namespace) -> int:
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "")
    head_sha = args.head_sha or os.environ.get("GITHUB_SHA", "")
    source_path = os.path.abspath(args.source_path)
    server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL
    source_code_repo = f"https://github.com/{repo}.git" if repo else source_path

    # Validate config
    missing = [n for n, v in [("GITHUB_REPOSITORY / --repo", repo), ("GITHUB_REF_NAME / --branch", branch)] if not v]
    if missing:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Missing required config: {', '.join(missing)}"],
        )
        print_human_output(output)
        return 2

    try:
        bearer_getter = build_bearer_getter(_scan_refresh_token(args))
        # Eagerly exchange the refresh token so a bad/expired token fails
        # here instead of after a full scan. Do not PAT-introspect it.
        access_token = bearer_getter()
        jwt_tenant_id = _tenant_id_from_access_jwt(access_token)
        if jwt_tenant_id:
            os.environ.setdefault("GR_TENANT_ID", jwt_tenant_id)
            os.environ.setdefault("LINEAJE_TENANT_ID", jwt_tenant_id)
            logger.info("Auth OK — tenant_id=%s from access JWT (no PAT introspect)", jwt_tenant_id)
        else:
            jwt_tenant_id = os.environ.get("GR_TENANT_ID") or os.environ.get("LINEAJE_TENANT_ID") or ""
            logger.info("Auth OK — renew-access-token exchange succeeded (token len=%d)", len(access_token))
    except Exception as exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Auth failed: {exc}"],
        )
        print_human_output(output)
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    scan_start = time.perf_counter()

    logger.info("Scanning source path: %s (repo=%s branch=%s sha=%s)", source_path, repo, branch, head_sha[:7] if head_sha else "?")

    # Step 1: Collect files
    file_list = collect_repo_files(source_path)
    if not file_list:
        logger.info("No scannable files found")
        output = build_json_output(
            status="compliant", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
        )
        print_human_output(output)
        return 0

    manifest_files = [f for f in file_list if _is_manifest_file(os.path.basename(f))]
    code_files = [f for f in file_list if not _is_manifest_file(os.path.basename(f))]
    scan_files = code_files if code_files else file_list
    batch_size = _batch_size(len(scan_files))
    batches = [scan_files[i: i + batch_size] for i in range(0, len(scan_files), batch_size)]
    logger.info(
        "Files: %d total (%d code, %d manifest) → %d batch(es) of ≤%d",
        len(file_list), len(code_files), len(manifest_files), len(batches), batch_size,
    )

    # Step 2: MCP scan
    with tempfile.TemporaryDirectory(prefix="gha-repo-scan-") as temp_dir:
        (
            all_violations, all_reports, all_aibom, failed_batches_count,
            failure_details, enforce_service_url, all_stub_insertions,
        ) = parallel_batch_scan(
            batches=batches,
            source_dir=source_path,
            temp_dir=temp_dir,
            source_code_repo=source_code_repo,
            branch=branch,
            head_sha=head_sha,
            run_id=run_id,
            server_url=server_url,
            bearer_getter=bearer_getter,
            manifest_files=manifest_files or None,
        )

    elapsed = time.perf_counter() - scan_start
    logger.info(
        "Scan complete in %.1fs: %d violation(s), %d AIBOM entry/ies, %d failed batch(es)",
        elapsed, len(all_violations), len(all_aibom), failed_batches_count,
    )

    combined_report = _combine_scan_reports(all_reports)

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details, enforce_service_url=enforce_service_url,
        )
        print_human_output(output)
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    # Step 3: Insert guardrail stubs and create PR.
    # Prefer MCP stub_insertions / patched_files. If --create-fix-pr is set
    # but the server returned nothing applyable, insert locally from
    # violations so a PR still opens. Do NOT apply remediation_actions.
    remediation_pr_number: Optional[int] = None
    remediation_branch = ""
    failed_rem_files: List[str] = []

    github_token = (
        getattr(args, "github_token", None)
        or os.environ.get("GH_TOKEN", "")
        or os.environ.get("GITHUB_TOKEN", "")
    )
    should_create_pr = bool(github_token and getattr(args, "create_fix_pr", False))
    validated_fixes: Dict[str, str] = {}
    fix_table: List[Dict[str, str]] = []

    if all_stub_insertions:
        logger.info(
            "STEP 3: Applying %d MCP stub insertion(s)",
            len(all_stub_insertions),
        )
        validated_fixes, failed_rem_files = apply_stub_insertions_to_clone(
            all_stub_insertions, source_path,
        )
        fix_table = [
            {
                "policy": ", ".join(
                    {pd.get("policy_id", "") for pd in (s.get("policy_details") or []) if pd.get("policy_id")}
                ) or "guardrail_stub",
                "description": s.get("description", "")[:200],
                "file": s.get("file", ""),
            }
            for s in all_stub_insertions
            if s.get("status") == "detected" and (s.get("file") or "") in validated_fixes
        ]

    if should_create_pr and not validated_fixes and all_violations:
        # Legacy fallback here used to import `gha_stub_insertion`, which
        # required this repo's full pipeline/stub/guardrail_stub_insertion.py
        # package on the runner — never true for a truly standalone script
        # (only this file + insertion_point_scanner.py are deployed into a
        # customer's .lineaje-scanner/scripts/), so it always threw
        # ModuleNotFoundError here and silently skipped the fix PR. Replaced
        # with a local scan via insertion_point_scanner.scan_project() — the
        # same deterministic candidate detector analyze_uploaded_archive uses
        # server-side — feeding its output through apply_stub_insertions_to_clone()
        # above (same function, same validated-Python-syntax guarantee) so this
        # path and the MCP-provided one behave identically.
        logger.info(
            "MCP returned 0 applyable stubs; scanning locally for insertion points "
            "so --create-fix-pr can open a PR (%d violation(s) found)",
            len(all_violations),
        )
        validated_fixes, failed_rem_files, fix_table, local_err = (
            try_local_stub_insertions_from_checkout(
                source_path, file_list, all_violations,
                lineaje_pat=_scan_refresh_token(args),
            )
        )
        if local_err:
            failure_details.append(local_err)

    if should_create_pr and validated_fixes:
        logger.info("Creating stub PR (%d file(s))", len(validated_fixes))
        try:
            remediation_pr_number, remediation_branch, pr_error = _create_fix_pr(
                github_token, repo, branch, head_sha,
                validated_fixes, fix_table,
                report=combined_report, failed_files=failed_rem_files,
                violations=all_violations,
            )
            if pr_error:
                failure_details.append(pr_error)
        except Exception as exc:
            logger.error("Stub insertion / PR step failed: %s", exc)
            failure_details.append(f"Stub insertion / PR step failed: {exc}")
    elif should_create_pr:
        logger.warning(
            "Skipping stub PR — --create-fix-pr was set but there were no stub files "
            "to commit (mcp stub_insertions=%d violations=%d)",
            len(all_stub_insertions), len(all_violations),
        )
    elif all_stub_insertions and not getattr(args, "create_fix_pr", False):
        logger.info("Skipping stub PR — pass --create-fix-pr to insert stubs and open a PR")
    elif all_stub_insertions:
        logger.info("Skipping stub PR — GITHUB_TOKEN / --github-token not set")

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        remediation_pr=remediation_pr_number,
        remediation_branch=remediation_branch,
        failed_remediation_files=failed_rem_files,
        scan_errors=failure_details,
        enforce_service_url=enforce_service_url,
    )
    print_human_output(output)
    return 0

# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lineaje AI Policy Scanner — GitHub Actions edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--source-path", default=".",
        help="Path to the checked-out source code (default: current directory)",
    )
    parser.add_argument(
        "--repo", default="",
        help="Repository owner/repo slug (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--branch", default="",
        help="Branch name (default: $GITHUB_REF_NAME)",
    )
    parser.add_argument(
        "--head-sha", default="",
        help="Commit SHA (default: $GITHUB_SHA)",
    )
    parser.add_argument(
        "--mcp-server-url", default="",
        help=f"MCP server URL (default: {MCP_SERVER_URL})",
    )
    parser.add_argument(
        "--github-token", default="",
        help="GitHub token for creating remediation PRs (default: $GH_TOKEN then $GITHUB_TOKEN). "
             "If not set, violations are reported but no PR is created.",
    )
    parser.add_argument(
        "--lineaje-pat", default="", dest="lineaje_pat",
        help="Lineaje PAT / refresh token for MCP auth (default: $LINEAJE_PAT_TOKEN). "
             "Inserted guardrail stubs read their own auth from GR_BEARER_TOKEN / "
             "LINEAJE_PAT_TOKEN / LINEAJE_PAT at the customer's own runtime — this "
             "flag only authenticates THIS scan's MCP calls.",
    )
    parser.add_argument(
        "--refresh-token", default="", dest="refresh_token",
        help="Alias for --lineaje-pat.",
    )
    parser.add_argument(
        "--create-fix-pr", default=False, action="store_true",
        help="Create a PR that inserts guardrail stubs and enforce-API config "
             "into the customer codebase (default: false). Does not apply "
             "remediation_actions / fix_code comments.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Always show INFO from this logger regardless of --debug
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print_human_output(err)
        return 1


if __name__ == "__main__":
    sys.exit(main())
