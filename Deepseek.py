#!/usr/bin/env python3
"""
Deepseek.py — Smart local relay server for the apmix chat page.

WHAT THIS DOES
    * Serves Deepseek.html at http://localhost:1000 (auto-picks next free port)
    * Relays /v1/* to the upstream API (your keys never leave your machine)
    * /v1/chat/completions — SMART parameter handling:
        - Auto-strips rejected parameters server-side (400 errors = no tokens wasted)
        - Remembers which params each model rejects (cached per model+host)
        - Retries automatically without the bad parameter
    * /smart-models — enriched model list with free/paid detection
        - NO live probe (no chat tokens consumed)
        - Uses name heuristics + provider metadata + known free model catalog
    * /model-info/<model> — detailed model metadata without any chat calls
    * /search  — web search (Tavily if a key is set, else DuckDuckGo)
    * /fs/*    — filesystem tools used by "agent mode"
    * /fs/disks — lists the drives / roots on this machine

TOKEN SAFETY
    * Parameter auto-strip only fires on 400/422 errors — these do NOT
      consume tokens because the request was rejected before inference.
    * Free model detection uses ONLY /models metadata (GET request, no
      inference tokens) and name pattern matching.

RUN
    python Deepseek.py        (Windows)
    python3 Deepseek.py       (macOS / Linux)
"""

import fnmatch
import hashlib
import http.client
import io
import ipaddress
import html as html_mod
import json
import os
import re
import string
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ------------------------------------------------------------------ config
UPSTREAM = "https://api.apmix.ai/v1"
FOLDER = os.path.dirname(os.path.abspath(__file__))
BASE_PORT = 1000
PORT_TRIES = 40

ALLOWED_UPSTREAM_HOSTS = {
    "api.apmix.ai",
    "api.deepseek.com",
    "api.openai.com",
    "api.anthropic.com",
    "openrouter.ai",
    "api.groq.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.cohere.com",
    "api.together.xyz",
    "api.deepinfra.com",
    "api.fireworks.ai",
    "api.novita.ai",
    "api.x.ai",
    "api.moonshot.cn",
    "api.moonshot.ai",
    "api.siliconflow.cn",
    "api.siliconflow.com",
    "dashscope.aliyuncs.com",
    "dashscope-intl.aliyuncs.com",
    "open.bigmodel.cn",
    "api.lingyiwanwu.com",
    "generativelanguage.googleapis.com",
    "api.stepfun.ai",
    "api.stepfun.com",
    "ark.cn-beijing.volces.com",
    "api.hunyuan.cloud.tencent.com",
    "api.baiduqianfan.ai",
    "qianfan.baidubce.com",
    "api.baichuan-ai.com",
    "api.minimaxi.com",
    "api.minimaxi.io",
    "opencode.ai",
    "api.cheaperinference.com",
    "api.cerebras.ai",
    "api.sambanova.ai",
    "api.reka.ai",
    "api.perplexity.ai",
    "api.ai21.com",
    "api.aleph-alpha.com",
    "api.upstage.ai",
    "api.writer.com",
    "api.nomic.ai",
    "api.voyageai.com",
    "api.jina.ai",
    "api.endpoints.anyscale.com",
    "api.studio.nebius.ai",
    "api.hyperbolic.xyz",
    "api.lepton.run",
    "router.huggingface.co",
    "api.replicate.com",
    "api.cloudflare.com",
    "ollama.com",
    "aiplatform.googleapis.com",
    "router.bynara.id",
    "tokenharbor.ai",
    "api.unorouter.com"
}

# Per-run token injected into the served page
LOCAL_TOKEN = os.urandom(24).hex()

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__",
    ".venv", "venv", "env", "dist", "build", "out", "target",
    ".next", ".nuxt", ".svelte-kit", ".cache", ".idea", ".vscode",
    ".gradle", ".terraform", "coverage", ".mypy_cache", ".pytest_cache",
}

SEARCH_SKIP_DIRS = SKIP_DIRS | {
    "windows", "program files", "program files (x86)", "programdata",
    "$recycle.bin", "system volume information", "appdata", "msocache",
    "recovery", "perflogs", "proc", "sys", "dev", "run", "tmp",
    "lost+found", "snap",
}

# ═══════════════════════════════════════════════════════════════════════
# AGENT SAFETY — hard server-side restrictions (safe write mode)
# ═══════════════════════════════════════════════════════════════════════

# Filesystem operations the agent is ALLOWED to use.
# shell is deliberately absent — it is permanently disabled.
AGENT_ALLOWED_OPS = frozenset({
    "list", "read", "search", "disks",
    "write", "patch", "mkdir",  # shell still absent
})

# Path fragments that are NEVER readable, writable, or searchable —
# even inside the workspace, even with full-disk access on.
# Matched case-insensitively against the full resolved path.
BLOCKED_PATH_FRAGMENTS = [
    # ── system / OS ──────────────────────────────────────────────
    "windows\\system32", "windows/syswow64", "/boot", "/etc/passwd",
    "/etc/shadow", "/etc/sudoers", "pagefile.sys", "hiberfil.sys",
    "swapfile.sys", "win.ini", "system.ini", "/kernel", "/mach_kernel",
    # ── credentials & keys ───────────────────────────────────────
    ".ssh", ".gnupg", ".gpg", ".aws", ".azure", ".gcloud",
    ".docker/config", ".kube", ".vault", ".terraform.d",
    ".env", ".env.", "credentials", "_credentials",
    "secrets", "secret_", "passwords", "passwd",
    ".pem", ".key", ".p12", ".pfx", ".crt", ".der",
    "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys",
    "known_hosts", "webproxy.pac",
    ".envrc",
    # ── browsers (cookies, saved logins, history) ────────────────
    "appdata\\local\\google\\chrome", "appdata\\roaming\\mozilla",
    ".mozilla/firefox", ".config/google-chrome", ".config/chromium",
    "application support/google/chrome", "application support/firefox",
    "login data", "cookies.sqlite", "cookies.db", "places.sqlite",
    "web data", "form history", "key4.db", "logins.json",
    # ── password managers & wallets ──────────────────────────────
    ".kdbx", "keepass", "1password", "bitwarden", "lastpass",
    ".password-store", "wallet.dat", ".bitcoin", ".ethereum",
    ".metamask", "keystore",
    # ── shell history & RC files (often contain secrets) ─────────
    ".bash_history", ".zsh_history", ".sh_history",
    "psreadline", "consolehost_history.txt",
    ".netrc", ".ftpconfig",
    # ── this app's own settings (contains API keys) ──────────────
    "apmix_settings", "deepseek.py", "deepseek.html",
]

# Extensions that are blocked from READ even if the path looks clean.
BLOCKED_READ_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".crt", ".der", ".cer",
    ".kdbx", ".keystore", ".jks", ".env",
    ".secret", ".credentials",
    ".gpg",
}

# Extensions the agent may WRITE to. Anything else is refused.
AGENT_WRITABLE_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".rst",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".jsonc",
    ".html", ".css", ".scss", ".less",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".rs", ".go",
    ".java", ".kt", ".swift", ".rb", ".php", ".lua", ".pl",
    ".sql", ".csv", ".tsv", ".xml",
    ".gitignore", ".dockerignore", ".editorconfig",
    "dockerfile", "makefile", "cmakelists.txt",
}

# Directory where backups are stored (inside workspace root).
# The agent cannot read from or write to this directory.
BACKUP_DIR_NAME = ".apmix_backups"

# Maximum content size the agent may write in one operation.
MAX_WRITE_BYTES = 2_000_000  # 2 MB

# How many backups to keep per file before pruning old ones.
MAX_BACKUPS_PER_FILE = 10

# Add the backup dir to blocked paths so the agent can't tamper with it
BLOCKED_PATH_FRAGMENTS.append(BACKUP_DIR_NAME)

# Regex patterns for content redaction — anything matching these
# in a tool RESULT gets replaced before the LLM ever sees it.
_REDACT_PATTERNS = [
    # API keys (common formats)
    (re.compile(r'(sk-[A-Za-z0-9]{20,})'), 'sk-[REDACTED]'),
    (re.compile(r'(ghp_[A-Za-z0-9]{36,})'), 'ghp_[REDACTED]'),
    (re.compile(r'(gho_[A-Za-z0-9]{36,})'), 'gho_[REDACTED]'),
    (re.compile(r'(glpat-[A-Za-z0-9\-]{20,})'), 'glpat-[REDACTED]'),
    (re.compile(r'(xox[bpoas]-[A-Za-z0-9\-]{10,})'), 'xox-[REDACTED]'),
    (re.compile(r'(AIza[A-Za-z0-9\-_]{35})'), 'AIza[REDACTED]'),
    (re.compile(r'(AKIA[0-9A-Z]{50})'), 'AKIA[REDACTED]'),
    (re.compile(r'(tvly-[A-Za-z0-9]{20,})'), 'tvly-[REDACTED]'),
    # Bearer / Authorization headers
    (re.compile(r'(Bearer\s+)[A-Za-z0-9\-_.~+/]+=*', re.I), r'\1[REDACTED]'),
    (re.compile(r'(Authorization["\']?\s*[:=]\s*["\']?)[^\s"\']+', re.I),
     r'\1[REDACTED]'),
    # Generic key=value secrets
    (re.compile(
        r'(?i)((?:api[_-]?key|apikey|secret|token|passwd|password|pwd)'
        r'["\']?\s*[:=]\s*["\']?)[A-Za-z0-9\-_.+/]{8,}["\']?'
    ), r'\1[REDACTED]'),
    # Private key blocks
    (re.compile(
        r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
        re.S
    ), '[PRIVATE KEY REDACTED]'),
    # AWS secret access keys (require key-ish context to avoid nuking git SHAs etc.)
    (re.compile(
        r'(?i)(aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?)'
        r'[A-Za-z0-9/+=]{40}'
    ), r'\1[REDACTED]'),
]

# Personal-info patterns (emails) — softer redaction
_PII_PATTERNS = [
    (re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    ), '[EMAIL-REDACTED]'),
]


# ── helpers for path_is_blocked ──────────────────────────────────────
_SEG_SPLIT_RE = re.compile(r"[\\/]+")


def _norm_for_match(s):
    """Lower-case + forward-slash a path or fragment (cross-platform)."""
    return str(s).lower().replace("\\", "/")


def _name_stem(name):
    """Name without its final extension.
    '.env.local'→'.env' · 'credentials.json'→'credentials' · 'id_rsa.pub'→'id_rsa'
    """
    i = name.rfind(".")
    return name if i <= 0 else name[:i]


_BLOCK_CACHE = {"count": -1, "items": ()}


def _compiled_block_fragments():
    """Normalize BLOCKED_PATH_FRAGMENTS once (rebuilt if the list grows)."""
    if _BLOCK_CACHE["count"] != len(BLOCKED_PATH_FRAGMENTS):
        items = tuple(
            (frag, _norm_for_match(frag))
            for frag in BLOCKED_PATH_FRAGMENTS
            if _norm_for_match(frag)
        )
        _BLOCK_CACHE["count"] = len(BLOCKED_PATH_FRAGMENTS)
        _BLOCK_CACHE["items"] = items
    return _BLOCK_CACHE["items"]


def _segment_matches(segs, f):
    """Match a separator-free fragment against whole path segments."""
    if f.endswith("_"):        # "secret_"      → any name starting with it
        return any(s.startswith(f) for s in segs)
    if f.startswith("_"):      # "_credentials" → any name ending with it
        return any(s.endswith(f) or _name_stem(s).endswith(f) for s in segs)
    if f.endswith("."):        # ".env."        → any name starting with it
        return any(s.startswith(f) for s in segs)
    for s in segs:             # exact name, or name + any extension
        if s == f or _name_stem(s) == f:
            return True
    return False


def path_is_blocked(full_path):
    """True if the resolved path matches any blocked pattern.

    Matching rules (per fragment):
      • contains a path separator ("windows\\system32", ".docker/config",
        "/etc/passwd", "application support/…") → substring of the full
        normalized path. These are specific enough to be safe.
      • bare name (".ssh", "credentials", "id_rsa", "deepseek.py"…) →
        must equal a WHOLE segment or the segment's stem, so
        "credentials" blocks credentials + credentials.json but NOT
        credentials-guide.md.
      • affix forms are honoured: "secret_" (prefix), "_credentials"
        (suffix), ".env." (prefix, e.g. .env.production).
      • any segment whose extension is in BLOCKED_READ_EXTENSIONS blocks
        the path (*.pem, *.key, *.kdbx…), regardless of its name.

    Everything is lower-cased and slash-normalized before matching, so
    backslash entries work on POSIX and mixed-case dirs (macOS
    "Application Support") are caught too.
    """
    p = _norm_for_match(full_path)
    if not p:
        return False, None
    segs = [s for s in _SEG_SPLIT_RE.split(p) if s]

    for orig, f in _compiled_block_fragments():
        if "/" in f:
            if f in p:
                return True, orig
        elif _segment_matches(segs, f):
            return True, orig

    # Extension defence-in-depth (same list op_read uses, now applied to
    # every operation and every path level).
    for s in segs:
        stem = _name_stem(s)
        if s != stem and s[len(stem):] in BLOCKED_READ_EXTENSIONS:
            return True, s[len(stem):]
    return False, None


def redact_text(text, redact_pii=False):
    """Strip secrets (and optionally PII) from tool output."""
    if not text:
        return text
    for pattern, repl in _REDACT_PATTERNS:
        text = pattern.sub(repl, text)
    if redact_pii:
        for pattern, repl in _PII_PATTERNS:
            text = pattern.sub(repl, text)
    return text


def redact_result(obj, redact_pii=False, _depth=0):
    """Recursively redact strings inside a tool-result dict/list."""
    if _depth > 8:
        return obj
    if isinstance(obj, str):
        return redact_text(obj, redact_pii)
    if isinstance(obj, dict):
        return {k: redact_result(v, redact_pii, _depth + 1)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_result(v, redact_pii, _depth + 1) for v in obj]
    return obj


def _backup_file(root, target):
    """Save a timestamped copy of a file before it gets modified.

    Backups go to <workspace>/.apmix_backups/<original_dir>/<timestamp>_<name>.
    Best-effort: if backup fails, the write still proceeds.
    """
    try:
        import shutil
        rel = rel_to(root, target)
        backup_dir = os.path.join(root, BACKUP_DIR_NAME, os.path.dirname(rel))
        os.makedirs(backup_dir, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        base = os.path.basename(target)
        backup_path = os.path.join(backup_dir, f"{ts}_{base}")

        counter = 0
        while os.path.exists(backup_path):
            counter += 1
            backup_path = os.path.join(backup_dir, f"{ts}_{counter}_{base}")

        shutil.copy2(target, backup_path)

        stamp_re = re.compile(
            r"^\d{8}_\d{6}(?:_\d+)?_" + re.escape(base) + r"$"
        )
        all_backups = sorted(
            f for f in os.listdir(backup_dir)
            if stamp_re.match(f) and f != os.path.basename(backup_path)
        )
        for old in all_backups[:-MAX_BACKUPS_PER_FILE]:
            try:
                os.remove(os.path.join(backup_dir, old))
            except OSError:
                pass

        return backup_path
    except Exception:
        return None


def _write_extension_ok(target):
    """True if the file extension is in the safe-to-write allowlist."""
    ext = os.path.splitext(target)[1].lower()
    name = os.path.basename(target).lower()
    if ext in AGENT_WRITABLE_EXTENSIONS:
        return True
    if name in AGENT_WRITABLE_EXTENSIONS:
        return True
    return False


MAX_READ_BYTES = 400_000
MAX_SEARCH_HITS = 200
MAX_POST_BODY_BYTES = 64 * 1024 * 1024

# Shared lock for every in-memory cache below. ThreadingHTTPServer runs
# each request on its own thread, so all reads/writes must be guarded.
_CACHE_LOCK = threading.Lock()

# Request-body keys that must NEVER be auto-stripped, even if the error
# message appears to name them (defense against over-eager regex matches).
PROTECTED_PARAMS = frozenset({"model", "messages", "stream", "input"})

# ------------------------------------------------------------------ smart model catalog
# Known free models per provider — updated based on common knowledge.
# This is a fallback when the provider doesn't expose pricing metadata.
KNOWN_FREE_MODELS = {
    # DeepSeek
    "deepseek-v4.1-flash-free", "deepseek-r1-free", "deepseek-chat-free",
    # Groq (free tier models)
    "llama-3.1-8b-instant", "llama-3.2-1b-preview", "llama-3.2-3b-preview",
    "llama-3.2-11b-vision-preview", "llama-3.2-90b-vision-preview",
    "mixtral-8x7b-32768", "gemma-7b-it", "gemma2-9b-it",
    # OpenRouter :free suffix models
    "meta-llama/llama-3.1-8b-instruct:free",
    "google/gemma-2-9b-it:free",
    "mistralai/mistral-7b-instruct:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "deepseek/deepseek-r1:free",
    "deepseek/deepseek-chat:free",
    # Cerebras (free tier)
    "llama3.1-8b", "llama3.1-70b",
    # Together (free tier models)
    "meta-llama/Llama-3.2-3B-Instruct-Turbo-Free",
    "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
    # SambaNova
    "Meta-Llama-3.1-8B-Instruct",
    # Additional patterns (name heuristics only — Mistral small/nemo
    # intentionally omitted: not reliably free on Mistral's paid API)
    "google/gemini-flash-1.5", "google/gemini-1.5-flash",
}

# Parameters that are commonly rejected by various providers
# Used to speed up the auto-strip process
COMMON_PARAM_ALIASES = {
    "top_k": ["top_k", "topk"],
    "repetition_penalty": ["repetition_penalty", "repeat_penalty", "rep_penalty"],
    "min_p": ["min_p", "minp"],
    "reasoning_effort": ["reasoning_effort", "thinking", "reasoning",
                          "extended_thinking", "budget_tokens"],
}

# Cache: {(model, host): [list of rejected params]}
_PARAM_REJECT_CACHE = {}

# Cache keys include the complete upstream base + a non-secret auth fingerprint.
# This prevents one account/provider path from receiving another account's model list.
_MODELS_URL_CACHE = {}

# Cache: {cache_key: enriched_models_data}
_MODELS_DATA_CACHE = {}
_MODELS_DATA_CACHE_TIME = {}


def host_allowed(host):
    """True if an upstream host may be relayed to.

    Private/loopback addresses are accepted only when the host string is a
    real IP (parsed via ipaddress). Domain names that merely *start* like
    private IPs (e.g. 10.evil.com, 127.evil.com) are rejected unless they
    appear on the explicit domain allowlist.
    """
    host = (host or "").lower().strip()
    if not host:
        return False
    if host in ("localhost", "::1", "0.0.0.0"):
        return True
    # IP-literal path: only true private/loopback/link-local IPs
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        return False  # public IP — not allowed as upstream
    except ValueError:
        pass  # not an IP — fall through to domain allowlist
    return any(host == h or host.endswith("." + h) for h in ALLOWED_UPSTREAM_HOSTS)


# ------------------------------------------------------------------ free model detection
def is_free_model_name(name):
    """Check if a model name suggests it's free (no API calls needed)."""
    n = str(name or "").lower().strip()
    if not n:
        return False

    # Direct patterns
    patterns = [
        r'(^|[-.:_/ ])free([-\.:_/ ]|$)',
        r':free$',
        r'-free$',
        r'_free$',
        r'^free[-_]',
        r'free[-_]tier',
        r'free[-_]preview',
    ]
    for p in patterns:
        if re.search(p, n):
            return True

    # Known free models list
    if n in KNOWN_FREE_MODELS:
        return True

    # Common free-tier indicators
    free_indicators = [
        "flash-free", "instant", "turbo-free", "mini-free",
        "nano-free", "lite-free", "basic-free", "starter",
    ]
    for ind in free_indicators:
        if ind in n:
            return True

    return False


def _num_or_none(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def extract_pricing_info(model_data):
    """Extract pricing info from model metadata without any chat calls.

    Note: a *numeric* 0 means free — it is falsy in Python, so we must
    never use `or` chains to pick a pricing field (the earlier version
    silently reported free models as *unknown*).
    """
    if not isinstance(model_data, dict):
        return None

    pricing = model_data.get("pricing")
    if pricing is None:
        pricing = model_data.get("price")
    if pricing is None:
        pricing = model_data.get("cost")

    if pricing is not None:
        if isinstance(pricing, dict):
            # Any non-zero numeric key means paid. All-present-keys-zero
            # means free. Non-numeric values are skipped.
            any_zero = False
            for key in ("prompt", "input", "completion", "output"):
                if key not in pricing:
                    continue
                n = _num_or_none(pricing.get(key))
                if n is None:
                    continue
                if n > 0:
                    return {"free": False, "source": "pricing_metadata",
                            "price": str(pricing.get(key))}
                any_zero = True
            if any_zero:
                return {"free": True, "source": "pricing_metadata"}
        else:
            n = _num_or_none(pricing)
            if n is not None:
                if n == 0:
                    return {"free": True, "source": "pricing_metadata"}
                return {"free": False, "source": "pricing_metadata",
                        "price": str(pricing)}

    # Direct flags
    if model_data.get("is_free") is True or model_data.get("free") is True:
        return {"free": True, "source": "explicit_flag"}

    details = model_data.get("details")
    if isinstance(details, dict):
        d_pricing = details.get("pricing")
        if isinstance(d_pricing, dict):
            for key in ("prompt", "input"):
                if key in d_pricing:
                    n = _num_or_none(d_pricing.get(key))
                    if n is not None and n == 0:
                        return {"free": True, "source": "details_pricing"}

    return None


def enrich_model_data(model_entry, host):
    """Add free/paid status and metadata to a model entry without chat calls."""
    if isinstance(model_entry, str):
        model_entry = {"id": model_entry, "name": model_entry}

    model_id = model_entry.get("id") or model_entry.get("name") or ""
    enriched = dict(model_entry)

    # 1. Check pricing metadata first (most reliable)
    pricing_info = extract_pricing_info(model_entry)

    # 2. Check name patterns
    name_free = is_free_model_name(model_id)

    # 3. Check known free models for this host
    host_lower = (host or "").lower()
    known_free = model_id.lower() in KNOWN_FREE_MODELS

    # Determine status
    if pricing_info and pricing_info.get("free"):
        enriched["_free"] = True
        enriched["_free_source"] = pricing_info.get("source", "metadata")
        enriched["_free_confidence"] = "high"
    elif pricing_info and not pricing_info.get("free"):
        enriched["_free"] = False
        enriched["_free_source"] = "pricing_metadata"
        enriched["_free_confidence"] = "high"
        enriched["_price"] = pricing_info.get("price", "unknown")
    elif name_free or known_free:
        enriched["_free"] = True
        enriched["_free_source"] = "name_pattern" if name_free else "known_catalog"
        enriched["_free_confidence"] = "medium"
    else:
        enriched["_free"] = None
        enriched["_free_source"] = "unknown"
        enriched["_free_confidence"] = "low"

    # Add context length if available (guard against top_provider: null)
    tp = model_entry.get("top_provider")
    tp_ctx = tp.get("context_length") if isinstance(tp, dict) else None
    ctx = (model_entry.get("context_length") or model_entry.get("context_window")
           or model_entry.get("max_context_tokens") or tp_ctx)
    if ctx:
        try:
            enriched["_context_length"] = int(ctx)
        except (ValueError, TypeError):
            pass

    # Add description if available
    desc = model_entry.get("description") or model_entry.get("about")
    if desc:
        enriched["_description"] = str(desc)[:500]

    return enriched


def _metadata_cache_key(base, auth_header=None):
    """Return a stable, non-secret cache key for an upstream + account."""
    p = urllib.parse.urlparse(base)
    auth = str(auth_header or "").encode("utf-8", "replace")
    auth_fp = hashlib.sha256(auth).hexdigest()[:16] if auth else "anonymous"
    return (
        (p.scheme or "https").lower(),
        (p.netloc or "").lower(),
        (p.path.rstrip("/") or "/"),
        auth_fp,
    )


def discover_models_url(base, auth_header=None):
    """Find a working /models endpoint by trying common path patterns."""
    parsed = urllib.parse.urlparse(base)
    host = parsed.hostname
    if not host or parsed.scheme not in ("http", "https"):
        return None

    cache_key = _metadata_cache_key(base, auth_header)
    with _CACHE_LOCK:
        cached = _MODELS_URL_CACHE.get(cache_key)
    if cached is not None:
        return cached

    scheme = parsed.scheme or "https"
    netloc = parsed.netloc
    base_path = parsed.path.rstrip("/")

    candidates = [base + "/models"]

    if base_path:
        parts = [p for p in base_path.split("/") if p]
        for i in range(len(parts), 0, -1):
            parent = "/" + "/".join(parts[:i])
            candidates.append(f"{scheme}://{netloc}{parent}/models")

    candidates.append(f"{scheme}://{netloc}/v1/models")
    candidates.append(f"{scheme}://{netloc}/v1beta/models")
    candidates.append(f"{scheme}://{netloc}/api/v1/models")
    candidates.append(f"{scheme}://{netloc}/api/paas/v4/models")

    if "/v1" in base_path:
        candidates.append(base.replace("/v1", "/v1beta") + "/models")
        candidates.append(base.replace("/v1", "/v4") + "/models")

    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    for url in unique:
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", UA)
            req.add_header("Accept", "application/json")
            if auth_header:
                req.add_header("Authorization", auth_header)
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    with _CACHE_LOCK:
                        _MODELS_URL_CACHE[cache_key] = url
                    return url
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue

    return None


def fetch_models_metadata(base_url, auth_header=None):
    """Fetch and cache model metadata from the upstream /models endpoint.
    This does NOT consume inference tokens — it's a metadata GET request."""
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or ""
    if not host or parsed.scheme not in ("http", "https"):
        return None

    # Check cache (valid for 5 minutes). Include provider path and account
    # fingerprint so switching accounts/providers cannot reuse stale metadata.
    cache_key = _metadata_cache_key(base_url, auth_header)
    now = time.time()
    with _CACHE_LOCK:
        ts = _MODELS_DATA_CACHE_TIME.get(cache_key)
        if ts is not None and now - ts < 300 and cache_key in _MODELS_DATA_CACHE:
            return _MODELS_DATA_CACHE[cache_key]

    # Discover the models URL
    models_url = discover_models_url(base_url, auth_header)
    if not models_url:
        return None

    try:
        req = urllib.request.Request(models_url, method="GET")
        req.add_header("User-Agent", UA)
        req.add_header("Accept", "application/json")
        if auth_header:
            req.add_header("Authorization", auth_header)
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", "replace")
            data = json.loads(raw) if raw else {}

            # Normalize to a list
            models_list = []
            if isinstance(data, list):
                models_list = data
            elif isinstance(data, dict):
                models_list = (data.get("models") or data.get("data")
                               or data.get("results") or [])

            # Enrich with free/paid info
            enriched = [enrich_model_data(m, host) for m in models_list if m]

            # Cache
            with _CACHE_LOCK:
                _MODELS_DATA_CACHE[cache_key] = enriched
                _MODELS_DATA_CACHE_TIME[cache_key] = now

            return enriched
    except Exception:
        return None


def get_model_details(base_url, model_id, auth_header=None):
    """Get details for a specific model without any chat/inference calls."""
    models = fetch_models_metadata(base_url, auth_header)
    if not models:
        # Fallback to name-based analysis
        heuristic_free = (
            is_free_model_name(model_id)
            or model_id.lower() in KNOWN_FREE_MODELS
        )
        return {
            "id": model_id,
            "_free": True if heuristic_free else None,
            "_free_source": "name_pattern" if heuristic_free else "unknown",
            "_free_confidence": "medium" if heuristic_free else "low",
            "_context_length": None,
            "_description": "",
            "_note": "No usable /models metadata was available; billing status is unknown unless the name strongly indicates a free model.",
        }

    # Find the specific model
    for m in models:
        mid = str(m.get("id") or m.get("name") or "")
        if mid == model_id or mid.lower() == model_id.lower():
            return m

    # Not found in list — use name heuristics
    return {
        "id": model_id,
        "_free": is_free_model_name(model_id),
        "_free_source": "name_pattern",
        "_free_confidence": "medium" if is_free_model_name(model_id) else "low",
        "_context_length": None,
        "_description": "",
        "_note": "Model not in /models list — may still work",
    }


# ------------------------------------------------------------------ smart parameter handling
def find_rejected_param_from_error(error_body):
    """Parse an API error response to find which parameter was rejected.
    Returns the parameter name, or None if it's not a parameter rejection."""
    if not error_body:
        return None

    text = error_body if isinstance(error_body, str) else json.dumps(error_body)

    patterns = [
        # OpenAI style
        r'unrecognized request argument[^:]*:\s*[`"\']?([A-Za-z0-9_]+)[`"\']?',
        r'unknown parameter[:\s\'"`\']+([A-Za-z0-9_]+)',
        # Pydantic style
        r'extra inputs are not permitted[^(]*\(([A-Za-z0-9_]+)\)',
        # Generic style
        r'unexpected keyword argument[:\s\'"`\']+([A-Za-z0-9_]+)',
        # "not supported" style
        r'[`"\']([A-Za-z0-9_]+)[`"\']\s+is not (?:a\s+)?(?:supported|allowed|recognized|valid)',
        r'(?:parameter|field)[\s\'"`":]+([A-Za-z0-9_]+)[\s\'"`"]+(?:is|are) not supported',
        r'does not support (?:the )?(?:parameter )?[`"\']?([A-Za-z0-9_]+)[`"\']?',
        # Validation error style
        r'validation error[^\n]*\n\s*([A-Za-z0-9_]+)\s*\n',
        # Invalid field style
        r'invalid field[:\s]+([A-Za-z0-9_]+)',
        # Not permitted
        r'([A-Za-z0-9_]+)\s+is not permitted',
        # Anthropic style
        r'([A-Za-z0-9_]+):\s*(?:Unknown|Unrecognized|Invalid)\s+(?:parameter|field|argument)',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            for i in range(1, len(match.groups()) + 1):
                g = match.group(i)
                if g and g not in PROTECTED_PARAMS:
                    return g

    return None


def strip_param_from_body(body_dict, param_name):
    """Remove a parameter from a request body. Handles nested structures."""
    if not param_name or param_name in PROTECTED_PARAMS:
        return False
    if param_name in body_dict:
        del body_dict[param_name]
        return True

    # Check nested response_format
    if "response_format" in body_dict and isinstance(body_dict["response_format"], dict):
        rf = body_dict["response_format"]
        if param_name in rf:
            del rf[param_name]
            return True
        if param_name in ("json_schema", "response_format"):
            del body_dict["response_format"]
            return True

    # Check nested json_schema
    if "json_schema" in body_dict and isinstance(body_dict["json_schema"], dict):
        js = body_dict["json_schema"]
        if param_name in js:
            del js[param_name]
            return True

    return False


def get_rejected_params(model, host):
    """Get a *copy* of rejected params for a model+host combo."""
    key = (str(model or "").lower(), str(host or "").lower())
    with _CACHE_LOCK:
        return list(_PARAM_REJECT_CACHE.get(key, []))


def add_rejected_param(model, host, param):
    """Remember that a parameter was rejected for this model+host."""
    if not param or param in PROTECTED_PARAMS:
        return
    key = (str(model or "").lower(), str(host or "").lower())
    with _CACHE_LOCK:
        lst = _PARAM_REJECT_CACHE.setdefault(key, [])
        if param not in lst:
            lst.append(param)


def auto_strip_request(body_dict, model, host):
    """Preemptively remove known-rejected parameters before sending.
    This avoids wasted round-trips."""
    rejected = get_rejected_params(model, host)
    for param in rejected:
        if param in PROTECTED_PARAMS:
            continue
        if param in body_dict:
            del body_dict[param]

    # Also check aliases
    for canonical, aliases in COMMON_PARAM_ALIASES.items():
        if canonical in rejected:
            for alias in aliases:
                if alias in PROTECTED_PARAMS:
                    continue
                if alias in body_dict:
                    del body_dict[alias]

    return body_dict


def ensure_user_last(body, strict=True):
    """Fix DeepSeek-style 400s: 'The last message must have role user'.

    DeepSeek (and routers that forward to it — Token Harbor, OpenRouter,
    etc.) reject requests where:
      1. the LAST message is not role=user
      2. the FIRST non-system message is not role=user

    Both fire when the chat page resends history that ends with the
    assistant's reply (regenerate flows) or starts with an assistant
    few-shot example. Normalizes the array in place; returns True if
    anything was changed.
    """
    if not strict:
        return False
    if not isinstance(body, dict):
        return False
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return False

    changed = False

    # Clean trailing empty assistant placeholders first (legacy behavior)
    try:
        while len(msgs) > 1:
            last = msgs[-1]
            if not isinstance(last, dict):
                break
            role = last.get("role")
            if role == "assistant":
                content = last.get("content") or ""
                if isinstance(content, list):
                    has_content = len(content) > 0
                else:
                    has_content = bool(str(content).strip())
                has_tools = bool(last.get("tool_calls"))
                if not has_content and not has_tools:
                    msgs.pop()
                    changed = True
                    continue
            break
    except Exception:
        pass

    # 1. Last message must be role=user
    if msgs:
        last = msgs[-1]
        if isinstance(last, dict) and last.get("role") in ("assistant", "system"):
            msgs.append({
                "role": "user",
                "content": "Continue from the assistant message above.",
            })
            changed = True

    # 2. First non-system message must be role=user
    # Drop leading orphan tool messages (need the assistant+tool_calls ahead).
    insert_at = 0
    while insert_at < len(msgs):
        m = msgs[insert_at]
        if isinstance(m, dict) and m.get("role") == "system":
            insert_at += 1
            continue
        if isinstance(m, dict) and m.get("role") == "tool":
            msgs.pop(insert_at)
            changed = True
            continue
        break
    for m in msgs[insert_at:]:
        if isinstance(m, dict) and m.get("role") == "system":
            insert_at += 1
            continue
        if isinstance(m, dict) and m.get("role") != "user":
            # Don't break tool calling loops: if first non-system is assistant
            # with tool_calls, leave the sequence alone.
            if m.get("role") == "assistant" and m.get("tool_calls"):
                break
            msgs.insert(insert_at, {"role": "user", "content": "Begin."})
            changed = True
        break

    return changed




def _needs_strict_user_last(body, upstream_host):
    """Only apply legacy last-user normalization to DeepSeek-family traffic."""
    host = str(upstream_host or "").lower()
    model = (
        str((body or {}).get("model") or "").lower()
        if isinstance(body, dict) else ""
    )
    # Only DeepSeek-native traffic should receive the legacy last-user
    # normalization. In particular, the shared apmix.ai gateway can expose
    # GPT/Claude/etc.; host-only gating there corrupts otherwise valid
    # OpenAI-style histories.
    host_is_deepseek = (
        host == "api.deepseek.com"
        or host.endswith(".deepseek.com")
    )
    model_is_deepseek = (
        model.startswith("deepseek")
        or "deepseek/" in model
        or "/deepseek-" in model
    )
    return host_is_deepseek or model_is_deepseek


# ------------------------------------------------------------------ static page
def find_page():
    for name in ("Deepseek.html", "apmix-chat.html", "index.html",
                 "chat.html", "apmix.html"):
        path = os.path.join(FOLDER, name)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                return name, f.read()
    for name in sorted(os.listdir(FOLDER)):
        if name.lower().endswith(".html"):
            with open(os.path.join(FOLDER, name), "rb") as f:
                return name, f.read()
    return None, None


PAGE_NAME, PAGE_BYTES = find_page()


# ------------------------------------------------------------------ http helpers
# Tiny connection pool so agent steps don't pay a full TLS handshake each time.
_POOL = {}
_POOL_LOCK = threading.Lock()


def _conn_key(url):
    p = urllib.parse.urlparse(url)
    return (
        p.scheme or "https",
        p.hostname,
        p.port or (443 if (p.scheme or "https") == "https" else 80),
    )


def _pooled_conn(key, timeout):
    with _POOL_LOCK:
        conn = _POOL.pop(key, None)
    if conn is not None:
        return conn
    if key[0] == "https":
        return http.client.HTTPSConnection(key[1], key[2], timeout=timeout)
    return http.client.HTTPConnection(key[1], key[2], timeout=timeout)


def _recycle(key, conn):
    with _POOL_LOCK:
        if len(_POOL) < 64:
            _POOL[key] = conn
            return
    try:
        conn.close()
    except Exception:
        pass


def http_open(req, timeout=30):
    return urllib.request.urlopen(req, timeout=timeout)


def http_json(url, payload=None, headers=None, method=None, timeout=30):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    method = method or ("POST" if data is not None else "GET")
    key = _conn_key(url)
    p = urllib.parse.urlparse(url)
    target = (p.path or "/") + (("?" + p.query) if p.query else "")
    for attempt in (1, 2):
        conn = _pooled_conn(key, timeout)
        try:
            conn.request(method, target, body=data, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            if attempt == 2:
                raise
            continue
        if resp.status >= 400:
            _recycle(key, conn)
            raise urllib.error.HTTPError(
                url, resp.status, resp.reason, resp.headers, io.BytesIO(raw)
            )
        _recycle(key, conn)
        return json.loads(raw.decode("utf-8", "replace")) if raw else {}
    return {}


# ------------------------------------------------------------------ search
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_tags(s):
    return _WS_RE.sub(" ", html_mod.unescape(_TAG_RE.sub("", s))).strip()


def ddg_unwrap(href):
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        if q.get("uddg"):
            return q["uddg"][0]
    except Exception:
        pass
    return href


_DDG_LINK_A = re.compile(
    r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S | re.I
)
_DDG_LINK_B = re.compile(
    r'<a[^>]*href="([^"]+)"[^>]*class="result__a"[^>]*>(.*?)</a>', re.S | re.I
)
_DDG_SNIP = re.compile(r'<a[^>]*class="result__snippet[^"]*"[^>]*>(.*?)</a>', re.S | re.I)


def search_tavily(query, api_key, max_results=6):
    data = http_json(
        "https://api.tavily.com/search",
        payload={
            "api_key": api_key,
            "query": query,
            "max_results": max_results,
            "search_depth": "basic",
            "include_answer": True,
        },
        method="POST",
        timeout=30,
    )
    results = []
    for item in data.get("results") or []:
        results.append({
            "title": item.get("title") or item.get("url") or "",
            "url": item.get("url") or "",
            "snippet": (item.get("content") or "")[:1200],
        })
    return {
        "provider": "tavily",
        "query": query,
        "answer": data.get("answer") or "",
        "results": results,
    }


def search_ddg(query, max_results=6):
    url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    with http_open(req, timeout=20) as resp:
        page = resp.read().decode("utf-8", "replace")
    links = _DDG_LINK_A.findall(page) or _DDG_LINK_B.findall(page)
    snips = _DDG_SNIP.findall(page)
    results = []
    for i, (href, title_html) in enumerate(links[:max_results]):
        href = ddg_unwrap(href)
        if not href.startswith("http"):
            continue
        results.append({
            "title": strip_tags(title_html) or href,
            "url": href,
            "snippet": strip_tags(snips[i]) if i < len(snips) else "",
        })
    if not results:
        raise RuntimeError("DuckDuckGo returned no parsable results")
    return {"provider": "duckduckgo", "query": query, "answer": "", "results": results}


# Local search engine (DeepseekSearchEngine.py) — tried before Tavily/DDG.
# The engine binds 1010 and moves up if busy, so probe a few ports.
# Set DEEPSEEK_SEARCH_URL to pin it explicitly (e.g. if you ran it with --port).
SEARCH_ENGINE_URL = os.environ.get("DEEPSEEK_SEARCH_URL", "").rstrip("/")
SEARCH_ENGINE_PORTS = (1010, 1011, 1012, 1013, 1014, 1001, 7500)  # last two = legacy docs
_ENGINE_BASE_CACHE = {"url": ""}


def search_via_local_engine(query, max_results=6):
    """Query the local DeepseekSearchEngine.py instance.

    Tries, in order: $DEEPSEEK_SEARCH_URL (explicit), the last URL that
    worked (sticky), then the ports the engine actually binds (1010+).
    Returns the first response containing results, else None — so
    do_search() falls back to Tavily / DuckDuckGo as before.
    """
    bases = []
    if SEARCH_ENGINE_URL:
        bases.append(SEARCH_ENGINE_URL)
    if _ENGINE_BASE_CACHE["url"]:
        bases.append(_ENGINE_BASE_CACHE["url"])
    bases += [f"http://localhost:{p}" for p in SEARCH_ENGINE_PORTS]
    bases = list(dict.fromkeys(bases))          # de-dupe, keep order

    for base in bases:
        try:
            url = (
                f"{base}/search?"
                f"q={urllib.parse.quote(query)}&limit={max_results}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            if data.get("results"):
                data.setdefault("provider", "local_engine")
                _ENGINE_BASE_CACHE["url"] = base   # remember what worked
                return data
        except Exception:
            continue                               # dead port / bad JSON → next
    return None


def do_search(query, tavily_key):
    """Priority: local engine → Tavily → DuckDuckGo."""
    # 1. Local search engine (free, cached, multi-backend)
    try:
        result = search_via_local_engine(query)
        if result:
            return result
    except Exception:
        pass  # Engine not running — fall through

    # 2. Tavily
    if tavily_key:
        try:
            return search_tavily(query, tavily_key)
        except Exception as e:
            note = "Tavily failed (%s) — fell back to DuckDuckGo" % e
            try:
                data = search_ddg(query)
                data["note"] = note
                return data
            except Exception as e2:
                return {
                    "provider": "none",
                    "query": query,
                    "results": [],
                    "note": "%s / %s" % (note, e2),
                }

    # 3. DuckDuckGo
    try:
        return search_ddg(query)
    except Exception as e:
        return {"provider": "none", "query": query, "results": [], "note": str(e)}


# ------------------------------------------------------------------ filesystem
def realpath(p):
    return os.path.realpath(os.path.expanduser(p))


def resolve_workspace(ws):
    if ws and str(ws).strip():
        p = str(ws).strip().strip('"').strip("'")
        if re.fullmatch(r"[A-Za-z]:", p):
            p += os.sep
        p = realpath(p)
        if not os.path.isdir(p):
            raise ValueError("workspace is not a directory: %s" % p)
        return p
    return realpath(FOLDER)


def _within(root, cand):
    r, c = os.path.normcase(root), os.path.normcase(cand)
    if c == r:
        return True
    if not (r.endswith(os.sep) or r.endswith("/")):
        r += os.sep
    return c.startswith(r)


def _unrestricted(body):
    return bool(body.get("unrestricted"))


def resolve_in(root, rel, unrestricted=False):
    rel = (rel or ".").strip() or "."
    if os.path.isabs(rel):
        if unrestricted:
            return realpath(rel)
        cand = realpath(rel)
    else:
        cand = realpath(os.path.join(root, rel))
    if not _within(root, cand):
        raise ValueError(
            "path escapes the workspace: %s "
            "(the user can enable full-disk access in Settings)" % rel
        )
    return cand


def rel_to(root, path):
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path


def op_list(root, body):
    target = resolve_in(root, body.get("path") or ".", _unrestricted(body))
    blocked, frag = path_is_blocked(target)
    if blocked:
        raise ValueError(
            "access denied: this path matches a protected pattern (%r)." % frag
        )
    if not os.path.isdir(target):
        raise ValueError("not a directory")
    entries = []
    skipped = 0
    try:
        names = sorted(
            os.listdir(target),
            key=lambda n: (not os.path.isdir(os.path.join(target, n)), n.lower()),
        )
    except OSError as e:
        raise ValueError("cannot list directory: %s" % e)
    for name in names:
        full = os.path.join(target, name)
        if path_is_blocked(full)[0]:
            skipped += 1
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext in BLOCKED_READ_EXTENSIONS:
            skipped += 1
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        entries.append({
            "name": name,
            "is_dir": os.path.isdir(full),
            "size": 0 if os.path.isdir(full) else st.st_size,
        })
    return {
        "ok": True,
        "root": root,
        "path": rel_to(root, target),
        "entries": entries[:500],
        "hidden_protected": skipped,
    }


def op_read(root, body):
    target = resolve_in(root, body.get("path") or "", _unrestricted(body))
    blocked, frag = path_is_blocked(target)
    if blocked:
        raise ValueError(
            "access denied: this path matches a protected pattern (%r). "
            "Credentials, keys, and browser data are off-limits to the agent."
            % frag
        )
    ext = os.path.splitext(target)[1].lower().lstrip(".")
    if ("." + ext) in BLOCKED_READ_EXTENSIONS:
        raise ValueError(
            "access denied: .%s files may contain secrets and cannot "
            "be read by the agent." % ext
        )
    if not os.path.isfile(target):
        raise ValueError("not a file")
    size = os.path.getsize(target)
    try:
        max_bytes = int(body.get("max_bytes") or MAX_READ_BYTES)
    except (TypeError, ValueError):
        max_bytes = MAX_READ_BYTES
    max_bytes = max(1024, min(max_bytes, MAX_READ_BYTES))

    # Byte-offset paging is essential for large JSON/log/code files. Without
    # it, a model that asks to "read more" receives the same first chunk and
    # can loop forever. Offset is deliberately byte-based so paging is
    # deterministic even for UTF-8 text.
    try:
        offset = int(body.get("offset") or 0)
    except (TypeError, ValueError):
        offset = 0
    offset = max(0, min(offset, size))

    with open(target, "rb") as f:
        f.seek(offset)
        raw = f.read(max_bytes)

    binary = b"\x00" in raw[:8192]
    content = "" if binary else raw.decode("utf-8", "replace")
    content = redact_text(content)
    next_offset = min(size, offset + len(raw))
    truncated = next_offset < size
    result = {
        "ok": True,
        "root": root,
        "path": rel_to(root, target),
        "size": size,
        "offset": offset,
        "next_offset": next_offset if truncated else None,
        "binary": binary,
        "truncated": truncated,
        "content": content,
    }
    if truncated:
        result["hint"] = (
            "Only a chunk was returned. Prefer fs_search to locate the "
            "relevant records. To continue reading this file, call fs_read "
            "again with offset=next_offset."
        )
    return result


def op_write(root, body):
    """Create or overwrite a file — SAFE MODE with auto-backup."""
    target = resolve_in(root, body.get("path") or "", _unrestricted(body))

    blocked, frag = path_is_blocked(target)
    if blocked:
        raise ValueError(
            "access denied: this path matches a protected pattern (%r)." % frag
        )

    if not _write_extension_ok(target):
        ext = os.path.splitext(target)[1].lower().lstrip(".") or "(none)"
        allowed = ", ".join(sorted(
            e.lstrip(".") for e in AGENT_WRITABLE_EXTENSIONS
            if not e.startswith(".") or len(e) > 1
        ))
        raise ValueError(
            "cannot write .%s files. Allowed extensions: %s "
            "(binary and executable formats are blocked to protect your system)"
            % (ext, allowed)
        )

    content = body.get("content")
    content = "" if content is None else str(content)
    content_bytes = len(content.encode("utf-8"))
    if content_bytes > MAX_WRITE_BYTES:
        raise ValueError(
            "content too large (%d bytes, max %d). Split the write into "
            "smaller chunks or use fs_patch to modify specific sections."
            % (content_bytes, MAX_WRITE_BYTES)
        )

    backup_path = None
    if os.path.isfile(target):
        backup_path = _backup_file(root, target)

    os.makedirs(os.path.dirname(target) or root, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="") as f:
        f.write(content)

    return {
        "ok": True,
        "path": rel_to(root, target),
        "bytes": content_bytes,
        "action": "overwritten" if backup_path else "created",
        "backup": rel_to(root, backup_path) if backup_path else None,
        "note": (
            "original backed up to .apmix_backups/ — restore manually if needed"
            if backup_path else "new file created"
        ),
    }


def op_patch(root, body):
    """Find & replace text in an existing file — SAFE MODE with auto-backup."""
    target = resolve_in(root, body.get("path") or "", _unrestricted(body))

    blocked, frag = path_is_blocked(target)
    if blocked:
        raise ValueError(
            "access denied: this path matches a protected pattern (%r)." % frag
        )

    if not _write_extension_ok(target):
        ext = os.path.splitext(target)[1].lower().lstrip(".") or "(none)"
        raise ValueError(
            "cannot modify .%s files — only text/code formats are allowed." % ext
        )

    if not os.path.isfile(target):
        raise ValueError("not a file: %s" % rel_to(root, target))

    find = str(body.get("find") or "")
    replace = str(body.get("replace") or "")
    if not find:
        raise ValueError("missing 'find'")

    with open(target, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    count = text.count(find)
    if count == 0:
        raise ValueError(
            "'find' text not present in %s — the file may have already "
            "been patched" % rel_to(root, target)
        )

    new_text = (
        text.replace(find, replace)
        if body.get("all")
        else text.replace(find, replace, 1)
    )
    if len(new_text.encode("utf-8")) > MAX_WRITE_BYTES:
        raise ValueError(
            "resulting file would exceed %d bytes — refusing to patch"
            % MAX_WRITE_BYTES
        )

    backup_path = _backup_file(root, target)

    with open(target, "w", encoding="utf-8", newline="") as f:
        f.write(new_text)

    return {
        "ok": True,
        "path": rel_to(root, target),
        "total_matches": count,
        "replaced": count if body.get("all") else 1,
        "backup": rel_to(root, backup_path) if backup_path else None,
    }


def op_mkdir(root, body):
    """Create a directory — SAFE MODE (path blocklist applies)."""
    target = resolve_in(root, body.get("path") or "", _unrestricted(body))

    blocked, frag = path_is_blocked(target)
    if blocked:
        raise ValueError(
            "access denied: this path matches a protected pattern (%r)." % frag
        )

    if target in ("/", "C:\\", os.path.expanduser("~")):
        raise ValueError("refusing to create a root/home directory")

    os.makedirs(target, exist_ok=True)
    return {"ok": True, "path": rel_to(root, target)}


# Extensions treated as binary for search (skip without opening)
SEARCH_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip",
    ".gz", ".rar", ".7z", ".exe", ".dll", ".so", ".mp3", ".mp4", ".wav",
    ".avi", ".mkv", ".iso", ".msi", ".db", ".sqlite", ".sqlite3", ".pyc",
    ".jar", ".woff", ".woff2", ".ttf", ".otf", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx",
}
SEARCH_MAX_FILE_BYTES = 30_000_000
SEARCH_WORKERS = 8


def _search_file(path, matcher, max_hits_per_file=30):
    """Chunked search so giant single-line JSON still yields snippets."""
    try:
        f = open(path, "rb")
    except OSError:
        return []
    try:
        if b"\x00" in f.read(8192):
            return []
        f.seek(0)
        hits, carry = [], ""
        char_base = nl_consumed = 0
        last_end = -1
        while len(hits) < max_hits_per_file:
            chunk = f.read(1 << 20)  # 1 MB
            data = carry + chunk.decode("utf-8", "replace")
            if not data:
                break
            pos = 0
            while len(hits) < max_hits_per_file:
                m = matcher.search(data, pos)
                if not m:
                    break
                s, e = m.span()
                if e <= s:
                    pos = s + 1
                    continue
                if char_base + s >= last_end:
                    last_end = char_base + e
                    snippet = data[max(0, s - 200):min(len(data), e + 200)]
                    hits.append({
                        "line": nl_consumed + data.count("\n", 0, s) + 1,
                        "text": " ".join(snippet.split())[:600],
                    })
                pos = e
            if not chunk or len(data) <= 32768:
                break
            consumed = len(data) - 32768
            nl_consumed += data[:consumed].count("\n")
            char_base += consumed
            carry = data[consumed:]
        return hits
    except OSError:
        return []
    finally:
        try:
            f.close()
        except Exception:
            pass


def _collect_search_files(start, max_files, include_logs, skip_dirs, glob_pat):
    files, skipped, stack = [], 0, [start]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        nl = e.name.lower()
                        if e.is_dir(follow_symlinks=False):
                            if (nl in skip_dirs or nl.startswith(".")
                                    or nl == BACKUP_DIR_NAME.lower()):
                                continue
                            if path_is_blocked(e.path)[0]:
                                skipped += 1
                                continue
                            stack.append(e.path)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if path_is_blocked(e.path)[0]:
                        skipped += 1
                        continue
                    if not fnmatch.fnmatch(e.name, glob_pat):
                        continue
                    ext = os.path.splitext(nl)[1]
                    if ext in BLOCKED_READ_EXTENSIONS or ext in SEARCH_BINARY_EXTS:
                        skipped += 1
                        continue
                    if not include_logs and (nl.endswith(".log") or ".log." in nl):
                        skipped += 1
                        continue
                    if ".tmp." in nl or nl.endswith((".bak", ".old")):
                        skipped += 1
                        continue
                    if st.st_size > SEARCH_MAX_FILE_BYTES or st.st_size == 0:
                        skipped += 1
                        continue
                    files.append((e.path, st.st_size))
                    if len(files) >= max_files:
                        return files, skipped, True
        except OSError:
            continue
    return files, skipped, False


def op_search(root, body):
    needle = str(body.get("query") or body.get("pattern") or body.get("q") or "").strip()
    if not needle:
        raise ValueError("missing 'query'")
    glob_pat = str(body.get("glob") or "*")
    case = bool(body.get("case_sensitive"))
    include_system = bool(body.get("include_system"))
    include_logs = bool(body.get("include_logs"))
    try:
        limit = int(body.get("limit") or body.get("max_hits") or MAX_SEARCH_HITS)
    except (TypeError, ValueError):
        limit = MAX_SEARCH_HITS
    limit = max(1, min(limit, MAX_SEARCH_HITS))
    try:
        max_files = int(body.get("max_files") or 20000)
    except (TypeError, ValueError):
        max_files = 20000
    max_files = max(100, min(max_files, 50000))
    try:
        budget = float(body.get("max_seconds") or 20)
    except (TypeError, ValueError):
        budget = 20.0
    budget = max(1.0, min(budget, 90.0))

    search_root = root
    if body.get("path"):
        search_root = resolve_in(root, body.get("path"), _unrestricted(body))

    blocked, frag = path_is_blocked(search_root)
    if blocked:
        raise ValueError(
            "access denied: search root matches a protected pattern (%r)." % frag
        )

    # Allow fs_search to target either a directory tree or one explicit file.
    # This is useful when the model already knows the exact large file to
    # inspect and prevents an unnecessary recursive scan.
    if os.path.isfile(search_root):
        single_name = os.path.basename(search_root).lower()
        single_ext = os.path.splitext(single_name)[1]
        if single_ext in BLOCKED_READ_EXTENSIONS or single_ext in SEARCH_BINARY_EXTS:
            raise ValueError("file type cannot be searched")
        if not include_logs and (single_name.endswith(".log") or ".log." in single_name):
            raise ValueError("log search is disabled unless include_logs=true")
        try:
            st = os.stat(search_root)
        except OSError as e:
            raise ValueError("cannot stat search file: %s" % e)
        if st.st_size > SEARCH_MAX_FILE_BYTES:
            raise ValueError("file is larger than the search limit")
        files = [(search_root, st.st_size)]
        skipped_blocked = 0
        truncated = False
    elif os.path.isdir(search_root):
        try:
            matcher = re.compile(
                needle if body.get("regex") else re.escape(needle),
                0 if case else re.IGNORECASE,
            )
        except re.error as e:
            raise ValueError("invalid regex: %s" % e)

        skip = SKIP_DIRS if include_system else SEARCH_SKIP_DIRS
        files, skipped_blocked, truncated = _collect_search_files(
            search_root, max_files, include_logs, skip, glob_pat
        )
    else:
        raise ValueError("search path is neither a file nor a directory")

    # Compile the matcher for the single-file branch too.
    if 'matcher' not in locals():
        try:
            matcher = re.compile(
                needle if body.get("regex") else re.escape(needle),
                0 if case else re.IGNORECASE,
            )
        except re.error as e:
            raise ValueError("invalid regex: %s" % e)

    files.sort(key=lambda t: t[1])  # small files first → hits sooner

    hits, scanned = [], 0
    deadline = time.monotonic() + budget
    timed_out = False
    ex = ThreadPoolExecutor(max_workers=SEARCH_WORKERS)
    try:
        futs = {
            ex.submit(_search_file, p, matcher, 30): p
            for p, _ in files
        }
        for fut in as_completed(futs):
            if time.monotonic() > deadline:
                timed_out = True
                break
            scanned += 1
            path = futs[fut]
            try:
                file_hits = fut.result() if fut.exception() is None else []
            except Exception:
                file_hits = []
            for h in file_hits:
                h["path"] = rel_to(search_root, path)
                h["text"] = redact_text(h.get("text") or "")
                hits.append(h)
            if len(hits) >= limit:
                truncated = True
                break
    finally:
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)

    out = {
        "ok": True,
        "root": search_root,
        "path": rel_to(root, search_root),
        "hits": hits[:limit],
        "truncated": truncated or timed_out,
        "files_scanned": scanned,
        "blocked_skipped": skipped_blocked,
    }
    if timed_out:
        out["note"] = (
            "stopped after %.0fs — narrow the query, add a path/glob, "
            "or raise max_seconds" % budget
        )
    return out


def op_disks(root, body):
    disks = []
    if os.name == "nt":
        for letter in string.ascii_uppercase:
            d = letter + ":\\"
            if os.path.isdir(d):
                disks.append({"path": d})
    else:
        disks.append({"path": "/"})
        for base in ("/Volumes", "/media", "/mnt"):
            if not os.path.isdir(base):
                continue
            try:
                names = os.listdir(base)
            except OSError:
                continue
            for name in names:
                full = os.path.join(base, name)
                if not os.path.isdir(full):
                    continue
                disks.append({"path": full})
                if base == "/media":
                    try:
                        for sub in os.listdir(full):
                            subfull = os.path.join(full, sub)
                            if os.path.isdir(subfull):
                                disks.append({"path": subfull})
                    except OSError:
                        pass
    return {"ok": True, "disks": disks}


# op_shell has been REMOVED. Do not re-add it.


FS_OPS = {
    "list": op_list,
    "read": op_read,
    "write": op_write,
    "patch": op_patch,
    "mkdir": op_mkdir,
    "search": op_search,
    "disks": op_disks,
    # "shell" deliberately absent — server returns 403 for it
}


# ------------------------------------------------------------------ handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "apmix/4"

    def log_message(self, *a):
        pass

    # -------- primitives
    @staticmethod
    def _is_local_origin(origin):
        """True if the Origin header names a localhost-ish host."""
        try:
            p = urllib.parse.urlparse(origin)
        except Exception:
            return False
        if p.scheme not in ("http", "https"):
            return False
        return (p.hostname or "").lower() in ("localhost", "127.0.0.1", "::1")

    def _cors(self):
        # Only mirror CORS for localhost origins. Any other Origin gets no
        # Access-Control-Allow-Origin header, so the browser blocks the
        # response — this stops evil.com from fetching the served page
        # (which embeds window.APMIX_LOCAL_TOKEN) and hijacking /fs/*.
        origin = (self.headers.get("Origin") or "").strip()
        if origin and self._is_local_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type, X-Tavily-Key, X-Upstream, X-Local-Token",
            )
            self.send_header(
                "Access-Control-Expose-Headers",
                "X-Apmix-Auto-Stripped",
            )

    def _token_ok(self):
        return (self.headers.get("X-Local-Token") or "").strip() == LOCAL_TOKEN

    def send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        return self.rfile.read(n) if n else b""

    def read_json(self):
        raw = self.read_body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return {}

    # -------- verbs
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path.startswith("/v1/"):
                self.proxy("GET")
            elif path == "/search":
                self.handle_search()
            elif path == "/smart-models":
                self.handle_smart_models()
            elif path.startswith("/model-info/"):
                self.handle_model_info(path[len("/model-info/"):])
            elif path == "/param-rejects":
                self.handle_param_rejects()
            elif path == "/health":
                self.send_json(200, {
                    "ok": True,
                    "page": PAGE_NAME,
                    "upstream": UPSTREAM,
                    "smart_features": {
                        "param_auto_strip": True,
                        "free_model_detection": "metadata_only",
                        "live_probe": False,
                    }
                })
            elif path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.serve_page()
        except Exception as e:
            try:
                self.send_json(500, {"error": str(e)})
            except Exception:
                pass

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            try:
                declared = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                declared = -1
            if declared < 0:
                self.send_json(400, {"error": "invalid Content-Length"})
                return
            if declared > MAX_POST_BODY_BYTES:
                self.send_json(413, {
                    "error": "request body too large",
                    "max_bytes": MAX_POST_BODY_BYTES,
                })
                return
            if path.startswith("/v1/"):
                self.proxy("POST")
            elif path == "/search":
                self.handle_search()
            elif path.startswith("/fs/"):
                self.handle_fs(path[4:])
            elif path == "/param-rejects/clear":
                self.handle_clear_param_rejects()
            else:
                self.send_json(404, {"error": "not found"})
        except Exception as e:
            try:
                self.send_json(500, {"error": str(e)})
            except Exception:
                pass

    # -------- static page
    def serve_page(self):
        if PAGE_BYTES is None:
            self.send_json(500, {
                "error": "No .html file found next to this script. "
                         "Save Deepseek.html here and restart."
            })
            return
        # Inject local token + canonical protected-param list so the
        # frontend never drifts from the server (single source of truth).
        bootstrap = (
            "\n<script>"
            "window.APMIX_LOCAL_TOKEN=%s;"
            "window.APMIX_PROTECTED_PARAMS=%s;"
            "</script>" % (
                json.dumps(LOCAL_TOKEN),
                json.dumps(sorted(PROTECTED_PARAMS)),
            )
        ).encode("utf-8")
        # The bootstrap MUST execute before the page's main JavaScript. The
        # previous implementation injected it immediately before </body>, which
        # was too late because Deepseek.html runs its main script first.
        lower_page = PAGE_BYTES.lower()
        marker = b"</head>"
        i = lower_page.find(marker)
        if i == -1:
            marker = b"<script"
            i = lower_page.find(marker)
        if i != -1:
            payload = PAGE_BYTES[:i] + bootstrap + PAGE_BYTES[i:]
        else:
            payload = bootstrap + PAGE_BYTES
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        # Security headers — CSP allows the inline bootstrap script and
        # the known CDN assets used by the page.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: blob: https:; "
            "connect-src 'self' http://localhost:* http://127.0.0.1:*; "
            "worker-src 'self' blob: https://cdn.jsdelivr.net; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(payload)
        except Exception:
            pass

    # -------- smart models (NO live probe — metadata only)
    def handle_smart_models(self):
        """Return enriched model list with free/paid info.
        Does NOT make any chat completion calls — zero inference tokens used."""
        if not self._token_ok():
            self.send_json(403, {"error": "missing local token"})
            return

        base = UPSTREAM
        upstream_hdr = (self.headers.get("X-Upstream") or "").strip()
        if upstream_hdr:
            parsed = urllib.parse.urlparse(upstream_hdr)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https") or not host:
                self.send_json(400, {"error": "invalid X-Upstream URL"})
                return
            if not host_allowed(host):
                self.send_json(403, {"error": "host not allowed"})
                return
            base = upstream_hdr.rstrip("/")

        auth = self.headers.get("Authorization") or ""

        try:
            models = fetch_models_metadata(base, auth)
            if models is None:
                # Fallback: try direct URL
                self.send_json(502, {
                    "error": "Could not fetch models from upstream",
                    "upstream": base,
                })
                return

            # Add rejected params info
            host = urllib.parse.urlparse(base).hostname or ""
            for m in models:
                mid = str(m.get("id") or m.get("name") or "")
                m["_rejected_params"] = get_rejected_params(mid, host)

            self.send_json(200, {
                "ok": True,
                "models": models,
                "method": "metadata_only_no_live_probe",
                "total": len(models),
                "free_count": sum(1 for m in models if m.get("_free") is True),
                "paid_count": sum(1 for m in models if m.get("_free") is False),
                "unknown_count": sum(1 for m in models if m.get("_free") is None),
            })
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    # -------- model info (NO live probe)
    def handle_model_info(self, model_id):
        """Get detailed info about a specific model without any inference calls."""
        if not self._token_ok():
            self.send_json(403, {"error": "missing local token"})
            return

        model_id = urllib.parse.unquote(model_id)
        if not model_id:
            self.send_json(400, {"error": "missing model id"})
            return

        base = UPSTREAM
        upstream_hdr = (self.headers.get("X-Upstream") or "").strip()
        if upstream_hdr:
            parsed = urllib.parse.urlparse(upstream_hdr)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https") or not host:
                self.send_json(400, {"error": "invalid X-Upstream URL"})
                return
            if not host_allowed(host):
                self.send_json(403, {"error": "host not allowed"})
                return
            base = upstream_hdr.rstrip("/")

        auth = self.headers.get("Authorization") or ""

        try:
            info = get_model_details(base, model_id, auth)
            host = urllib.parse.urlparse(base).hostname or ""
            info["_rejected_params"] = get_rejected_params(model_id, host)
            info["_method"] = "metadata_only_no_live_probe"
            self.send_json(200, {"ok": True, "model": info})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    # -------- param rejects
    def handle_param_rejects(self):
        """Get all cached parameter rejections."""
        if not self._token_ok():
            self.send_json(403, {"error": "missing local token"})
            return
        with _CACHE_LOCK:
            result = {f"{m}@{h}": list(p)
                      for (m, h), p in _PARAM_REJECT_CACHE.items()}
        self.send_json(200, {"ok": True, "rejects": result})

    def handle_clear_param_rejects(self):
        """Clear all cached parameter rejections."""
        if not self._token_ok():
            self.send_json(403, {"error": "missing local token"})
            return
        body = self.read_json()
        model = body.get("model")
        if model:
            with _CACHE_LOCK:
                to_remove = [k for k in _PARAM_REJECT_CACHE
                             if k[0] == model.lower()]
                for key in to_remove:
                    del _PARAM_REJECT_CACHE[key]
            self.send_json(200, {"ok": True, "cleared": model})
        else:
            with _CACHE_LOCK:
                _PARAM_REJECT_CACHE.clear()
            self.send_json(200, {"ok": True, "cleared": "all"})

    # -------- /search
    def handle_search(self):
        if not self._token_ok():
            self.send_json(403, {
                "error": "missing local token — reload the page served by Deepseek.py"
            })
            return
        tavily_key = (self.headers.get("X-Tavily-Key") or "").strip()
        if self.command == "GET":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            query = (params.get("q") or [""])[0].strip()
        else:
            body = self.read_json()
            query = str(body.get("q") or body.get("query") or "").strip()
            if not tavily_key:
                tavily_key = str(body.get("tavilyKey") or "").strip()
        if not query:
            self.send_json(400, {"error": "missing query"})
            return
        self.send_json(200, do_search(query[:400], tavily_key))

    # -------- /fs/*
    def handle_fs(self, action):
        if not self._token_ok():
            self.send_json(403, {
                "error": "missing local token — reload the page served by Deepseek.py"
            })
            return
        # ── SAFETY: hard allowlist — refuse unknown/disabled ops ──
        if action not in AGENT_ALLOWED_OPS:
            self.send_json(403, {
                "error": "operation '%s' is not permitted. Allowed: %s"
                % (action, ", ".join(sorted(AGENT_ALLOWED_OPS)))
            })
            return
        body = self.read_json()
        op = FS_OPS.get(action)
        if op is None:
            self.send_json(404, {"error": "unknown fs op: " + action})
            return
        try:
            root = resolve_workspace(body.get("workspace"))
            result = op(root, body)
        except Exception as e:
            self.send_json(400, {"error": str(e)})
            return
        # ── SAFETY: redact the entire result before it leaves ────
        result = redact_result(result, redact_pii=True)
        result.setdefault("ok", True)
        self.send_json(200, result)

    # -------- /v1/* relay with SMART parameter handling
    def proxy(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length else None

        base = UPSTREAM
        upstream_hdr = (self.headers.get("X-Upstream") or "").strip()
        if upstream_hdr:
            if not self._token_ok():
                self.send_json(403, {"error": "missing local token"})
                return
            parsed = urllib.parse.urlparse(upstream_hdr)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https") or not host:
                self.send_json(400, {"error": "invalid X-Upstream URL"})
                return
            if not host_allowed(host):
                self.send_json(403, {"error": "host not allowed"})
                return
            base = upstream_hdr.rstrip("/")

        parsed_self = urllib.parse.urlparse(self.path)
        path = parsed_self.path
        query = parsed_self.query
        if path.startswith("/v1"):
            path = path[3:]
        if path and not path.startswith("/"):
            path = "/" + path
        target = base + path
        if query:
            target += "?" + query

        auth = self.headers.get("Authorization") or ""
        upstream_host = urllib.parse.urlparse(base).hostname or ""

        # ── Handle /models specially with enrichment ───────────────────
        if path == "/models" and method == "GET":
            try:
                req = urllib.request.Request(target, method="GET")
                req.add_header("User-Agent", UA)
                req.add_header("Accept", "application/json")
                if auth:
                    req.add_header("Authorization", auth)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                    data = json.loads(raw) if raw else {}
                    # Normalize
                    models_list = []
                    if isinstance(data, list):
                        models_list = data
                    elif isinstance(data, dict):
                        models_list = data.get("models") or data.get("data") or []
                    # Enrich
                    enriched = [enrich_model_data(m, upstream_host) for m in models_list if m]
                    # Return enriched
                    self.send_json(200, {
                        "object": "list",
                        "data": enriched,
                        "_smart": True,
                        "_method": "metadata_enrichment_no_live_probe",
                    })
                    return
            except urllib.error.HTTPError as e:
                # Try discovery
                discovered = discover_models_url(base, auth)
                if discovered and discovered != target:
                    target = discovered
                    try:
                        req = urllib.request.Request(target, method="GET")
                        req.add_header("User-Agent", UA)
                        req.add_header("Accept", "application/json")
                        if auth:
                            req.add_header("Authorization", auth)
                        with urllib.request.urlopen(req, timeout=15) as resp:
                            raw = resp.read().decode("utf-8", "replace")
                            data = json.loads(raw) if raw else {}
                            models_list = []
                            if isinstance(data, list):
                                models_list = data
                            elif isinstance(data, dict):
                                models_list = data.get("models") or data.get("data") or []
                            enriched = [enrich_model_data(m, upstream_host) for m in models_list if m]
                            self.send_json(200, {
                                "object": "list",
                                "data": enriched,
                                "_smart": True,
                                "_discovered_url": target,
                            })
                            return
                    except Exception:
                        pass
                # Fall through to normal proxy
            except Exception:
                pass

        # ── FIX for "The last message must have role=user" ────────────
        # DeepSeek + routers that forward to it (Token Harbor, OpenRouter, etc.)
        # reject requests where last != user or first non-system != user.
        # This now delegates to ensure_user_last (full fix, not just empty placeholders).
        def _fix_messages_payload(d):
            try:
                ensure_user_last(
                    d,
                    strict=_needs_strict_user_last(d, upstream_host),
                )
            except Exception:
                pass
            return d

        # ── SMART parameter handling for POST requests ─────────────────
        if method == "POST" and raw_body:
            try:
                body_dict = json.loads(raw_body.decode("utf-8", "replace"))
                body_dict = _fix_messages_payload(body_dict)
                model = body_dict.get("model", "")

                # Preemptively strip known-rejected params
                body_dict = auto_strip_request(body_dict, model, upstream_host)

                # SMART retry loop for parameter rejections
                max_retries = 6
                for attempt in range(max_retries):
                    updated_body = json.dumps(body_dict).encode("utf-8")
                    req = urllib.request.Request(target, data=updated_body, method=method)
                    for header in ("Authorization", "Content-Type", "Accept"):
                        value = self.headers.get(header)
                        if value:
                            req.add_header(header, value)
                    req.add_header("Accept-Encoding", "identity")
                    req.add_header("User-Agent", UA)
                    req.add_header("Content-Length", str(len(updated_body)))

                    try:
                        upstream = urllib.request.urlopen(req, timeout=600)
                        # Success — relay the response
                        self._relay_response_with_note(
                            upstream,
                            note={"_auto_stripped": get_rejected_params(model, upstream_host)}
                            if get_rejected_params(model, upstream_host) else None
                        )
                        return
                    except urllib.error.HTTPError as e:
                        if e.code in (400, 422) and attempt < max_retries - 1:
                            # Read the error body
                            try:
                                error_body = e.read().decode("utf-8", "replace")
                            except Exception:
                                error_body = ""

                            # Find which parameter was rejected
                            rejected_param = find_rejected_param_from_error(error_body)

                            if rejected_param:
                                # Remove the parameter and remember it
                                if strip_param_from_body(body_dict, rejected_param):
                                    add_rejected_param(model, upstream_host, rejected_param)
                                    continue  # Retry without the param
                            # If we can't identify the param, relay the error
                            self._relay_http_error(e, error_body)
                            return
                        else:
                            # Non-parameter error, or max retries reached
                            try:
                                error_body = e.read().decode("utf-8", "replace")
                            except Exception:
                                error_body = ""
                            self._relay_http_error(e, error_body)
                            return
                    except Exception as e:
                        self.send_json(502, {
                            "error": {
                                "message": "Could not reach %s — (%s)" % (target, e)
                            }
                        })
                        return

                # If we get here, all retries failed
                self.send_json(500, {"error": "All retry attempts exhausted"})
                return

            except json.JSONDecodeError:
                pass  # Fall through to normal proxying for non-JSON bodies

        # ── Normal proxying (GET, or POST without valid JSON) ──────────
        req = urllib.request.Request(target, data=raw_body, method=method)
        for header in ("Authorization", "Content-Type", "Accept"):
            value = self.headers.get(header)
            if value:
                req.add_header(header, value)
        req.add_header("Accept-Encoding", "identity")
        req.add_header("User-Agent", UA)

        try:
            upstream = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            try:
                error_body = e.read().decode("utf-8", "replace")
            except Exception:
                error_body = ""
            self._relay_http_error(e, error_body)
            return
        except Exception as e:
            self.send_json(502, {
                "error": {
                    "message": "Could not reach %s — (%s)" % (target, e)
                }
            })
            return

        self._relay_response(upstream)

    def _relay_http_error(self, e, error_body=""):
        """Forward an upstream HTTP error to the client with context."""
        try:
            status = e.code
            # Try to parse the error body for a cleaner message
            error_msg = error_body
            try:
                error_json = json.loads(error_body)
                if isinstance(error_json, dict) and "error" in error_json:
                    error_msg = error_json["error"]
                    if isinstance(error_msg, dict):
                        error_msg = error_msg.get("message") or json.dumps(error_msg)
            except (json.JSONDecodeError, TypeError):
                pass

            self.send_json(status, {
                "error": {
                    "message": error_msg or f"HTTP {status} from upstream",
                    "type": "upstream_error",
                    "code": status,
                }
            })
        except Exception:
            pass

    def _relay_response(self, upstream):
        """Forward an upstream response to the client."""
        try:
            status = getattr(upstream, "status", None) or getattr(upstream, "code", 200)
            self.send_response(int(status))
            for key, value in upstream.headers.items():
                kl = key.lower()
                # Drop content-length so HTTP/1.0 close-delimited framing
                # marks EOF correctly (some SSE gateways set both CL + chunked).
                if kl not in HOP_HEADERS and kl != "content-length":
                    self.send_header(key, value)
            self._cors()
            self.end_headers()
            while True:
                chunk = upstream.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            try:
                upstream.close()
            except Exception:
                pass

    def _relay_response_with_note(self, upstream, note=None):
        """Forward an upstream response, optionally adding metadata."""
        try:
            status = getattr(upstream, "status", None) or getattr(upstream, "code", 200)
            self.send_response(int(status))
            for key, value in upstream.headers.items():
                kl = key.lower()
                # Drop content-length so HTTP/1.0 close-delimited framing
                # marks EOF correctly (some SSE gateways set both CL + chunked).
                if kl not in HOP_HEADERS and kl != "content-length":
                    self.send_header(key, value)
            if note:
                stripped = note.get("_auto_stripped") or []
                if stripped:
                    try:
                        hv = ", ".join(str(p) for p in stripped if p)
                    except Exception:
                        hv = ""
                    if hv:
                        self.send_header("X-Apmix-Auto-Stripped", hv)
            self._cors()
            self.end_headers()
            while True:
                chunk = upstream.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            try:
                upstream.close()
            except Exception:
                pass


# ------------------------------------------------------------------ main
def main():
    if PAGE_BYTES is None:
        print("!!  No .html file found in:")
        print("      " + FOLDER)
        print("    Save Deepseek.html there next to this script, then run again.")
        sys.exit(1)

    server, port = None, None
    for offset in range(PORT_TRIES):
        candidate = BASE_PORT + offset
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate), Handler)
            port = candidate
            break
        except OSError:
            continue
    if server is None:
        print(
            "!!  No free port in %d..%d. Close whatever is using them and retry."
            % (BASE_PORT, BASE_PORT + PORT_TRIES - 1)
        )
        sys.exit(1)

    url = "http://localhost:%d" % port
    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║  apmix chat — SMART MODE                                 ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print()
    print("  ->  " + url)
    print("  serving   %s" % PAGE_NAME)
    print("  upstream  %s (used verbatim — /v1 never auto-appended)" % UPSTREAM)
    print("  allowed   ALLOWED_UPSTREAM_HOSTS + localhost/LAN")
    print("  workspace %s  — set ANY folder or drive in Settings" % realpath(FOLDER))
    print()
    print("  ── SMART FEATURES ──────────────────────────────────────────")
    print("  ✓ Parameter auto-strip: rejected params removed + retried")
    print("    (400 errors = 0 tokens consumed — safe!)")
    print("  ✓ Per-model rejection memory (cached, auto-cleared on restart)")
    print("  ✓ Free model detection: metadata + name patterns only")
    print("    (NO live probe — zero inference tokens used)")
    print("  ✓ Smart /models enrichment with free/paid badges")
    print("  ✓ /smart-models — enriched model list endpoint")
    print("  ✓ /model-info/<id> — detailed model info (no chat calls)")
    print("  ✓ /param-rejects — view/clear rejected parameter cache")
    print()
    print("  ── ENDPOINTS ──────────────────────────────────────────────")
    print("  /v1/*          → relayed to upstream (with smart handling)")
    print("  /smart-models  → enriched model list (free/paid info)")
    print("  /model-info/X  → details for model X (no inference)")
    print("  /param-rejects → see which params each model rejected")
    print("  /search        → web search (Tavily/DuckDuckGo)")
    print("  /fs/*          → filesystem operations (agent mode)")
    print("  /health        → server status")
    print()
    print("  press Ctrl+C to stop")
    print()
    threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped.")
        print("  (param rejection cache cleared)")


if __name__ == "__main__":
    main()