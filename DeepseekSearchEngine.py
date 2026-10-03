#!/usr/bin/env python3
"""
DeepseekSearchEngine.py — local multi-backend search service for Deepseek.py.

Features
--------
- HTTP API on localhost:1010 (moves upward if busy)
- SearXNG when explicitly enabled and available
- Optional ddgs package backend
- Wikipedia, Hacker News, and DuckDuckGo HTML fallbacks
- SQLite FTS5 local page index with crawling
- Thread-safe LRU/TTL cache
- Parallel backend queries
- Localhost-only CORS
- Request-size limits
- SSRF-aware URL validation for crawl/content fetches
- Python 3.8+ standard-library core; ddgs/Docker are optional

Deepseek.py integration is automatic when this service is running on 1010–1014.
"""

from __future__ import annotations

import argparse
import copy
import html
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_PORT = 1010
PORT_TRIES = 20
CACHE_TTL = 300
CACHE_MAX_ENTRIES = 500
REQUEST_TIMEOUT = 15
MAX_RESULTS_DEFAULT = 10
MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024
MAX_INDEX_CONTENT_BYTES = 500_000
MAX_FETCH_CONTENT_CHARS = 4000
MAX_CRAWL_PAGES = 100
CRAWL_DELAY = 1.0
SEARCH_WORKERS = 6

SEARXNG_PORTS = [8888, 8080, 8889]
SEARXNG_DOCKER_IMAGE = os.environ.get("SEARXNG_DOCKER_IMAGE", "searxng/searxng:latest")
SEARXNG_DOCKER_PORT = 8888

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX_DB = os.path.join(HERE, "search_index.db")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0 Safari/537.36"
)

ALLOW_PRIVATE_FETCH = os.environ.get("DEEPSEEK_SEARCH_ALLOW_PRIVATE", "0") == "1"


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{time.strftime('%H:%M:%S')}] [{level:4s}] {msg}")


def _is_loopback_or_private_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in {"localhost", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return any(
            ipaddress.ip_address(info[4][0]).is_private
            or ipaddress.ip_address(info[4][0]).is_loopback
            or ipaddress.ip_address(info[4][0]).is_link_local
            or ipaddress.ip_address(info[4][0]).is_reserved
            for info in infos
        )
    except Exception:
        return False


def validate_remote_url(url: str, *, allow_private: bool = False) -> str:
    """Validate a URL before any outbound fetch/crawl request."""
    p = urllib.parse.urlparse(str(url).strip())
    if p.scheme not in {"http", "https"}:
        raise ValueError("only http/https URLs are allowed")
    if not p.hostname:
        raise ValueError("URL has no hostname")
    if not allow_private and not ALLOW_PRIVATE_FETCH and _is_loopback_or_private_host(p.hostname):
        raise ValueError("private/loopback destinations are blocked")
    if p.username or p.password:
        raise ValueError("URLs containing embedded credentials are blocked")
    return urllib.parse.urlunparse(p._replace(fragment=""))


def http_get_text(url: str, headers: dict | None = None, timeout: int = REQUEST_TIMEOUT, allow_private: bool = False) -> str:
    url = validate_remote_url(url, allow_private=allow_private)
    hdrs = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(5_000_001)
    if len(raw) > 5_000_000:
        raw = raw[:5_000_000]
    return raw.decode("utf-8", "replace")


def http_get_json(url: str, headers: dict | None = None, timeout: int = REQUEST_TIMEOUT, allow_private: bool = False) -> dict:
    text = http_get_text(url, headers=headers, timeout=timeout, allow_private=allow_private)
    return json.loads(text) if text else {}


class SearchCache:
    def __init__(self, max_entries: int = CACHE_MAX_ENTRIES, ttl: int = CACHE_TTL):
        self._cache = OrderedDict()
        self._lock = threading.RLock()
        self._max = max_entries
        self._ttl = ttl
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _key(query: str, limit: int) -> str:
        return f"{query.strip().casefold()}\x00{limit}"

    def get(self, query: str, limit: int):
        key = self._key(query, limit)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            if time.time() - entry["ts"] > self._ttl:
                self._cache.pop(key, None)
                self._misses += 1
                return None
            self._cache.move_to_end(key)
            self._hits += 1
            return copy.deepcopy(entry["data"])

    def set(self, query: str, limit: int, data: dict) -> None:
        key = self._key(query, limit)
        with self._lock:
            self._cache[key] = {"ts": time.time(), "data": copy.deepcopy(data)}
            self._cache.move_to_end(key)
            while len(self._cache) > self._max:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> dict:
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries": len(self._cache),
                "max_entries": self._max,
                "ttl_seconds": self._ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round((self._hits / total) * 100, 1) if total else 0,
            }


class SearXNGManager:
    def __init__(self):
        self.running_url = None
        self.docker_container = None
        self._lock = threading.Lock()

    def detect(self):
        with self._lock:
            if self.running_url:
                return self.running_url
            for port in SEARXNG_PORTS:
                url = f"http://127.0.0.1:{port}"
                try:
                    data = http_get_json(
                        f"{url}/search?q=test&format=json",
                        headers={"Accept": "application/json"},
                        timeout=3,
                        allow_private=True,
                    )
                    if isinstance(data, dict) and "results" in data:
                        self.running_url = url
                        log(f"SearXNG detected at {url}", "OK")
                        return url
                except Exception:
                    continue
        return None

    def _write_settings(self, settings_dir: str) -> str:
        os.makedirs(settings_dir, exist_ok=True)
        settings_path = os.path.join(settings_dir, "settings.yml")
        if not os.path.exists(settings_path):
            secret = os.urandom(32).hex()
            with open(settings_path, "w", encoding="utf-8") as f:
                f.write(
                    "use_default_settings: true\n\n"
                    "server:\n"
                    f"  secret_key: \"{secret}\"\n"
                    "  bind_address: \"0.0.0.0\"\n"
                    "  port: 8080\n\n"
                    "search:\n"
                    "  formats:\n"
                    "    - html\n"
                    "    - json\n"
                    "  autocomplete: \"\"\n"
                    "  default_lang: \"\"\n"
                )
        return settings_path

    def start_docker(self):
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

        container = "searxng-searchengine"
        try:
            existing = subprocess.run(
                ["docker", "ps", "-a", "--filter", f"name=^{container}$", "--format", "{{{{.Names}}}}"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            if existing == container:
                running = subprocess.run(
                    ["docker", "ps", "--filter", f"name=^{container}$", "--format", "{{{{.Names}}}}"],
                    capture_output=True, text=True, timeout=5,
                ).stdout.strip()
                if running != container:
                    subprocess.run(["docker", "start", container], capture_output=True, timeout=30)
                self.docker_container = container
                self.running_url = f"http://127.0.0.1:{SEARXNG_DOCKER_PORT}"
                return self.running_url
        except Exception as exc:
            log(f"Docker inspection failed: {exc}", "WARN")

        settings_dir = os.path.join(HERE, "searxng_settings")
        try:
            self._write_settings(settings_dir)
            result = subprocess.run(
                [
                    "docker", "run", "-d", "--name", container,
                    "-p", f"127.0.0.1:{SEARXNG_DOCKER_PORT}:8080",
                    "-v", f"{settings_dir}:/etc/searxng",
                    "--restart", "unless-stopped",
                    "-m", "256m",
                    SEARXNG_DOCKER_IMAGE,
                ],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                log(result.stderr.strip() or "SearXNG docker start failed", "WARN")
                return None
            self.docker_container = container
            self.running_url = f"http://127.0.0.1:{SEARXNG_DOCKER_PORT}"
            for _ in range(30):
                time.sleep(1)
                try:
                    req = urllib.request.Request(f"{self.running_url}/healthz", headers={"User-Agent": UA})
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        if resp.status == 200:
                            log("SearXNG started", "OK")
                            return self.running_url
                except Exception:
                    continue
            log("SearXNG container started; readiness check timed out", "WARN")
            return self.running_url
        except Exception as exc:
            log(f"Failed to start SearXNG: {exc}", "WARN")
            return None

    def stop_docker(self):
        if not self.docker_container:
            return
        try:
            subprocess.run(["docker", "stop", self.docker_container], capture_output=True, timeout=30)
        except Exception as exc:
            log(f"Failed to stop SearXNG: {exc}", "WARN")

    def search(self, query, max_results=MAX_RESULTS_DEFAULT):
        if not self.running_url:
            return None
        try:
            data = http_get_json(
                f"{self.running_url}/search?{urllib.parse.urlencode({'q': query, 'format': 'json'})}",
                timeout=10,
                allow_private=True,
            )
            rows = []
            for item in (data.get("results") or [])[:max_results]:
                url = item.get("url") or ""
                if not url.startswith(("http://", "https://")):
                    continue
                rows.append({"title": item.get("title") or url, "url": url, "snippet": (item.get("content") or "")[:1200]})
            return {"provider": "searxng", "query": query, "answer": "", "results": rows} if rows else None
        except Exception as exc:
            log(f"SearXNG search failed: {exc}", "WARN")
            return None


def search_ddgs(query, max_results=MAX_RESULTS_DEFAULT):
    try:
        from ddgs import DDGS
    except ImportError:
        return None
    try:
        rows = []
        for item in DDGS().text(query, max_results=max_results):
            url = item.get("href") or ""
            if not url.startswith(("http://", "https://")):
                continue
            rows.append({"title": item.get("title") or url, "url": url, "snippet": (item.get("body") or "")[:1200]})
        return {"provider": "ddgs", "query": query, "answer": "", "results": rows} if rows else None
    except Exception as exc:
        log(f"ddgs failed: {exc}", "WARN")
        return None


def search_wikipedia(query, max_results=5):
    try:
        url = "https://en.wikipedia.org/w/api.php?" + urllib.parse.urlencode({
            "action": "query", "list": "search", "format": "json", "srsearch": query,
            "srlimit": min(max_results, 10),
        })
        data = http_get_json(url, timeout=10)
        rows = []
        for item in data.get("query", {}).get("search", []):
            title = item.get("title") or ""
            rows.append({
                "title": title,
                "url": "https://en.wikipedia.org/wiki/" + urllib.parse.quote(title.replace(" ", "_")),
                "snippet": re.sub(r"<[^>]+>", "", item.get("snippet", ""))[:1000],
            })
        return {"provider": "wikipedia", "query": query, "answer": "", "results": rows} if rows else None
    except Exception as exc:
        log(f"Wikipedia failed: {exc}", "WARN")
        return None


def search_hackernews(query, max_results=5):
    try:
        url = "https://hn.algolia.com/api/v1/search?" + urllib.parse.urlencode({"query": query, "hitsPerPage": min(max_results, 10)})
        data = http_get_json(url, timeout=10)
        rows = []
        for item in data.get("hits", []):
            title = item.get("title") or ""
            if not title:
                continue
            rows.append({
                "title": title,
                "url": item.get("url") or f"https://news.ycombinator.com/item?id={item.get('objectID', '')}",
                "snippet": (item.get("story_text") or "")[:1000],
            })
        return {"provider": "hackernews", "query": query, "answer": "", "results": rows} if rows else None
    except Exception as exc:
        log(f"Hacker News failed: {exc}", "WARN")
        return None


_TAG_RE = re.compile(r"<[^>]+>", re.S)
_DDG_LINK_A = re.compile(r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S | re.I)
_DDG_LINK_B = re.compile(r'<a[^>]*href="([^"]+)"[^>]*class="result__a"[^>]*>(.*?)</a>', re.S | re.I)
_DDG_SNIP = re.compile(r'<a[^>]*class="result__snippet[^"]*"[^>]*>(.*?)</a>', re.S | re.I)


def strip_tags(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(_TAG_RE.sub("", value or ""))).strip()


def ddg_unwrap(href: str) -> str:
    if href.startswith("//"):
        href = "https:" + href
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        return q["uddg"][0] if q.get("uddg") else href
    except Exception:
        return href


def search_duckduckgo_html(query, max_results=MAX_RESULTS_DEFAULT):
    try:
        page = http_get_text(
            "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query}),
            headers={"Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9"},
            timeout=15,
        )
        links = _DDG_LINK_A.findall(page) or _DDG_LINK_B.findall(page)
        snips = _DDG_SNIP.findall(page)
        rows = []
        for i, (href, title_html) in enumerate(links[:max_results]):
            href = ddg_unwrap(href)
            if not href.startswith(("http://", "https://")):
                continue
            rows.append({"title": strip_tags(title_html) or href, "url": href, "snippet": strip_tags(snips[i]) if i < len(snips) else ""})
        return {"provider": "duckduckgo_html", "query": query, "answer": "", "results": rows} if rows else None
    except Exception as exc:
        log(f"DuckDuckGo HTML failed: {exc}", "WARN")
        return None


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.title = []
        self.text = []
        self._title_depth = 0
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "title":
            self._title_depth += 1
        elif tag in {"script", "style", "nav", "footer", "header", "noscript"}:
            self._skip_depth += 1
        elif tag == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.links.append(value)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._title_depth = max(0, self._title_depth - 1)
        elif tag in {"script", "style", "nav", "footer", "header", "noscript"}:
            self._skip_depth = max(0, self._skip_depth - 1)

    def handle_data(self, data):
        if self._title_depth:
            self.title.append(data)
        elif not self._skip_depth:
            self.text.append(data)


class LocalIndex:
    def __init__(self, db_path=INDEX_DB):
        self.db_path = db_path
        self._schema_lock = threading.Lock()
        self._init_db()

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def _init_db(self):
        with self._schema_lock:
            db = self._connect()
            try:
                db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS pages USING fts5(url, title, content, fetched_at UNINDEXED)")
                db.execute("CREATE TABLE IF NOT EXISTS crawl_log(url TEXT PRIMARY KEY, fetched_at REAL, status TEXT)")
                db.commit()
            finally:
                db.close()
        log(f"Local index initialized: {self.db_path}", "OK")

    def index_page(self, url, title, content):
        url = validate_remote_url(url, allow_private=True)
        content = str(content)[:MAX_INDEX_CONTENT_BYTES]
        db = self._connect()
        try:
            db.execute("DELETE FROM pages WHERE url = ?", (url,))
            db.execute("INSERT INTO pages(url,title,content,fetched_at) VALUES(?,?,?,?)", (url, str(title)[:500], content, time.time()))
            db.execute("INSERT OR REPLACE INTO crawl_log(url,fetched_at,status) VALUES(?,?,?)", (url, time.time(), "ok"))
            db.commit()
        finally:
            db.close()

    def search(self, query, limit=10):
        tokens = re.findall(r"[A-Za-z0-9_]+", str(query or ""))
        if not tokens:
            return None
        safe = " OR ".join('"' + t.replace('"', '""') + '"' for t in tokens)
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT url,title,snippet(pages,2,'→','←','...',30) "
                "FROM pages WHERE pages MATCH ? ORDER BY bm25(pages) LIMIT ?",
                (safe, max(1, min(int(limit), 50))),
            ).fetchall()
        except sqlite3.Error as exc:
            log(f"Local index search failed: {exc}", "WARN")
            return None
        finally:
            db.close()
        results = [{"title": r[1], "url": r[0], "snippet": r[2] or ""} for r in rows]
        return {"provider": "local_index", "query": query, "answer": "", "results": results} if results else None

    def crawl(self, start_url, max_pages=MAX_CRAWL_PAGES, same_domain=True):
        start_url = validate_remote_url(start_url)
        max_pages = max(1, min(int(max_pages), 1000))
        base_domain = urllib.parse.urlparse(start_url).netloc.lower()
        queue = deque([start_url])
        queued = {start_url}
        visited = set()
        crawled = 0
        errors = 0

        log(f"Starting crawl: {start_url} (max {max_pages} pages)")
        while queue and crawled < max_pages:
            url = queue.popleft()
            visited.add(url)
            if same_domain and urllib.parse.urlparse(url).netloc.lower() != base_domain:
                continue
            try:
                page = http_get_text(url, timeout=10)
                parser = LinkExtractor()
                parser.feed(page)
                title = " ".join(parser.title).strip() or url
                content = re.sub(r"\s+", " ", " ".join(parser.text)).strip()
                self.index_page(url, title, content)
                crawled += 1
                for href in parser.links:
                    absolute = urllib.parse.urldefrag(urllib.parse.urljoin(url, href))[0]
                    parsed = urllib.parse.urlparse(absolute)
                    if parsed.scheme not in {"http", "https"}:
                        continue
                    absolute = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
                    if absolute in queued or absolute in visited:
                        continue
                    if same_domain and parsed.netloc.lower() != base_domain:
                        continue
                    try:
                        validate_remote_url(absolute)
                    except ValueError:
                        continue
                    queue.append(absolute)
                    queued.add(absolute)
                time.sleep(max(0.0, CRAWL_DELAY))
            except Exception as exc:
                errors += 1
                if errors <= 3:
                    log(f"Failed to fetch {url}: {exc}", "WARN")
        return {"crawled": crawled, "errors": errors, "visited": len(visited)}

    def stats(self):
        db = self._connect()
        try:
            total = db.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
            last = db.execute("SELECT MAX(fetched_at) FROM pages").fetchone()[0]
        except Exception:
            total, last = 0, None
        finally:
            db.close()
        return {
            "total_pages": total,
            "last_crawl": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last)) if last else "never",
            "db_size_bytes": os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
        }


class SearchEngine:
    def __init__(self, use_searxng=True):
        self.cache = SearchCache()
        self.searxng = SearXNGManager()
        self.local_index = LocalIndex()
        self._stats_lock = threading.Lock()
        self.backends = []

        if use_searxng:
            self.searxng.detect()
            if not self.searxng.running_url:
                self.searxng.start_docker()

        if self.searxng.running_url:
            self.backends.append(("searxng", self.searxng.search, 1.0))
        self.backends.extend([
            ("ddgs", search_ddgs, 0.9),
            ("local_index", self.local_index.search, 0.85),
            ("wikipedia", search_wikipedia, 0.7),
            ("hackernews", search_hackernews, 0.6),
            ("duckduckgo_html", search_duckduckgo_html, 0.5),
        ])
        self.backend_stats = {name: {"calls": 0, "successes": 0, "failures": 0} for name, _, _ in self.backends}

    def _bump(self, name, key):
        with self._stats_lock:
            self.backend_stats[name][key] += 1

    def search(self, query, limit=MAX_RESULTS_DEFAULT, use_cache=True):
        query = str(query or "").strip()
        limit = max(1, min(int(limit), 50))
        if not query:
            raise ValueError("query cannot be empty")
        if use_cache:
            cached = self.cache.get(query, limit)
            if cached is not None:
                cached["cached"] = True
                return cached

        all_results = []
        successful = []
        max_workers = max(1, min(SEARCH_WORKERS, len(self.backends)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for name, fn, weight in self.backends:
                self._bump(name, "calls")
                futures[pool.submit(fn, query, limit)] = (name, weight)
            for fut in as_completed(futures):
                name, weight = futures[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    self._bump(name, "failures")
                    log(f"Backend '{name}' error: {exc}", "WARN")
                    continue
                if not result or not result.get("results"):
                    self._bump(name, "failures")
                    continue
                self._bump(name, "successes")
                successful.append(name)
                for i, row in enumerate(result["results"]):
                    url = row.get("url") or ""
                    if not url.startswith(("http://", "https://")):
                        continue
                    all_results.append({**row, "_source": name, "_score": weight / (i + 1)})

        unique = []
        seen_urls = set()
        for row in sorted(all_results, key=lambda x: -x["_score"]):
            key = row["url"].rstrip("/").lower()
            if key in seen_urls:
                continue
            seen_urls.add(key)
            unique.append({k: v for k, v in row.items() if not k.startswith("_")})
            if len(unique) >= limit:
                break

        result = {
            "query": query,
            "cached": False,
            "backends_used": sorted(set(successful)),
            "total_found": len(all_results),
            "unique_results": len(unique),
            "results": unique,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if use_cache:
            self.cache.set(query, limit, result)
        return result

    def search_with_content(self, query, limit=5, fetch_top=3):
        result = self.search(query, limit)
        fetch_top = max(0, min(int(fetch_top), min(5, len(result["results"]))))
        for row in result["results"][:fetch_top]:
            try:
                url = validate_remote_url(row.get("url", ""))
                page = http_get_text(url, timeout=10)
                text = re.sub(r"<script[^>]*>.*?</script>", " ", page, flags=re.S | re.I)
                text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.S | re.I)
                text = strip_tags(text)
                row["full_content"] = text[:MAX_FETCH_CONTENT_CHARS]
            except Exception:
                row["full_content"] = ""
        # Never mutate the cached object with full_content.
        result["cached"] = False
        return result

    def get_stats(self):
        with self._stats_lock:
            backend_stats = copy.deepcopy(self.backend_stats)
        return {
            "cache": self.cache.stats(),
            "backends": backend_stats,
            "local_index": self.local_index.stats(),
            "searxng_url": self.searxng.running_url,
        }


START_TIME = time.time()


def _local_origin(origin: str | None) -> bool:
    if not origin:
        return False
    try:
        p = urllib.parse.urlparse(origin)
        return p.scheme in {"http", "https"} and (p.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}
    except Exception:
        return False


class APIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    engine = None
    server_version = "DeepseekSearchEngine/2.0"

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        origin = self.headers.get("Origin")
        if _local_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_error(self, code, message):
        self._send_json(code, {"error": str(message)})

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin and not _local_origin(origin):
            self._send_error(403, "CORS origin not allowed")
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("invalid Content-Length")
        if length < 0 or length > MAX_HTTP_BODY_BYTES:
            raise OverflowError("request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            raise ValueError("invalid JSON")
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        try:
            if path == "/search":
                q = (params.get("q") or [""])[0].strip()
                if not q:
                    return self._send_error(400, "missing 'q' parameter")
                try:
                    limit = int((params.get("limit") or [str(MAX_RESULTS_DEFAULT)])[0])
                except ValueError:
                    return self._send_error(400, "limit must be an integer")
                self._send_json(200, self.engine.search(q, max(1, min(limit, 50))))
            elif path == "/search/enhanced":
                q = (params.get("q") or [""])[0].strip()
                if not q:
                    return self._send_error(400, "missing 'q' parameter")
                try:
                    limit = int((params.get("limit") or ["5"])[0])
                    fetch_top = int((params.get("fetch_top") or ["3"])[0])
                except ValueError:
                    return self._send_error(400, "limit and fetch_top must be integers")
                self._send_json(200, self.engine.search_with_content(q, max(1, min(limit, 50)), max(0, min(fetch_top, 5))))
            elif path == "/health":
                self._send_json(200, {
                    "status": "ok", "version": "2.0",
                    "searxng": self.engine.searxng.running_url,
                    "backends": [name for name, _, _ in self.engine.backends],
                    "uptime": round(time.time() - START_TIME, 1),
                })
            elif path == "/stats":
                self._send_json(200, self.engine.get_stats())
            elif path == "/backends":
                self._send_json(200, {"backends": [
                    {"name": name, "weight": weight, **self.engine.backend_stats.get(name, {})}
                    for name, _, weight in self.engine.backends
                ]})
            elif path in {"/", ""}:
                self._send_root()
            else:
                self._send_error(404, "not found")
        except Exception as exc:
            log(f"GET handler error: {exc}", "ERR")
            self._send_error(500, str(exc))

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            body = self._read_json_body()
        except OverflowError as exc:
            return self._send_error(413, str(exc))
        except ValueError as exc:
            return self._send_error(400, str(exc))

        try:
            if path == "/crawl":
                url = str(body.get("url") or "").strip()
                if not url:
                    return self._send_error(400, "missing 'url'")
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url
                try:
                    url = validate_remote_url(url)
                except ValueError as exc:
                    return self._send_error(400, str(exc))
                max_pages = max(1, min(int(body.get("max_pages", MAX_CRAWL_PAGES)), 1000))
                same_domain = bool(body.get("same_domain", True))

                def run():
                    result = self.engine.local_index.crawl(url, max_pages, same_domain)
                    log(f"Crawl result: {result}", "OK")
                threading.Thread(target=run, daemon=True, name="search-crawl").start()
                self._send_json(202, {"ok": True, "message": f"crawl started for {url}", "max_pages": max_pages, "same_domain": same_domain})
            elif path == "/index":
                url = str(body.get("url") or "").strip()
                title = str(body.get("title") or url)
                content = str(body.get("content") or "")
                if not url or not content:
                    return self._send_error(400, "missing 'url' or 'content'")
                if len(content.encode("utf-8")) > MAX_INDEX_CONTENT_BYTES:
                    return self._send_error(413, "content too large")
                self.engine.local_index.index_page(url, title, content)
                self._send_json(200, {"ok": True, "message": f"indexed {url}"})
            elif path == "/cache/clear":
                self.engine.cache.clear()
                self._send_json(200, {"ok": True, "message": "cache cleared"})
            else:
                self._send_error(404, "not found")
        except (ValueError, TypeError) as exc:
            self._send_error(400, str(exc))
        except Exception as exc:
            log(f"POST handler error: {exc}", "ERR")
            self._send_error(500, str(exc))

    def _send_root(self):
        port = self.server.server_address[1]
        html_doc = f'''<!doctype html><html><head><meta charset="utf-8"><title>Deepseek Search Engine</title>
<style>body{{font-family:system-ui;max-width:850px;margin:40px auto;padding:0 20px;background:#0f1117;color:#e9ecf5}}h1{{color:#6d6afe}}code,pre{{background:#1c2030;padding:2px 6px;border-radius:4px}}.endpoint{{margin:12px 0;padding:12px;background:#151823;border:1px solid #272c3f;border-radius:8px}}.method{{color:#34d399;font-weight:bold;margin-right:8px}}</style></head>
<body><h1>🔍 Deepseek Search Engine v2</h1><p>Running on <code>http://127.0.0.1:{port}</code>.</p>
<div class="endpoint"><span class="method">GET</span><code>/search?q=...</code> multi-backend search</div>
<div class="endpoint"><span class="method">GET</span><code>/search/enhanced?q=...</code> search + page content</div>
<div class="endpoint"><span class="method">GET</span><code>/health</code> health/status</div>
<div class="endpoint"><span class="method">GET</span><code>/stats</code> cache/backend/index stats</div>
<div class="endpoint"><span class="method">POST</span><code>/crawl</code> crawl and index a public HTTP(S) site</div>
<div class="endpoint"><span class="method">POST</span><code>/index</code> manually add a page</div>
<div class="endpoint"><span class="method">POST</span><code>/cache/clear</code> clear search cache</div>
<p>Deepseek.py probes this service automatically on ports 1010–1014, or use <code>DEEPSEEK_SEARCH_URL</code>.</p></body></html>'''
        data = html_doc.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


class QuietHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError)):
            return  # client hung up mid-request; nothing to do
        super().handle_error(request, client_address)


def bind_server(base_port: int):
    for offset in range(PORT_TRIES):
        port = base_port + offset
        try:
            return QuietHTTPServer(("127.0.0.1", port), APIHandler), port
        except OSError:
            continue
    return None, None

def main():
    parser = argparse.ArgumentParser(description="Deepseek Search Engine")
    parser.add_argument("--port", type=int, default=BASE_PORT)
    parser.add_argument("--with-searxng", action="store_true", help="detect/start SearXNG")
    parser.add_argument("--no-searxng", action="store_true", help="disable SearXNG")
    parser.add_argument("--crawl", nargs="+", metavar="ARG", help="crawl URL [MAX_PAGES] and exit")
    parser.add_argument("--stats", action="store_true", help="show local index stats and exit")
    args = parser.parse_args()

    engine = SearchEngine(use_searxng=bool(args.with_searxng and not args.no_searxng))

    if args.crawl:
        depth = int(args.crawl[1]) if len(args.crawl) > 1 else MAX_CRAWL_PAGES
        print(json.dumps(engine.local_index.crawl(args.crawl[0], depth), indent=2))
        return
    if args.stats:
        print(json.dumps(engine.get_stats(), indent=2))
        return

    APIHandler.engine = engine
    server, port = bind_server(args.port)
    if server is None:
        print(f"No free port in range {args.port}-{args.port + PORT_TRIES - 1}", file=sys.stderr)
        raise SystemExit(1)

    print()
    print("  ╔═══════════════════════════════════════════════════════════════╗")
    print("  ║             🔍  DEEPSEEK SEARCH ENGINE  v2.0                 ║")
    print("  ╚═══════════════════════════════════════════════════════════════╝")
    print(f"  API:     http://127.0.0.1:{port}")
    print(f"  SearXNG: {engine.searxng.running_url or 'disabled / unavailable'}")
    print(f"  Index:   {INDEX_DB}")
    print("  Ctrl+C to stop")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        server.server_close()
        engine.searxng.stop_docker()


if __name__ == "__main__":
    main()