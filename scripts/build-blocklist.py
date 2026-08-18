#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.txt"
OUTPUT_FILE = ROOT / "ads.txt"
LOCAL_FILES = [
    ROOT / "pihole" / "smart-tv-strict-blocklist.txt",
]
MIN_FINAL_RULES = 100_000
MAX_OUTPUT_BYTES = 95 * 1024 * 1024
USER_AGENT = "travismills82-blocklists-ads/1.0 (+https://github.com/travismills82/blocklists-ads)"
RETRIES = 4

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$",
    re.IGNORECASE,
)

COSMETIC_MARKERS = ("##", "#$#", "#@#", "#?#", "#%#")


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or len(value) > 253 or "." not in value:
        return None
    if value.startswith(".") or ".." in value:
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not DOMAIN_RE.fullmatch(value):
        return None
    for label in value.split("."):
        if len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return None
    return value


def parse_line(raw_line: str) -> tuple[set[str], set[str]]:
    exact: set[str] = set()
    abp: set[str] = set()

    line = raw_line.lstrip("\ufeff").strip()
    if not line:
        return exact, abp

    if line.startswith(("#", "!", ";", "[")):
        return exact, abp

    if line.startswith("@@"):
        return exact, abp

    if any(marker in line for marker in COSMETIC_MARKERS):
        return exact, abp

    # DNS-oriented ABP/AdGuard rule. Pi-hole v6+ natively accepts ||domain^.
    if line.startswith("||"):
        token = line.split()[0]
        domain_part = token[2:]
        if "^" in domain_part:
            domain_part = domain_part.split("^", 1)[0]
        else:
            domain_part = re.split(r"[$/|]", domain_part, maxsplit=1)[0]
        domain = normalize_domain(domain_part)
        if domain:
            abp.add(domain)
        return exact, abp

    # Common dnsmasq forms such as address=/example.com/0.0.0.0
    if line.startswith(("address=/", "server=/")):
        parts = line.split("/")
        if len(parts) >= 2:
            domain = normalize_domain(parts[1])
            if domain:
                abp.add(domain)
        return exact, abp

    # URL-based source rows: keep only the hostname.
    if line.startswith(("http://", "https://")):
        try:
            domain = normalize_domain(urllib.parse.urlsplit(line).hostname or "")
        except ValueError:
            domain = None
        if domain:
            exact.add(domain)
        return exact, abp

    # Remove trailing comments only after whitespace.
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    if not line:
        return exact, abp

    tokens = line.split()
    if not tokens:
        return exact, abp

    # HOSTS format: 0.0.0.0 domain or 127.0.0.1 domain
    try:
        ipaddress.ip_address(tokens[0])
        for token in tokens[1:]:
            domain = normalize_domain(token)
            if domain:
                exact.add(domain)
        return exact, abp
    except ValueError:
        pass

    # Wildcard domain syntax. Preserve wildcard semantics as a Pi-hole ABP rule.
    if tokens[0].startswith("*."):
        domain = normalize_domain(tokens[0])
        if domain:
            abp.add(domain)
        return exact, abp

    # Plain one-domain-per-line format.
    domain = normalize_domain(tokens[0])
    if domain:
        exact.add(domain)

    return exact, abp


def read_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        raise SystemExit(f"Missing {SOURCES_FILE.relative_to(ROOT)}")
    sources: list[str] = []
    for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            sources.append(line)
    if not sources:
        raise SystemExit("No sources configured")
    return sources


def fetch_and_parse(url: str) -> tuple[set[str], set[str], int]:
    last_error: Exception | None = None

    for attempt in range(1, RETRIES + 1):
        source_exact: set[str] = set()
        source_abp: set[str] = set()
        lines = 0
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/plain,*/*;q=0.8",
                },
            )
            with urllib.request.urlopen(request, timeout=180) as response:
                status = getattr(response, "status", 200)
                if status and status >= 400:
                    raise RuntimeError(f"HTTP {status}")

                for raw in response:
                    lines += 1
                    line = raw.decode("utf-8", errors="replace")
                    exact, abp = parse_line(line)
                    source_exact.update(exact)
                    source_abp.update(abp)

            if lines == 0 or (not source_exact and not source_abp):
                raise RuntimeError("source returned no usable rules")

            print(
                f"OK  {url}\n"
                f"    lines={lines:,} exact={len(source_exact):,} abp={len(source_abp):,}"
            )
            return source_exact, source_abp, lines

        except Exception as exc:
            last_error = exc
            print(f"WARN attempt {attempt}/{RETRIES} failed for {url}: {exc}", file=sys.stderr)
            if attempt < RETRIES:
                time.sleep(attempt * 3)

    raise RuntimeError(f"Unable to download/parse {url}: {last_error}")


def parse_local_file(path: Path) -> tuple[set[str], set[str], int]:
    if not path.exists():
        raise RuntimeError(f"Missing local blocklist: {path.relative_to(ROOT)}")

    exact: set[str] = set()
    abp: set[str] = set()
    lines = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            lines += 1
            row_exact, row_abp = parse_line(line)
            exact.update(row_exact)
            abp.update(row_abp)

    print(
        f"LOCAL {path.relative_to(ROOT)}\n"
        f"      lines={lines:,} exact={len(exact):,} abp={len(abp):,}"
    )
    return exact, abp, lines


def has_abp_parent(domain: str, abp_domains: set[str], include_self: bool = True) -> bool:
    labels = domain.split(".")
    start = 0 if include_self else 1
    for index in range(start, len(labels) - 1):
        if ".".join(labels[index:]) in abp_domains:
            return True
    return False


def collapse_rules(exact_domains: set[str], abp_domains: set[str]) -> tuple[set[str], set[str]]:
    # A parent ABP rule (||example.com^) covers all subdomains, so child ABP
    # rules and exact entries under that parent are redundant for Pi-hole v6+.
    collapsed_abp: set[str] = set()
    for domain in sorted(abp_domains, key=lambda d: (d.count("."), len(d), d)):
        if not has_abp_parent(domain, collapsed_abp, include_self=False):
            collapsed_abp.add(domain)

    collapsed_exact = {
        domain
        for domain in exact_domains
        if not has_abp_parent(domain, collapsed_abp, include_self=True)
    }

    return collapsed_exact, collapsed_abp


def build_output(exact_domains: set[str], abp_domains: set[str], source_count: int) -> str:
    lines = [
        "# Travis Mills Combined Pi-hole Blocklist",
        "# Automatically rebuilt from configured upstream sources and repository-local exact rules",
        "# Target: Pi-hole v6+ (exact domains plus supported ABP domain rules)",
        f"# Sources: {source_count}",
        f"# Exact rules: {len(exact_domains)}",
        f"# ABP domain rules: {len(abp_domains)}",
        f"# Total rules: {len(exact_domains) + len(abp_domains)}",
        "",
    ]
    lines.extend(sorted(exact_domains))
    lines.extend(f"||{domain}^" for domain in sorted(abp_domains))
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def main() -> int:
    sources = read_sources()
    all_exact: set[str] = set()
    all_abp: set[str] = set()

    print(f"Configured upstream sources: {len(sources)}")

    for url in sources:
        exact, abp, _ = fetch_and_parse(url)
        all_exact.update(exact)
        all_abp.update(abp)

    for local_path in LOCAL_FILES:
        exact, abp, _ = parse_local_file(local_path)
        all_exact.update(exact)
        all_abp.update(abp)

    before_exact = len(all_exact)
    before_abp = len(all_abp)
    all_exact, all_abp = collapse_rules(all_exact, all_abp)

    total = len(all_exact) + len(all_abp)
    if total < MIN_FINAL_RULES:
        raise RuntimeError(
            f"Safety check failed: only {total:,} final rules; expected at least {MIN_FINAL_RULES:,}"
        )

    output = build_output(all_exact, all_abp, len(sources))
    output_bytes = len(output.encode("utf-8"))
    if output_bytes > MAX_OUTPUT_BYTES:
        raise RuntimeError(
            f"Safety check failed: ads.txt would be {output_bytes / 1024 / 1024:.2f} MiB, "
            "too close to GitHub's normal 100 MiB single-file limit"
        )

    current = OUTPUT_FILE.read_text(encoding="utf-8") if OUTPUT_FILE.exists() else None
    if current == output:
        print("ads.txt is already up to date; no file change required.")
    else:
        atomic_write(OUTPUT_FILE, output)
        print("ads.txt updated.")

    print(
        "\nSummary\n"
        f"  upstream sources: {len(sources)}\n"
        f"  raw unique exact domains: {before_exact:,}\n"
        f"  raw unique ABP domains: {before_abp:,}\n"
        f"  final exact rules: {len(all_exact):,}\n"
        f"  final ABP rules: {len(all_abp):,}\n"
        f"  final total rules: {total:,}\n"
        f"  ads.txt size: {output_bytes / 1024 / 1024:.2f} MiB"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
