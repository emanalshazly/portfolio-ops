#!/usr/bin/env python3
"""Build a conservative inventory of MONNA's prompt/research corpus.

The script never changes source files. It emits a CSV manifest, a JSON summary,
and a Markdown quarantine report. Unknown provenance is quarantined by design.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".json", ".yaml", ".yml"}
IGNORED_DIRS = {
    ".git", ".next", ".nuxt", ".venv", "venv", "node_modules", "dist",
    "build", "coverage", "__pycache__", ".cache", ".turbo", "vendor",
}
UNSAFE_PATH_MARKERS = {"system_prompts_leaks", "prompt leak", "system prompt leak"}
EXTERNAL_PATH_MARKERS = {
    "github", "download", "scrape", "dataset", "data-202", "system_prompts",
    "claudeprojects", "export", "archive",
}

DOMAIN_RULES = {
    "cybersecurity": ("security", "cyber", "incident", "vulnerability", "prompt injection", "jailbreak", "threat"),
    "growth": ("marketing", "sales", "email", "seo", "content", "campaign", "brand", "viral", "audience"),
    "education": ("education", "learning", "course", "teacher", "student", "tutor", "study"),
    "research": ("research", "literature", "scientific", "evidence", "analysis", "dataset", "benchmark"),
    "business": ("business", "strategy", "finance", "product", "market", "client", "pricing", "legal"),
    "agent_design": ("agent", "workflow", "automation", "orchestrat", "tool use", "multi-agent"),
}

USE_CASE_RULES = {
    "prompt_product": ("prompt", "instructions", "variables", "output format"),
    "research_note": ("research", "evidence", "findings", "sources", "literature"),
    "implementation_plan": ("roadmap", "todo", "implementation", "architecture", "technical specification"),
    "marketing_asset": ("listing", "sales copy", "landing page", "campaign", "seo"),
    "evaluation_asset": ("benchmark", "rubric", "test case", "evaluation", "score"),
}

SENSITIVE_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def read_text(path: Path) -> tuple[str, str | None]:
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "cp1252"):
        try:
            return path.read_text(encoding=encoding), None
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            return "", str(exc)
    return "", "unsupported_encoding"


def normalized_hash(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip().casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def detect_language(text: str) -> str:
    sample = text[:20000]
    arabic = len(re.findall(r"[\u0600-\u06FF]", sample))
    latin = len(re.findall(r"[A-Za-z]", sample))
    if arabic and latin and min(arabic, latin) / max(arabic, latin) >= 0.15:
        return "mixed_ar_en"
    if arabic > latin:
        return "ar"
    if latin:
        return "en"
    return "unknown"


def best_label(haystack: str, rules: dict[str, tuple[str, ...]], fallback: str) -> str:
    scored = {label: sum(haystack.count(term) for term in terms) for label, terms in rules.items()}
    label, score = max(scored.items(), key=lambda item: item[1])
    return label if score else fallback


def provenance(relative: str) -> tuple[str, str]:
    lowered = relative.casefold()
    if any(marker in lowered for marker in UNSAFE_PATH_MARKERS):
        return "external_or_leaked", "restricted"
    if any(marker in lowered for marker in EXTERNAL_PATH_MARKERS):
        return "external_or_imported", "unknown"
    return "internal_candidate", "unknown"


def nearby_license(path: Path, root: Path) -> str:
    current = path.parent
    while current == root or root in current.parents:
        for name in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
            candidate = current / name
            if candidate.is_file():
                text, _ = read_text(candidate)
                first = next((line.strip() for line in text.splitlines() if line.strip()), "license_file_present")
                return first[:120]
        if current == root:
            break
        current = current.parent
    return "unknown"


def quality_score(text: str, title: str, error: str | None) -> int:
    if error:
        return 0
    words = re.findall(r"\w+", text, flags=re.UNICODE)
    score = 25
    score += 20 if len(words) >= 150 else 10 if len(words) >= 50 else 0
    score += 15 if len(set(word.casefold() for word in words)) >= 75 else 5
    score += 10 if re.search(r"(?m)^(?:#{1,4}\s|\s*[-*]\s)", text) else 0
    score += 10 if re.search(r"(?i)example|مثال|output|مخرجات", text) else 0
    score += 10 if re.search(r"(?i)source|reference|مصدر|مراجع|https?://", text) else 0
    score += 10 if title and title.casefold() not in {"untitled", "todo", "pasted_content"} else 0
    return min(score, 100)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    candidates = sorted(
        path for path in source.rglob("*")
        if path.is_file()
        and path.suffix.casefold() in TEXT_EXTENSIONS
        and not any(part.casefold() in IGNORED_DIRS for part in path.relative_to(source).parts)
    )

    rows: list[dict[str, object]] = []
    hash_members: dict[str, list[int]] = defaultdict(list)
    for path in candidates:
        relative = path.relative_to(source).as_posix()
        text, error = read_text(path)
        digest = normalized_hash(text) if not error else hashlib.sha256(relative.encode()).hexdigest()
        source_type, forced_license = provenance(relative)
        license_value = forced_license if forced_license == "restricted" else nearby_license(path, source)
        lowered = f"{relative}\n{text[:30000]}".casefold()
        sensitive = any(pattern.search(text) for pattern in SENSITIVE_PATTERNS)
        risk_reasons = []
        if source_type == "external_or_leaked": risk_reasons.append("leaked/system-prompt material")
        if source_type == "external_or_imported": risk_reasons.append("external/imported provenance")
        if license_value == "unknown": risk_reasons.append("license unknown")
        if sensitive: risk_reasons.append("possible embedded secret")
        risk = "critical" if sensitive else "high" if source_type == "external_or_leaked" else "medium" if risk_reasons else "low"
        status = "quarantine" if risk != "low" else "reviewed_candidate"
        row = {
            "id": f"asset_{len(rows)+1:05d}",
            "path": relative,
            "title": path.stem,
            "extension": path.suffix.casefold(),
            "bytes": path.stat().st_size,
            "word_count": len(re.findall(r"\w+", text, flags=re.UNICODE)),
            "language": detect_language(text),
            "domain": best_label(lowered, DOMAIN_RULES, "uncategorized"),
            "use_case": best_label(lowered, USE_CASE_RULES, "reference_or_other"),
            "source": source_type,
            "license": license_value,
            "risk": risk,
            "risk_reason": "; ".join(risk_reasons) or "none detected",
            "quality_score": quality_score(text, path.stem, error),
            "content_sha256": digest,
            "duplicate_group": "",
            "status": status,
            "read_error": error or "",
        }
        hash_members[digest].append(len(rows))
        rows.append(row)

    duplicate_groups = 0
    duplicate_files = 0
    for digest, indexes in hash_members.items():
        if len(indexes) < 2:
            continue
        duplicate_groups += 1
        group = f"dup_{duplicate_groups:04d}"
        duplicate_files += len(indexes)
        for index in indexes:
            rows[index]["duplicate_group"] = group
            if rows[index]["status"] == "reviewed_candidate":
                rows[index]["status"] = "duplicate_review"

    fields = list(rows[0]) if rows else ["id", "path"]
    with (output / "corpus_manifest.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    review_queue = sorted(
        (
            row for row in rows
            if row["source"] == "internal_candidate"
            and row["risk"] != "critical"
            and not row["duplicate_group"]
        ),
        key=lambda row: (-int(row["quality_score"]), str(row["path"])),
    )
    with (output / "publication_review_queue.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(review_queue)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "grain": "one row per eligible text file",
        "total_files": len(rows),
        "total_words": sum(int(row["word_count"]) for row in rows),
        "status_counts": Counter(str(row["status"]) for row in rows),
        "risk_counts": Counter(str(row["risk"]) for row in rows),
        "domain_counts": Counter(str(row["domain"]) for row in rows),
        "language_counts": Counter(str(row["language"]) for row in rows),
        "source_counts": Counter(str(row["source"]) for row in rows),
        "duplicate_groups": duplicate_groups,
        "duplicate_files": duplicate_files,
        "publication_review_queue": len(review_queue),
        "limitations": [
            "Source, license, domain, use-case, and risk are heuristic classifications requiring human review.",
            "Duplicate detection is exact after whitespace/case normalization; semantic near-duplicates are not detected.",
            "A file marked reviewed_candidate is not approved for publication until IP ownership is confirmed.",
        ],
    }
    with (output / "corpus_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2, default=dict)

    quarantined = [row for row in rows if row["status"] == "quarantine"]
    report = [
        "# Corpus Quarantine Report", "",
        f"Generated: {summary['generated_at_utc']}", "",
        f"- Total eligible files: {len(rows)}",
        f"- Quarantined: {len(quarantined)}",
        f"- Exact duplicate groups: {duplicate_groups}",
        f"- Files in duplicate groups: {duplicate_files}", "",
        "## Publication Rule", "",
        "No quarantined file may be published or used for a public dataset until provenance, license, and sensitive-content review pass.", "",
        "## Quarantined Files", "",
        "| Path | Risk | Reason |",
        "|---|---|---|",
    ]
    report.extend(f"| `{row['path']}` | {row['risk']} | {row['risk_reason']} |" for row in quarantined)
    (output / "QUARANTINE_REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=dict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
