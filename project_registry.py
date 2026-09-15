#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path


IGNORED_DIRS = {'.git', 'node_modules', '.next', '.venv', 'venv', 'dist', 'build', '__pycache__', '.cache', '.turbo'}


def project_signals(path: Path) -> dict[str, object]:
    files: list[Path] = []
    for current, directories, names in os.walk(path):
        directories[:] = [name for name in directories if name not in IGNORED_DIRS]
        files.extend(Path(current) / name for name in names)
    return {
        'file_count': len(files),
        'has_git': (path / '.git').is_dir(),
        'has_readme': any(item.name.casefold().startswith('readme') for item in files),
        'has_tests': any('test' in part.casefold() for item in files for part in item.relative_to(path).parts),
        'has_node_manifest': (path / 'package.json').is_file(),
        'has_python_manifest': any((path / name).is_file() for name in ('pyproject.toml', 'requirements.txt', 'setup.py')),
    }


def build(workspace: Path, decisions_path: Path) -> list[dict[str, object]]:
    decisions = json.loads(decisions_path.read_text(encoding='utf-8'))
    roots = [workspace / '[02_IN_PROGRESS]', workspace]
    discovered: dict[str, Path] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.iterdir():
            if not path.is_dir() or path.name.startswith(('.', '[')) or path.name in {'portfolio_ops', 'domain-scout-worker'}:
                continue
            discovered.setdefault(path.name, path)
    rows = []
    for name, path in sorted(discovered.items(), key=lambda item: item[0].casefold()):
        decision = decisions['projects'].get(name, {
            'status': decisions['default_status'], 'canonical': False, 'priority': 'P4',
            'decision': 'Unclassified project; frozen pending evidence review.'
        })
        rows.append({
            'project': name,
            'path': str(path.resolve()),
            'priority': decision['priority'],
            'status': decision['status'],
            'canonical': decision['canonical'],
            'decision': decision['decision'],
            **project_signals(path),
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--decisions', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = build(args.workspace.resolve(), args.decisions.resolve())
    args.output.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else ['project']
    with (args.output / 'project_registry.csv').open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    counts: dict[str, int] = {}
    for row in rows: counts[row['status']] = counts.get(row['status'], 0) + 1
    report = [
        '# Portfolio Project Registry', '',
        f"**As of:** {json.loads(args.decisions.read_text(encoding='utf-8'))['as_of']}", '',
        '> Registry status is governance metadata. No project was moved, deleted, published, or modified.', '',
        '## Status Summary', '',
        '| Status | Projects |', '|---|---:|',
        *[f'| {status} | {count} |' for status, count in sorted(counts.items())], '',
        '## Canonical Build Repositories', '',
        '| Priority | Project | Evidence signals | Decision |', '|---|---|---|---|',
    ]
    for row in rows:
        if row['canonical']:
            signals = f"git={row['has_git']}; readme={row['has_readme']}; tests={row['has_tests']}"
            report.append(f"| {row['priority']} | `{row['project']}` | {signals} | {row['decision']} |")
    report.extend(['', '## Full Decision Ledger', '', '| Project | Priority | Status | Decision |', '|---|---|---|---|'])
    report.extend(f"| `{row['project']}` | {row['priority']} | {row['status']} | {row['decision']} |" for row in rows)
    (args.output / 'PROJECT_REGISTRY.md').write_text('\n'.join(report) + '\n', encoding='utf-8')
    print(json.dumps({'projects': len(rows), 'status_counts': counts}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
