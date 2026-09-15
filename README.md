# Portfolio Corpus Operations

Reproducible, read-only inventory tooling for the text assets under
`[01_IDEAS_AND_PROMPTS]`.

The included browser demo calculates file statistics and exact-duplicate hashes
locally; selected files are not uploaded. The repository excludes the owner's
real project-decision ledger and provides `portfolio_decisions.example.json`
instead.

## Run

```powershell
python .\portfolio_ops\corpus_inventory.py `
  --source '.\[01_IDEAS_AND_PROMPTS]' `
  --output '.\portfolio_ops\output'
```

## Outputs

- `corpus_manifest.csv`: one row per eligible text file.
- `corpus_summary.json`: counts, distributions, and limitations.
- `QUARANTINE_REPORT.md`: files blocked from publication pending review.
- `publication_review_queue.csv`: deduplicated internal candidates ordered by
  heuristic quality score for human IP/licensing review.

Classification is conservative. Unknown licensing is quarantined; no source
file is moved, renamed, edited, or deleted.

## Project registry

```powershell
py -3.10 .\portfolio_ops\project_registry.py `
  --workspace . `
  --decisions .\portfolio_ops\portfolio_decisions.json `
  --output .\portfolio_ops\output
```

This produces `project_registry.csv` and `PROJECT_REGISTRY.md`. Projects absent
from the explicit decision file default to `freeze_review`.

## Validation

```powershell
py -3.10 -m unittest .\portfolio_ops\test_corpus_inventory.py -v
```
