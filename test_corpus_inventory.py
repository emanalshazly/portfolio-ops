import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("corpus_inventory.py")


class CorpusInventoryTest(unittest.TestCase):
    def test_exclusions_duplicates_and_quarantine(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            output = root / "output"
            (source / "node_modules" / "pkg").mkdir(parents=True)
            (source / "system_prompts_leaks").mkdir(parents=True)
            (source / "Marketing").mkdir(parents=True)
            prompt = "# Email Campaign\n\nPrompt example with output format. " * 30
            (source / "Marketing" / "one.md").write_text(prompt, encoding="utf-8")
            (source / "Marketing" / "two.md").write_text(prompt.upper(), encoding="utf-8")
            (source / "node_modules" / "pkg" / "README.md").write_text("ignore", encoding="utf-8")
            (source / "system_prompts_leaks" / "leak.txt").write_text("system prompt", encoding="utf-8")

            subprocess.run(
                [sys.executable, str(SCRIPT), "--source", str(source), "--output", str(output)],
                check=True,
                capture_output=True,
                text=True,
            )
            with (output / "corpus_summary.json").open(encoding="utf-8") as handle:
                summary = json.load(handle)
            with (output / "corpus_manifest.csv").open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(summary["total_files"], 3)
            self.assertEqual(summary["duplicate_groups"], 1)
            self.assertEqual(summary["duplicate_files"], 2)
            self.assertFalse(any("node_modules" in row["path"] for row in rows))
            leak = next(row for row in rows if "system_prompts_leaks" in row["path"])
            self.assertEqual(leak["risk"], "high")
            self.assertEqual(leak["license"], "restricted")


if __name__ == "__main__":
    unittest.main()
