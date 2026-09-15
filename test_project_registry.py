import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from project_registry import build


class ProjectRegistryTest(unittest.TestCase):
    def test_decisions_and_safe_default(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / '[02_IN_PROGRESS]' / 'legacy').mkdir(parents=True)
            (root / 'canonical').mkdir()
            decisions = root / 'decisions.json'
            decisions.write_text(json.dumps({
                'default_status': 'freeze_review',
                'projects': {'canonical': {'status': 'active_build', 'canonical': True, 'priority': 'P1', 'decision': 'Build'}}
            }), encoding='utf-8')
            rows = {row['project']: row for row in build(root, decisions)}
            self.assertEqual(rows['canonical']['status'], 'active_build')
            self.assertTrue(rows['canonical']['canonical'])
            self.assertEqual(rows['legacy']['status'], 'freeze_review')


if __name__ == '__main__':
    unittest.main()
