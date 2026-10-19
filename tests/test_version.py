import unittest
from pathlib import Path

class TestProject(unittest.TestCase):
    def test_version_declared(self):
        root = Path(__file__).resolve().parents[1]  # independent of the working directory
        content = (root / "src" / "murus_igneus" / "__init__.py").read_text()
        self.assertIn("0.3.0-alpha", content)

if __name__ == "__main__":
    unittest.main()
