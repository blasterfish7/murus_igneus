import unittest
from pathlib import Path

class TestProject(unittest.TestCase):
    def test_version_declared(self):
        content = Path("src/murus_igneus/__init__.py").read_text()
        self.assertIn("0.3.0-alpha", content)

if __name__ == "__main__":
    unittest.main()
