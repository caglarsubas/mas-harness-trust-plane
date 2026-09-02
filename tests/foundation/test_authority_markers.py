from __future__ import annotations

import ast
import unittest
from pathlib import Path

from tests.foundation.support import ROOT


class PackageMarkerAuthorityTests(unittest.TestCase):
    def parse_regular_file(self, relative_path: str) -> ast.Module:
        path = ROOT / relative_path
        self.assertTrue(path.is_file())
        self.assertFalse(path.is_symlink())
        return ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)

    def test_public_package_marker_is_closed_and_inert(self):
        module = self.parse_regular_file("src/planeon_trust/__init__.py")
        self.assertEqual(ast.get_docstring(module), "Public Planeon trust-plane package boundary.")
        self.assertEqual(len(module.body), 3)

        version = module.body[1]
        exports = module.body[2]
        self.assertIsInstance(version, ast.Assign)
        self.assertIsInstance(exports, ast.Assign)
        self.assertEqual([target.id for target in version.targets if isinstance(target, ast.Name)], ["__version__"])
        self.assertEqual(ast.literal_eval(version.value), "0.1.0")
        self.assertEqual([target.id for target in exports.targets if isinstance(target, ast.Name)], ["__all__"])
        self.assertEqual(ast.literal_eval(exports.value), ("__version__",))
        self.assertFalse(any(isinstance(node, (ast.Call, ast.Import, ast.ImportFrom)) for node in ast.walk(module)))

    def test_test_package_marker_is_docstring_only(self):
        module = self.parse_regular_file("tests/__init__.py")
        self.assertEqual(ast.get_docstring(module), "Planeon trust-plane test package marker.")
        self.assertEqual(len(module.body), 1)
        self.assertIsInstance(module.body[0], ast.Expr)


if __name__ == "__main__":
    unittest.main()
