#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Tests for scripts/release_notes.py: the highlights parser and check.

Run with ``make release-notes`` (stdlib unittest, no dependencies).
"""

import tempfile
import unittest
from pathlib import Path

import release_notes as rn

NOTE = """# project 0.0.40

## Highlights

{a} A first highlight that wraps
  onto a second line.
{b} A second highlight.
{c} A third highlight.

## Notes

{a} Not a highlight.
"""

JOINED = [
    "{a} A first highlight that wraps onto a second line.",
    "{b} A second highlight.",
    "{c} A third highlight.",
]


class Highlights(unittest.TestCase):
    def test_dash_bullets(self) -> None:
        note = NOTE.format(a="-", b="-", c="-")
        expected = [row.format(a="*", b="*", c="*") for row in JOINED]
        self.assertEqual(rn.highlights(note), expected)

    def test_star_bullets(self) -> None:
        note = NOTE.format(a="*", b="*", c="*")
        expected = [row.format(a="*", b="*", c="*") for row in JOINED]
        self.assertEqual(rn.highlights(note), expected)

    def test_mixed_bullets(self) -> None:
        note = NOTE.format(a="-", b="*", c="-")
        expected = [row.format(a="*", b="*", c="*") for row in JOINED]
        self.assertEqual(rn.highlights(note), expected)

    def test_too_few(self) -> None:
        with self.assertRaisesRegex(rn.ReleaseNotesError, "found 1"):
            rn.highlights("## Highlights\n\n- Only one.\n")

    def test_too_many(self) -> None:
        note = "## Highlights\n\n" + "- One.\n" * 5
        with self.assertRaisesRegex(rn.ReleaseNotesError, "found 5"):
            rn.highlights(note)


class Check(unittest.TestCase):
    def _root(self, heading: str, note: str | None) -> Path:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "Cargo.toml").write_text(
            '[package]\nname = "x"\nversion = "0.0.40"\n', encoding="utf-8"
        )
        (root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [0.0.40] - {heading}\n", encoding="utf-8"
        )
        if note is not None:
            (root / "releases").mkdir()
            (root / "releases" / "v0.0.40.md").write_text(note, encoding="utf-8")
        return root

    def test_undated(self) -> None:
        root = self._root("Unreleased", None)
        self.assertIn("not dated yet", rn.check(root))

    def test_dated_with_dash_note(self) -> None:
        root = self._root("2026-11-16", NOTE.format(a="-", b="-", c="-"))
        self.assertEqual(rn.check(root), "releases/v0.0.40.md: 3 highlights")

    def test_dated_without_note(self) -> None:
        root = self._root("2026-11-16", None)
        with self.assertRaisesRegex(rn.ReleaseNotesError, "missing"):
            rn.check(root)


if __name__ == "__main__":
    unittest.main()
