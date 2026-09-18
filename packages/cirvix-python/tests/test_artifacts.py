from __future__ import annotations

import contextlib
import io
import re
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from check_artifacts import check


class ArtifactInventory(unittest.TestCase):
    def build_fixture_archives(self, directory, omit=None, extra=False, dependency=False, sdist_extra=None):
        version = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
        runtime = {f"cirvix/{p.name}": p.read_bytes() for p in (ROOT / "cirvix").glob("*.py")}
        info = f"cirvix-{version}.dist-info/"
        metadata = f"Metadata-Version: 2.4\nName: cirvix\nVersion: {version}\n"
        if dependency:
            metadata += "Requires-Dist: sample-dependency\n"
        wheel = dict(runtime)
        wheel.update({info + "METADATA": metadata.encode(), info + "WHEEL": b"Wheel-Version: 1.0\n", info + "RECORD": b""})
        for name in ("LICENSE", "NOTICE"):
            wheel[info + "licenses/" + name] = (ROOT / name).read_bytes()
        if omit:
            wheel.pop(omit)
        if extra:
            wheel["cirvix/sample.txt"] = b"benign fixture"
        with zipfile.ZipFile(directory / f"cirvix-{version}-py3-none-any.whl", "w") as archive:
            for name, data in wheel.items():
                archive.writestr(name, data)
        sdist = dict(runtime)
        for name in ("LICENSE", "NOTICE", "README.md", "pyproject.toml", "check_artifacts.py"):
            sdist[name] = (ROOT / name).read_bytes()
        for path in (ROOT / "tests").glob("*.py"):
            sdist[f"tests/{path.name}"] = path.read_bytes()
        fixture = ROOT / "conformance" / "policy-conformance.json"
        if not fixture.is_file():
            fixture = ROOT.parent / "conformance" / "policy-conformance.json"
        sdist["conformance/policy-conformance.json"] = fixture.read_bytes()
        sdist["PKG-INFO"] = metadata.encode()
        sdist.update(sdist_extra or {})
        with tarfile.open(directory / f"cirvix-{version}.tar.gz", "w:gz") as archive:
            for name, data in sdist.items():
                member = tarfile.TarInfo(f"cirvix-{version}/{name}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def test_complete_fixture_inventories_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            self.build_fixture_archives(Path(temp))
            with contextlib.redirect_stdout(io.StringIO()):
                check(Path(temp))

    def test_missing_runtime_file_is_rejected(self):
        for name in ("__init__", "canonical", "guard", "policy", "testing"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                self.build_fixture_archives(Path(temp), omit=f"cirvix/{name}.py")
                with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                    check(Path(temp))

    def test_unapproved_benign_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            self.build_fixture_archives(Path(temp), extra=True)
            with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                check(Path(temp))

    def test_hatchling_root_gitignore_matches_source(self):
        source = next(parent / ".gitignore" for parent in (ROOT, *ROOT.parents) if (parent / ".gitignore").is_file())
        with tempfile.TemporaryDirectory() as temp:
            self.build_fixture_archives(Path(temp), sdist_extra={".gitignore": source.read_bytes()})
            with contextlib.redirect_stdout(io.StringIO()):
                check(Path(temp))

    def test_hidden_sdist_members_and_changed_gitignore_are_rejected(self):
        for name in (".gitignore", ".env", "cirvix/.gitignore"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                self.build_fixture_archives(Path(temp), sdist_extra={name: b"unexpected fixture"})
                with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                    check(Path(temp))

    def test_runtime_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            self.build_fixture_archives(Path(temp), dependency=True)
            with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                check(Path(temp))


if __name__ == "__main__":
    unittest.main()
