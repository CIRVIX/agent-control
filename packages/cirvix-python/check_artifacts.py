from __future__ import annotations

import re
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath


def check(directory: Path) -> None:
    root = Path(__file__).resolve().parent
    version = re.search(r'^version\s*=\s*"([^"]+)"', (root / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
    runtime = {f"cirvix/{p.name}": p.read_bytes() for p in (root / "cirvix").glob("*.py")}
    required = {"cirvix/__init__.py", "cirvix/canonical.py", "cirvix/guard.py", "cirvix/policy.py", "cirvix/testing.py"}
    if not required <= runtime.keys():
        raise ValueError("Required runtime sources are missing")
    expected = {f"cirvix-{version}-py3-none-any.whl", f"cirvix-{version}.tar.gz"}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("Expected exactly the current-version wheel and sdist")
    for artifact in sorted(directory.iterdir()):
        wheel = artifact.suffix == ".whl"
        if wheel:
            with zipfile.ZipFile(artifact) as archive:
                names = archive.namelist()
                if any((i.external_attr >> 16) & 0o170000 == 0o120000 for i in archive.infolist()):
                    raise ValueError("Symlink in wheel")
                contents = {n: archive.read(n) for n in names}
        else:
            with tarfile.open(artifact, "r:gz") as archive:
                members = archive.getmembers()
                if any(not m.isfile() for m in members):
                    raise ValueError("Non-regular sdist member")
                names = [m.name for m in members]
                contents = {m.name: archive.extractfile(m).read() for m in members}
        if len(names) != len(set(names)):
            raise ValueError("Duplicate artifact member")
        prefix = "" if wheel else f"cirvix-{version}/"
        # Hatchling force-includes the nearest VCS ignore file in an sdist.
        # Allow only this exact root member, with bytes verified below.
        vcs_member = prefix + ".gitignore" if not wheel else None
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or "\\" in name or ":" in name or any(p in ("", ".", "..") for p in name.split("/")):
                raise ValueError("Unsafe artifact path")
            if name != vcs_member and (any(p.startswith(".") or p == "__pycache__" for p in path.parts) or path.suffix in (".pyc", ".pem", ".key")):
                raise ValueError("Unexpected private or generated artifact member")
        for name, source in runtime.items():
            if contents.get(prefix + name) != source:
                raise ValueError("Artifact runtime differs from current source")
        if wheel:
            info = f"cirvix-{version}.dist-info/"
            allowed = set(runtime) | {info + n for n in ("METADATA", "WHEEL", "RECORD", "licenses/LICENSE", "licenses/NOTICE")}
            metadata = contents.get(info + "METADATA", b"")
            license_prefix = info + "licenses/"
        else:
            fixture = root / "conformance" / "policy-conformance.json"
            if not fixture.is_file():
                fixture = root.parent / "conformance" / "policy-conformance.json"
            fixture_member = "tests/fixtures/policy-conformance.json"
            if (prefix + fixture_member) not in contents:
                fixture_member = "conformance/policy-conformance.json"
            if contents.get(prefix + fixture_member) != fixture.read_bytes():
                raise ValueError("Shared conformance fixture missing or changed")
            extras = {"README.md", "LICENSE", "NOTICE", "pyproject.toml", "PKG-INFO", fixture_member}
            if (root / "hatch_build.py").is_file() and (prefix + "hatch_build.py") in contents:
                extras.add("hatch_build.py")
            if (prefix + "check_artifacts.py") in contents:
                extras.add("check_artifacts.py")
            if vcs_member in contents:
                source_ignore = None
                for parent in (root, *root.parents):
                    candidate = parent / ".gitignore"
                    if candidate.is_file():
                        source_ignore = candidate
                        break
                    if (parent / ".git").exists():
                        break
                if source_ignore is None or contents[vcs_member] != source_ignore.read_bytes():
                    raise ValueError("Sdist VCS ignore file differs from source")
                extras.add(".gitignore")
            tests = {f"tests/{p.name}" for p in (root / "tests").glob("*.py")}
            allowed = {prefix + n for n in set(runtime) | extras | tests}
            metadata = contents.get(prefix + "PKG-INFO", b"")
            license_prefix = prefix
        if set(names) != allowed:
            raise ValueError("Artifact inventory differs from the approved file set")
        parsed = BytesParser().parsebytes(metadata)
        if parsed.get("Name") != "cirvix" or parsed.get("Version") != version or parsed.get_all("Requires-Dist"):
            raise ValueError("Invalid distribution metadata or runtime dependencies")
        for name in ("LICENSE", "NOTICE"):
            if contents.get(license_prefix + name) != (root / name).read_bytes():
                raise ValueError("Missing or changed license material")
        print(f"Verified {artifact.name}: runtime source equality, inventory, metadata, licenses")


if __name__ == "__main__":
    check(Path(sys.argv[1]))
