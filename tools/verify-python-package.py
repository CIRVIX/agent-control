import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from email.parser import BytesParser
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "packages" / "cirvix-python"
FIXTURE = "tests/fixtures/policy-conformance.json"


def run(args, cwd, expected=0):
    command = [str(arg) for arg in args]
    print(f"cwd={cwd}\n{subprocess.list2cmdline(command)}", flush=True)
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(command, cwd=cwd, env=env, check=False)
    if result.returncode != expected:
        raise RuntimeError(f"Exit code {result.returncode}, expected {expected}")


def check_metadata(data, version):
    metadata = BytesParser().parsebytes(data)
    assert metadata["Name"] == "cirvix", metadata["Name"]
    assert metadata["Version"] == version, metadata["Version"]
    assert not metadata.get_all("Requires-Dist"), metadata.get_all("Requires-Dist")


def extract_checked(archive, destination, canonical, version):
    prefix = f"cirvix-{version}"
    with tarfile.open(archive) as source:
        names = source.getnames()
        assert len(names) == len(set(names)), "Duplicate archive members"
        assert names.count(f"{prefix}/{FIXTURE}") == 1
        assert source.extractfile(f"{prefix}/{FIXTURE}").read() == canonical
        check_metadata(source.extractfile(f"{prefix}/PKG-INFO").read(), version)
        source.extractall(destination, filter="data")
    extracted = destination / prefix
    assert (extracted / FIXTURE).read_bytes() == canonical
    assert not (extracted.parent / "conformance").exists()
    print(f"Fixture byte equality passed: {archive} ({len(canonical)} bytes)", flush=True)
    return extracted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--temp-parent", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--expected-version", default="0.2.1")
    args = parser.parse_args()
    output = Path(tempfile.mkdtemp(prefix="cirvix-sdist-", dir=args.temp_parent)).resolve()
    print(f"Artifacts retained at: {output}", flush=True)
    version = args.expected_version
    canonical = (PACKAGE.parent / "conformance" / "policy-conformance.json").read_bytes()
    python = Path(sys.executable)
    tests = [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"]
    run(tests, PACKAGE)
    run([python, "-m", "build", "--no-isolation", "--sdist", "--outdir", output / "checkout"], PACKAGE)
    extracted = extract_checked(
        output / "checkout" / f"cirvix-{version}.tar.gz",
        output / "extracted",
        canonical,
        version,
    )
    run(tests, extracted)
    run(
        [python, "-m", "build", "--no-isolation", "--sdist", "--wheel", "--outdir", output / "rebuilt"],
        extracted,
    )
    rebuilt = extract_checked(
        output / "rebuilt" / f"cirvix-{version}.tar.gz",
        output / "reextracted",
        canonical,
        version,
    )
    run(tests, rebuilt)
    wheel = output / "rebuilt" / f"cirvix-{version}-py3-none-any.whl"
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)), "Duplicate wheel members"
        assert not any(name.startswith("tests/") or name == "hatch_build.py" for name in names)
        check_metadata(archive.read(f"cirvix-{version}.dist-info/METADATA"), version)
    environment = output / "install-venv"
    run([python, "-m", "venv", environment], output)
    installed_python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run([installed_python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", wheel], output)
    run(
        [
            installed_python,
            "-I",
            "-c",
            "import cirvix, importlib.metadata as m, pathlib, sys; "
            f"assert m.version('cirvix') == {version!r}; "
            "assert not m.requires('cirvix'); "
            "assert pathlib.Path(cirvix.__file__).is_relative_to(pathlib.Path(sys.prefix)); "
            "print('Installed cirvix', m.version('cirvix'), cirvix.__file__)",
        ],
        output,
    )
    bundled = extracted / FIXTURE
    bundled.unlink()
    try:
        run(
            [python, "-m", "build", "--no-isolation", "--sdist", "--outdir", output / "missing-fixture"],
            extracted,
            expected=1,
        )
        assert not list((output / "missing-fixture").glob("*.tar.gz"))
    finally:
        bundled.write_bytes(canonical)
    print(f"Packaging regression passed; fixture SHA256={hashlib.sha256(canonical).hexdigest()}")
    print(f"Artifacts retained at: {output}")


if __name__ == "__main__":
    main()
