# CIRVIX launch quickstart verification

This is the canonical install verification for the public engine. It records
the commands that must pass before a public launch. Registry checks remain
blocked until the packages are published; local tarball checks are the
authoritative pre-publish substitute.

## Local, pre-publish verification

```bash
npm ci
npm run verify:version
npm run verify:package
python -m build packages/cirvix-python --outdir .artifacts/python
python -m unittest discover -s packages/cirvix-python/tests -v
```

`verify:package` packs `@cirvix_ai/agent-control`, installs that tarball into a
brand-new temporary npm project, checks the CLI version, runs `init`, validates
a policy, expects a credential-file read to be denied, and imports the package
through a one-decision smoke test.

## Published-package verification

Run from a clean temporary directory after publication:

```bash
mkdir cirvix-clean && cd cirvix-clean
npm init -y
npm install @cirvix_ai/agent-control
npx --no-install cirvix --version
npx --no-install cirvix init
npx --no-install cirvix check --action fs.read --resource .env.production
npx --no-install cirvix check --action fs.read --resource src/index.mjs
npx --no-install cirvix demo --fast
```

Expected: install succeeds; the version equals the release tag; `init`
succeeds; the credential-file check exits `1` with `DENY`; the workspace read
exits `0` with `PERMIT`; and the demo ends with credential and exfiltration
attempts denied.

Python, from a fresh virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cirvix
python -c "import cirvix; print(cirvix.__version__)"
python -m unittest discover -s packages/cirvix-python/tests -v
```

The Python package has no CLI; its first decision is verified with
`guard.wrap()` in `docs/examples/python_wrap.py`.

## Current registry status

As of 2026-08-23, publication credentials and registry access were not
available in this workspace. Do not claim the public `npm install` or `pip
install` paths work until the published commands above have been run.

Human unblock, one line: **Configure npm trusted publishing for
`CIRVIX/agent-control` and PyPI trusted publishing for `cirvix`, then push a
`v0.1.0` tag.**
