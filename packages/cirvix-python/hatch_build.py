from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class ConformanceFixtureHook(BuildHookInterface):
    def initialize(self, version, build_data):
        source = str((Path(self.root) / "../conformance/policy-conformance.json").resolve())
        target = "tests/fixtures/policy-conformance.json"
        if Path(source).is_file():
            return
        bundled = Path(self.root) / target
        if not bundled.is_file():
            raise FileNotFoundError(f"Conformance fixture not found: {source} or {bundled}")
        self.build_config.force_include.pop(source)
        build_data["force_include"][str(bundled)] = target
