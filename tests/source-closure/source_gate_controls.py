"""Owned-source controls only: no third-party PHP import or execution."""
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("gate", ROOT / "bin/verify-source-closure.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class SourceGateControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        shutil.copytree(ROOT / "build/dependency-sources", self.root / "build/dependency-sources")
        shutil.copyfile(ROOT / "composer.json", self.root / "composer.json")

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_tracked_copy(self):
        self.assertEqual(12, gate.source_gate(self.root)["testcase_src_files"])

    def test_changed_copied_source_is_rejected(self):
        file = self.root / "build/dependency-sources/wp-graphql-testcase/src/Constraint/QueryConstraint.php"
        file.write_bytes(file.read_bytes() + b"\n// injected mutation\n")
        with self.assertRaises(ValueError):
            gate.source_gate(self.root)

    def test_unlisted_file_and_symlink_are_rejected(self):
        pkg = self.root / "build/dependency-sources/wp-cli-bundle"
        (pkg / "unexpected.php").write_text("<?php exit(0);")
        with self.assertRaises(ValueError):
            gate.source_gate(self.root)
        (pkg / "unexpected.php").unlink()
        (pkg / "unexpected.php").symlink_to("LICENSE")
        with self.assertRaises(ValueError):
            gate.source_gate(self.root)

    def test_injected_non_native_helper_consumer_is_rejected(self):
        fixture = self.root / "consumer.php"
        fixture.write_text("<?php $callback = 'str_icontains'; $callback('a', 'A');")
        self.assertTrue(gate.helper_consumers([fixture]))

    def test_runtime_archive_source_leak_is_rejected(self):
        archive = self.root / "leak.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("plugin/build/dependency-sources/wp-cli-bundle/LICENSE", "fixture")
        with self.assertRaises(ValueError):
            gate.archive_gate(archive)

    def test_displaced_fork_identity_is_rejected_without_php_execution(self):
        vendor = self.root / "vendor"
        (vendor / "composer").mkdir(parents=True)
        (vendor / "composer/installed.json").write_text(json.dumps({"packages": [{"name": "wp-cli/process", "version": "v5.9.99"}]}))
        with self.assertRaises(ValueError):
            gate.installed_gate(vendor, self.root)

    def test_false_patched_metadata_does_not_admit_old_source(self):
        vendor = self.root / "vendor"
        (vendor / "composer").mkdir(parents=True)
        (vendor / "symfony/process").mkdir(parents=True)
        (vendor / "composer/installed.json").write_text(json.dumps({"packages": [{"name": "symfony/process", "version": "v5.4.51", "source": {"reference": "467bfc56f18f5ef6d5ccb09324d7e988c1c0a98f"}}]}))
        (vendor / "symfony/process/Process.php").write_text("<?php namespace Symfony\\Component\\Process; class Process {}")
        with self.assertRaises(ValueError):
            gate.installed_gate(vendor, self.root)

    def test_exact_old_process_bytes_are_rejected_without_execution(self):
        archive = Path(os.environ["HEADLESS_OFFICIAL_PROCESS_ARCHIVE"])
        old = Path(os.environ["HEADLESS_OLD_PROCESS_FILE"])
        vendor = self.root / "vendor"
        (vendor / "composer").mkdir(parents=True)
        shutil.copytree(self.root / "build/dependency-sources/wp-graphql-testcase", vendor / "kodekrakan-commerce/headless-graphql-testcase")
        with zipfile.ZipFile(archive) as source:
            for member in source.namelist():
                relative = Path(*Path(member).parts[1:])
                if member.endswith("/") or "Tests" in relative.parts or relative.suffix != ".php":
                    continue
                target = vendor / "symfony/process" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read(member))
                target.chmod(0o644)
        packages = [{"name": "symfony/process", "version": "v5.4.51", "source": {"reference": "467bfc56f18f5ef6d5ccb09324d7e988c1c0a98f"}}]
        packages += [{"name": name, "version": gate.VERSION} for name in ("kodekrakan-commerce/headless-wp-cli-bundle", "kodekrakan-commerce/headless-graphql-testcase")]
        (vendor / "composer/installed.json").write_text(json.dumps({"packages": packages}))
        self.assertEqual([], gate.installed_gate(vendor, self.root)["helper_consumers"])
        shutil.copyfile(old, vendor / "symfony/process/Process.php")
        with self.assertRaisesRegex(ValueError, "Process source-family"):
            gate.installed_gate(vendor, self.root)

if __name__ == "__main__":
    unittest.main()
