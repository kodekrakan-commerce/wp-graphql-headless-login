"""Source-only review controls: fixture metadata + mocked dispatch, never vendor execution."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).absolute().parents[2]
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
gate = load("review_gate", ROOT / "bin/verify-source-closure.py")
runner = load("review_runner", ROOT / "bin/run-source-closure-tests.py")

class GuardReviewControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "checkout"
        self.root.mkdir()
        for name in ("build/dependency-sources", "src", "vendor-prefixed", "tests/_support/Helper", "tests/source-closure"):
            shutil.copytree(ROOT / name, self.root / name)
        for name in ("composer.json", "composer.lock", ".phpcs.xml.dist", "wp-graphql-headless-login.php", "readme.txt", "activation.php", "deactivation.php", "tests/wpunit/ProviderMutationsInstagramTest.php", "access-functions.php", "bin/verify-source-closure.py", "bin/run-source-closure-tests.py", "bin/security-wp-cli.php"):
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, self.root / name)
        # Synthetic source-only proof flag for mocked dispatch; never actual Git/tool admission.
        policy_path = self.root / "build/dependency-sources/retirement-checker-source-pins.json"
        policy = json.loads(policy_path.read_text())
        for item in policy["checker_cohort"].values():
            item["git_verified"] = True
            item["export_ignore_verified"] = True
        policy_path.write_text(json.dumps(policy))
        vendor = self.root / "vendor"
        (vendor / "composer").mkdir(parents=True)
        shutil.copytree(self.root / "build/dependency-sources/wp-graphql-testcase", vendor / "kodekrakan-commerce/headless-graphql-testcase")
        with zipfile.ZipFile(os.environ["HEADLESS_OFFICIAL_PROCESS_ARCHIVE"]) as source:
            for member in source.namelist():
                relative = Path(*Path(member).parts[1:])
                if member.endswith("/") or "Tests" in relative.parts or relative.suffix != ".php": continue
                target = vendor / "symfony/process" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read(member)); target.chmod(0o644)
        packages = [{"name": "symfony/process", "version": "v5.4.51", "source": {"reference": "467bfc56f18f5ef6d5ccb09324d7e988c1c0a98f"}}]
        packages += [{"name": name, "version": gate.VERSION} for name in ("kodekrakan-commerce/headless-wp-cli-bundle", "kodekrakan-commerce/headless-graphql-testcase")]
        archive_names = {"axepress/wp-graphql-cs": "axepress-current-stable.zip", "phpcompatibility/php-compatibility": "phpcompatibility-alpha2.zip", "phpcompatibility/phpcompatibility-wp": "wp-alpha2.zip", "phpcompatibility/phpcompatibility-paragonie": "paragonie-alpha2.zip"}
        for name, item in policy["checker_cohort"].items():
            packages.append({"name": name, "version": item["version"], "source": {"reference": item["source_reference"]}})
            with zipfile.ZipFile(Path(os.environ["HEADLESS_CHECKER_ARCHIVE_DIR"]) / archive_names[name]) as archive:
                for member in archive.infolist():
                    if member.is_dir(): continue
                    target = vendor / name / Path(*Path(member.filename).parts[1:])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(member.filename)); target.chmod(0o644)
        (vendor / "composer/installed.json").write_text(json.dumps({"packages": packages}))
        for file in ("autoload.php", "phpunit/phpunit/phpunit"):
            target = vendor / file; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("<?php /* SOURCE-ONLY DISPATCH SENTINEL; MUST NEVER BE EXECUTED */")
        self.php = self.root / "fixture-php-not-executable"
        self.php.write_text("Owned mock executable identity only; no process may execute this file.")
        self.receipt = self.root / "fixture-admission.json"
        closure = gate.installed_gate(vendor, self.root)
        self.data = {
            "schema": "headless-source-closure-installed-admission/v1", "php_version": "8.2.34",
            "php_binary": str(self.php), "php_binary_sha256": gate.digest(self.php),
            "source_hashes": gate.source_input_inventory(self.root), "harness_files": gate.harness_inventory(self.root),
            "vendor_files": gate.regular_inventory(vendor),
            "removed_api_review": {p: {"sha256": gate.digest(vendor / p), "disposition": "Source-only fixture candidate; read-only classified for mocked dispatch control, not installed admission."} for p in closure["removed_api_candidates_requiring_review"]},
        }
        self.save()

    def save(self): self.receipt.write_text(json.dumps(self.data))
    def tearDown(self): self.temp.cleanup()
    def assert_refused_before_dispatch(self):
        dispatch = Mock(side_effect=AssertionError("unadmitted dispatch attempted"))
        with self.assertRaises((ValueError, KeyError, OSError)):
            runner.main(["--admission", str(self.receipt)], root=self.root, dispatch=dispatch)
        dispatch.assert_not_called()

    def test_lifecycle_source_changed_missing_python_php_refuse_before_dispatch(self):
        php=os.environ['HEADLESS_SOURCE_CONTROL_PHP'];expected=self.root/'expected-source-only.json';expected.write_text(json.dumps(self.data['source_hashes']))
        expression="require $argv[1]; headless_assert_source_inputs($argv[2], json_decode(file_get_contents($argv[3]),true,512,JSON_THROW_ON_ERROR)); fwrite(STDOUT,'OWNED_DISPATCH_SEAM_REACHED');"
        command=[php,'-r',expression,str(ROOT/'tests/source-closure/admission.php'),str(self.root),str(expected)]
        outputs=[]
        good=subprocess.run(command,capture_output=True,text=True,env={'PATH':str(Path(php).parent)})
        self.assertEqual(good.returncode,0,good.stderr);self.assertEqual(good.stdout,'OWNED_DISPATCH_SEAM_REACHED')
        for name in ('activation.php','deactivation.php'):
            self.assertIn(name,self.data['source_hashes']);file=self.root/name;old=file.read_bytes()
            for kind in ('changed','missing'):
                if kind=='changed':file.write_bytes(old+b'\n/* inert source-only altered lifecycle fixture */\n')
                else:file.unlink()
                self.assert_refused_before_dispatch()
                bad=subprocess.run(command,capture_output=True,text=True,env={'PATH':str(Path(php).parent)})
                self.assertNotEqual(bad.returncode,0);self.assertNotIn('OWNED_DISPATCH_SEAM_REACHED',bad.stdout);self.assertIn('Admission membership/hash mismatch: source_hashes',bad.stderr)
                outputs.append({'input':name,'change':kind,'exit':bad.returncode,'stdout':bad.stdout,'stderr':bad.stderr,'python_mock_dispatch':'not called'})
                file.write_bytes(old)
        if os.environ.get('HEADLESS_LIFECYCLE_CONTROL_RECEIPT'):
            Path(os.environ['HEADLESS_LIFECYCLE_CONTROL_RECEIPT']).write_text(json.dumps({'scope':'Actual owned Python/PHP source gate with inert mutations; only owned post-gate dispatch marker, never vendor/WP/checker','argv':command,'environment':{'PATH':str(Path(php).parent)},'php_sha256':gate.digest(Path(php)),'admission_php_sha256':gate.digest(ROOT/'tests/source-closure/admission.php'),'lifecycle_bound_hashes':{n:self.data['source_hashes'][n] for n in ('activation.php','deactivation.php')},'positive':{'exit':good.returncode,'stdout':good.stdout,'stderr':good.stderr},'refusals':outputs},indent=2)+'\n')

    def test_valid_fixture_reaches_only_mocked_dispatch(self):
        dispatch = Mock(side_effect=[subprocess.CompletedProcess([], 0, "8.2.34", ""), subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 1, "FAILURES!", "")])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, runner.main(["--admission", str(self.receipt)], root=self.root, dispatch=dispatch))
        self.assertEqual(3, dispatch.call_count)

    def test_checker_exact_source_mode_byte_and_member_controls_before_dispatch(self):
        # Adversarially refresh whole-vendor hash receipt: the independent pinned-source gate must still refuse.
        original=json.loads(json.dumps(self.data));vendor=self.root/'vendor'
        meta=vendor/'composer/installed.json';oldmeta=meta.read_bytes();data=json.loads(oldmeta)
        next(p for p in data['packages'] if p['name']=='phpcompatibility/php-compatibility')['source']['reference']='0'*40
        meta.write_text(json.dumps(data));self.data['vendor_files']=gate.regular_inventory(vendor);self.save();self.assert_refused_before_dispatch();meta.write_bytes(oldmeta)
        file=vendor/'phpcompatibility/php-compatibility/composer.json';old=file.read_bytes()
        for change in ('mode','bytes','extra'):
            if change=='mode':file.chmod(0o600)
            elif change=='bytes':file.write_bytes(old+b'\n')
            else:(file.parent/'unexpected.txt').write_text('inert extra fixture')
            self.data=json.loads(json.dumps(original));self.data['vendor_files']=gate.regular_inventory(vendor);self.save();self.assert_refused_before_dispatch()
            file.chmod(0o644);file.write_bytes(old)
            if (file.parent/'unexpected.txt').exists():(file.parent/'unexpected.txt').unlink()
        self.data=original;self.save()

    def test_changed_vendor_entrypoint_or_autoload_refused_before_dispatch(self):
        for name in ("phpunit/phpunit/phpunit", "autoload.php", "composer/installed.json"):
            file = self.root / "vendor" / name; old = file.read_bytes(); file.write_bytes(old + b"\nchanged")
            self.assert_refused_before_dispatch(); file.write_bytes(old)

    def test_missing_schema_hash_or_selected_harness_input_refused(self):
        original = json.loads(json.dumps(self.data))
        for field in ("schema", "php_version", "php_binary", "php_binary_sha256", "source_hashes", "harness_files", "vendor_files", "removed_api_review"):
            self.data = json.loads(json.dumps(original)); del self.data[field]; self.save(); self.assert_refused_before_dispatch()
        for name in ("tests/source-closure/phpunit.xml", "tests/source-closure/ProcessConsumersTest.php", "tests/source-closure/DeliberateFailureTest.php", "tests/source-closure/child.php", "tests/source-closure/wp-cli-boundary.php", "tests/source-closure/guard_review_controls.py"):
            self.data = json.loads(json.dumps(original)); del self.data["harness_files"][name]; self.save(); self.assert_refused_before_dispatch()
        self.data = json.loads(json.dumps(original)); self.data["source_hashes"]["composer.lock"] = "not-a-hash"; self.save(); self.assert_refused_before_dispatch()
        self.data = json.loads(json.dumps(original)); self.data["removed_api_review"]["unknown.php"] = {"sha256": None, "disposition": "Invalid unknown member"}; self.save(); self.assert_refused_before_dispatch()

    def test_php_owned_defense_inventory_parity_and_ancestor_refusal(self):
        # Execute only owned filesystem functions on fixture bytes; no admission or vendor PHP.
        php = os.environ["HEADLESS_SOURCE_CONTROL_PHP"]
        expression = "require $argv[1]; fwrite(STDOUT, json_encode(['source'=>headless_source_inputs($argv[2]),'harness'=>headless_harness_inputs($argv[2]),'vendor'=>headless_inventory($argv[2].'/vendor')], JSON_THROW_ON_ERROR));"
        command = [php, "-r", expression, str(ROOT / "tests/source-closure/admission.php"), str(self.root)]
        result = subprocess.run(command, capture_output=True, text=True, env={"PATH": str(Path(php).parent)})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual({"source": self.data["source_hashes"], "harness": self.data["harness_files"], "vendor": self.data["vendor_files"]}, json.loads(result.stdout))
        path = self.root / "build/dependency-sources"; saved = path.with_name("dependency-sources-real"); path.rename(saved); path.symlink_to(saved)
        result = subprocess.run(command, capture_output=True, text=True, env={"PATH": str(Path(php).parent)})
        self.assertNotEqual(0, result.returncode); self.assertIn("Symlink root/ancestor", result.stderr)

    def test_changed_or_unlisted_harness_and_root_autoload_refused(self):
        for name in ("tests/source-closure/phpunit.xml", "tests/source-closure/bootstrap.php", "access-functions.php", "activation.php", "deactivation.php", "src/Autoloader.php", "vendor-prefixed/firebase/php-jwt/src/JWT.php"):
            file = self.root / name; old = file.read_bytes(); file.write_bytes(old + b"\nchanged")
            self.assert_refused_before_dispatch(); file.write_bytes(old)
        (self.root / "tests/source-closure/unlisted.php").write_text("<?php /* inert source fixture */")
        self.assert_refused_before_dispatch()

    def test_symlink_receipt_vendor_harness_php_roots_and_ancestors_refused(self):
        for name in ("fixture-admission.json", "vendor", "vendor/composer", "tests/source-closure", "fixture-php-not-executable"):
            path = self.root / name; saved = path.with_name(path.name + "-real"); path.rename(saved); path.symlink_to(saved)
            self.assert_refused_before_dispatch(); path.unlink(); saved.rename(path)

    def test_source_package_and_area_root_ancestor_links_refused(self):
        for name in ("build/dependency-sources/wp-cli-bundle", "build/dependency-sources", "build", "build/dependency-sources/source-manifest.json"):
            path = self.root / name; saved = path.with_name(path.name + "-real"); path.rename(saved); path.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, "symlink"): gate.source_gate(self.root)
            path.unlink(); saved.rename(path)
        alias = self.root.parent / "checkout-link"; alias.symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, "symlink"): gate.source_gate(alias)

    def test_installed_package_namespace_metadata_ancestor_links_refused(self):
        for name in ("vendor/kodekrakan-commerce/headless-graphql-testcase", "vendor/kodekrakan-commerce", "vendor/symfony/process", "vendor/symfony", "vendor/composer", "vendor"):
            path = self.root / name; saved = path.with_name(path.name + "-real"); path.rename(saved); path.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, "symlink"): gate.installed_gate(self.root / "vendor", self.root)
            path.unlink(); saved.rename(path)

    def test_lowercase_post_comment_and_mixed_case_helper_candidates(self):
        fixture = self.root / "consumer.php"
        for code in ("<?php // ordinary comment\nstr_icontains('a', 'A');", "<?php STR_ISTARTS_WITH('a', 'A');", "<?php $callable='sTr_IeNdS_wItH';", "<?php new pHpExTeNdEd\\pOlYfIlL\\sTrUtIlS;"):
            fixture.write_text(code); self.assertTrue(gate.helper_consumers([fixture]))
        fixture.write_text("<?php // ordinary comment\nstr_icontains('a', 'A');")
        self.assertEqual(2, gate.helper_consumers([fixture])[0]["line"])

    def test_mixed_case_process_class_method_and_callable_candidates(self):
        file = self.root / "vendor" / "consumer.php"
        file.write_text("<?php // comment\nnew pRoCeSsBuIlDeR; $p->sEtCoMmAnDlInE('x'); $cb='gEtOpTiOnS';")
        self.assertIn("consumer.php", gate.installed_gate(self.root / "vendor", self.root)["removed_api_candidates_requiring_review"])

    def test_mixed_case_installed_helper_rejected(self):
        (self.root / "vendor/consumer.php").write_text("<?php // comment\nStR_iCoNtAiNs('a','A');")
        with self.assertRaisesRegex(ValueError, "removed helper"): gate.installed_gate(self.root / "vendor", self.root)

class CliBoundaryControls(unittest.TestCase):
    def test_ancestor_project_requires_and_ambient_requires_refused_before_vendor(self):
        php = os.environ["HEADLESS_SOURCE_CONTROL_PHP"]
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve(); cwd = parent / "empty"; cwd.mkdir()
            marker = parent / "target-executed"
            target = parent / "unreviewed.php"; target.write_text("<?php file_put_contents(" + repr(str(marker)) + ",'executed');")
            for name in ("wp-cli.yml", "wp-cli.local.yml"):
                config = parent / name; config.write_text("require:\n  - " + str(target) + "\n")
                result = subprocess.run([php, str(ROOT / "bin/security-wp-cli.php"), "cli", "version"], cwd=cwd, env={"PATH": str(Path(php).parent)}, capture_output=True, text=True)
                self.assertNotEqual(0, result.returncode); self.assertIn("Ancestor WP-CLI project config", result.stderr); self.assertFalse(marker.exists()); config.unlink()
            for name in ("WP_CLI_REQUIRE", "WP_CLI_EARLY_REQUIRE", "WP_CLI_CONFIG_PATH"):
                result = subprocess.run([php, str(ROOT / "bin/security-wp-cli.php"), "cli", "version"], cwd=cwd, env={"PATH": str(Path(php).parent), name: str(target)}, capture_output=True, text=True)
                self.assertNotEqual(0, result.returncode); self.assertIn("Ambient WP-CLI require/config input", result.stderr); self.assertFalse(marker.exists())

if __name__ == "__main__": unittest.main()
