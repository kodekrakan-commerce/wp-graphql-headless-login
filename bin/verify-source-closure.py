#!/usr/bin/env python3
"""Read-only source/installed/archive gates; never imports third-party PHP."""
import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).absolute().parents[1]
VERSION = "dev-codex-headless-source-closure"
CHECKER_PINS = {
    "axepress/wp-graphql-cs": ("2.1.0", "25ad34bc19a672d1028ec9635f75b47f424b9aad"),
    "phpcompatibility/php-compatibility": ("10.0.0-alpha2", "e0f0e5a3dc819a4a0f8d679a0f2453d941976e18"),
    "phpcompatibility/phpcompatibility-wp": ("3.0.0-alpha2", "bd53f24e7528422ac51d64dc8d53e8d4c4a877b3"),
    "phpcompatibility/phpcompatibility-paragonie": ("2.0.0-alpha2", "7a979711c87d8202b52f56c56bd719d09d8ed7f5"),
}
HELPERS = re.compile(r"\b(?:str_icontains|str_istarts_with|str_iends_with|PhpExtended|StrUtils)\b", re.I)
REMOVED_APIS = re.compile(r"\b(?:ProcessBuilder|ProcessUtils|setCommandLine|getOptions|inheritEnvironmentVariables|setEnhanceWindowsCompatibility|setEnhanceSigchildCompatibility)\b", re.I)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def reject_symlink_path(path):
    """Check the named path and every ancestor before opening/traversing it."""
    path = Path(path).absolute()
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise ValueError("symlink root/ancestor: " + str(entry))
    return path

def regular_inventory(directory):
    directory = reject_symlink_path(directory)
    if not directory.is_dir():
        raise ValueError("missing directory: " + str(directory))
    result = {}
    for path in sorted(directory.rglob("*")):
        reject_symlink_path(path)
        if path.is_file():
            result[str(path.relative_to(directory))] = digest(path)
        elif not path.is_dir():
            raise ValueError("nonregular inventory member: " + str(path))
    return result

def relative_key(value):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/") or any(p in ("", ".", "..") for p in value.split("/")):
        raise ValueError("unsafe inventory path")
    return value

def hash_map(value, label):
    if not isinstance(value, dict) or not value:
        raise ValueError("missing complete " + label)
    for path, fingerprint in value.items():
        relative_key(path)
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("invalid hash in " + label)
    return value

def source_input_inventory(root):
    """Bind mandatory metadata and all root Composer autoload inputs outside vendor."""
    root = reject_symlink_path(root)
    result = {}
    for name in ("composer.json", "composer.lock", ".phpcs.xml.dist", "wp-graphql-headless-login.php", "readme.txt", "activation.php", "deactivation.php"):
        path = reject_symlink_path(root / name)
        result[name] = digest(path)
    area = root / "build/dependency-sources"
    result.update({"build/dependency-sources/" + p: h for p, h in regular_inventory(area).items()})
    composer = json.loads((root / "composer.json").read_text())
    reached = {"access-functions.php"}
    for section in ("autoload", "autoload-dev"):
        config = composer.get(section, {})
        reached.update(config.get("files", []))
        reached.update(config.get("classmap", []))
        for mapping in ("psr-4", "psr-0"):
            for paths in config.get(mapping, {}).values():
                reached.update(paths if isinstance(paths, list) else [paths])
    for relative in sorted(reached):
        relative = relative_key(relative.rstrip("/"))
        path = reject_symlink_path(root / relative)
        if path.is_dir():
            result.update({relative + "/" + p: h for p, h in regular_inventory(path).items()})
        else:
            if not path.is_file():
                raise ValueError("missing root autoload input: " + relative)
            result[relative] = digest(path)
    return result

def harness_inventory(root):
    result = {}
    for name in ("bin/run-source-closure-tests.py", "bin/verify-source-closure.py", "bin/security-wp-cli.php"):
        result[name] = digest(reject_symlink_path(root / name))
    result.update({"tests/source-closure/" + p: h for p, h in regular_inventory(root / "tests/source-closure").items()})
    result["tests/wpunit/ProviderMutationsInstagramTest.php"] = digest(reject_symlink_path(root / "tests/wpunit/ProviderMutationsInstagramTest.php"))
    return result

def validate_admission(root, receipt_path):
    """Entire pre-vendor boundary: data/file checks only, no executable dispatch."""
    root = reject_symlink_path(root)
    receipt_path = reject_symlink_path(receipt_path)
    receipt = json.loads(receipt_path.read_text())
    required = {"schema", "php_version", "php_binary", "php_binary_sha256", "source_hashes", "harness_files", "vendor_files", "removed_api_review"}
    if not isinstance(receipt, dict) or not required.issubset(receipt) or receipt["schema"] != "headless-source-closure-installed-admission/v1" or receipt["php_version"] != "8.2.34":
        raise ValueError("invalid complete admission schema/PHP version")
    for name, actual in (("source_hashes", source_input_inventory(root)), ("harness_files", harness_inventory(root)), ("vendor_files", regular_inventory(root / "vendor"))):
        expected = hash_map(receipt[name], name)
        if actual != expected:
            raise ValueError("admission membership/hash mismatch: " + name)
    mandatory_vendor = {"autoload.php", "composer/installed.json", "phpunit/phpunit/phpunit", "symfony/process/Process.php"}
    if not mandatory_vendor.issubset(receipt["vendor_files"]):
        raise ValueError("mandatory vendor entrypoint/metadata not bound")
    if not isinstance(receipt["php_binary"], str) or not Path(receipt["php_binary"]).is_absolute() or not isinstance(receipt["php_binary_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt["php_binary_sha256"]):
        raise ValueError("exact admitted PHP path/hash required")
    php = reject_symlink_path(receipt["php_binary"])
    if not php.is_file() or digest(php) != receipt["php_binary_sha256"]:
        raise ValueError("admitted PHP binary differs")
    source_gate(root)
    closure = installed_gate(root / "vendor", root)
    checker_installed_gate(root / "vendor", root)
    reviewed = receipt["removed_api_review"]
    if not isinstance(reviewed, dict):
        raise ValueError("invalid removed API review")
    for path, record in reviewed.items():
        relative_key(path)
        if path not in receipt["vendor_files"] or not isinstance(record, dict) or record.get("sha256") != receipt["vendor_files"][path] or not isinstance(record.get("disposition"), str) or not record["disposition"].strip():
            raise ValueError("invalid removed API disposition: " + path)
    for candidate in closure["removed_api_candidates_requiring_review"]:
        if candidate not in reviewed:
            raise ValueError("unreviewed Process API candidate: " + candidate)
    return receipt

def source_gate(root):
    root = reject_symlink_path(root)
    area = root / "build/dependency-sources"
    reject_symlink_path(area / "source-manifest.json")
    reject_symlink_path(root / "composer.json")
    manifest = json.loads((area / "source-manifest.json").read_text())
    for relative, expected in manifest["provenance_files"].items():
        reject_symlink_path(area / relative)
        if digest(area / relative) != expected:
            raise ValueError("source provenance file changed: " + relative)
    actual = {}
    for package in ("wp-cli-bundle", "wp-graphql-testcase"):
        reject_symlink_path(area / package)
        for path in sorted((area / package).rglob("*")):
            if path.is_symlink():
                raise ValueError(f"symlink: {path}")
            if path.is_file():
                actual[str(path.relative_to(root))] = {"sha256": digest(path), "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"}
    if actual != manifest["package_files"]:
        raise ValueError("owned package path/hash/mode manifest differs (missing, changed or unlisted file)")
    mappings = json.loads((area / "advisory-source-mappings.json").read_text())["packages"]
    for mapping in mappings:
        pkg = root / mapping["path"]
        meta = json.loads((pkg / "composer.json").read_text())
        if meta["name"] != mapping["owned_name"] or meta["version"] != VERSION or meta["require"]["php"] != ">=8.2":
            raise ValueError("owned metadata identity/PHP mismatch")
        if any(k in meta for k in ("replace", "provide", "extra", "scripts")):
            raise ValueError("owned package must not impersonate or execute upstream metadata")
        if not (pkg / "LICENSE").is_file():
            raise ValueError("missing license")
        if "upstream_src" in mapping:
            src = {str(p.relative_to(pkg)): digest(p) for p in (pkg / "src").rglob("*") if p.is_file()}
            if src != {p: h["sha256"] for p, h in mapping["upstream_src"].items()} or len(src) != 12:
                raise ValueError("testcase upstream source drift")
        else:
            before = json.loads((pkg / "UPSTREAM-COMPOSER.json").read_text())["require"]
            after = dict(before, php=">=8.2")
            del after["wp-cli/process"]
            after["symfony/process"] = "5.4.51"
            if meta["require"] != after or meta["type"] != "metapackage" or "autoload" in meta:
                raise ValueError("WP-CLI command map drift")
    before = json.loads((area / "root-candidate-before-closure.json").read_text())
    expected = json.loads(json.dumps(before))
    del expected["require-dev"]["wp-cli/wp-cli-bundle"]
    del expected["require-dev"]["wp-graphql/wp-graphql-testcase"]
    expected["repositories"] = []
    for mapping in mappings:
        name = mapping["owned_name"]
        expected["require-dev"][name] = VERSION
        expected["repositories"].append({"type": "path", "url": mapping["path"], "options": {"symlink": False, "reference": "config", "versions": {name: VERSION}}})
    expected["archive"]["exclude"].append("/build/dependency-sources")
    del expected["require"]["league/oauth2-instagram"]
    expected["extra"]["strauss"]["packages"].remove("league/oauth2-instagram")
    for name, (version, _) in CHECKER_PINS.items():
        expected["require-dev"][name] = version
    if json.loads((root / "composer.json").read_text()) != expected:
        raise ValueError("unexpected candidate root metadata change")
    pins_path = reject_symlink_path(area / "retirement-checker-source-pins.json")
    pins = json.loads(pins_path.read_text())
    if set(pins["checker_cohort"]) != set(CHECKER_PINS):
        raise ValueError("unexpected checker cohort membership")
    for name, (version, reference) in CHECKER_PINS.items():
        item = pins["checker_cohort"][name]
        if item["version"] != version or item["source_reference"] != reference or item["role"] != "development":
            raise ValueError("checker source/version/role mismatch")
        if not item.get("license_sha256") or not item.get("archive_members"):
            raise ValueError("missing checker license/source inventory")
    baseline_xml = reject_symlink_path(area / "headless-phpcs-baseline.xml.txt").read_bytes()
    if reject_symlink_path(root / ".phpcs.xml.dist").read_bytes() != baseline_xml.replace(b'name="testVersion" value="7.4-"', b'name="testVersion" value="8.2"'):
        raise ValueError("inherited checker configuration/rules weakened or changed")
    for name in ("wp-graphql-headless-login.php", "readme.txt"):
        if not re.search(r"Requires PHP:\s*8\.2\s*$", reject_symlink_path(root / name).read_text(), re.M):
            raise ValueError("advertised PHP minimum not aligned")
    return {"package_files": len(actual), "testcase_src_files": 12, "root_scope": "exact reviewed changes", "checker_git_tag_tree_gate": "verified" if all(p["git_verified"] for p in pins["checker_cohort"].values()) else "pending; no installed execution admission"}

def checker_installed_gate(vendor, root=ROOT):
    vendor = reject_symlink_path(vendor)
    pins = json.loads(reject_symlink_path(root / "build/dependency-sources/retirement-checker-source-pins.json").read_text())
    if not all(p["git_verified"] and p.get("export_ignore_verified") for p in pins["checker_cohort"].values()):
        raise ValueError("checker Git/tag/tree verification not admitted")
    installed = json.loads(reject_symlink_path(vendor / "composer/installed.json").read_text())
    names = {p["name"]: p for p in installed["packages"]}
    for name, (version, reference) in CHECKER_PINS.items():
        selected = names.get(name, {})
        if selected.get("version", "").lstrip("v") != version or selected.get("source", {}).get("reference") != reference:
            raise ValueError("checker installed identity differs: " + name)
        package = reject_symlink_path(vendor / name)
        actual = regular_inventory(package)
        expected = pins["checker_cohort"][name]["archive_members"]
        hash_map({p: m["sha256"] for p, m in expected.items()}, "checker members")
        # Composer may add installed package metadata only through a separately reviewed delta.
        if actual != {p: m["sha256"] for p, m in expected.items()}:
            raise ValueError("checker installed membership/content differs: " + name)
        for relative, entry in expected.items():
            path = package / relative
            if type(entry["bytes"]) is not int or path.stat().st_size != entry["bytes"] or stat.S_IMODE(path.stat().st_mode) != int(entry["required_installed_mode"], 8):
                raise ValueError("checker installed byte/mode differs: " + name + "/" + relative)
    return {"checker_packages": 4, "qualification": "exact tagged development source; genuine checker behavior still required"}

def helper_consumers(paths):
    findings = []
    for root in paths:
        root = reject_symlink_path(root)
        files = [root] if root.is_file() else sorted(root.rglob("*.php"))
        for path in files:
            reject_symlink_path(path)
            code = path.read_text(errors="strict")
            # Preserve all text/line boundaries, including comments, strings and heredocs.
            # False-positive candidates require classification; regex is not lexical absence proof.
            for line, text in enumerate(code.splitlines(), 1):
                if HELPERS.search(text):
                    findings.append({"file": str(path), "line": line, "text": text.strip(), "kind": "conservative case-insensitive identifier/callable candidate"})
    return findings

def installed_gate(vendor, root=ROOT):
    root = reject_symlink_path(root)
    vendor = reject_symlink_path(vendor)
    reject_symlink_path(vendor / "composer/installed.json")
    reject_symlink_path(root / "build/dependency-sources/source-manifest.json")
    reject_symlink_path(root / "build/dependency-sources/official-process-source.json")
    metadata = json.loads((vendor / "composer/installed.json").read_text())
    packages = metadata["packages"] if isinstance(metadata, dict) else metadata
    names = {p["name"]: p for p in packages}
    forbidden = {"wp-cli/process", "php-extended/polyfill-php80-str-utils", "wp-cli/wp-cli-bundle", "wp-graphql/wp-graphql-testcase", "league/oauth2-instagram", "jakeasmith/http_build_url"}
    if forbidden.intersection(names):
        raise ValueError("displaced package remains in installed graph")
    for name in ("kodekrakan-commerce/headless-wp-cli-bundle", "kodekrakan-commerce/headless-graphql-testcase"):
        if names.get(name, {}).get("version") != VERSION:
            raise ValueError("owned development package identity/version missing")
    source_manifest = json.loads((root / "build/dependency-sources/source-manifest.json").read_text())
    prefix = "build/dependency-sources/wp-graphql-testcase/"
    copied = vendor / "kodekrakan-commerce/headless-graphql-testcase"
    reject_symlink_path(copied)
    regular_inventory(copied)
    expected_copy = {p[len(prefix):]: m for p, m in source_manifest["package_files"].items() if p.startswith(prefix)}
    actual_copy = {str(p.relative_to(copied)): {"sha256": digest(p), "mode": f"{stat.S_IMODE(p.stat().st_mode):04o}"} for p in copied.rglob("*") if p.is_file()}
    if any(p.is_symlink() for p in copied.rglob("*")) or actual_copy != expected_copy:
        raise ValueError("mirrored installed testcase differs from tracked owned source")
    process = names.get("symfony/process", {})
    if process.get("version", "").lstrip("v") != "5.4.51" or process.get("source", {}).get("reference") != "467bfc56f18f5ef6d5ccb09324d7e988c1c0a98f":
        raise ValueError("genuine Process source/version not admitted")
    expected = json.loads((root / "build/dependency-sources/official-process-source.json").read_text())["source_php_files"]
    process_root = vendor / "symfony/process"
    reject_symlink_path(process_root)
    regular_inventory(process_root)
    actual = {str(p.relative_to(process_root)): {"sha256": digest(p), "mode": f"{stat.S_IMODE(p.stat().st_mode):04o}"} for p in process_root.rglob("*.php") if "Tests" not in p.relative_to(process_root).parts}
    if any(p.is_symlink() for p in process_root.rglob("*")) or actual != expected:
        raise ValueError("Process source-family content/mode/membership differs from exact official archive")
    providers, old_api_candidates = [], []
    for path in sorted(vendor.rglob("*.php")):
        reject_symlink_path(path)
        text = path.read_text()
        if re.search(r"namespace\s+Symfony\\Component\\Process\s*;", text, re.I) and re.search(r"\bclass\s+Process\b", text, re.I):
            providers.append(str(path.resolve()))
        if REMOVED_APIS.search(text):
            old_api_candidates.append(str(path.relative_to(vendor)))
    if providers != [str((vendor / "symfony/process/Process.php").resolve())]:
        raise ValueError("multiple or misplaced Symfony Process providers")
    helpers = helper_consumers([vendor])
    if helpers:
        raise ValueError("removed helper literal candidate requires classification: " + json.dumps(helpers))
    # Old API names require owner classification; unrelated console getOptions is not rejected blindly.
    return {"process_provider": providers, "removed_api_candidates_requiring_review": old_api_candidates, "helper_consumers": []}

def archive_gate(archive, root=ROOT):
    forbidden = ("build/dependency-sources/", "vendor/kodekrakan-commerce/", "vendor/wp-cli/", "vendor/symfony/process/", "vendor/wp-graphql/wp-graphql-testcase/", "vendor/php-extended/polyfill-php80-str-utils/", "vendor/phpcompatibility/", "vendor/axepress/wp-graphql-cs/", "vendor/league/oauth2-instagram/", "vendor/jakeasmith/http_build_url/")
    with zipfile.ZipFile(archive) as zipped:
        paths = zipped.namelist()
        policy = json.loads(reject_symlink_path(root / "build/dependency-sources/retirement-checker-source-pins.json").read_text())
        dev_paths = tuple(prefix + name + "/" for name in policy["excluded_development_names"] for prefix in ("vendor/", "vendor-prefixed/"))
        retired_paths = tuple(prefix + name + "/" for name in policy["retired_packages"] for prefix in ("vendor/", "vendor-prefixed/"))
        bad = [p for p in paths if any(f in p for f in forbidden + dev_paths + retired_paths)]
    if bad:
        raise ValueError("development source/code leaked into runtime archive: " + json.dumps(bad))
    return {"archive_files": len(paths), "development_members": []}

def production_autoload_gate(directory, root=ROOT):
    directory = reject_symlink_path(directory)
    files = sorted(directory.glob("autoload*.php"))
    if not files:
        raise ValueError("missing generated production autoload maps")
    policy = json.loads(reject_symlink_path(root / "build/dependency-sources/retirement-checker-source-pins.json").read_text())
    markers = policy["excluded_development_names"] + policy["retired_packages"] + ["PHPCompatibility", "http_build_url", "League\\\\OAuth2\\\\Client\\\\Provider\\\\Instagram"]
    for path in files:
        reject_symlink_path(path)
        code = path.read_text()
        if any(marker.lower() in code.lower() for marker in markers):
            raise ValueError("development/retired code in production autoload map: " + str(path))
    return {"production_autoload_maps": len(files), "development_or_retired_markers": []}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--vendor", type=Path)
    parser.add_argument("--scan-consumers", type=Path, nargs="+")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--production-autoload", type=Path)
    args = parser.parse_args()
    try:
        result = {"source": source_gate(args.root)}
        if args.vendor:
            result["installed"] = installed_gate(args.vendor, args.root)
        if args.scan_consumers:
            findings = helper_consumers(args.scan_consumers)
            if findings:
                raise ValueError("removed helper literal candidate requires classification: " + json.dumps(findings))
            result["consumer_scan"] = "no raw literal helper candidates; not a lexical/dynamic absence proof"
        if args.archive:
            result["archive"] = archive_gate(args.archive, args.root)
        if args.production_autoload:
            result["production_autoload"] = production_autoload_gate(args.production_autoload, args.root)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
