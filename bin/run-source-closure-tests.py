#!/usr/bin/env python3
"""Future admitted installed-graph runner. No downloads, solver or installation."""
import argparse
import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).absolute().parents[1]
spec = importlib.util.spec_from_file_location("source_gate", ROOT / "bin/verify-source-closure.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

def main(argv=None, root=ROOT, dispatch=subprocess.run):
    parser = argparse.ArgumentParser()
    parser.add_argument("--admission", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = gate.validate_admission(root, args.admission)
    php = Path(receipt["php_binary"])
    env = {"PATH": str(php.parent), "HEADLESS_CLOSURE_ADMISSION": str(args.admission.absolute()), "LANG": "C"}
    # This first dispatch executes only the admitted PHP binary and owned version expression.
    version = dispatch([str(php), "-r", "fwrite(STDOUT, PHP_VERSION);"], cwd=root, env=env, capture_output=True, text=True)
    if version.returncode or version.stdout != "8.2.34":
        raise ValueError("actual admitted PHP version differs")
    phpunit = root / "vendor/phpunit/phpunit/phpunit"
    command = [str(php), str(phpunit), "--configuration", str(root / "tests/source-closure/phpunit.xml")]
    result = dispatch(command, cwd=root, env=env)
    if result.returncode:
        return result.returncode
    negative = [str(php), str(phpunit), "--bootstrap", str(root / "tests/source-closure/bootstrap.php"), "--no-configuration", str(root / "tests/source-closure/DeliberateFailureTest.php")]
    control = dispatch(negative, cwd=root, env=env, capture_output=True, text=True)
    if control.returncode != 1 or "FAILURES!" not in control.stdout:
        raise ValueError("deliberately failing assertion did not propagate with PHPUnit exit1")
    print(json.dumps({"positive_command": command, "positive_exit": 0, "negative_command": negative, "negative_exit": control.returncode, "negative_output": control.stdout + control.stderr, "windows_qualification": "unrun; separate admitted Windows/MSYS2 gate required"}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
