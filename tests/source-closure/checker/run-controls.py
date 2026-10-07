#!/usr/bin/env python3
"""Future genuine PHPCS consumer controls; UNRUN until source/tool/registration admission."""
import argparse, hashlib, importlib.util, json, os, re, shutil, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).absolute().parents[3]
spec=importlib.util.spec_from_file_location('gate',ROOT/'bin/verify-source-closure.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

def validate_registration(path,receipt,root=ROOT):
    path=gate.reject_symlink_path(path)
    area=gate.reject_symlink_path(root/'tests/source-closure/checker')
    if not path.is_file() or not path.is_relative_to(area):raise ValueError('Selected registration must be a bound checker harness input')
    key=str(path.relative_to(root))
    if receipt.get('harness_files',{}).get(key)!=gate.digest(path):raise ValueError('Selected registration membership/hash not bound by admission')
    registration=json.loads(path.read_text())
    if not isinstance(registration,dict) or registration.get('schema')!='headless-checker-registration/v1' or registration.get('phpcs_version')!='3.13.6' or registration.get('cli_config_source_verified') is not True:
        raise ValueError('Exact PHPCS3.13.6 registration/config-source admission required')
    extra=registration.get('argv')
    if not isinstance(extra,list) or any(not isinstance(a,str) for a in extra) or extra[:2]!=['--runtime-set','installed_paths'] or len(extra)!=3:
        raise ValueError('Only separately reviewed temporary installed_paths registration is allowed')
    standard_paths=[gate.reject_symlink_path(p) for p in extra[2].split(',')]
    if any(not p.is_dir() or not p.is_relative_to(root/'vendor') for p in standard_paths):raise ValueError('Standards must resolve inside fully admitted vendor')
    return extra

REQUIRED_STANDARDS = {'WPGraphQL','WPGraphQL-Core','WPGraphQL-Docs','WPGraphQL-Extra','WPGraphQL-Strict','WPGraphQL-Minimum','PHPCompatibilityWP','PHPCompatibility','PHPCompatibilityParagonieRandomCompat','PHPCompatibilityParagonieSodiumCompat'}
PHP81_DIAGNOSTICS = {
    'PHPCompatibility.Classes.NewReadonlyClasses.Found': 2,
    'PHPCompatibility.FunctionDeclarations.NewParamTypeDeclarations.DNFTypeFound': 5,
    'PHPCompatibility.FunctionDeclarations.NewReturnTypeDeclarations.DNFTypeFound': 5,
}
SNIFF_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*')

def validate_standard_discovery(text):
    match=re.fullmatch(r'The installed coding standards are (.+)',text.strip())
    if not match:raise ValueError('Unrecognized installed-standard output; parser requires source review')
    names=re.split(r',\s*(?:and\s+)?|\s+and\s+',match.group(1))
    if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*',name) for name in names) or len(names)!=len(set(names)):
        raise ValueError('Invalid or duplicate standard identifier')
    if not REQUIRED_STANDARDS.issubset(set(names)):raise ValueError('Incomplete exact standard discovery')
    return set(names)

def roster_fingerprint(sniffs):
    return hashlib.sha256(('\n'.join(sorted(sniffs))+'\n').encode()).hexdigest()

def validate_expected_roster(path,receipt,root=ROOT):
    # Future independently SOURCE-reviewed data, never derived from this runner's -e output.
    path=gate.reject_symlink_path(path);area=gate.reject_symlink_path(root/'tests/source-closure/checker')
    if not path.is_file() or not path.is_relative_to(area):raise ValueError('Expected roster must be a bound checker harness input')
    if receipt.get('harness_files',{}).get(str(path.relative_to(root)))!=gate.digest(path):raise ValueError('Expected roster membership/hash not bound')
    data=json.loads(path.read_text())
    if not isinstance(data,dict) or data.get('schema')!='headless-checker-source-expected-roster/v1' or data.get('source_reviewed') is not True or data.get('cli_registry_parser_source_verified') is not True or data.get('diagnostic_contract_source_reviewed') is not True:
        raise ValueError('Independently source-reviewed complete roster/parser/diagnostic proof required')
    if gate.hash_map(data.get('source_hashes'),'expected roster source')!=receipt['source_hashes'] or gate.hash_map(data.get('vendor_files'),'expected roster vendor')!=receipt['vendor_files']:
        raise ValueError('Expected roster complete source/vendor membership or hash differs')
    sniffs=data.get('expected_sniffs')
    if not isinstance(sniffs,list) or not sniffs or any(not isinstance(n,str) or not SNIFF_IDENTIFIER.fullmatch(n) for n in sniffs) or sniffs!=sorted(set(sniffs)):
        raise ValueError('Expected complete sniff identifiers must be unique and sorted')
    if data.get('expected_sniffs_sha256')!=roster_fingerprint(sniffs):raise ValueError('Expected sniff roster fingerprint differs')
    severity=data.get('php81_error_severity')
    if type(severity) is not int or not 1<=severity<=10:raise ValueError('Exact source-reviewed PHPCS diagnostic severity required')
    fixture=gate.reject_symlink_path(area/'php82-positive.php')
    if data.get('fixture_sha256')!=gate.digest(fixture) or receipt.get('harness_files',{}).get(str(fixture.relative_to(root)))!=gate.digest(fixture):raise ValueError('PHP8.1/8.2 diagnostic fixture not bound')
    return data

def validate_sniff_registry(text,expected):
    names=[line.strip() for line in text.splitlines() if SNIFF_IDENTIFIER.fullmatch(line.strip())]
    if not names or len(names)!=len(set(names)):raise ValueError('Empty or duplicate actual sniff registry')
    if set(names)!=set(expected):raise ValueError('Inherited sniff registry differs: missing='+repr(sorted(set(expected)-set(names)))+' unexpected='+repr(sorted(set(names)-set(expected))))
    return set(names)

def validate_php81_diagnostics(messages,fixture,severity):
    for code,line in PHP81_DIAGNOSTICS.items():
        if not any(m[0]==code and m[1]=='ERROR' and type(m[2]) is int and m[2]==severity and type(m[3]) is int and m[3]==line and Path(m[4]).absolute()==fixture.absolute() for m in messages):
            raise ValueError('Exact PHP8.1 readonly/DNF diagnostic missing or wrong type/severity/location: '+code)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--admission',type=Path,required=True);parser.add_argument('--registration',type=Path,required=True);parser.add_argument('--expected-roster',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    # Registration is reviewed data: do not infer PHPCS CLI/config support or run installer plugins.
    receipt=gate.validate_admission(ROOT,args.admission);gate.checker_installed_gate(ROOT/'vendor',ROOT)
    extra=validate_registration(args.registration,receipt)
    expected_roster=validate_expected_roster(args.expected_roster,receipt)
    php=receipt['php_binary'];entry=ROOT/'vendor/squizlabs/php_codesniffer/bin/phpcs'
    if 'squizlabs/php_codesniffer/bin/phpcs' not in receipt['vendor_files']:raise ValueError('PHPCS entrypoint not bound')
    output=gate.reject_symlink_path(args.output);output.mkdir(exist_ok=False)
    env={'PATH':str(Path(php).parent),'LANG':'C'};commands=[]
    def dispatch(arguments,cwd=ROOT):
        current=gate.validate_admission(ROOT,args.admission);gate.checker_installed_gate(ROOT/'vendor',ROOT)
        validate_expected_roster(args.expected_roster,current);validate_registration(args.registration,current)
        command=[php,str(entry),*extra,*arguments]
        result=subprocess.run(command,cwd=cwd,env=env,capture_output=True,text=True)
        commands.append({'argv':command,'cwd':str(cwd),'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        return result
    version=subprocess.run([php,'-r','fwrite(STDOUT, PHP_VERSION);'],env=env,capture_output=True,text=True)
    if version.returncode or version.stdout!='8.2.34':raise ValueError('Actual PHP8.2.34 required')
    registered=dispatch(['-i'])
    if registered.returncode:raise ValueError('Standard discovery command failed')
    validate_standard_discovery(registered.stdout)
    registry=dispatch(['-e','--standard='+str(ROOT/'.phpcs.xml.dist')])
    if registry.returncode:raise ValueError('Inherited sniff registry command failed')
    validate_sniff_registry(registry.stdout,expected_roster['expected_sniffs'])
    (output/'complete-sniff-registry.txt').write_text(registry.stdout)
    fixtures=ROOT/'tests/source-closure/checker'
    cases=[('php82-positive.php','PHPCompatibility','8.2',[]),('php82-positive.php','PHPCompatibility','8.1',list(PHP81_DIAGNOSTICS)),('removed-deprecated.php','PHPCompatibilityWP','8.2',['utf8_encodeDeprecated','eachFound','RemovedDollarBraceStringEmbeds']),('php83-negative.php','PHPCompatibility','8.2',['PHPCompatibility.Classes.NewTypedConstants.Found']),('wp-polyfill.php','PHPCompatibility','7.4',['str_containsFound','eachDeprecated']),('wp-polyfill.php','PHPCompatibilityWP','7.4',['eachDeprecated'])]
    def report(arguments,cwd=ROOT):
        result=dispatch(['--report=json','--parallel=1','--severity=1','--warning-severity=1','--extensions=php',*arguments],cwd)
        data=json.loads(result.stdout);messages=[m for f in data['files'].values() for m in f['messages']]
        return result,sorted((m['source'],m['type'],m['severity'],m['line'],name) for name,f in data['files'].items() for m in f['messages'])
    for file,standard,target,expected in cases:
        reports=[]
        for cache in ('--no-cache','--cache='+str(output/(file+'.cache')),'--cache='+str(output/(file+'.cache'))):
            result,messages=report(['--standard='+standard,'--runtime-set','testVersion',target,cache,str(fixtures/file)])
            if bool(expected)!=(result.returncode!=0):raise ValueError('Genuine fixture exit mismatch: '+file+'/'+target)
            if not expected and messages:raise ValueError('PHP8.2 legal fixture rejected')
            if file=='php82-positive.php' and target=='8.1':validate_php81_diagnostics(messages,fixtures/file,expected_roster['php81_error_severity'])
            for code in expected:
                if not any(code in m[0] for m in messages):raise ValueError('Required genuine diagnostic missing: '+code)
            if file=='wp-polyfill.php' and standard=='PHPCompatibilityWP' and any('str_contains' in m[0] for m in messages):raise ValueError('WP polyfill exception lost')
            reports.append((result.returncode,messages))
        if reports[0]!=reports[1] or reports[1]!=reports[2]:raise ValueError('Fixture cache/uncached diagnostic drift')
    # Full inherited scan and seeded source/excluded-fixture pair use owned disposable copies.
    with tempfile.TemporaryDirectory(prefix='headless-checker-seeded-') as temp:
        copy=Path(temp).resolve()
        for name in ('src','access-functions.php','wp-graphql-headless-login.php','activation.php','deactivation.php','.phpcs.xml.dist'):
            source=ROOT/name;target=copy/name
            if source.is_dir():shutil.copytree(source,target)
            else:shutil.copyfile(source,target)
        baselines=[]
        for cache in ('--no-cache','--cache='+str(output/'full-baseline.cache'),'--cache='+str(output/'full-baseline.cache')):
            baseline_result,baseline=report(['--standard='+str(copy/'.phpcs.xml.dist'),cache],copy)
            baselines.append((baseline_result.returncode,baseline))
        if baselines[0]!=baselines[1] or baselines[1]!=baselines[2]:raise ValueError('Full inherited baseline cache drift')
        seed=copy/'src/retirement-checker-seed.php';seed.write_text('<?php\neach([]);\n')
        (copy/'vendor').mkdir();(copy/'vendor/excluded.php').write_text('<?php\neach([]);\n')
        seeded=[]
        for cache in ('--no-cache','--cache='+str(output/'full-seeded.cache'),'--cache='+str(output/'full-seeded.cache')):
            result,messages=report(['--standard='+str(copy/'.phpcs.xml.dist'),cache,*[str(copy/name) for name in ('src','access-functions.php','wp-graphql-headless-login.php','activation.php','deactivation.php','vendor/excluded.php')]],copy)
            if not result.returncode or not any('RemovedFunctions.eachFound' in m[0] and m[4].endswith('src/retirement-checker-seed.php') for m in messages):raise ValueError('Full inherited seeded source did not genuinely fail at included seed path')
            if 'vendor/excluded.php' in result.stdout:raise ValueError('Configured vendor exclusion changed')
            seeded.append((result.returncode,messages))
        if seeded[0]!=seeded[1] or seeded[1]!=seeded[2]:raise ValueError('Full seeded scan cache drift')
        (output/'full-source-baseline.json').write_text(json.dumps({'exit':baseline_result.returncode,'diagnostics':baseline,'qualification':'Review every real inherited style/compatibility finding; seeded failure is not a baseline pass'},indent=2)+'\n')
    return 0
if __name__=='__main__':raise SystemExit(main())
