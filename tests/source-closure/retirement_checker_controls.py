"""Source/data-only negative controls; no actual checker/provider code executes."""
import hashlib, importlib.util, json, os, shutil, subprocess, tempfile, unittest, zipfile
from pathlib import Path
ROOT=Path(__file__).absolute().parents[2]
spec=importlib.util.spec_from_file_location('gate',ROOT/'bin/verify-source-closure.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class RetirementCheckerControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        shutil.copytree(ROOT/'build/dependency-sources',self.root/'build/dependency-sources')
        for name in ('composer.json','.phpcs.xml.dist','wp-graphql-headless-login.php','readme.txt'):shutil.copyfile(ROOT/name,self.root/name)
    def tearDown(self):self.temp.cleanup()
    def test_owned_native_refusal_and_missing_client_guard_negative(self):
        php=os.environ['HEADLESS_SOURCE_CONTROL_PHP']
        for name in ('tests/source-closure/retirement-source-controls.php','src/Auth/ProviderConfig/OAuth2/Instagram.php','src/Auth/Client.php','src/Auth/Auth.php','src/Auth/ProviderRegistry.php'):
            target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        script=self.root/'tests/source-closure/retirement-source-controls.php'
        good=subprocess.run([php,str(script)],capture_output=True,text=True,env={'PATH':'/usr/bin:/bin','HOME':str(self.root)})
        self.assertEqual(good.returncode,0,good.stderr);self.assertEqual(len(json.loads(good.stdout)['refusals']),12)
        before={str(p.relative_to(self.root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((self.root/'src').rglob('*.php'))}
        client=self.root/'src/Auth/Client.php';text=client.read_text();guard="\t\tif ( Instagram::get_slug() === $slug ) {\n\t\t\tInstagram::assert_available();\n\t\t}\n"
        self.assertEqual(text.count(guard),1);client.write_text(text.replace(guard,''))
        bad=subprocess.run([php,str(script)],capture_output=True,text=True,env={'PATH':'/usr/bin:/bin','HOME':str(self.root)})
        self.assertNotEqual(bad.returncode,0);self.assertIn('RuntimeException: Unexpected external autoload:',bad.stderr);self.assertNotIn('Parse error',bad.stderr)
        if os.environ.get('HEADLESS_SOURCE_NEGATIVE_RECEIPT'):
            Path(os.environ['HEADLESS_SOURCE_NEGATIVE_RECEIPT']).write_text(json.dumps({'scope':'Owned copied source/native stand-ins only; no library/WordPress/vendor runtime','php_binary':php,'php_binary_sha256':hashlib.sha256(Path(php).read_bytes()).hexdigest(),'argv':[php,str(script)],'environment':{'PATH':'/usr/bin:/bin','HOME':str(self.root)},'source_before_sha256':before,'source_after_removed_client_guard_sha256':hashlib.sha256(client.read_bytes()).hexdigest(),'removed_guard':guard,'seam_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),'positive':{'exit':good.returncode,'stdout':good.stdout,'stderr':good.stderr},'negative':{'exit':bad.returncode,'stdout':bad.stdout,'stderr':bad.stderr},'required_negative_marker':'RuntimeException: Unexpected external autoload:','startup_failure_not_accepted':True,'temporary_inputs_cleaned_by_teardown':True},indent=2)+'\n')
    def test_checker_selected_registration_bound_before_dispatch(self):
        spec=importlib.util.spec_from_file_location('checker_runner',ROOT/'tests/source-closure/checker/run-controls.py');checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
        directory=self.root/'tests/source-closure/checker';directory.mkdir(parents=True);file=directory/'fixture-registration.json'
        standard=self.root/'vendor/phpcompatibility/php-compatibility';standard.mkdir(parents=True)
        data={'schema':'headless-checker-registration/v1','phpcs_version':'3.13.6','cli_config_source_verified':True,'argv':['--runtime-set','installed_paths',str(standard)]}
        file.write_text(json.dumps(data));receipt={'harness_files':{str(file.relative_to(self.root)):gate.digest(file)}}
        self.assertEqual(data['argv'],checker.validate_registration(file,receipt,self.root))
        file.write_text(json.dumps(dict(data,cli_config_source_verified='true')))
        with self.assertRaises(ValueError):checker.validate_registration(file,receipt,self.root)
        receipt['harness_files'][str(file.relative_to(self.root))]=gate.digest(file)
        with self.assertRaises(ValueError):checker.validate_registration(file,receipt,self.root)
        outside=self.root/'unbound-registration.json';outside.write_text(json.dumps(data))
        with self.assertRaises(ValueError):checker.validate_registration(outside,receipt,self.root)
    def checker_module(self):
        spec=importlib.util.spec_from_file_location('checker_source_controls',ROOT/'tests/source-closure/checker/run-controls.py');checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker);return checker
    def test_exact_standard_discovery_missing_base_refuses(self):
        checker=self.checker_module();allnames=sorted(checker.REQUIRED_STANDARDS)
        self.assertEqual(set(allnames),checker.validate_standard_discovery('The installed coding standards are '+', '.join(allnames)))
        missing=[n for n in allnames if n!='WPGraphQL']
        with self.assertRaises(ValueError):checker.validate_standard_discovery('The installed coding standards are '+', '.join(missing))
    def test_independent_complete_roster_and_exact_synthetic_counterparts(self):
        # All fields/reports here are explicitly synthetic data, never a genuine source-review/PHPCS result.
        checker=self.checker_module();area=self.root/'tests/source-closure/checker';area.mkdir(parents=True)
        fixture=area/'php82-positive.php';shutil.copyfile(ROOT/'tests/source-closure/checker/php82-positive.php',fixture)
        file=area/'synthetic-expected-roster.json';sniffs=['Fixture.Style.One','PHPCompatibility.Classes.NewReadonlyClasses','PHPCompatibility.FunctionDeclarations.NewParamTypeDeclarations','PHPCompatibility.FunctionDeclarations.NewReturnTypeDeclarations']
        data={'schema':'headless-checker-source-expected-roster/v1','source_reviewed':True,'cli_registry_parser_source_verified':True,'diagnostic_contract_source_reviewed':True,'source_hashes':{'.phpcs.xml.dist':gate.digest(self.root/'.phpcs.xml.dist')},'vendor_files':{'inert-synthetic-source.txt':'1'*64},'expected_sniffs':sorted(sniffs),'expected_sniffs_sha256':checker.roster_fingerprint(sniffs),'php81_error_severity':5,'fixture_sha256':gate.digest(fixture)}
        file.write_text(json.dumps(data));receipt={'source_hashes':data['source_hashes'],'vendor_files':data['vendor_files'],'harness_files':{str(file.relative_to(self.root)):gate.digest(file),str(fixture.relative_to(self.root)):gate.digest(fixture)}}
        self.assertEqual(sorted(sniffs),checker.validate_expected_roster(file,receipt,self.root)['expected_sniffs'])
        valid='Synthetic prepared registry, not PHPCS output\n'+'\n'.join('  '+n for n in sniffs)
        self.assertEqual(set(sniffs),checker.validate_sniff_registry(valid,sniffs))
        for actual in (sniffs[1:2],sniffs[:-1],sniffs+['Fixture.Unexpected.Sniff']):
            with self.assertRaises(ValueError):checker.validate_sniff_registry('\n'.join(actual),sniffs)
        old=file.read_text()
        for key,value in (('source_reviewed','true'),('cli_registry_parser_source_verified','true'),('diagnostic_contract_source_reviewed',False),('source_hashes',{}),('vendor_files',{}),('expected_sniffs_sha256','0'*64),('php81_error_severity',True)):
            file.write_text(json.dumps(dict(data,**{key:value})));receipt['harness_files'][str(file.relative_to(self.root))]=gate.digest(file)
            with self.assertRaises(ValueError):checker.validate_expected_roster(file,receipt,self.root)
        file.write_text(old);receipt['harness_files'][str(file.relative_to(self.root))]=gate.digest(file)
        file.write_text(old+'\n')
        with self.assertRaises(ValueError):checker.validate_expected_roster(file,receipt,self.root)
        receipt['harness_files'].pop(str(file.relative_to(self.root)))
        with self.assertRaises(ValueError):checker.validate_expected_roster(file,receipt,self.root)
        with self.assertRaises(ValueError):checker.validate_expected_roster(area/'absent-roster.json',receipt,self.root)
    def test_readonly_only_or_either_dnf_missing_refuses_source_derived_prepared_reports(self):
        # Synthetic tuples test owned assertions only; severity5 is fixture data, not a checker result.
        checker=self.checker_module();fixture=ROOT/'tests/source-closure/checker/php82-positive.php'
        full=[(code,'ERROR',5,line,str(fixture)) for code,line in checker.PHP81_DIAGNOSTICS.items()]
        checker.validate_php81_diagnostics(full,fixture,5)
        for reduced in ([full[0]],full[:2],[full[0],full[2]]):
            with self.assertRaises(ValueError):checker.validate_php81_diagnostics(reduced,fixture,5)
        for index,value in ((1,'WARNING'),(2,4),(3,99),(4,str(self.root/'other.php'))):
            changed=list(full);entry=list(changed[1]);entry[index]=value;changed[1]=tuple(entry)
            with self.assertRaises(ValueError):checker.validate_php81_diagnostics(changed,fixture,5)
    def test_four_only_pins_no_alias_or_global_alpha(self):
        for package in gate.CHECKER_PINS:
            file=self.root/'composer.json';old=file.read_text();data=json.loads(old);data['require-dev'][package]='dev-main';file.write_text(json.dumps(data))
            with self.assertRaises(ValueError):gate.source_gate(self.root)
            file.write_text(old)
        file=self.root/'composer.json';data=json.loads(file.read_text());data['minimum-stability']='alpha';file.write_text(json.dumps(data))
        with self.assertRaises(ValueError):gate.source_gate(self.root)
    def test_provider_dependency_reintroduction_and_rule_weakening_refuse(self):
        file=self.root/'composer.json';old=file.read_text();data=json.loads(old);data['require']['league/oauth2-instagram']='^3.1';file.write_text(json.dumps(data))
        with self.assertRaises(ValueError):gate.source_gate(self.root)
        file.write_text(old);xml=self.root/'.phpcs.xml.dist';xml.write_text(xml.read_text().replace('value="1"','value="0"'))
        with self.assertRaises(ValueError):gate.source_gate(self.root)
    def test_wrong_checker_role_or_source_refuse(self):
        file=self.root/'build/dependency-sources/retirement-checker-source-pins.json';old=file.read_text()
        for key,value in (('role','production'),('source_reference','0'*40)):
            data=json.loads(old);data['checker_cohort']['phpcompatibility/php-compatibility'][key]=value;file.write_text(json.dumps(data))
            with self.assertRaises(ValueError):gate.source_gate(self.root)
    def test_dev_archive_and_production_autoload_leaks_refuse(self):
        archive=self.root/'fixture.zip'
        for name in ('phpcompatibility/phpcompatibility-wp','phpunit/phpunit','league/oauth2-instagram','jakeasmith/http_build_url'):
            for prefix in ('vendor','vendor-prefixed'):
                with zipfile.ZipFile(archive,'w') as z:z.writestr('plugin/'+prefix+'/'+name+'/fixture.php','inert')
                with self.assertRaises(ValueError):gate.archive_gate(archive,self.root)
        maps=self.root/'autoload';maps.mkdir();(maps/'autoload_classmap.php').write_text("<?php /* inert fixture */ 'PHPCompatibility\\Sniff'")
        with self.assertRaises(ValueError):gate.production_autoload_gate(maps,self.root)
if __name__=='__main__':unittest.main()
