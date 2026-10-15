"""Run native regressions and parse real reports using only Python's standard library."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time


def run(executable, *args, cwd=None):
    started = time.perf_counter()
    try:
        result = subprocess.run([str(executable), *args], cwd=cwd, capture_output=True, timeout=180, check=True)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode('utf-8-sig', errors='replace').strip()
        raise RuntimeError(f"{executable.name} exited with {error.returncode}: {detail}") from error
    return result.stdout.decode('utf-8-sig'), time.perf_counter() - started


def export_report(app, *options):
    with tempfile.TemporaryDirectory(prefix='sa-json-') as folder:
        path = Path(folder) / 'saved report.json'
        output, elapsed = run(app, '--json', '1', str(path), *options)
        assert output.startswith('JSON report saved to:') and not output.lstrip().startswith('{')
        report = json.loads(path.read_text(encoding='utf-8'))
        rejected = subprocess.run([str(app), '--json', 'view', str(path)], capture_output=True, timeout=15)
        assert rejected.returncode == 1 and b'compact exports only' in rejected.stderr
        compact_path = Path(folder) / 'compact.json'
        run(app, '--json', '0', str(compact_path), *options)
        compact = json.loads(compact_path.read_text(encoding='utf-8'))
        assert compact['v'] == 2 and set(compact) == {'v', 'd'}
        assert 'system' not in compact and 's' not in compact
        assert len(compact_path.read_bytes()) < len(path.read_bytes())
        def direct_data(value):
            if isinstance(value, dict):
                return all(k.isdecimal() and int(k) > 0 and direct_data(v) for k, v in value.items())
            if isinstance(value, list):
                return all(direct_data(v) for v in value)
            return value is None or type(value) in (str, int, float)
        assert direct_data(compact['d'])
        assert compact['d']['7']['1'] == report['system']['productName']
        assert compact['d']['7']['2'] == report['system']['build']
        assert compact['d']['81']['88']['3'] in (0, 1, 2, 3)
        viewed, _ = run(app, '--json', 'view', str(compact_path))
        assert viewed.startswith('Windows Security Assessment')
        assert viewed.index('Windows Security Assessment') < viewed.index('[!] BACKUP REPORT') < viewed.index('-- System')
        assert 'You are viewing a backup.' in viewed and 'current system state.' in viewed
        assert '-- Applications' not in viewed
        assert 'Windows Security Assessment' in viewed and 'Rule breakdown' in viewed
        assert 'Warnings are disabled when viewing an export' in viewed
        assert 'No warnings from the evaluated checks.' not in viewed
        assert 'warnings' not in report['score']
        assert report['system']['computerName'] in viewed
        # Viewing uses saved values even if they differ from this machine.
        modified = json.loads(json.dumps(compact))
        modified['d']['7']['11'] = 'OFFLINE_COMPUTER_SENTINEL'
        modified['d']['213']['214'] = 123
        offline = Path(folder) / 'offline.json'
        offline.write_text(json.dumps(modified), encoding='utf-8')
        restored, _ = run(app, '--json', 'view', str(offline))
        assert 'OFFLINE_COMPUTER_SENTINEL' in restored and '123 / 1000' in restored
        assert 'OLD_WARNING_SENTINEL' not in restored
        before = path.read_bytes()
        duplicate = subprocess.run([str(app), '--json', '1', str(path), '--no-hash'], capture_output=True, timeout=65)
        assert duplicate.returncode == 1 and path.read_bytes() == before
        return report, elapsed



def assert_no_hidden_fields(report):
    hidden = {'source', 'adapters', 'endpoints', 'endpointScope', 'rdpPort', 'rdpPortStatus',
              'tcp4Status', 'tcp6Status', 'udp4Status', 'udp6Status', 'modules', 'maxMhz',
              'processorGroups', 'volumeId', 'driveType', 'bitLockerStatus', 'protectionMethod',
              'encryptionPercentage', 'subkeyCount', 'dirCount', 'command', 'location',
              'cachedOnly', 'lastSearchUtc', 'lastInstallationUtc', 'lastInstallationTitle',
              'lastInstallationResult', 'pendingCount', 'optionalCount', 'startType',
              'threatsCount', 'threatsKnown', 'manufacturerId', 'persistence', 'persistenceStatus'}
    def check(value):
        if isinstance(value, dict):
            assert not hidden.intersection(value), hidden.intersection(value)
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(report)
    assert 'services' not in report
    assert all('reason' not in rule for rule in report['score']['rules'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary_dir', type=Path)
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    binaries = args.binary_dir.resolve()
    app = binaries / 'SecurityAssessment.exe'
    tests = binaries / 'SecurityAssessmentTests.exe'
    with tempfile.TemporaryDirectory(prefix='sa-smoke-', dir=binaries.parent) as scratch:
        output, _ = run(tests, cwd=scratch)
        fixture = json.loads((Path(scratch) / 'regression-output.json').read_text(encoding='utf-8'))
        assert_no_hidden_fields(fixture)
        assert fixture['system']['productName'] == 'quoted "name"'
        assert fixture['defender']['reason'] == 'tabs\tand\nnewlines'
        assert 'privacy' not in fixture
        assert all(rule['id'] != 'acc.password' for rule in fixture['score']['rules'])
        evaluation = json.loads((Path(scratch) / 'evaluation-output.json').read_text(encoding='utf-8'))
        evaluation_rules = {rule['id']: rule for rule in evaluation['score']['rules']}
        assert evaluation_rules['os.sac']['awardedPoints'] == 25 and evaluation_rules['os.sac']['maxPoints'] == 50
        assert evaluation_rules['os.sac']['state'] == 'Evaluation'
        assert evaluation_rules['mp.threats']['awardedPoints'] == 20 and evaluation_rules['mp.threats']['state'] == 'Clear'
        assert 'os.patch' not in evaluation_rules
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['category'] == 'OS Security') == 200
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['category'] == 'Windows Update') == 60
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['id'].startswith('mp.')) == 180
        antivirus = json.loads((Path(scratch) / 'antivirus-output.json').read_text(encoding='utf-8'))
        assert any(not p['isDefender'] for p in antivirus['antivirus']['products'])
        assert antivirus['defender']['periodicScanning'] == 'Yes'
        assert [p['awardedPoints'] for p in antivirus['score']['antivirusScores']] == [180, 0, 0]
        assert antivirus['antivirus']['products'][0]['name'] == 'Example "Antivirus" A'
        assert antivirus['score']['total'] == 180 and antivirus['score']['maximum'] == 1000
        partial = json.loads((Path(scratch) / 'partial-output.json').read_text(encoding='utf-8'))
        assert partial['defender']['cloudProtectionStatus'] == 'Success'
        assert partial['defender']['realTimeProtectionStatus'] == 'Unavailable'
        assert next(r for r in partial['score']['rules'] if r['id'] == 'hyg.startup')['state'] == 'Unknown'
        updates = json.loads((Path(scratch) / 'windows-update-output.json').read_text(encoding='utf-8'))
        assert updates['windowsUpdate']['pendingStatus'] == 'Success'
        assert updates['windowsUpdate']['updates'][0]['title'] == 'Pending "Windows" update'
        assert updates['windowsUpdate']['updates'][0]['kbArticles'] == ['1234567']
        update_rules = {rule['id']: rule for rule in updates['score']['rules']}
        assert 'wu.pending' not in update_rules
        assert updates['windowsUpdate']['updates'][0]['classifications'] == ['Security Updates']
        assert updates['windowsUpdate']['updates'][0]['products'] == ['Microsoft .NET Framework']
        assert updates['windowsUpdate']['updates'][0]['severity'] == 'Critical'
        assert updates['windowsUpdate']['updates'][1]['updateType'] == 'Driver'
        unknown_updates = json.loads((Path(scratch) / 'windows-update-unknown.json').read_text(encoding='utf-8'))
        assert unknown_updates['windowsUpdate']['pendingStatus'] != 'Success'
        assert 'pendingCount' not in unknown_updates['windowsUpdate']
        print(output.strip())

    help_text, _ = run(app, '--help')
    assert 'Usage:' in help_text
    invalid = subprocess.run([str(app), '--no-hahs'], capture_output=True, timeout=10)
    assert invalid.returncode == 2 and b'Unknown option:' in invalid.stderr and not invalid.stdout
    report, no_hash_time = export_report(app, '--no-hash')
    expected = {'system', 'hardware', 'security', 'defender', 'firewall', 'storage', 'network',
                'antivirus', 'hardening', 'registryFindings', 'directoryFindings', 'score', 'windowsUpdate'}
    assert expected <= report.keys()
    assert report['score']['maximum'] == sum(r['maxPoints'] for r in report['score']['rules']) == 1000
    assert report['score']['total'] == sum(r['awardedPoints'] for r in report['score']['rules'])
    registered = report['score']['registeredAntivirusScoring']
    products = report['antivirus'].get('products', [])
    assert ('periodicScanning' in report['defender']) == any(not p['isDefender'] for p in products)
    assert len(products) == len(report['score'].get('antivirusScores', []))
    for product, score in zip(products, report['score'].get('antivirusScores', [])):
        assert score['maxPoints'] == 180
        assert score['awardedPoints'] == (180 if product['status'] == 'Success' and product['state'] == 'Enabled' else 0)
    rules = {rule['id']: rule for rule in report['score']['rules']}
    assert 'os.patch' not in rules and 'wu.pending' not in rules
    assert sum(rule['maxPoints'] for rule in rules.values() if rule['category'] == 'Windows Update') == 60
    assert all(r['maxPoints'] or r['id'] == 'hyg.startup' for r in rules.values())
    assert_no_hidden_fields(report)
    assert rules['os.sac']['maxPoints'] == 50
    if rules['os.sac']['state'] == 'Evaluation':
        assert rules['os.sac']['awardedPoints'] == 25
    elif rules['os.sac']['state'] == 'Enabled':
        assert rules['os.sac']['awardedPoints'] == 50
    else:
        assert rules['os.sac']['awardedPoints'] == 0
    if 'mp.threats' in rules:
        assert rules['mp.threats']['maxPoints'] == 20
        assert rules['mp.threats']['state'] != 'Enabled'
    for field, rule_id in [('enabled', 'mp.defender'), ('realTimeProtection', 'mp.rtp'),
                           ('behaviorMonitor', 'mp.bm'), ('ioav', 'mp.ioav'),
                           ('cloudProtection', 'mp.cloud'), ('tamperProtection', 'mp.tamper')]:
        if rule_id in rules and report['defender'].get(field + 'Status', 'Unavailable') != 'Success':
            assert rules[rule_id]['state'] == 'Unknown' and rules[rule_id]['awardedPoints'] == 0
    services = report['windowsUpdate']['services']
    assert len({s['name'].lower() for s in services}) == len(services)
    assert all(f['name'] for f in report['registryFindings'])
    assert 'applications' not in report
    assert 'hyg.appinv' not in rules
    normal, default_time = export_report(app)
    assert 'applications' not in normal
    console, _ = run(app, '--no-hash')
    assert 'SECURITY SCORE' in console and '\x1b[' not in console
    assert 'BACKUP REPORT' not in console and '-- Applications' not in console
    assert 'Windows update details available' not in console
    assert console.index('Rule breakdown') < console.index('SECURITY SCORE') < console.index('-- Warnings')
    assert all(hidden not in console for hidden in ['Active Network Adapters', 'UDP Port 69', 'Configured RDP port', 'RDP scope', 'Local TCP Listeners'])
    assert 'hardening' in report and 'warnings' not in report['score']
    assert rules['enc.bl']['maxPoints'] == 50
    assert sum(rule['maxPoints'] for rule in rules.values() if rule['category'] == 'Network Security') == 200
    assert 'Update Services' in console and 'Pending Updates' in console
    with tempfile.TemporaryDirectory(prefix='sa-auto-json-') as folder:
        output, _ = run(app, '--json', '1', '--no-hash', cwd=folder)
        generated = list(Path(folder).glob('security-assessment-*.json'))
        assert len(generated) == 1 and output.startswith('JSON report saved to:')
        assert json.loads(generated[0].read_text(encoding='utf-8'))['score']['maximum'] == 1000
    # Interactive format choices, retry handling and clean EOF for unattended callers.
    for mode in ('0', '1'):
        with tempfile.TemporaryDirectory(prefix='sa-prompt-') as folder:
            prompted = subprocess.run([str(app), '--json'], cwd=folder, input=('invalid\n'+mode+'\n').encode(),
                                      capture_output=True, timeout=90)
            assert prompted.returncode == 0 and b'Please enter 0' in prompted.stdout
            assert b'cannot be viewed in the app' in prompted.stdout
            files = list(Path(folder).glob('security-assessment-*.json'))
            assert len(files) == 1
            data = json.loads(files[0].read_text(encoding='utf-8'))
            assert ('v' in data) == (mode == '0')
    with tempfile.TemporaryDirectory(prefix='sa-eof-') as folder:
        eof = subprocess.run([str(app), '--json'], cwd=folder, input=b'', capture_output=True, timeout=10)
        assert eof.returncode == 2 and not list(Path(folder).glob('*.json'))
    with tempfile.TemporaryDirectory(prefix='sa-invalid-compact-') as folder:
        invalid_path = Path(folder) / 'bad.json'
        corruptions = [
            {'v': 2, 'd': {'0': 0}},
            {'v': 2, 'd': {'7': {'11': 999}}},
            {'v': 2, 'd': {'81': {'88': {'3': 9}}}},
            {'v': 2, 'd': {'7': {'1': True}}},

            {'v': 999, 's': [], 'd': {}},
            {'v': 1, 's': ['bad', 'Enabled', 'Unknown', 'N/A'], 'd': {}},
            {'v': 1, 's': ['Disabled', 'Enabled', 'Unknown', 'N/A'], 'd': {'zz': 0}},
            {'v': 1, 's': ['Disabled', 'Enabled', 'Unknown', 'N/A'], 'd': {'4': {'a': 999}}},
            {'v': 1, 's': ['Disabled', 'Enabled', 'Unknown', 'N/A'], 'd': {'28': {'2f': {'0': 9}}}},
        ]
        for bad in corruptions:
            invalid_path.write_text(json.dumps(bad), encoding='utf-8')
            rejected = subprocess.run([str(app), '--json', 'view', str(invalid_path)], capture_output=True, timeout=15)
            assert rejected.returncode == 1 and not rejected.stdout
    for options in [('--json', '2'), ('--json', '0', 'extra.json', 'extra'), ('--json', 'view'), ('--json', '--json'), ('--json', 'view', 'missing.json', '--no-hash')]:
        invalid = subprocess.run([str(app), *options], capture_output=True, timeout=10)
        assert invalid.returncode == 2 and not invalid.stdout
    assert 'privacy' not in report and 'minimumPasswordLength' not in report['hardening']
    assert all(rule['id'] != 'acc.password' for rule in report['score']['rules'])
    print(f"Smoke checks passed: direct-value compact JSON, readable export, prompt, numeric codes, viewer, help, redirected console; elevated={report['security']['elevated']}.")
    print(f"Elapsed: --no-hash {no_hash_time:.3f}s; default {default_time:.3f}s (single runs, not a benchmark).")
    if args.baseline:
        with tempfile.TemporaryDirectory(prefix='sa-baseline-') as folder:
            baseline_path = Path(folder) / 'baseline.json'
            run(args.baseline.resolve(), '--json', '1', str(baseline_path))
            baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
            old = {r['id']: r for r in baseline['score']['rules'] if r['maxPoints']}
            new = {r['id']: r for r in report['score']['rules'] if r['maxPoints']}
            assert old.keys() == new.keys()
            assert all(old[k]['maxPoints'] == new[k]['maxPoints'] for k in old)
            print('Baseline comparison: all scored rules and weights retained.')




if __name__ == '__main__':
    main()
