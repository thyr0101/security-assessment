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
        assert compact['v'] == 1 and compact['s'][:4] == ['Disabled', 'Enabled', 'Unknown', 'N/A']
        assert 'system' not in compact and set(compact) == {'v', 's', 'd'}
        assert len(compact_path.read_bytes()) < len(path.read_bytes())
        def numeric_data(value):
            if isinstance(value, dict):
                return all(len(k) <= 2 and numeric_data(v) for k, v in value.items())
            if isinstance(value, list):
                return all(numeric_data(v) for v in value)
            return value is None or type(value) in (int, float)
        assert numeric_data(compact['d'])
        assert compact['d']['28']['2f']['0'] in (0, 1, 2, 3)
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
        modified['d']['4']['a'] = len(modified['s'])
        modified['s'].append('OFFLINE_COMPUTER_SENTINEL')
        modified['d']['5w']['5x'] = 123
        offline = Path(folder) / 'offline.json'
        offline.write_text(json.dumps(modified), encoding='utf-8')
        restored, _ = run(app, '--json', 'view', str(offline))
        assert 'OFFLINE_COMPUTER_SENTINEL' in restored and '123 / 1000' in restored
        assert 'OLD_WARNING_SENTINEL' not in restored
        before = path.read_bytes()
        duplicate = subprocess.run([str(app), '--json', '1', str(path), '--no-hash'], capture_output=True, timeout=65)
        assert duplicate.returncode == 1 and path.read_bytes() == before
        return report, elapsed


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
        assert fixture['system']['productName'] == 'quoted "name"'
        assert fixture['hardening']['lsaProtection']['reason'] == 'tabs\tand\nnewlines'
        assert 'privacy' not in fixture
        assert all(rule['id'] != 'acc.password' for rule in fixture['score']['rules'])
        evaluation = json.loads((Path(scratch) / 'evaluation-output.json').read_text(encoding='utf-8'))
        evaluation_rules = {rule['id']: rule for rule in evaluation['score']['rules']}
        assert evaluation_rules['os.sac']['awardedPoints'] == 25 and evaluation_rules['os.sac']['maxPoints'] == 50
        assert evaluation_rules['os.sac']['state'] == 'Evaluation'
        assert evaluation_rules['mp.threats']['awardedPoints'] == 20 and evaluation_rules['mp.threats']['state'] == 'Clear'
        assert evaluation_rules['os.patch']['description'] == 'Windows update details available'
        assert evaluation_rules['os.patch']['state'] == 'Available'
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['category'] == 'OS Security') == 200
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['category'] == 'Windows Update') == 60
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['id'].startswith('mp.')) == 180
        antivirus = json.loads((Path(scratch) / 'antivirus-output.json').read_text(encoding='utf-8'))
        assert antivirus['antivirus']['hasThirdParty'] is True
        assert antivirus['defender']['periodicScanning'] == 'Yes'
        assert [p['awardedPoints'] for p in antivirus['score']['antivirusScores']] == [180, 0, 0]
        assert antivirus['score']['antivirusScores'][0]['name'] == 'Example "Antivirus" A'
        assert antivirus['score']['total'] == 180 and antivirus['score']['maximum'] == 1000
        partial = json.loads((Path(scratch) / 'partial-output.json').read_text(encoding='utf-8'))
        assert partial['defender']['cloudProtectionStatus'] == 'Success'
        assert partial['defender']['realTimeProtectionStatus'] == 'Unavailable'
        assert partial['servicesStatus'] == 'Error' and partial['persistenceStatus'] == 'Error'
        updates = json.loads((Path(scratch) / 'windows-update-output.json').read_text(encoding='utf-8'))
        assert updates['windowsUpdate']['pendingCount'] == 1 and updates['windowsUpdate']['cachedOnly'] is True
        assert updates['windowsUpdate']['updates'][0]['title'] == 'Pending "Windows" update'
        assert updates['windowsUpdate']['updates'][0]['kbArticles'] == ['1234567']
        update_rules = {rule['id']: rule for rule in updates['score']['rules']}
        assert update_rules['wu.pending']['awardedPoints'] == 0 and update_rules['wu.pending']['maxPoints'] == 0
        assert updates['windowsUpdate']['updates'][0]['classifications'] == ['Security Updates']
        assert updates['windowsUpdate']['updates'][0]['products'] == ['Microsoft .NET Framework']
        assert updates['windowsUpdate']['updates'][0]['severity'] == 'Critical'
        assert updates['windowsUpdate']['updates'][1]['updateType'] == 'Driver'
        assert update_rules['os.patch']['category'] == 'Windows Update'
        unknown_updates = json.loads((Path(scratch) / 'windows-update-unknown.json').read_text(encoding='utf-8'))
        assert unknown_updates['windowsUpdate']['pendingCount'] is None
        assert unknown_updates['windowsUpdate']['optionalCount'] is None
        assert next(rule for rule in unknown_updates['score']['rules'] if rule['id'] == 'wu.pending')['awardedPoints'] == 0
        print(output.strip())

    help_text, _ = run(app, '--help')
    assert 'Usage:' in help_text
    invalid = subprocess.run([str(app), '--no-hahs'], capture_output=True, timeout=10)
    assert invalid.returncode == 2 and b'Unknown option:' in invalid.stderr and not invalid.stdout
    report, no_hash_time = export_report(app, '--no-hash')
    expected = {'system', 'hardware', 'security', 'defender', 'firewall', 'storage', 'network',
                'services', 'registryFindings', 'directoryFindings', 'persistence', 'score', 'windowsUpdate'}
    assert expected <= report.keys()
    assert report['score']['maximum'] == sum(r['maxPoints'] for r in report['score']['rules']) == 1000
    assert report['score']['total'] == sum(r['awardedPoints'] for r in report['score']['rules'])
    assert 'antivirus' in report and 'periodicScanning' in report['defender']
    assert len(report['antivirus']['products']) == len(report['score']['antivirusScores'])
    for product, score in zip(report['antivirus']['products'], report['score']['antivirusScores']):
        assert score['maxPoints'] == 180
        assert score['awardedPoints'] == (180 if product['status'] == 'Success' and product['state'] == 'Enabled' else 0)
    rules = {rule['id']: rule for rule in report['score']['rules']}
    assert rules['os.patch']['category'] == 'Windows Update'
    assert sum(rule['maxPoints'] for rule in rules.values() if rule['category'] == 'Windows Update') == 60
    assert rules['wu.pending']['maxPoints'] == 0 and rules['wu.pending']['awardedPoints'] == 0
    updates = report['windowsUpdate']
    assert updates['cachedOnly'] is True
    if updates['pendingStatus'] == 'Success':
        assert updates['pendingCount'] == sum(item['optional'] == 'No' for item in updates['updates'])
        assert updates['optionalCount'] == sum(item['optional'] == 'Yes' for item in updates['updates'])
        assert rules['wu.pending']['awardedPoints'] == 0
    else:
        assert updates['pendingCount'] is None and rules['wu.pending']['state'] == 'Unknown'
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
        if rule_id in rules and report['defender'][field + 'Status'] != 'Success':
            assert rules[rule_id]['state'] == 'Unknown' and rules[rule_id]['awardedPoints'] == 0
    assert len({s['name'].lower() for s in report['services']}) == len(report['services'])
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
    print(f"Smoke checks passed: compact/readable JSON, prompt, numeric codes, viewer, help, redirected console; elevated={report['security']['elevated']}.")
    print(f"Elapsed: --no-hash {no_hash_time:.3f}s; default {default_time:.3f}s (single runs, not a benchmark).")
    if args.baseline:
        with tempfile.TemporaryDirectory(prefix='sa-baseline-') as folder:
            baseline_text, elapsed = run(args.baseline.resolve(), '--json', '--no-hash', cwd=folder)
            if baseline_text.lstrip().startswith('{'):
                baseline = json.loads(baseline_text)
            else:
                exported = list(Path(folder).glob('security-assessment-*.json'))
                assert len(exported) == 1
                baseline = json.loads(exported[0].read_text(encoding='utf-8'))
            assert baseline.keys() - {'privacy', 'applications'} <= report.keys()
            print(f"Baseline export: {elapsed:.3f}s; retained report sections preserved.")



if __name__ == '__main__':
    main()
