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
        privacy_rule = next(r for r in fixture['score']['rules'] if r['id'].startswith('priv.'))
        assert privacy_rule['id'] == 'priv.quoted "name"'
        assert privacy_rule['reason'] == 'tabs\tand\nnewlines'
        evaluation = json.loads((Path(scratch) / 'evaluation-output.json').read_text(encoding='utf-8'))
        evaluation_rules = {rule['id']: rule for rule in evaluation['score']['rules']}
        assert evaluation_rules['os.sac']['awardedPoints'] == 25 and evaluation_rules['os.sac']['maxPoints'] == 50
        assert evaluation_rules['os.sac']['state'] == 'Evaluation'
        assert evaluation_rules['mp.threats']['awardedPoints'] == 20 and evaluation_rules['mp.threats']['state'] == 'Clear'
        assert evaluation_rules['os.patch']['description'] == 'Windows update details available'
        assert evaluation_rules['os.patch']['state'] == 'Available'
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['category'] == 'OS Security') == 145
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['category'] == 'Windows Update') == 100
        assert sum(rule['maxPoints'] for rule in evaluation_rules.values() if rule['id'].startswith('mp.')) == 195
        antivirus = json.loads((Path(scratch) / 'antivirus-output.json').read_text(encoding='utf-8'))
        assert antivirus['antivirus']['hasThirdParty'] is True
        assert antivirus['defender']['periodicScanning'] == 'Yes'
        assert [p['awardedPoints'] for p in antivirus['score']['antivirusScores']] == [195, 0, 0]
        assert antivirus['score']['antivirusScores'][0]['name'] == 'Example "Antivirus" A'
        assert antivirus['score']['total'] == 195 and antivirus['score']['maximum'] == 1000
        partial = json.loads((Path(scratch) / 'partial-output.json').read_text(encoding='utf-8'))
        assert partial['defender']['cloudProtectionStatus'] == 'Success'
        assert partial['defender']['realTimeProtectionStatus'] == 'Unavailable'
        assert partial['servicesStatus'] == 'Error' and partial['persistenceStatus'] == 'Error'
        updates = json.loads((Path(scratch) / 'windows-update-output.json').read_text(encoding='utf-8'))
        assert updates['windowsUpdate']['pendingCount'] == 1 and updates['windowsUpdate']['cachedOnly'] is True
        assert updates['windowsUpdate']['updates'][0]['title'] == 'Pending "Windows" update'
        assert updates['windowsUpdate']['updates'][0]['kbArticles'] == ['1234567']
        update_rules = {rule['id']: rule for rule in updates['score']['rules']}
        assert update_rules['wu.pending']['awardedPoints'] == 35
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
    json_text, no_hash_time = run(app, '--json', '--no-hash')
    report = json.loads(json_text)
    expected = {'system', 'hardware', 'security', 'defender', 'firewall', 'storage', 'network',
                'services', 'applications', 'registryFindings', 'directoryFindings', 'persistence', 'privacy', 'score', 'windowsUpdate'}
    assert expected <= report.keys()
    assert report['score']['maximum'] == sum(r['maxPoints'] for r in report['score']['rules']) == 1000
    assert report['score']['total'] == sum(r['awardedPoints'] for r in report['score']['rules'])
    assert 'antivirus' in report and 'periodicScanning' in report['defender']
    assert len(report['antivirus']['products']) == len(report['score']['antivirusScores'])
    for product, score in zip(report['antivirus']['products'], report['score']['antivirusScores']):
        assert score['maxPoints'] == 195
        assert score['awardedPoints'] == (195 if product['status'] == 'Success' and product['state'] == 'Enabled' else 0)
    rules = {rule['id']: rule for rule in report['score']['rules']}
    assert rules['os.patch']['category'] == 'Windows Update'
    assert sum(rule['maxPoints'] for rule in rules.values() if rule['category'] == 'Windows Update') == 100
    updates = report['windowsUpdate']
    assert updates['cachedOnly'] is True
    if updates['pendingStatus'] == 'Success':
        assert updates['pendingCount'] == sum(item['optional'] == 'No' for item in updates['updates'])
        assert updates['optionalCount'] == sum(item['optional'] == 'Yes' for item in updates['updates'])
        assert rules['wu.pending']['awardedPoints'] == max(0, 40 - 5 * updates['pendingCount'])
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
    assert all(not loc['sha256'] for group in report['applications'] for app_item in group['apps'] for loc in app_item['locations'])
    hashed_text, hash_time = run(app, '--json')
    hashed = json.loads(hashed_text)
    for group in hashed['applications']:
        for app_item in group['apps']:
            for loc in app_item['locations']:
                assert not loc['sha256'] or len(loc['sha256']) == 64
    console, _ = run(app, '--no-hash')
    assert 'SECURITY SCORE' in console and '\x1b[' not in console
    assert 'Windows update details available' in console
    assert 'Update services' in console and 'Pending updates' in console
    print(f"Smoke checks passed: JSON, hashes, help, redirected console; elevated={report['security']['elevated']}.")
    print(f"Elapsed: --no-hash {no_hash_time:.3f}s; hashing {hash_time:.3f}s (single runs, not a benchmark).")
    if args.baseline:
        baseline_text, elapsed = run(args.baseline.resolve(), '--json', '--no-hash')
        baseline = json.loads(baseline_text)
        assert baseline.keys() <= report.keys()
        print(f"Baseline --no-hash: {elapsed:.3f}s; original report sections preserved.")


if __name__ == '__main__':
    main()
