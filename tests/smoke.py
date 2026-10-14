"""Run native regressions and parse real reports using only Python's standard library."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time


def run(executable, *args, cwd=None):
    started = time.perf_counter()
    result = subprocess.run([str(executable), *args], cwd=cwd, capture_output=True, timeout=180, check=True)
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
        antivirus = json.loads((Path(scratch) / 'antivirus-output.json').read_text(encoding='utf-8'))
        assert antivirus['antivirus']['hasThirdParty'] is True
        assert antivirus['defender']['periodicScanning'] == 'Yes'
        assert [p['awardedPoints'] for p in antivirus['score']['antivirusScores']] == [200, 0, 0]
        assert antivirus['score']['antivirusScores'][0]['name'] == 'Example "Antivirus" A'
        assert antivirus['score']['total'] == 200 and antivirus['score']['maximum'] == 1000
        print(output.strip())

    help_text, _ = run(app, '--help')
    assert 'Usage:' in help_text
    json_text, no_hash_time = run(app, '--json', '--no-hash')
    report = json.loads(json_text)
    expected = {'system', 'hardware', 'security', 'defender', 'firewall', 'storage', 'network',
                'services', 'applications', 'registryFindings', 'directoryFindings', 'persistence', 'privacy', 'score'}
    assert expected <= report.keys()
    assert report['score']['maximum'] == sum(r['maxPoints'] for r in report['score']['rules']) == 1000
    assert report['score']['total'] == sum(r['awardedPoints'] for r in report['score']['rules'])
    assert 'antivirus' in report and 'periodicScanning' in report['defender']
    assert len(report['antivirus']['products']) == len(report['score']['antivirusScores'])
    for product, score in zip(report['antivirus']['products'], report['score']['antivirusScores']):
        assert score['maxPoints'] == 200
        assert score['awardedPoints'] == (200 if product['status'] == 'Success' and product['state'] == 'Enabled' else 0)
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
    print(f"Smoke checks passed: JSON, hashes, help, redirected console; elevated={report['security']['elevated']}.")
    print(f"Elapsed: --no-hash {no_hash_time:.3f}s; hashing {hash_time:.3f}s (single runs, not a benchmark).")
    if args.baseline:
        baseline_text, elapsed = run(args.baseline.resolve(), '--json', '--no-hash')
        baseline = json.loads(baseline_text)
        assert baseline.keys() <= report.keys()
        print(f"Baseline --no-hash: {elapsed:.3f}s; original report sections preserved.")


if __name__ == '__main__':
    main()
