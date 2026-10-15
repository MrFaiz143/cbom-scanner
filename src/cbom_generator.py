"""
CBOM Generator - CycloneDX 1.6 format mein report banata hai.
Yeh India ke NQM roadmap ke according standard format hai.

v0.9.0 Changes:
- PQC replacement mapping added (config se)
- Recommended replacement + NIST standard CBOM me
"""

import json
import uuid
import sys
import os
from datetime import datetime

# Config se PQC mapping import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from config import PQC_REPLACEMENTS, APP_NAME, APP_VERSION
except ImportError:
    PQC_REPLACEMENTS = {}
    APP_NAME = "CBOM Scanner"
    APP_VERSION = "0.9.0"


def generate_cbom(scan_results, output_path=None):
    """
    Scan results ko CycloneDX 1.6 CBOM format mein convert karo.

    Args:
        scan_results (dict): scanner.scan_folder() ka output
        output_path (str): JSON file ka path (optional)

    Returns:
        dict: CycloneDX CBOM
    """
    components = []
    seen = set()

    for finding in scan_results.get('findings', []):
        key = (finding['file'], finding['algorithm'])
        if key in seen:
            continue
        seen.add(key)

        algo = finding['algorithm']
        pqc = PQC_REPLACEMENTS.get(algo, {})

        component = {
            'type': 'cryptographic-asset',
            'bom-ref': f"crypto-{uuid.uuid4().hex[:8]}",
            'name': algo,
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': {
                    'primitive': _get_primitive(algo),
                    'parameterSetIdentifier': finding.get('key_size', 'unknown'),
                    'executionEnvironment': 'software',
                    'implementationPlatform': 'unknown',
                    'certificationLevel': [],
                    'mode': 'unknown',
                    'padding': 'unknown',
                    'cryptoFunctions': ['keygen', 'encrypt', 'decrypt']
                }
            },
            'evidence': {
                'occurrences': [{
                    'location': finding['file'],
                    'line': finding.get('line', 0),
                    'additionalContext': finding.get('context', '')
                }]
            },
            'properties': [
                {'name': 'risk-level', 'value': finding['risk']},
                {'name': 'reason', 'value': finding['reason']},
                {'name': 'quantum-vulnerable', 'value': 'true'},
                {'name': 'recommended-replacement', 'value': pqc.get('replacement', 'N/A')},
                {'name': 'nist-standard', 'value': pqc.get('standard', 'N/A')},
                {'name': 'migration-note', 'value': pqc.get('note', '')},
            ]
        }
        components.append(component)

    cbom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': f"urn:uuid:{uuid.uuid4()}",
        'version': 1,
        'metadata': {
            'timestamp': datetime.now().isoformat() + 'Z',
            'tools': [{
                'vendor': APP_NAME,
                'name': 'cbom-scanner',
                'version': APP_VERSION
            }],
            'component': {
                'type': 'application',
                'name': 'Scanned Project',
                'bom-ref': 'root-app'
            }
        },
        'components': components
    }

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(cbom, f, indent=2)
        print(f"[INFO] CBOM saved to: {output_path}")

    return cbom


def _get_primitive(algorithm):
    """Algorithm ka cryptographic primitive return karo."""
    primitives = {
        'RSA': 'pke',
        'ECDSA': 'signature',
        'ECDH': 'key-agree',
        'DSA': 'signature',
        'DH': 'key-agree',
        'DHE': 'key-agree',
        'SHA-1': 'hash',
        'MD5': 'hash',
        '3DES': 'block-cipher',
        'RC4': 'stream-cipher',
        'DES': 'block-cipher',
    }
    return primitives.get(algorithm, 'unknown')


if __name__ == "__main__":
    # Test ke liye dummy data
    sample_results = {
        'findings': [
            {
                'file': 'example.py',
                'line': 42,
                'algorithm': 'RSA',
                'risk': 'HIGH',
                'reason': "Shor's algorithm breaks RSA",
                'context': 'key = RSA.generate(2048)',
                'key_size': '2048'
            }
        ]
    }

    cbom = generate_cbom(sample_results, 'sample_cbom.json')
    print(json.dumps(cbom, indent=2))