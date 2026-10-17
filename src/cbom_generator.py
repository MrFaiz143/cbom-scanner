"""
CBOM Generator - CycloneDX 1.6 format mein report banata hai.
Yeh India ke NQM roadmap ke according standard format hai.

v1.0.0 Changes:
- 'quantum-vulnerable' property ab sirf RSA/ECDSA/ECDH/DH/DSA ke liye true
- Nayi property 'algorithm-category' (quantum_vulnerable / weak_classical / configuration)
- cryptoFunctions primitive ke hisaab se (hash ke liye digest, etc.)
- Network findings (jinme 'file' nahi hota) pe KeyError nahi aayega

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


CATEGORY_QUANTUM = 'quantum_vulnerable'
CATEGORY_WEAK = 'weak_classical'
CATEGORY_CONFIG = 'configuration'

# Purane saved scans me 'category' nahi hota, isliye naam se nikalte hain
_QUANTUM_ALGOS = {'RSA', 'ECDSA', 'ECDH', 'DH', 'DHE', 'DSA'}
_WEAK_ALGOS = {'SHA-1', 'MD5', '3DES', 'RC4', 'DES'}


def get_category(finding):
    """Finding ka category return karo (finding me ho to wahi, warna algorithm se)."""
    category = finding.get('category')
    if category:
        return category
    algo = str(finding.get('algorithm', '')).upper()
    if algo in _QUANTUM_ALGOS:
        return CATEGORY_QUANTUM
    if algo in _WEAK_ALGOS:
        return CATEGORY_WEAK
    return CATEGORY_CONFIG


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
        # Folder scan me 'file' hota hai, network scan me 'source'/'context'
        location = finding.get('file') or finding.get('source') or 'network'
        algo = finding['algorithm']

        key = (location, algo)
        if key in seen:
            continue
        seen.add(key)

        category = get_category(finding)
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
                    'cryptoFunctions': _get_functions(algo)
                }
            },
            'evidence': {
                'occurrences': [{
                    'location': location,
                    'line': finding.get('line', 0),
                    'additionalContext': finding.get('context', '')
                }]
            },
            'properties': [
                {'name': 'risk-level', 'value': finding.get('risk', 'UNKNOWN')},
                {'name': 'reason', 'value': finding.get('reason', '')},
                {'name': 'algorithm-category', 'value': category},
                {'name': 'quantum-vulnerable',
                 'value': 'true' if category == CATEGORY_QUANTUM else 'false'},
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
            'timestamp': datetime.utcnow().isoformat() + 'Z',
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


def _get_functions(algorithm):
    """Primitive ke hisaab se cryptoFunctions (CycloneDX 1.6 values)."""
    primitive = _get_primitive(algorithm)
    functions = {
        'pke': ['keygen', 'encrypt', 'decrypt'],
        'signature': ['keygen', 'sign', 'verify'],
        'key-agree': ['keygen', 'keyderive'],
        'hash': ['digest'],
        'block-cipher': ['encrypt', 'decrypt'],
        'stream-cipher': ['encrypt', 'decrypt'],
    }
    return functions.get(primitive, ['other'])


if __name__ == "__main__":
    # Test ke liye dummy data
    sample_results = {
        'findings': [
            {
                'file': 'example.py',
                'line': 42,
                'algorithm': 'RSA',
                'category': 'quantum_vulnerable',
                'risk': 'HIGH',
                'reason': "Shor's algorithm breaks RSA",
                'context': 'key = RSA.generate(2048)',
                'key_size': '2048'
            },
            {
                'file': 'example.py',
                'line': 57,
                'algorithm': 'MD5',
                'category': 'weak_classical',
                'risk': 'HIGH',
                'reason': 'MD5 is a broken hash function',
                'context': 'h = hashlib.md5(data)',
            }
        ]
    }

    cbom = generate_cbom(sample_results, 'sample_cbom.json')
    print(json.dumps(cbom, indent=2))