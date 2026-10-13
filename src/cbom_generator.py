"""
CBOM Generator - CycloneDX 1.6 format mein report banata hai.
Yeh India ke NQM roadmap ke according standard format hai.
"""

import json
import uuid
from datetime import datetime


def generate_cbom(scan_results, output_path=None):
    """
    Scan results ko CycloneDX 1.6 CBOM format mein convert karo.
    
    Args:
        scan_results (dict): scanner.scan_folder() ka output
        output_path (str): JSON file ka path (optional)
    
    Returns:
        dict: CycloneDX CBOM
    """
    # Unique components banao (algorithm + file combination)
    components = []
    seen = set()
    
    for finding in scan_results.get('findings', []):
        key = (finding['file'], finding['algorithm'])
        if key in seen:
            continue
        seen.add(key)
        
        component = {
            'type': 'cryptographic-asset',
            'bom-ref': f"crypto-{uuid.uuid4().hex[:8]}",
            'name': finding['algorithm'],
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': {
                    'primitive': _get_primitive(finding['algorithm']),
                    'parameterSetIdentifier': 'unknown',
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
                {'name': 'quantum-vulnerable', 'value': 'true'}
            ]
        }
        components.append(component)
    
    # CycloneDX document banao
    cbom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': f"urn:uuid:{uuid.uuid4()}",
        'version': 1,
        'metadata': {
            'timestamp': datetime.now().isoformat() + 'Z',
            'tools': [{
                'vendor': 'CBOM Scanner',
                'name': 'cbom-scanner',
                'version': '0.1.0'
            }],
            'component': {
                'type': 'application',
                'name': 'Scanned Project',
                'bom-ref': 'root-app'
            }
        },
        'components': components
    }
    
    # File mein save karo
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
        'SHA-1': 'hash',
        'MD5': 'hash',
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
                'context': 'key = RSA.generate(2048)'
            }
        ]
    }
    
    cbom = generate_cbom(sample_results, 'sample_cbom.json')
    print(json.dumps(cbom, indent=2))