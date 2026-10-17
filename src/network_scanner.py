"""
Network Scanner - Live servers se TLS, SSH, LDAP, SQL, aur Email
algorithms detect karta hai.

Supports:
- Well-known ports (1-1024) via config
- TLS/SSL (HTTPS, LDAPS, IMAPS, POP3S, SMTPS)
- SSH (port 22)
- LDAP (389, 636)
- MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- Certificate parsing with detailed info

v1.0.0 Changes:
- Har finding me 'category' field:
    quantum_vulnerable -> RSA, ECDSA, ECDH, DH, DSA (Shor's algorithm)
    weak_classical     -> SHA-1, MD5, 3DES, RC4, DES (classically weak)
    configuration      -> expired cert, old TLS version, open DB/LDAP ports
- Cipher suite matching ab tokens se hota hai (pehle ECDHE me 'DH' galat se
  alag finding ban jaata tha)

v0.9.0 Changes:
- TOP_1000_PORTS removed (config se STANDARD_PORTS import)
- Bare except clauses fixed (specific exceptions)
- Logging added
- Timeout/max_workers parameters from config
"""

import re
import socket
import ssl
import logging
from datetime import datetime
import concurrent.futures

# Config se import
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from config import (
        STANDARD_PORTS, QUICK_PORTS,
        PORT_TIMEOUT, MAX_WORKERS,
        LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT,
    )
except ImportError:
    # Fallback agar config nahi mila
    STANDARD_PORTS = list(range(1, 1025))
    QUICK_PORTS = [443, 22, 8443, 993, 995, 465, 636]
    PORT_TIMEOUT = 3
    MAX_WORKERS = 50
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Logging setup
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
logger = logging.getLogger("cbom.network")


# ============================================================
# CATEGORIES
# ============================================================

CATEGORY_QUANTUM = 'quantum_vulnerable'
CATEGORY_WEAK = 'weak_classical'
CATEGORY_CONFIG = 'configuration'

CATEGORY_LABELS = {
    CATEGORY_QUANTUM: 'Quantum-vulnerable',
    CATEGORY_WEAK: 'Weak / deprecated',
    CATEGORY_CONFIG: 'Configuration',
}


# ============================================================
# VULNERABLE ALGORITHMS
# ============================================================

VULNERABLE_NETWORK_ALGOS = {
    'RSA': {
        'risk': 'HIGH', 'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks RSA (quantum-vulnerable)",
    },
    'ECDSA': {
        'risk': 'HIGH', 'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks ECDSA (quantum-vulnerable)",
    },
    'ECDH': {
        'risk': 'HIGH', 'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks ECDH (quantum-vulnerable)",
    },
    'DH': {
        'risk': 'HIGH', 'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks Diffie-Hellman (quantum-vulnerable)",
    },
    'DSA': {
        'risk': 'HIGH', 'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks DSA (quantum-vulnerable)",
    },
    'SHA-1': {
        'risk': 'MEDIUM', 'category': CATEGORY_WEAK,
        'reason': "SHA-1 has practical collision attacks and is deprecated (classically weak, not a quantum issue)",
    },
    'MD5': {
        'risk': 'HIGH', 'category': CATEGORY_WEAK,
        'reason': "MD5 is a broken hash function with classical collisions (weak, not a quantum issue)",
    },
    '3DES': {
        'risk': 'HIGH', 'category': CATEGORY_WEAK,
        'reason': "64-bit block cipher, vulnerable to Sweet32 (classically weak)",
    },
    'RC4': {
        'risk': 'HIGH', 'category': CATEGORY_WEAK,
        'reason': "RC4 is a broken stream cipher (classically weak)",
    },
    'DES': {
        'risk': 'HIGH', 'category': CATEGORY_WEAK,
        'reason': "DES has a 56-bit key and is easily broken (classically weak)",
    },
}

# Cipher suite ke tokens -> algorithm (ECDHE ko ECDH, DHE ko DH maanenge)
CIPHER_TOKEN_MAP = {
    'RSA': 'RSA',
    'ECDSA': 'ECDSA',
    'ECDH': 'ECDH',
    'ECDHE': 'ECDH',
    'DH': 'DH',
    'DHE': 'DH',
    'DSS': 'DSA',
    'DSA': 'DSA',
    '3DES': '3DES',
    'DES': 'DES',
    'RC4': 'RC4',
    'MD5': 'MD5',
}


def _finding(algorithm, risk, reason, context, source, category=None):
    """Ek standard finding dict banao (category ke saath)."""
    if category is None:
        category = VULNERABLE_NETWORK_ALGOS.get(algorithm, {}).get('category', CATEGORY_CONFIG)
    return {
        'algorithm': algorithm,
        'category': category,
        'risk': risk,
        'reason': reason,
        'context': context,
        'source': source,
    }


def _algo_finding(algorithm, context, source, reason=None):
    """Known algorithm ke liye finding (risk/category/reason table se)."""
    info = VULNERABLE_NETWORK_ALGOS[algorithm]
    return _finding(
        algorithm, info['risk'], reason or info['reason'],
        context, source, info['category'],
    )


# ============================================================
# PORT GROUPS
# ============================================================

TLS_PORTS = [
    443, 8443, 993, 995, 465, 636, 1433, 5432, 3306, 27017, 6379,
    25, 587, 110, 143, 990, 992, 994, 5061, 3389, 5986, 3269, 3268,
    989, 2083, 2087, 2096, 8080, 8888, 9443, 10443, 2376, 6443, 10250,
]
SSH_PORTS = [22, 2222, 22222, 2022, 8022]
LDAP_PORTS = [389, 636, 3268, 3269]
DB_PORTS = [3306, 5432, 1433, 27017, 6379, 1521, 5984, 9042, 11211]


# ============================================================
# PORT CHECK
# ============================================================

def check_port(host, port, timeout=PORT_TIMEOUT):
    """Check karo ki port open hai ya nahi."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ============================================================
# CERTIFICATE PARSING
# ============================================================

def parse_certificate(der_cert):
    """
    DER format certificate parse karo.
    Compatible with all pyopenssl versions.
    """
    try:
        from OpenSSL import crypto
        cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

        # Subject
        subject_components = dict(cert_obj.get_subject().get_components())
        subject = {k.decode(): v.decode() for k, v in subject_components.items()}

        # Issuer
        issuer_components = dict(cert_obj.get_issuer().get_components())
        issuer = {k.decode(): v.decode() for k, v in issuer_components.items()}

        # Validity
        not_before = cert_obj.get_notBefore().decode()
        not_after = cert_obj.get_notAfter().decode()

        def format_date(date_str):
            if len(date_str) >= 14:
                return f"{date_str[0:4]}-{date_str[4:6]}-{date_str[6:8]} {date_str[8:10]}:{date_str[10:12]}:{date_str[12:14]}"
            return date_str

        # Signature algorithm
        try:
            sig_algo = cert_obj.get_signature_algorithm().decode()
        except Exception:
            sig_algo = 'unknown'

        # SAN parsing
        san_list = []
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_crypto = x509.load_der_x509_certificate(der_cert, default_backend())
            try:
                san_ext = cert_crypto.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_list = [str(name.value) for name in san_ext.value]
            except x509.ExtensionNotFound:
                san_list = []
        except ImportError:
            try:
                ext_count = cert_obj.get_extension_count()
                for i in range(ext_count):
                    ext = cert_obj.get_extension(i)
                    if ext.get_short_name() == b'subjectAltName':
                        san_str = str(ext)
                        san_list = [s.strip() for s in san_str.split(',')]
            except Exception:
                san_list = []
        except Exception:
            san_list = []

        # Public key detection
        key_type = 'Unknown'
        pubkey_bits = 0

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, dh

            cert_crypto = x509.load_der_x509_certificate(der_cert, default_backend())
            crypto_pubkey = cert_crypto.public_key()

            if isinstance(crypto_pubkey, rsa.RSAPublicKey):
                key_type = 'RSA'
                pubkey_bits = crypto_pubkey.key_size
            elif isinstance(crypto_pubkey, dsa.DSAPublicKey):
                key_type = 'DSA'
                pubkey_bits = crypto_pubkey.key_size
            elif isinstance(crypto_pubkey, ec.EllipticCurvePublicKey):
                key_type = 'EC'
                pubkey_bits = crypto_pubkey.curve.key_size
            elif isinstance(crypto_pubkey, dh.DHPublicKey):
                key_type = 'DH'
                pubkey_bits = crypto_pubkey.key_size
            else:
                key_type = type(crypto_pubkey).__name__
        except ImportError:
            try:
                pubkey = cert_obj.get_pubkey()
                pubkey_bits = pubkey.bits()
                pubkey_type = pubkey.type()
                key_type_map = {
                    0: 'RSA', 1: 'DSA', 2: 'DH', 3: 'EC',
                    4: 'HMAC', 5: 'CMAC', 6: 'RSA', 7: 'RSA',
                }
                key_type = key_type_map.get(pubkey_type, f'Unknown({pubkey_type})')
            except Exception:
                pass
        except Exception:
            pass

        cert_details = {
            'subject': subject,
            'issuer': issuer,
            'serial_number': hex(cert_obj.get_serial_number()),
            'version': cert_obj.get_version() + 1,
            'not_before': format_date(not_before),
            'not_after': format_date(not_after),
            'signature_algorithm': sig_algo,
            'public_key': {'type': key_type, 'bits': pubkey_bits},
            'subject_alt_names': san_list,
            'raw_size_bytes': len(der_cert),
        }

        # Expiry status
        try:
            expiry_date = datetime.strptime(not_after[:14], '%Y%m%d%H%M%S')
            days_left = (expiry_date - datetime.now()).days
            cert_details['days_until_expiry'] = days_left
            if days_left < 0:
                cert_details['expiry_status'] = 'EXPIRED'
            elif days_left < 30:
                cert_details['expiry_status'] = 'EXPIRING_SOON'
            else:
                cert_details['expiry_status'] = 'VALID'
        except Exception:
            cert_details['days_until_expiry'] = None
            cert_details['expiry_status'] = 'unknown'

        return cert_details

    except ImportError:
        return {
            'raw_size_bytes': len(der_cert),
            'note': 'pyopenssl install nahi hai — pip install pyopenssl',
        }
    except Exception as e:
        return {
            'raw_size_bytes': len(der_cert),
            'error': f'Certificate parse error: {str(e)[:100]}',
        }


# ============================================================
# TLS SCANNING
# ============================================================

def scan_tls_server(host, port=443, timeout=10):
    """Ek TLS server scan karo."""
    result = {
        'target': f"{host}:{port}",
        'protocol': 'TLS',
        'port': port,
        'status': 'unknown',
        'tls_version': None,
        'cipher_suite': None,
        'certificate': None,
        'findings': []
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result['status'] = 'success'
                result['tls_version'] = ssock.version()
                result['cipher_suite'] = ssock.cipher()

                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    result['certificate'] = parse_certificate(der_cert)

                result['findings'] = detect_algorithms_in_tls(
                    result['tls_version'],
                    result['cipher_suite'],
                    result['certificate']
                )

    except socket.timeout:
        result['status'] = 'timeout'
    except ConnectionRefusedError:
        result['status'] = 'refused'
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)[:100]

    return result


def _cipher_algorithms(cipher_name):
    """Cipher suite ke naam se algorithms nikalo (token-based, false match nahi)."""
    tokens = re.split(r'[_\-\s]+', str(cipher_name).upper())
    found = []
    for token in tokens:
        algo = CIPHER_TOKEN_MAP.get(token)
        if algo and algo not in found:
            found.append(algo)
    return found


def detect_algorithms_in_tls(tls_version, cipher_suite, certificate):
    """TLS handshake + certificate se vulnerable algorithms detect karo."""
    findings = []
    seen_algos = set()

    if cipher_suite:
        cipher_name = cipher_suite[0] if isinstance(cipher_suite, (tuple, list)) else str(cipher_suite)

        for algo in _cipher_algorithms(cipher_name):
            if algo not in seen_algos:
                seen_algos.add(algo)
                findings.append(_algo_finding(
                    algo, f"Cipher suite: {cipher_name}", 'TLS cipher suite'
                ))

    if certificate and isinstance(certificate, dict):
        sig_algo = certificate.get('signature_algorithm', '')
        if sig_algo:
            sig_upper = sig_algo.upper()
            if ('SHA1' in sig_upper or 'SHA-1' in sig_upper) and 'SHA-1' not in seen_algos:
                seen_algos.add('SHA-1')
                findings.append(_algo_finding(
                    'SHA-1', f"Signature: {sig_algo}", 'Certificate signature',
                    reason='SHA-1 certificate signature is deprecated (classically weak, not a quantum issue)',
                ))

            if 'MD5' in sig_upper and 'MD5' not in seen_algos:
                seen_algos.add('MD5')
                findings.append(_algo_finding(
                    'MD5', f"Signature: {sig_algo}", 'Certificate signature',
                    reason='MD5 certificate signature is broken (classically weak, not a quantum issue)',
                ))

            if 'RSA' in sig_upper and 'RSA' not in seen_algos:
                seen_algos.add('RSA')
                findings.append(_algo_finding(
                    'RSA', f"Signature: {sig_algo}", 'Certificate signature',
                    reason="Shor's algorithm breaks RSA certificate signature (quantum-vulnerable)",
                ))

        pubkey = certificate.get('public_key', {})
        if pubkey:
            key_type = pubkey.get('type', '').upper()
            key_bits = pubkey.get('bits', 0)

            if 'RSA' in key_type and 'RSA' not in seen_algos:
                seen_algos.add('RSA')
                findings.append(_algo_finding(
                    'RSA', f"Public key: RSA-{key_bits}", 'Certificate public key',
                    reason=f"RSA-{key_bits} public key is quantum-vulnerable",
                ))

            if ('EC' in key_type or 'ECDSA' in key_type) and 'ECDSA' not in seen_algos:
                seen_algos.add('ECDSA')
                findings.append(_algo_finding(
                    'ECDSA', f"Public key: EC-{key_bits}", 'Certificate public key',
                    reason=f"ECDSA-{key_bits} public key is quantum-vulnerable",
                ))

            if key_type == 'DSA' and 'DSA' not in seen_algos:
                seen_algos.add('DSA')
                findings.append(_algo_finding(
                    'DSA', f"Public key: DSA-{key_bits}", 'Certificate public key',
                    reason=f"DSA-{key_bits} public key is quantum-vulnerable",
                ))

        expiry_status = certificate.get('expiry_status', '')
        if expiry_status == 'EXPIRED':
            findings.append(_finding(
                'Certificate-Expired', 'HIGH', 'Certificate has expired',
                f"Expired: {certificate.get('not_after')}", 'Certificate validity',
                CATEGORY_CONFIG,
            ))
        elif expiry_status == 'EXPIRING_SOON':
            days = certificate.get('days_until_expiry', 0)
            findings.append(_finding(
                'Certificate-ExpiringSoon', 'MEDIUM', f'Certificate expires in {days} days',
                f"Expires: {certificate.get('not_after')}", 'Certificate validity',
                CATEGORY_CONFIG,
            ))

    if tls_version and tls_version in ['TLSv1.0', 'TLSv1.1']:
        findings.append(_finding(
            tls_version, 'HIGH', f'{tls_version} is deprecated',
            f"TLS version: {tls_version}", 'TLS version',
            CATEGORY_CONFIG,
        ))

    return findings


# ============================================================
# SSH SCANNING
# ============================================================

def scan_ssh_server(host, port=22, timeout=10):
    """Ek SSH server scan karo."""
    result = {
        'target': f"{host}:{port}",
        'protocol': 'SSH',
        'port': port,
        'status': 'unknown',
        'ssh_version': None,
        'kex_algorithms': [],
        'ciphers': [],
        'host_key_algorithms': [],
        'findings': []
    }

    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username='test', timeout=timeout,
                       allow_agent=False, look_for_keys=False)

        transport = client.get_transport()
        result['status'] = 'success'
        result['ssh_version'] = transport.remote_version

        opts = transport.get_security_options()
        result['kex_algorithms'] = list(opts.kex)
        result['ciphers'] = list(opts.ciphers)
        result['host_key_algorithms'] = list(opts.key_types)

        result['findings'] = detect_algorithms_in_ssh(
            result['kex_algorithms'],
            result['ciphers'],
            result['host_key_algorithms']
        )

        client.close()

    except ImportError:
        result['status'] = 'error'
        result['error'] = 'paramiko not installed'
    except Exception as e:
        # AuthenticationException bhi isme aata hai
        err_name = type(e).__name__
        if 'Authentication' in err_name:
            result['status'] = 'auth_required'
        elif isinstance(e, socket.timeout):
            result['status'] = 'timeout'
        elif isinstance(e, ConnectionRefusedError):
            result['status'] = 'refused'
        else:
            result['status'] = 'error'
            result['error'] = str(e)[:100]

    return result


def detect_algorithms_in_ssh(kex_algorithms, ciphers, host_key_algorithms):
    """SSH handshake se vulnerable algorithms detect karo."""
    findings = []
    seen_algos = set()

    for kex in kex_algorithms:
        kex_lower = kex.lower()

        # KEX naam se algorithm pehchano (ecdh pehle, taaki 'dh' galat match na ho)
        if 'ecdh' in kex_lower:
            kex_algo = 'ECDH'
        elif 'diffie-hellman' in kex_lower or kex_lower.startswith('dh-'):
            kex_algo = 'DH'
        elif kex_lower.startswith('rsa'):
            kex_algo = 'RSA'
        else:
            kex_algo = None

        if kex_algo and kex_algo not in seen_algos:
            seen_algos.add(kex_algo)
            findings.append(_algo_finding(
                kex_algo, f"KEX: {kex}", 'SSH KEX',
                reason=f"{kex_algo} based key exchange is quantum-vulnerable",
            ))

        if 'sha1' in kex_lower and 'SHA-1' not in seen_algos:
            seen_algos.add('SHA-1')
            findings.append(_algo_finding(
                'SHA-1', f"KEX: {kex}", 'SSH KEX',
                reason='SHA-1 based KEX is deprecated (classically weak, not a quantum issue)',
            ))

    for cipher in ciphers:
        if '3des' in cipher.lower() and '3DES' not in seen_algos:
            seen_algos.add('3DES')
            findings.append(_algo_finding(
                '3DES', f"Cipher: {cipher}", 'SSH cipher',
                reason='3DES is vulnerable to Sweet32 (classically weak)',
            ))
        if 'rc4' in cipher.lower() and 'RC4' not in seen_algos:
            seen_algos.add('RC4')
            findings.append(_algo_finding(
                'RC4', f"Cipher: {cipher}", 'SSH cipher',
                reason='RC4 is broken (classically weak)',
            ))

    for key_algo in host_key_algorithms:
        if 'rsa' in key_algo.lower() and 'RSA' not in seen_algos:
            seen_algos.add('RSA')
            findings.append(_algo_finding(
                'RSA', f"Host key: {key_algo}", 'SSH host key',
                reason="Shor's algorithm breaks RSA host key (quantum-vulnerable)",
            ))
        if 'ecdsa' in key_algo.lower() and 'ECDSA' not in seen_algos:
            seen_algos.add('ECDSA')
            findings.append(_algo_finding(
                'ECDSA', f"Host key: {key_algo}", 'SSH host key',
                reason="Shor's algorithm breaks ECDSA host key (quantum-vulnerable)",
            ))

    return findings


# ============================================================
# LDAP SCANNING
# ============================================================

def scan_ldap_server(host, port=389, timeout=5):
    """LDAP server scan karo."""
    result = {
        'target': f"{host}:{port}",
        'protocol': 'LDAP',
        'port': port,
        'status': 'unknown',
        'findings': []
    }

    try:
        with socket.create_connection((host, port), timeout=timeout):
            result['status'] = 'open'
            if port == 389:
                result['findings'].append(_finding(
                    'LDAP-Plaintext', 'MEDIUM',
                    'LDAP port 389 open - plaintext authentication possible',
                    'Check StartTLS configuration', 'LDAP', CATEGORY_CONFIG,
                ))
            elif port == 636:
                result['findings'].append(_finding(
                    'LDAPS', 'LOW',
                    'LDAPS port 636 open - secure LDAP',
                    'TLS-based LDAP', 'LDAP', CATEGORY_CONFIG,
                ))
    except (socket.timeout, ConnectionRefusedError, OSError):
        result['status'] = 'closed'

    return result


# ============================================================
# DATABASE SCANNING
# ============================================================

def scan_database_server(host, port, timeout=5):
    """Database server scan karo."""
    db_names = {
        3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL',
        27017: 'MongoDB', 6379: 'Redis', 1521: 'Oracle',
        5984: 'CouchDB', 9042: 'Cassandra', 11211: 'Memcached',
    }

    db_name = db_names.get(port, 'Unknown DB')

    result = {
        'target': f"{host}:{port}",
        'protocol': db_name,
        'port': port,
        'status': 'unknown',
        'findings': []
    }

    try:
        with socket.create_connection((host, port), timeout=timeout):
            result['status'] = 'open'
            result['findings'].append(_finding(
                f'{db_name}-Auth', 'MEDIUM',
                f'{db_name} port open - check authentication and TLS',
                f'Port {port} open', db_name, CATEGORY_CONFIG,
            ))
    except (socket.timeout, ConnectionRefusedError, OSError):
        result['status'] = 'closed'

    return result


# ============================================================
# HOST SCANNING
# ============================================================

def scan_host(host, ports=None, timeout=PORT_TIMEOUT, max_workers=MAX_WORKERS):
    """Ek host ke multiple ports scan karo (concurrent threads)."""
    if ports is None:
        ports = STANDARD_PORTS

    results = {
        'host': host,
        'scan_time': datetime.now().isoformat(),
        'total_ports_scanned': len(ports),
        'open_ports': [],
        'services': []
    }

    logger.info(f"Scanning host: {host} ({len(ports)} ports, {max_workers} workers)")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, host, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception as e:
                logger.debug(f"Port {port} check failed: {e}")

    results['open_ports'] = sorted(open_ports)
    logger.info(f"Open ports: {len(open_ports)}")

    for port in sorted(open_ports):
        if port in TLS_PORTS:
            tls_result = scan_tls_server(host, port, timeout=10)
            if tls_result['status'] == 'success':
                logger.debug(f"[TLS] {port}: {tls_result['tls_version']}")
                results['services'].append(tls_result)

        elif port in SSH_PORTS:
            ssh_result = scan_ssh_server(host, port, timeout=10)
            if ssh_result['status'] in ['success', 'auth_required']:
                logger.debug(f"[SSH] {port}: {ssh_result['ssh_version']}")
                results['services'].append(ssh_result)

        elif port in LDAP_PORTS:
            ldap_result = scan_ldap_server(host, port, timeout=5)
            if ldap_result['status'] == 'open':
                results['services'].append(ldap_result)

        elif port in DB_PORTS:
            db_result = scan_database_server(host, port, timeout=5)
            if db_result['status'] == 'open':
                results['services'].append(db_result)

    logger.info(f"Services detected: {len(results['services'])}")
    return results


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    host = input("Enter hostname or IP: ").strip()
    results = scan_host(host)

    print("\n" + "=" * 70)
    print("NETWORK SCAN RESULTS")
    print("=" * 70)
    print(f"Host: {results['host']}")
    print(f"Open Ports: {results['open_ports']}")
    print(f"Services: {len(results['services'])}")
    print("=" * 70)