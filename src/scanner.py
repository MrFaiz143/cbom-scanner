"""
CBOM Scanner - Main Scanning Module (v0.4.0)
Yeh module code files ko scan karta hai aur cryptographic
algorithms ko detect karta hai.

v0.4.0 Changes:
- Har finding me 'category' field:
    quantum_vulnerable -> RSA, ECDSA, ECDH, DH, DSA (Shor's algorithm se tootte hain)
    weak_classical     -> MD5, SHA-1 (classically broken, quantum ki wajah se nahi)
- MD5/SHA-1 ka reason clear kiya (quantum-related nahi)
- Category-wise summary helper

v0.3.0 Changes:
- VS Code history folder skip (self-detection se bachne ke liye)
- TypeScript type definitions filter (RsaHashedKeyGenParams etc.)
- Documentation patterns ko aur strict kiya
"""

import os
import re
from datetime import datetime


# ============================================================
# CATEGORIES
# ============================================================
CATEGORY_QUANTUM = 'quantum_vulnerable'
CATEGORY_WEAK = 'weak_classical'

CATEGORY_LABELS = {
    CATEGORY_QUANTUM: 'Quantum-vulnerable',
    CATEGORY_WEAK: 'Weak / deprecated',
}


# Algorithms with SPECIFIC patterns
VULNERABLE_ALGORITHMS = {
    'RSA': {
        'risk': 'HIGH',
        'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks RSA (quantum-vulnerable)",
        'patterns': [
            r'RSA\.generate',
            r'RSA_generate_key',
            r'RSA_public_encrypt',
            r'RSA_private_decrypt',
            r'RSA_public_key',
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA',
            r'crypto\.subtle.*RSA',
            r'-----BEGIN\s+RSA',
            r'new\s+RSA',
            r'RSA\s*\.\s*generate',
            r'from\s+Crypto\.PublicKey\s+import\s+RSA',
        ]
    },
    'ECDSA': {
        'risk': 'HIGH',
        'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks ECDSA (quantum-vulnerable)",
        'patterns': [
            r'ECDSA\.generate',
            r'ecdsa\.SigningKey',
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC',
            r'crypto\.subtle.*ECDSA',
            r'Signature\.getInstance\s*\(\s*["\']SHA\d+withECDSA',
            r'-----BEGIN\s+EC\s+PRIVATE',
        ]
    },
    'ECDH': {
        'risk': 'HIGH',
        'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks ECDH (quantum-vulnerable)",
        'patterns': [
            r'ECDH\.generate',
            r'KeyAgreement\.getInstance\s*\(\s*["\']ECDH',
            r'crypto\.subtle.*ECDH',
            r'generateECDHKeyPair',
        ]
    },
    'DSA': {
        'risk': 'HIGH',
        'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks DSA (quantum-vulnerable)",
        'patterns': [
            r'DSA\.generate',
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']DSA',
            r'Signature\.getInstance\s*\(\s*["\']SHA\d+withDSA',
            r'DSA_generate_parameters',
        ]
    },
    'DH': {
        'risk': 'HIGH',
        'category': CATEGORY_QUANTUM,
        'reason': "Shor's algorithm breaks Diffie-Hellman (quantum-vulnerable)",
        'patterns': [
            r'Diffie[- ]?Hellman',
            r'DH_generate_parameters',
            r'DH_generate_key',
            r'DH_compute_key',
            r'KeyAgreement\.getInstance\s*\(\s*["\']DH',
            r'generateDHKeyPair',
            r'crypto\.subtle.*DH',
        ]
    },
    'SHA-1': {
        'risk': 'MEDIUM',
        'category': CATEGORY_WEAK,
        'reason': "SHA-1 has practical collision attacks and is deprecated (classically weak, not a quantum issue)",
        'patterns': [
            r'hashlib\.sha1',
            r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1',
            r'crypto\.createHash\s*\(\s*["\']sha1',
            r'SHA1_Init',
            r'hashlib\.sha1\(',
        ]
    },
    'MD5': {
        'risk': 'HIGH',
        'category': CATEGORY_WEAK,
        'reason': "MD5 is a broken hash function with classical collisions (weak, not a quantum issue)",
        'patterns': [
            r'hashlib\.md5',
            r'MessageDigest\.getInstance\s*\(\s*["\']MD5',
            r'crypto\.createHash\s*\(\s*["\']md5',
            r'MD5_Init',
            r'md5\.new\(',
            r'from\s+hashlib\s+import\s+md5',
        ]
    },
}

# File extensions jo scan karne hain
SCANNABLE_EXTENSIONS = (
    '.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.c', '.cpp', '.h', '.hpp',
    '.go', '.rs', '.php', '.rb', '.cs', '.swift', '.kt', '.scala',
    '.conf', '.config', '.cfg', '.ini',
    '.yml', '.yaml', '.json', '.env', '.properties',
    '.pem', '.crt', '.key', '.pub'
)

# Files jo skip karni hain (naam ke hisaab se)
SKIP_FILES = {
    'license', 'license.txt', 'licence', 'copying', 'copyright',
    'readme', 'readme.txt', 'readme.md', 'changelog', 'changes',
    'news', 'news.txt', 'authors', 'contributors', 'thanks',
    'setup.xml', 'branding.xml',  # Office installer metadata
}

# Folders jo skip karne hain
SKIP_FOLDERS = {
    # Development
    'node_modules', 'venv', 'env', '.git', '__pycache__',
    'dist', 'build', 'target', '.vscode', '.idea', 'vendor',
    'bower_components', 'jspm_packages',

    # VS Code history aur AppData (self-detection se bachne ke liye)
    'History',
    'Roaming',

    # Office installers
    'office 2007', 'Office 2007', 'OFFICE 2007',
    'Office 2013', 'office 2013', 'OFFICE 2013',
    'Office Professional Plus 2010', 'office professional plus 2010',
    'Office 2010', 'Office 2016', 'Office 2019', 'Office 365',

    # Backup aur archive folders
    'backup', 'Backup', 'BACKUP',
    'archive', 'Archive', 'ARCHIVE',
    'old', 'Old', 'OLD',

    # Apne scanner ke output
    'reports',
}

# File name patterns jo skip karne hain
SKIP_FILE_PATTERNS = [
    r'.*\.min\.js$',       # Minified JS
    r'.*\.min\.css$',      # Minified CSS
    r'.*-min\.js$',        # Minified JS (alternative)
    r'.*\.bundle\.js$',    # Bundled JS
    r'.*\.chunk\.js$',     # Chunked JS
    r'.*\.map$',           # Source maps
]

# Paths jo skip karne hain (self-exclusion)
SKIP_PATH_KEYWORDS = [
    'Cbom-Scanner',
    'cbom-scanner',
    'CBOM-Scanner',
]


def get_algorithm_category(algorithm):
    """Algorithm ka category return karo (quantum_vulnerable / weak_classical / None)."""
    info = VULNERABLE_ALGORITHMS.get(algorithm)
    if info:
        return info.get('category')
    return None


def should_skip_path(filepath):
    """Check karo ki filepath ko skip karna chahiye ya nahi."""
    for keyword in SKIP_PATH_KEYWORDS:
        if keyword in filepath:
            return True
    return False


def should_skip_file(filename):
    """Check karo ki filename ko skip karna chahiye ya nahi."""
    filename_lower = filename.lower()

    # Exact name check
    if filename_lower in SKIP_FILES:
        return True

    # Pattern check
    for pattern in SKIP_FILE_PATTERNS:
        if re.match(pattern, filename, re.IGNORECASE):
            return True

    return False


def is_real_crypto_usage(line, match_start, algorithm):
    """
    Check karo ki yeh line actually cryptographic usage hai ya nahi.

    Returns:
        bool: True agar real crypto usage hai
    """
    # Noise patterns - agar yeh hain to skip karo
    noise_patterns = [
        # Comments
        r'^\s*#',              # Python comment
        r'^\s*//',             # C/JS comment
        r'^\s*\*',             # Block comment
        r'^\s*<!--',           # HTML comment
        r'^\s*"""',            # Python docstring
        r'^\s*\'\'\'',         # Python docstring

        # Time format strings
        r'%dH%dM',
        r'%dH',

        # License text patterns
        r'[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Z][a-z]+',
        r'Inc\.',
        r'Corporation',
        r'Foundation',
        r'Copyright',

        # TypeScript type definitions
        r'RsaHashedKeyGenParams',
        r'EcKeyGenParams',
        r'ReadonlyArray<KeyUsage>',
        r'algorithm:\s*\w+Params',
        r'generateKey\(algorithm:',

        # Type annotations (colon followed by type name)
        r':\s*Rsa\w+',
        r':\s*Ec\w+',
    ]

    for pattern in noise_patterns:
        if re.search(pattern, line):
            return False

    # Line bahut lambi hai? Minified code ho sakta hai
    if len(line) > 500:
        return False

    # Check karo ki line mein actual code syntax hai
    code_indicators = [
        r'=',                  # Assignment
        r'\(',                 # Function call
        r'import',             # Import statement
        r'from',               # Import statement
        r'require',            # Require statement
        r'new\s+',             # Object creation
        r'\.',                 # Method call
    ]

    has_code_syntax = any(re.search(p, line) for p in code_indicators)

    if not has_code_syntax:
        return False

    return True


def scan_file(filepath):
    """Ek file ko scan karo aur vulnerable algorithms detect karo."""
    findings = []

    # File ka naam check karo
    filename = os.path.basename(filepath)
    if should_skip_file(filename):
        return findings

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

            for algo, info in VULNERABLE_ALGORITHMS.items():
                for line_num, line in enumerate(lines, 1):
                    for pattern in info['patterns']:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            # Check karo ki real usage hai ya nahi
                            if not is_real_crypto_usage(line, match.start(), algo):
                                continue

                            findings.append({
                                'file': filepath,
                                'line': line_num,
                                'column': match.start() + 1,
                                'algorithm': algo,
                                'category': info['category'],
                                'risk': info['risk'],
                                'reason': info['reason'],
                                'context': line.strip()[:120],
                                'matched_pattern': pattern,
                            })
                            break  # Ek line mein ek hi finding per algorithm
    except Exception as e:
        print(f"[ERROR] Cannot read {filepath}: {e}")

    return findings


def scan_folder(folder_path):
    """Poore folder ko recursively scan karo."""
    all_findings = []
    files_scanned = 0
    files_skipped = 0
    files_self_excluded = 0

    print(f"[INFO] Scanning folder: {folder_path}")
    print(f"[INFO] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    for root, dirs, files in os.walk(folder_path):
        # Skip unnecessary folders
        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]

        for file in files:
            filepath = os.path.join(root, file)

            # Self-exclusion check
            if should_skip_path(filepath):
                files_self_excluded += 1
                continue

            if file.endswith(SCANNABLE_EXTENSIONS):
                findings = scan_file(filepath)
                all_findings.extend(findings)
                files_scanned += 1
            else:
                files_skipped += 1

    summary = {
        'scan_time': datetime.now().isoformat(),
        'folder': folder_path,
        'files_scanned': files_scanned,
        'files_skipped': files_skipped,
        'files_self_excluded': files_self_excluded,
        'total_findings': len(all_findings),
        'quantum_vulnerable_count': sum(1 for f in all_findings if f.get('category') == CATEGORY_QUANTUM),
        'weak_classical_count': sum(1 for f in all_findings if f.get('category') == CATEGORY_WEAK),
        'findings': all_findings
    }

    print(f"[INFO] Files scanned: {files_scanned}")
    print(f"[INFO] Files skipped: {files_skipped}")
    print(f"[INFO] Files self-excluded: {files_self_excluded}")
    print(f"[INFO] Total findings: {len(all_findings)}")
    print(f"[INFO] Quantum-vulnerable: {summary['quantum_vulnerable_count']} | "
          f"Weak/deprecated: {summary['weak_classical_count']}")

    return summary


def get_algorithm_summary(findings):
    """Algorithm-wise count return karo."""
    algo_count = {}
    for f in findings:
        algo = f['algorithm']
        if algo not in algo_count:
            algo_count[algo] = {
                'count': 0,
                'risk': f['risk'],
                'category': f.get('category') or get_algorithm_category(algo),
            }
        algo_count[algo]['count'] += 1
    return algo_count


def get_category_summary(findings):
    """Category-wise count return karo."""
    counts = {CATEGORY_QUANTUM: 0, CATEGORY_WEAK: 0}
    for f in findings:
        category = f.get('category') or get_algorithm_category(f.get('algorithm'))
        if category in counts:
            counts[category] += 1
    return counts


if __name__ == "__main__":
    target = input("Enter folder path to scan: ").strip().strip('"')

    if not os.path.exists(target):
        print(f"[ERROR] Path does not exist: {target}")
    else:
        results = scan_folder(target)

        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)

        algo_summary = get_algorithm_summary(results['findings'])
        for algo, data in sorted(algo_summary.items(), key=lambda x: -x[1]['count']):
            label = CATEGORY_LABELS.get(data['category'], 'Other')
            print(f"  {algo:8s} | {label:18s} | Risk: {data['risk']:6s} | Occurrences: {data['count']}")