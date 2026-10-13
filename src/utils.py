"""
Utils - Helper functions for CBOM Scanner
"""

import os
import json
from datetime import datetime


def print_banner():
    """Tool ka banner print karo."""
    banner = """
    ╔══════════════════════════════════════════════════════╗
    ║           CBOM SCANNER v0.1.0                        ║
    ║   Cryptographic Bill of Materials Generator          ║
    ║   Aligned with India NQM Roadmap 2027-2028           ║
    ╚══════════════════════════════════════════════════════╝
    """
    print(banner)


def save_json_report(data, output_path):
    """Kisi bhi data ko JSON file mein save karo."""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"[OK] Report saved: {output_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Cannot save report: {e}")
        return False


def get_risk_color(risk):
    """Risk level ke according emoji return karo."""
    colors = {
        'HIGH': '🔴',
        'MEDIUM': '🟡',
        'LOW': '🟢',
    }
    return colors.get(risk, '⚪')


def format_timestamp():
    """Current timestamp formatted return karo."""
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def validate_path(path):
    """Check karo ki path valid hai ya nahi."""
    if not path:
        return False, "Path empty hai"
    if not os.path.exists(path):
        return False, f"Path exist nahi karta: {path}"
    if not os.path.isdir(path):
        return False, f"Yeh folder nahi hai: {path}"
    return True, "OK"


def print_findings_table(findings):
    """Findings ko table format mein print karo."""
    if not findings:
        print("  Koi finding nahi mili.")
        return
    
    print(f"\n  {'ALGORITHM':<12} {'RISK':<8} {'FILE':<40} {'LINE':<6}")
    print("  " + "-" * 70)
    
    for f in findings[:20]:  # Sirf pehle 20 dikhao
        file_short = f['file'][-38:] if len(f['file']) > 38 else f['file']
        print(f"  {f['algorithm']:<12} {f['risk']:<8} {file_short:<40} {f.get('line', 0):<6}")
    
    if len(findings) > 20:
        print(f"  ... aur {len(findings) - 20} findings")