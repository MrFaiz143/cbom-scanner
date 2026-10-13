"""
Reporter - Scan results ko different formats mein output karta hai.
"""

import json
from datetime import datetime


def print_console_report(scan_results):
    """Console par detailed report print karo."""
    findings = scan_results.get('findings', [])
    
    print("\n" + "=" * 70)
    print("CBOM SCAN REPORT")
    print("=" * 70)
    print(f"Scan Time:      {scan_results.get('scan_time', 'N/A')}")
    print(f"Folder:         {scan_results.get('folder', 'N/A')}")
    print(f"Files Scanned:  {scan_results.get('files_scanned', 0)}")
    print(f"Total Findings: {scan_results.get('total_findings', 0)}")
    print("=" * 70)
    
    if not findings:
        print("\n  ✅ Koi vulnerable algorithm nahi mila.")
        return
    
    # Group by file
    by_file = {}
    for f in findings:
        filepath = f['file']
        if filepath not in by_file:
            by_file[filepath] = []
        by_file[filepath].append(f)
    
    print("\n  DETAILED FINDINGS:")
    print("  " + "-" * 66)
    
    for filepath, file_findings in by_file.items():
        print(f"\n  📄 {filepath}")
        for f in file_findings:
            risk_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(f['risk'], '⚪')
            print(f"     {risk_icon} Line {f['line']:4d} | {f['algorithm']:8s} | {f['reason']}")
            print(f"        → {f['context']}")


def save_json_report(scan_results, output_path):
    """Scan results ko JSON file mein save karo."""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=2)
        print(f"\n[OK] JSON report saved: {output_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Cannot save JSON: {e}")
        return False


def save_text_report(scan_results, output_path):
    """Scan results ko text file mein save karo."""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("CBOM SCAN REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Scan Time: {scan_results.get('scan_time')}\n")
            f.write(f"Folder: {scan_results.get('folder')}\n")
            f.write(f"Files Scanned: {scan_results.get('files_scanned')}\n")
            f.write(f"Total Findings: {scan_results.get('total_findings')}\n")
            f.write("=" * 70 + "\n\n")
            
            for finding in scan_results.get('findings', []):
                f.write(f"[{finding['risk']}] {finding['algorithm']}\n")
                f.write(f"  File: {finding['file']}\n")
                f.write(f"  Line: {finding['line']}, Column: {finding.get('column', 'N/A')}\n")
                f.write(f"  Reason: {finding['reason']}\n")
                f.write(f"  Context: {finding['context']}\n\n")
        
        print(f"[OK] Text report saved: {output_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Cannot save text report: {e}")
        return False