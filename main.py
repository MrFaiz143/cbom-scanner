"""
CBOM Scanner - Main Entry Point (v0.4.2)
Yeh script scanner ko chalata hai aur saari reports generate karta hai.

v0.4.2 Changes:
- Certificate details display in reports
- Expiry status in findings
- Public key algorithm detection
- Certificate signature algorithm detection
"""

import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanner import scan_folder
from cbom_generator import generate_cbom
from reporter import print_console_report, save_json_report, save_text_report
from network_scanner import scan_host, TOP_1000_PORTS


def print_banner():
    """Tool ka banner print karo."""
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║           CBOM SCANNER v0.4.2                        ║
    ║   Cryptographic Bill of Materials Generator          ║
    ║   Aligned with India NQM Roadmap 2027-2028           ║
    ╚══════════════════════════════════════════════════════╝
    """)


def print_menu():
    """Menu options print karo."""
    print("\n" + "=" * 60)
    print("SCAN TYPE CHUNO")
    print("=" * 60)
    print("  1. Local Folder Scan (code files scan karo)")
    print("  2. Network Scan (live TLS/SSH server scan karo)")
    print("  3. Exit")
    print("=" * 60)


def get_reports_dir():
    """Reports folder banao aur path return karo."""
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


# ============================================================
# FOLDER SCAN
# ============================================================

def do_folder_scan():
    """Folder scanning ka poora process."""
    print("\n" + "-" * 60)
    print("LOCAL FOLDER SCAN")
    print("-" * 60)
    
    target = input("Enter folder path to scan: ").strip().strip('"')
    
    if not os.path.exists(target):
        print(f"[ERROR] Path does not exist: {target}")
        return
    
    results = scan_folder(target)
    print_console_report(results)
    
    reports_dir = get_reports_dir()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    json_path = os.path.join(reports_dir, f'scan_{timestamp}.json')
    save_json_report(results, json_path)
    
    txt_path = os.path.join(reports_dir, f'scan_{timestamp}.txt')
    save_text_report(results, txt_path)
    
    cbom_path = os.path.join(reports_dir, f'cbom_{timestamp}.json')
    generate_cbom(results, cbom_path)
    
    print(f"\n[OK] Saari reports saved in: {reports_dir}")


# ============================================================
# NETWORK SCAN
# ============================================================

def do_network_scan():
    """Network scanning ka poora process."""
    print("\n" + "-" * 60)
    print("NETWORK SCAN (TLS + SSH + LDAP + Databases)")
    print("-" * 60)
    print("[NOTE] Sirf un servers ko scan karo jinki aapko permission hai.")
    print()
    
    host = input("Enter hostname or IP (e.g., google.com): ").strip()
    
    if not host:
        print("[ERROR] Host empty hai.")
        return
    
    print("\n" + "-" * 60)
    print("PORTS OPTION")
    print("-" * 60)
    print("  1. Default (5 common ports: 443, 22, 8443, 993, 995)")
    print("     → Fast scan (10-30 seconds)")
    print()
    print("  2. Top 1000 ports (full network scan)")
    print("     → Slow scan (5-15 minutes)")
    print("     → Sab services detect hongi (LDAP, MySQL, MSSQL, etc.)")
    print()
    print("  3. Custom ports (aap khud ports daalo)")
    print("-" * 60)
    
    port_choice = input("Enter choice (1/2/3, default=1): ").strip()
    
    if port_choice == "2":
        ports = TOP_1000_PORTS
        print(f"\n[INFO] Using Top 1000 ports ({len(ports)} total)")
        print("[WARN] Yeh scan mein 5-15 minute lag sakte hain. Please wait...")
        print("[INFO] Aap Ctrl+C dabakar kabhi bhi rok sakte ho.\n")
    
    elif port_choice == "3":
        ports_input = input("Enter ports (comma-separated, e.g., 443,22,8080): ").strip()
        try:
            ports = [int(p.strip()) for p in ports_input.split(',')]
            print(f"\n[INFO] Using {len(ports)} custom ports: {ports}")
        except ValueError:
            print("[ERROR] Invalid ports. Default 5 ports use kar rahe hain.")
            ports = [443, 22, 8443, 993, 995]
    
    else:
        ports = [443, 22, 8443, 993, 995]
        print(f"\n[INFO] Using default ports: {ports}")
    
    print()
    results = scan_host(host, ports=ports)
    
    print_network_report(results)
    
    reports_dir = get_reports_dir()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    json_path = os.path.join(reports_dir, f'network_scan_{timestamp}.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\n[OK] Network JSON report saved: {json_path}")
    
    txt_path = os.path.join(reports_dir, f'network_scan_{timestamp}.txt')
    save_network_text_report(results, txt_path)
    print(f"[OK] Network text report saved: {txt_path}")
    
    print(f"\n[OK] Saari reports saved in: {reports_dir}")


def print_network_report(results):
    """Network scan results console par print karo."""
    print("\n" + "=" * 70)
    print("NETWORK SCAN REPORT")
    print("=" * 70)
    print(f"Host:              {results.get('host', 'N/A')}")
    print(f"Scan Time:         {results.get('scan_time', 'N/A')}")
    print(f"Total Ports:       {results.get('total_ports_scanned', 0)}")
    print(f"Open Ports:        {len(results.get('open_ports', []))}")
    print(f"Services Detected: {len(results.get('services', []))}")
    print("=" * 70)
    
    open_ports = results.get('open_ports', [])
    if open_ports:
        print(f"\n📡 OPEN PORTS:")
        for i in range(0, len(open_ports), 10):
            chunk = open_ports[i:i+10]
            print(f"   {', '.join(str(p) for p in chunk)}")
    
    services = results.get('services', [])
    if not services:
        print("\n  ⚠️  Koi service detail nahi mili.")
        return
    
    total_findings = 0
    
    for service in services:
        print(f"\n{'─' * 70}")
        print(f"📡 {service['protocol']} on {service['target']}")
        print(f"{'─' * 70}")
        print(f"   Status: {service['status']}")
        
        if service.get('tls_version'):
            print(f"   TLS Version: {service['tls_version']}")
        
        if service.get('cipher_suite'):
            cipher = service['cipher_suite']
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            print(f"   Cipher Suite: {cipher_name}")
        
        # Certificate details
        cert = service.get('certificate')
        if cert and isinstance(cert, dict):
            print(f"\n   📜 CERTIFICATE DETAILS:")
            
            if 'error' in cert:
                print(f"      ❌ Error: {cert['error']}")
            elif 'note' in cert:
                print(f"      ⚠️  {cert['note']}")
            else:
                subject = cert.get('subject', {})
                if subject:
                    cn = subject.get('CN', 'N/A')
                    org = subject.get('O', '')
                    print(f"      Subject:  {cn}" + (f" ({org})" if org else ""))
                
                issuer = cert.get('issuer', {})
                if issuer:
                    cn = issuer.get('CN', 'N/A')
                    org = issuer.get('O', '')
                    print(f"      Issuer:   {cn}" + (f" ({org})" if org else ""))
                
                not_before = cert.get('not_before', 'N/A')
                not_after = cert.get('not_after', 'N/A')
                print(f"      Valid:    {not_before} → {not_after}")
                
                expiry_status = cert.get('expiry_status', '')
                days_left = cert.get('days_until_expiry')
                if expiry_status == 'EXPIRED':
                    print(f"      ⚠️  EXPIRED")
                elif expiry_status == 'EXPIRING_SOON':
                    print(f"      ⚠️  Expiring in {days_left} days")
                elif days_left is not None:
                    print(f"      Status:   ✅ Valid ({days_left} days left)")
                
                pubkey = cert.get('public_key', {})
                if pubkey:
                    print(f"      Public Key: {pubkey.get('type', 'N/A')}-{pubkey.get('bits', 'N/A')} bits")
                
                sig_algo = cert.get('signature_algorithm', '')
                if sig_algo:
                    print(f"      Signature: {sig_algo}")
                
                serial = cert.get('serial_number', '')
                if serial:
                    print(f"      Serial:   {serial}")
                
                sans = cert.get('subject_alt_names', [])
                if sans:
                    print(f"      SAN:      {', '.join(sans[:5])}")
                    if len(sans) > 5:
                        print(f"                ... aur {len(sans) - 5} more")
        
        if service.get('ssh_version'):
            print(f"   SSH Version: {service['ssh_version']}")
        
        if service.get('kex_algorithms'):
            kex_list = service['kex_algorithms'][:5]
            print(f"   KEX Algorithms: {', '.join(kex_list)}")
        
        if service.get('host_key_algorithms'):
            key_list = service['host_key_algorithms'][:5]
            print(f"   Host Key Algos: {', '.join(key_list)}")
        
        findings = service.get('findings', [])
        if findings:
            print(f"\n   🔍 Findings ({len(findings)}):")
            for finding in findings:
                icon = '🔴' if finding['risk'] == 'HIGH' else '🟡'
                print(f"      {icon} [{finding['risk']}] {finding['algorithm']}")
                print(f"         → {finding['reason']}")
                print(f"         → {finding['context']}")
                total_findings += 1
        else:
            print("\n   ✅ Koi vulnerable algorithm nahi mila.")
    
    print("\n" + "=" * 70)
    print(f"TOTAL FINDINGS: {total_findings}")
    print("=" * 70)


def save_network_text_report(results, output_path):
    """Network scan results ko text file mein save karo."""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("NETWORK SCAN REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Host: {results.get('host')}\n")
            f.write(f"Scan Time: {results.get('scan_time')}\n")
            f.write(f"Total Ports Scanned: {results.get('total_ports_scanned')}\n")
            f.write(f"Open Ports: {len(results.get('open_ports', []))}\n")
            f.write(f"Services Found: {len(results.get('services', []))}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Open Ports: {results.get('open_ports', [])}\n\n")
            
            for service in results.get('services', []):
                f.write("\n" + "-" * 70 + "\n")
                f.write(f"{service['protocol']} on {service['target']}\n")
                f.write("-" * 70 + "\n")
                f.write(f"  Status: {service['status']}\n")
                
                if service.get('tls_version'):
                    f.write(f"  TLS Version: {service['tls_version']}\n")
                if service.get('cipher_suite'):
                    f.write(f"  Cipher Suite: {service['cipher_suite']}\n")
                
                cert = service.get('certificate')
                if cert and isinstance(cert, dict):
                    f.write(f"\n  CERTIFICATE DETAILS:\n")
                    if 'error' in cert:
                        f.write(f"    Error: {cert['error']}\n")
                    elif 'note' in cert:
                        f.write(f"    Note: {cert['note']}\n")
                    else:
                        f.write(f"    Subject: {cert.get('subject')}\n")
                        f.write(f"    Issuer: {cert.get('issuer')}\n")
                        f.write(f"    Valid From: {cert.get('not_before')}\n")
                        f.write(f"    Valid Until: {cert.get('not_after')}\n")
                        f.write(f"    Expiry Status: {cert.get('expiry_status')}\n")
                        f.write(f"    Days Until Expiry: {cert.get('days_until_expiry')}\n")
                        f.write(f"    Public Key: {cert.get('public_key')}\n")
                        f.write(f"    Signature Algorithm: {cert.get('signature_algorithm')}\n")
                        f.write(f"    Serial: {cert.get('serial_number')}\n")
                        f.write(f"    SAN: {cert.get('subject_alt_names')}\n")
                
                if service.get('ssh_version'):
                    f.write(f"  SSH Version: {service['ssh_version']}\n")
                if service.get('kex_algorithms'):
                    f.write(f"  KEX Algorithms: {service['kex_algorithms']}\n")
                if service.get('host_key_algorithms'):
                    f.write(f"  Host Key Algorithms: {service['host_key_algorithms']}\n")
                
                findings = service.get('findings', [])
                if findings:
                    f.write(f"\n  Findings ({len(findings)}):\n")
                    for finding in findings:
                        f.write(f"    [{finding['risk']}] {finding['algorithm']}\n")
                        f.write(f"      Reason: {finding['reason']}\n")
                        f.write(f"      Context: {finding['context']}\n")
                        f.write(f"      Source: {finding['source']}\n\n")
                else:
                    f.write("\n  No vulnerable algorithms found.\n")
        
        return True
    except Exception as e:
        print(f"[ERROR] Cannot save text report: {e}")
        return False


# ============================================================
# MAIN
# ============================================================

def main():
    """Main entry point."""
    while True:
        print_banner()
        print_menu()
        
        choice = input("\nEnter choice (1/2/3): ").strip()
        
        if choice == "1":
            do_folder_scan()
            input("\n[Press Enter to continue...]")
        
        elif choice == "2":
            do_network_scan()
            input("\n[Press Enter to continue...]")
        
        elif choice == "3":
            print("\n[OK] Goodbye! 🚀")
            break
        
        else:
            print("\n[ERROR] Invalid choice. 1, 2, ya 3 daalo.")
            input("[Press Enter to continue...]")


if __name__ == "__main__":
    main()