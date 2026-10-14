"""
CBOM Scanner - Data Visualization (v0.5.1)
Yeh script scan reports ko visual HTML report mein convert karta hai.

v0.5.1 Changes:
- Multiple reports load karta hai (auto-merge)
- Duplicate hosts skip karta hai
- Combined visualization

Usage:
    python visualize.py
    python visualize.py reports/multi_host_scan_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import glob
from datetime import datetime
from collections import Counter


def load_all_reports(reports_dir='reports'):
    """Saari multi-host reports load karo aur merge karo."""
    pattern = os.path.join(reports_dir, 'multi_host_scan_*.json')
    files = sorted(glob.glob(pattern))
    
    if not files:
        print(f"[ERROR] Koi report nahi mili: {pattern}")
        return None
    
    print(f"[INFO] Total reports found: {len(files)}")
    
    all_hosts = {}
    total_findings = 0
    
    for filepath in files:
        print(f"[INFO] Loading: {os.path.basename(filepath)}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for host_data in data.get('hosts', []):
                host = host_data.get('host', 'unknown')
                
                # Duplicate skip karo
                if host in all_hosts:
                    continue
                
                all_hosts[host] = host_data
                services = host_data.get('services', [])
                findings = sum(len(s.get('findings', [])) for s in services)
                total_findings += findings
        except Exception as e:
            print(f"[WARN] Cannot load {filepath}: {e}")
    
    print(f"[INFO] Total unique hosts: {len(all_hosts)}")
    
    return {
        'scan_time': datetime.now().isoformat(),
        'total_hosts': len(all_hosts),
        'total_findings': total_findings,
        'hosts': list(all_hosts.values())
    }


def load_report(filepath):
    """Specific report load karo."""
    if not os.path.exists(filepath):
        print(f"[ERROR] File nahi mili: {filepath}")
        return None
    
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_data(data):
    """Data analyze karo aur statistics nikaalo."""
    stats = {
        'total_hosts': len(data.get('hosts', [])),
        'total_findings': data.get('total_findings', 0),
        'tls_versions': Counter(),
        'cipher_suites': Counter(),
        'algorithms': Counter(),
        'issuers': Counter(),
        'expiry_status': Counter(),
        'public_key_types': Counter(),
        'hosts_with_findings': 0,
        'hosts_no_findings': 0,
        'hosts_with_data': 0,
        'hosts_no_data': 0,
        'host_details': []
    }
    
    for host_data in data.get('hosts', []):
        host = host_data.get('host', 'unknown')
        services = host_data.get('services', [])
        
        host_findings = 0
        host_tls = []
        host_ciphers = []
        host_algorithms = []
        host_issuer = None
        host_expiry = None
        host_pubkey = None
        
        if not services:
            stats['hosts_no_data'] += 1
        else:
            stats['hosts_with_data'] += 1
        
        for service in services:
            # TLS version
            tls = service.get('tls_version')
            if tls:
                stats['tls_versions'][tls] += 1
                host_tls.append(tls)
            
            # Cipher suite
            cipher = service.get('cipher_suite')
            if cipher and isinstance(cipher, list):
                cipher_name = cipher[0]
                stats['cipher_suites'][cipher_name] += 1
                host_ciphers.append(cipher_name)
            
            # Certificate
            cert = service.get('certificate')
            if cert and isinstance(cert, dict):
                # Issuer
                issuer = cert.get('issuer', {})
                if issuer:
                    issuer_cn = issuer.get('CN', 'Unknown')
                    stats['issuers'][issuer_cn] += 1
                    host_issuer = issuer_cn
                
                # Expiry status
                expiry = cert.get('expiry_status', 'unknown')
                stats['expiry_status'][expiry] += 1
                host_expiry = expiry
                
                # Public key
                pubkey = cert.get('public_key', {})
                if pubkey:
                    key_type = pubkey.get('type', 'Unknown')
                    key_bits = pubkey.get('bits', 0)
                    key_str = f"{key_type}-{key_bits}"
                    stats['public_key_types'][key_str] += 1
                    host_pubkey = key_str
            
            # Findings
            findings = service.get('findings', [])
            for finding in findings:
                algo = finding.get('algorithm', 'Unknown')
                stats['algorithms'][algo] += 1
                host_algorithms.append(algo)
                host_findings += 1
        
        if host_findings > 0:
            stats['hosts_with_findings'] += 1
        else:
            stats['hosts_no_findings'] += 1
        
        stats['host_details'].append({
            'host': host,
            'tls': host_tls[0] if host_tls else 'N/A',
            'cipher': host_ciphers[0] if host_ciphers else 'N/A',
            'issuer': host_issuer or 'N/A',
            'expiry': host_expiry or 'N/A',
            'public_key': host_pubkey or 'N/A',
            'findings_count': host_findings,
            'algorithms': list(set(host_algorithms))
        })
    
    return stats


def generate_html(stats, output_path):
    """HTML report generate karo."""
    
    # Pie chart data (TLS versions)
    tls_labels = list(stats['tls_versions'].keys())
    tls_values = list(stats['tls_versions'].values())
    
    # Bar chart data (Algorithms)
    algo_labels = list(stats['algorithms'].keys())
    algo_values = list(stats['algorithms'].values())
    
    # Bar chart data (Issuers)
    issuer_labels = list(stats['issuers'].keys())[:10]
    issuer_values = [stats['issuers'][label] for label in issuer_labels]
    
    # Bar chart data (Public Key Types)
    pubkey_labels = list(stats['public_key_types'].keys())
    pubkey_values = list(stats['public_key_types'].values())
    
    # Host details table rows (sorted by findings count)
    table_rows = ""
    for host in sorted(stats['host_details'], key=lambda x: -x['findings_count']):
        findings_badge = '🔴' if host['findings_count'] > 0 else '✅'
        expiry_badge = {
            'VALID': '✅',
            'EXPIRING_SOON': '⚠️',
            'EXPIRED': '❌',
            'unknown': '❓'
        }.get(host['expiry'], '❓')
        
        table_rows += f"""
        <tr>
            <td>{host['host']}</td>
            <td>{host['tls']}</td>
            <td>{host['cipher'][:40]}...</td>
            <td>{host['issuer']}</td>
            <td>{expiry_badge} {host['expiry']}</td>
            <td>{host['public_key']}</td>
            <td>{findings_badge} {host['findings_count']}</td>
        </tr>
        """
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CBOM Scanner - Visual Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid #30363d;
            margin-bottom: 30px;
        }}
        header h1 {{
            font-size: 2.5em;
            color: #58a6ff;
            margin-bottom: 10px;
        }}
        header p {{ color: #8b949e; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #58a6ff;
        }}
        .stat-card .label {{
            color: #8b949e;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .chart-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .chart-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
        }}
        .chart-card h3 {{
            color: #58a6ff;
            margin-bottom: 15px;
            font-size: 1.1em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }}
        th {{
            background: #21262d;
            color: #58a6ff;
            font-weight: 600;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        tr:hover {{ background: #1c2128; }}
        footer {{
            text-align: center;
            padding: 30px 0;
            color: #8b949e;
            font-size: 0.9em;
            border-top: 1px solid #30363d;
            margin-top: 40px;
        }}
        footer a {{ color: #58a6ff; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 CBOM Scanner</h1>
            <p>Post-Quantum Cryptography Readiness Report</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{stats['total_hosts']}</div>
                <div class="label">Total Hosts</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats['total_findings']}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats['hosts_with_findings']}</div>
                <div class="label">Hosts with Findings</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats['hosts_with_data']}</div>
                <div class="label">Hosts with Data</div>
            </div>
        </div>
        
        <div class="chart-grid">
            <div class="chart-card">
                <h3>📊 TLS Version Distribution</h3>
                <canvas id="tlsChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>🔐 Quantum-Vulnerable Algorithms</h3>
                <canvas id="algoChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>🏢 Certificate Issuers</h3>
                <canvas id="issuerChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>🔑 Public Key Types</h3>
                <canvas id="pubkeyChart"></canvas>
            </div>
        </div>
        
        <h2 style="color: #58a6ff; margin-bottom: 20px;">📋 Host Details ({stats['total_hosts']} hosts)</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>TLS</th>
                    <th>Cipher Suite</th>
                    <th>Issuer</th>
                    <th>Expiry</th>
                    <th>Public Key</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
        
        <footer>
            <p>Generated by <a href="https://github.com/MrFaiz143/cbom-scanner">CBOM Scanner</a> v0.5.1</p>
            <p>Aligned with India NQM Roadmap 2027-2028</p>
        </footer>
    </div>
    
    <script>
        new Chart(document.getElementById('tlsChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(tls_labels)},
                datasets: [{{
                    data: {json.dumps(tls_values)},
                    backgroundColor: ['#58a6ff', '#f0883e', '#3fb950', '#f85149', '#a371f7']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9' }} }}
                }}
            }}
        }});
        
        new Chart(document.getElementById('algoChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(algo_labels)},
                datasets: [{{
                    label: 'Occurrences',
                    data: {json.dumps(algo_values)},
                    backgroundColor: '#f85149'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    y: {{ ticks: {{ color: '#c9d1d9' }}, grid: {{ color: '#30363d' }} }},
                    x: {{ ticks: {{ color: '#c9d1d9' }}, grid: {{ color: '#30363d' }} }}
                }}
            }}
        }});
        
        new Chart(document.getElementById('issuerChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(issuer_labels)},
                datasets: [{{
                    label: 'Certificates',
                    data: {json.dumps(issuer_values)},
                    backgroundColor: '#3fb950'
                }}]
            }},
            options: {{
                indexAxis: 'y',
                responsive: true,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    y: {{ ticks: {{ color: '#c9d1d9' }}, grid: {{ color: '#30363d' }} }},
                    x: {{ ticks: {{ color: '#c9d1d9' }}, grid: {{ color: '#30363d' }} }}
                }}
            }}
        }});
        
        new Chart(document.getElementById('pubkeyChart'), {{
            type: 'pie',
            data: {{
                labels: {json.dumps(pubkey_labels)},
                datasets: [{{
                    data: {json.dumps(pubkey_values)},
                    backgroundColor: ['#58a6ff', '#f0883e', '#3fb950', '#f85149']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[OK] HTML report saved: {output_path}")
    return output_path


def main():
    """Main function."""
    print("=" * 60)
    print("CBOM SCANNER - DATA VISUALIZATION (v0.5.1)")
    print("=" * 60)
    
    # Report file decide karo
    if len(sys.argv) > 1:
        report_file = sys.argv[1]
        data = load_report(report_file)
    else:
        data = load_all_reports()
    
    if not data:
        print("[ERROR] Data load nahi hua.")
        return
    
    print(f"\n[INFO] Analyzing data...")
    stats = analyze_data(data)
    
    # Output path
    reports_dir = 'reports'
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = os.path.join(reports_dir, f'visual_report_{timestamp}.html')
    
    # HTML generate karo
    generate_html(stats, output_path)
    
    # Summary print karo
    print("\n" + "=" * 60)
    print("DATA SUMMARY")
    print("=" * 60)
    print(f"Total Hosts: {stats['total_hosts']}")
    print(f"Hosts with Data: {stats['hosts_with_data']}")
    print(f"Hosts without Data: {stats['hosts_no_data']}")
    print(f"Total Findings: {stats['total_findings']}")
    print(f"Hosts with Findings: {stats['hosts_with_findings']}")
    print()
    print("TLS Versions:")
    for tls, count in stats['tls_versions'].most_common():
        print(f"  {tls}: {count}")
    print()
    print("Top Algorithms:")
    for algo, count in stats['algorithms'].most_common(10):
        print(f"  {algo}: {count}")
    print()
    print("Top Issuers:")
    for issuer, count in stats['issuers'].most_common(5):
        print(f"  {issuer}: {count}")
    print()
    print("=" * 60)
    print(f"[OK] Open this file in browser: {output_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()