// ============================================================
// CBOM Scanner - Scan page script
// CSRF header + scan_id support + XSS-safe rendering
// ============================================================

// ---------- Helpers ----------
function getCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
}

function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Saare scan POST requests yahin se jayenge (CSRF header automatic)
async function postScan(url, formData) {
    const csrf = getCookie('csrf_token');
    const headers = {};
    if (csrf) headers['x-csrf-token'] = csrf;

    const response = await fetch(url, {
        method: 'POST',
        headers: headers,
        body: formData,
        credentials: 'same-origin'
    });

    if (response.status === 401) {
        window.location.href = '/login';
        throw new Error('Session expired. Please login again.');
    }
    if (response.status === 403) {
        throw new Error('Security token missing ya expire ho gaya. Logout karke dobara login karo.');
    }

    let data;
    try {
        data = await response.json();
    } catch (e) {
        throw new Error('Server se invalid response aaya (status ' + response.status + ')');
    }
    return data;
}

function scanSavedBanner(scanId) {
    if (!scanId) return '';
    return `
        <div class="result-card">
            <p>✅ Scan save ho gaya (ID: <strong>${escapeHtml(scanId)}</strong>).
            <a href="/dashboard">Dashboard me dekho →</a></p>
        </div>
    `;
}

// ---------- Tab switching ----------
function showTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    if (typeof event !== 'undefined' && event && event.target) {
        event.target.classList.add('active');
    }
    const content = document.getElementById(`${tabName}-tab`);
    if (content) content.classList.add('active');
}

// ---------- Folder scan ----------
document.getElementById('folder-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const folderPath = document.getElementById('folder-path').value;

    showLoading();

    try {
        const formData = new FormData();
        formData.append('folder_path', folderPath);

        const data = await postScan('/api/scan/folder', formData);
        hideLoading();

        if (data.error) {
            showError(data.error);
        } else {
            showFolderResults(data);
        }
    } catch (error) {
        hideLoading();
        showError(error.message);
    }
});

// ---------- Network scan ----------
document.getElementById('network-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = document.getElementById('network-host').value;
    const portOption = document.getElementById('port-option').value;

    showLoading();

    try {
        const formData = new FormData();
        formData.append('host', host);
        formData.append('port_option', portOption);

        const data = await postScan('/api/scan/network', formData);
        hideLoading();

        if (data.error) {
            showError(data.error);
        } else {
            showNetworkResults(data);
        }
    } catch (error) {
        hideLoading();
        showError(error.message);
    }
});

// ---------- Multi-host scan ----------
document.getElementById('multi-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById('hosts-file');

    if (!fileInput.files.length) {
        showError('Please select a file');
        return;
    }

    showLoading();

    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        const data = await postScan('/api/scan/multi', formData);
        hideLoading();

        if (data.error) {
            showError(data.error);
        } else {
            showMultiResults(data);
        }
    } catch (error) {
        hideLoading();
        showError(error.message);
    }
});

// ---------- UI helpers ----------
function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
}

function showError(message) {
    const resultsDiv = document.getElementById('results');
    const contentDiv = document.getElementById('results-content');
    contentDiv.innerHTML = `<div class="result-card"><h3>❌ Error</h3><p>${escapeHtml(message)}</p></div>`;
    resultsDiv.classList.remove('hidden');
}

function riskClassFor(risk) {
    return risk === 'HIGH' ? '' : risk === 'MEDIUM' ? 'medium' : 'low';
}

// ---------- Results ----------
function showFolderResults(data) {
    const resultsDiv = document.getElementById('results');
    const contentDiv = document.getElementById('results-content');

    let html = scanSavedBanner(data.scan_id) + `
        <div class="result-card">
            <h3>📁 Folder Scan Results</h3>
            <p><strong>Folder:</strong> ${escapeHtml(data.folder)}</p>
            <p><strong>Files Scanned:</strong> ${escapeHtml(data.files_scanned)}</p>
            <p><strong>Total Findings:</strong> ${escapeHtml(data.total_findings)}</p>
        </div>
    `;

    if (data.findings && data.findings.length > 0) {
        html += '<div class="result-card"><h3>🔍 Findings</h3>';
        data.findings.forEach(f => {
            html += `
                <div class="finding ${riskClassFor(f.risk)}">
                    <strong>${escapeHtml(f.algorithm)}</strong> — ${escapeHtml(f.risk)}
                    <br><small>${escapeHtml(f.file)}:${escapeHtml(f.line)}</small>
                    <br><small>${escapeHtml(f.reason)}</small>
                </div>
            `;
        });
        html += '</div>';
    }

    contentDiv.innerHTML = html;
    resultsDiv.classList.remove('hidden');
}

function showNetworkResults(data) {
    const resultsDiv = document.getElementById('results');
    const contentDiv = document.getElementById('results-content');

    const openPorts = (data.open_ports || []).map(escapeHtml).join(', ');

    let html = scanSavedBanner(data.scan_id) + `
        <div class="result-card">
            <h3>🌐 Network Scan Results</h3>
            <p><strong>Host:</strong> ${escapeHtml(data.host)}</p>
            <p><strong>Open Ports:</strong> ${openPorts || 'None'}</p>
            <p><strong>Total Findings:</strong> ${escapeHtml(data.total_findings)}</p>
        </div>
    `;

    if (data.services) {
        data.services.forEach(service => {
            const cipher = Array.isArray(service.cipher_suite)
                ? service.cipher_suite[0]
                : service.cipher_suite;

            html += `
                <div class="result-card">
                    <h3>📡 ${escapeHtml(service.protocol)} on ${escapeHtml(service.target)}</h3>
                    <p><strong>TLS Version:</strong> ${escapeHtml(service.tls_version || 'N/A')}</p>
                    <p><strong>Cipher Suite:</strong> ${escapeHtml(cipher || 'N/A')}</p>
            `;

            if (service.certificate) {
                const cert = service.certificate;
                html += `
                    <h4>Certificate Details:</h4>
                    <p><strong>Subject:</strong> ${escapeHtml(cert.subject?.CN || 'N/A')}</p>
                    <p><strong>Issuer:</strong> ${escapeHtml(cert.issuer?.CN || 'N/A')}</p>
                    <p><strong>Valid Until:</strong> ${escapeHtml(cert.not_after || 'N/A')}</p>
                    <p><strong>Status:</strong> ${escapeHtml(cert.expiry_status || 'N/A')}</p>
                `;
            }

            if (service.findings && service.findings.length > 0) {
                html += '<h4>Findings:</h4>';
                service.findings.forEach(f => {
                    html += `
                        <div class="finding ${riskClassFor(f.risk)}">
                            <strong>${escapeHtml(f.algorithm)}</strong> — ${escapeHtml(f.risk)}
                            <br><small>${escapeHtml(f.reason)}</small>
                        </div>
                    `;
                });
            }

            html += '</div>';
        });
    }

    contentDiv.innerHTML = html;
    resultsDiv.classList.remove('hidden');
}

function showMultiResults(data) {
    const resultsDiv = document.getElementById('results');
    const contentDiv = document.getElementById('results-content');

    let html = scanSavedBanner(data.scan_id) + `
        <div class="result-card">
            <h3>📋 Multi-Host Scan Results</h3>
            <p><strong>Total Hosts:</strong> ${escapeHtml(data.total_hosts)}</p>
        </div>
    `;

    (data.results || []).forEach(result => {
        html += `
            <div class="result-card">
                <h3>${escapeHtml(result.host)}</h3>
        `;

        if (result.error) {
            html += `<p>❌ ${escapeHtml(result.error)}</p>`;
        } else {
            html += `
                <p><strong>Open Ports:</strong> ${(result.open_ports || []).map(escapeHtml).join(', ')}</p>
                <p><strong>Services:</strong> ${(result.services || []).length}</p>
            `;
        }

        html += '</div>';
    });

    contentDiv.innerHTML = html;
    resultsDiv.classList.remove('hidden');
}