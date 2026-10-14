// Tab switching
function showTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(`${tabName}-tab`).classList.add('active');
}

// Folder scan
document.getElementById('folder-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const folderPath = document.getElementById('folder-path').value;
    
    showLoading();
    
    try {
        const formData = new FormData();
        formData.append('folder_path', folderPath);
        
        const response = await fetch('/api/scan/folder', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
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

// Network scan
document.getElementById('network-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = document.getElementById('network-host').value;
    const portOption = document.getElementById('port-option').value;
    
    showLoading();
    
    try {
        const formData = new FormData();
        formData.append('host', host);
        formData.append('port_option', portOption);
        
        const response = await fetch('/api/scan/network', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
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

// Multi-host scan
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
        
        const response = await fetch('/api/scan/multi', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
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
    contentDiv.innerHTML = `<div class="result-card"><h3>❌ Error</h3><p>${message}</p></div>`;
    resultsDiv.classList.remove('hidden');
}

function showFolderResults(data) {
    const resultsDiv = document.getElementById('results');
    const contentDiv = document.getElementById('results-content');
    
    let html = `
        <div class="result-card">
            <h3>📁 Folder Scan Results</h3>
            <p><strong>Folder:</strong> ${data.folder}</p>
            <p><strong>Files Scanned:</strong> ${data.files_scanned}</p>
            <p><strong>Total Findings:</strong> ${data.total_findings}</p>
        </div>
    `;
    
    if (data.findings && data.findings.length > 0) {
        html += '<div class="result-card"><h3>🔍 Findings</h3>';
        data.findings.forEach(f => {
            const riskClass = f.risk === 'HIGH' ? '' : f.risk === 'MEDIUM' ? 'medium' : 'low';
            html += `
                <div class="finding ${riskClass}">
                    <strong>${f.algorithm}</strong> — ${f.risk}
                    <br><small>${f.file}:${f.line}</small>
                    <br><small>${f.reason}</small>
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
    
    let html = `
        <div class="result-card">
            <h3>🌐 Network Scan Results</h3>
            <p><strong>Host:</strong> ${data.host}</p>
            <p><strong>Open Ports:</strong> ${data.open_ports.join(', ')}</p>
            <p><strong>Total Findings:</strong> ${data.total_findings}</p>
        </div>
    `;
    
    if (data.services) {
        data.services.forEach(service => {
            html += `
                <div class="result-card">
                    <h3>📡 ${service.protocol} on ${service.target}</h3>
                    <p><strong>TLS Version:</strong> ${service.tls_version || 'N/A'}</p>
                    <p><strong>Cipher Suite:</strong> ${service.cipher_suite ? service.cipher_suite[0] : 'N/A'}</p>
            `;
            
            if (service.certificate) {
                const cert = service.certificate;
                html += `
                    <h4>Certificate Details:</h4>
                    <p><strong>Subject:</strong> ${cert.subject?.CN || 'N/A'}</p>
                    <p><strong>Issuer:</strong> ${cert.issuer?.CN || 'N/A'}</p>
                    <p><strong>Valid Until:</strong> ${cert.not_after || 'N/A'}</p>
                    <p><strong>Status:</strong> ${cert.expiry_status || 'N/A'}</p>
                `;
            }
            
            if (service.findings) {
                html += '<h4>Findings:</h4>';
                service.findings.forEach(f => {
                    const riskClass = f.risk === 'HIGH' ? '' : f.risk === 'MEDIUM' ? 'medium' : 'low';
                    html += `
                        <div class="finding ${riskClass}">
                            <strong>${f.algorithm}</strong> — ${f.risk}
                            <br><small>${f.reason}</small>
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
    
    let html = `
        <div class="result-card">
            <h3>📋 Multi-Host Scan Results</h3>
            <p><strong>Total Hosts:</strong> ${data.total_hosts}</p>
        </div>
    `;
    
    data.results.forEach(result => {
        html += `
            <div class="result-card">
                <h3>${result.host}</h3>
        `;
        
        if (result.error) {
            html += `<p>❌ ${result.error}</p>`;
        } else {
            html += `
                <p><strong>Open Ports:</strong> ${(result.open_ports || []).join(', ')}</p>
                <p><strong>Services:</strong> ${(result.services || []).length}</p>
            `;
        }
        
        html += '</div>';
    });
    
    contentDiv.innerHTML = html;
    resultsDiv.classList.remove('hidden');
}