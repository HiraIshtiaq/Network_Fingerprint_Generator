let protocolChart = null;
let packetSizeChart = null;
let trafficTimeline = null;
let compareProtocolChart = null;
let compareTimelineChart = null;

let currentMode = 'single';
let isAnalyzing = false;

function switchMode(mode) {
    if (isAnalyzing) {
        showError("Analysis in progress, please wait");
        return;
    }
    
    currentMode = mode;
    
    document.getElementById('singleMode').style.display = mode === 'single' ? 'block' : 'none';
    document.getElementById('compareMode').style.display = mode === 'compare' ? 'block' : 'none';
    
    document.getElementById('singleResults').style.display = 'none';
    document.getElementById('compareResults').style.display = 'none';
    document.getElementById('error').style.display = 'none';
    
    if (protocolChart) protocolChart.destroy();
    if (packetSizeChart) packetSizeChart.destroy();
    if (trafficTimeline) trafficTimeline.destroy();
    if (compareProtocolChart) compareProtocolChart.destroy();
    if (compareTimelineChart) compareTimelineChart.destroy();
    
    protocolChart = null;
    packetSizeChart = null;
    trafficTimeline = null;
    compareProtocolChart = null;
    compareTimelineChart = null;
}

function validateURL(url, errorElementId) {
    if (!url || url.trim() === '') {
        showInlineError(errorElementId, 'URL is required');
        return false;
    }
    
    let cleanUrl = url.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        cleanUrl = 'https://' + cleanUrl;
    }
    
    try {
        new URL(cleanUrl);
        hideInlineError(errorElementId);
        return true;
    } catch (e) {
        showInlineError(errorElementId, 'Invalid URL format');
        return false;
    }
}

function showInlineError(elementId, message) {
    const div = document.getElementById(elementId);
    if (div) {
        div.textContent = message;
        div.style.display = 'block';
    }
    const inputId = elementId.replace('Error', '');
    const input = document.getElementById(inputId);
    if (input) input.classList.add('error');
}

function hideInlineError(elementId) {
    const div = document.getElementById(elementId);
    if (div) div.style.display = 'none';
    const inputId = elementId.replace('Error', '');
    const input = document.getElementById(inputId);
    if (input) input.classList.remove('error');
}

async function analyzeSingle() {
    if (isAnalyzing) return;
    isAnalyzing = true;
    
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    
    if (!validateURL(url, 'urlError')) {
        isAnalyzing = false;
        return;
    }
    
    let formattedUrl = url;
    if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
        formattedUrl = 'https://' + formattedUrl;
    }
    urlInput.value = formattedUrl;
    
    showLoading(true, 'Analyzing network traffic...');
    document.getElementById('singleResults').style.display = 'none';
    document.getElementById('compareResults').style.display = 'none';
    document.getElementById('error').style.display = 'none';
    
    const btn = document.getElementById('analyzeBtn');
    btn.disabled = true;
    btn.textContent = 'Analyzing...';
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: formattedUrl })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Analysis failed');
        }
        
        const fingerprint = await response.json();
        displaySingleResults(fingerprint);
        
    } catch (error) {
        showError(error.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Analyze';
        showLoading(false);
        isAnalyzing = false;
    }
}

async function analyzeCompare() {
    if (isAnalyzing) return;
    isAnalyzing = true;
    
    const url1 = document.getElementById('urlInput1').value.trim();
    const url2 = document.getElementById('urlInput2').value.trim();
    
    const valid1 = validateURL(url1, 'url1Error');
    const valid2 = validateURL(url2, 'url2Error');
    
    if (!valid1 || !valid2) {
        isAnalyzing = false;
        return;
    }
    
    let formattedUrl1 = url1;
    let formattedUrl2 = url2;
    if (!formattedUrl1.startsWith('http://') && !formattedUrl1.startsWith('https://')) {
        formattedUrl1 = 'https://' + formattedUrl1;
    }
    if (!formattedUrl2.startsWith('http://') && !formattedUrl2.startsWith('https://')) {
        formattedUrl2 = 'https://' + formattedUrl2;
    }
    document.getElementById('urlInput1').value = formattedUrl1;
    document.getElementById('urlInput2').value = formattedUrl2;
    
    showLoading(true, 'Comparing websites...');
    document.getElementById('singleResults').style.display = 'none';
    document.getElementById('compareResults').style.display = 'none';
    document.getElementById('error').style.display = 'none';
    
    const btn = document.getElementById('compareBtn');
    btn.disabled = true;
    btn.textContent = 'Comparing...';
    
    try {
        const response = await fetch('/api/compare', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url1: formattedUrl1, url2: formattedUrl2 })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Comparison failed');
        }
        
        const data = await response.json();
        displayComparisonResults(data);
        
    } catch (error) {
        showError(error.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Compare';
        showLoading(false);
        isAnalyzing = false;
    }
}

function displaySingleResults(fp) {
    document.getElementById('singleResults').style.display = 'block';
    
    const container = document.getElementById('summaryContent');
    const behavior = fp.behavior_label || 'Unknown';
    let badgeClass = 'behavior-unknown';
    
    if (behavior === 'Streaming') badgeClass = 'behavior-streaming';
    else if (behavior === 'Social Media') badgeClass = 'behavior-social';
    else if (behavior === 'Static Content') badgeClass = 'behavior-static';
    else if (behavior === 'API-Heavy') badgeClass = 'behavior-api-heavy';
    
    container.innerHTML = `
        <div class="summary-grid">
            <div class="summary-item">
                <div class="summary-label">URL</div>
                <div class="summary-value small">${escapeHtml(fp.site_url)}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Behavior</div>
                <span class="behavior-badge ${badgeClass}">${behavior}</span>
            </div>
            <div class="summary-item">
                <div class="summary-label">Confidence</div>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${(fp.confidence || 0) * 100}%"></div>
                </div>
                <div class="confidence-text">${((fp.confidence || 0) * 100).toFixed(1)}%</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Total Packets</div>
                <div class="summary-value">${(fp.total_packets || 0).toLocaleString()}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Total Data</div>
                <div class="summary-value">${formatBytes(fp.total_bytes || 0)}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Top Protocol</div>
                <div class="summary-value small">${fp.top_protocol || 'N/A'}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Unique IPs</div>
                <div class="summary-value">${fp.unique_ips || 0}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Mean Packet Size</div>
                <div class="summary-value">${(fp.mean_packet_size || 0).toFixed(0)} bytes</div>
            </div>
        </div>
        ${fp.classification_characteristics ? `
        <div class="characteristics">
            <h4>Key Characteristics:</h4>
            ${fp.classification_characteristics.map(c => `<div class="characteristic-item">${escapeHtml(c)}</div>`).join('')}
        </div>
        ` : ''}
        ${fp.dns_queries && fp.dns_queries.length ? `
        <div class="dns-section">
            <h4>DNS Queries:</h4>
            <div class="dns-list">
                ${fp.dns_queries.slice(0, 10).map(q => `<div class="dns-item">${escapeHtml(q)}</div>`).join('')}
                ${fp.dns_queries.length > 10 ? `<div class="dns-item">...and ${fp.dns_queries.length - 10} more</div>` : ''}
            </div>
        </div>
        ` : ''}
        ${fp.capture_metadata ? `
        <div class="dns-section">
            <h4>Capture Diagnostics:</h4>
            <div class="dns-list">
                <div class="dns-item">Hostname: ${escapeHtml(fp.capture_metadata.target_hostname || '?')}</div>
                <div class="dns-item">Resolved IPs (${(fp.capture_metadata.target_ips || []).length}): ${escapeHtml((fp.capture_metadata.target_ips || []).join(', ') || 'none')}</div>
                <div class="dns-item">BPF filter: <code>${escapeHtml(fp.capture_metadata.bpf_filter || 'n/a')}</code></div>
                <div class="dns-item">Packets captured: ${fp.capture_metadata.packets_captured_raw || 0}</div>
            </div>
        </div>
        ` : ''}
    `;
    
    createProtocolChart(fp);
    createPacketSizeHistogram(fp);
    createTrafficTimeline(fp);
    
    document.getElementById('singleResults').scrollIntoView({ behavior: 'smooth' });
}

function createProtocolChart(fp) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    if (protocolChart) protocolChart.destroy();
    
    const dist = fp.protocol_distribution || {};
    const colors = ['#667eea', '#764ba2', '#f5576c', '#4facfe', '#43e97b'];
    
    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(dist),
            datasets: [{
                data: Object.values(dist),
                backgroundColor: colors.slice(0, Object.keys(dist).length),
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { position: 'bottom' },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.label}: ${ctx.parsed.toFixed(1)}%`
                    }
                }
            }
        }
    });
}

function createPacketSizeHistogram(fp) {
    const ctx = document.getElementById('packetSizeChart').getContext('2d');
    if (packetSizeChart) packetSizeChart.destroy();
    
    const sizes = fp.packet_sizes_sample || [];
    const buckets = [0, 0, 0, 0];
    
    sizes.forEach(s => {
        if (s <= 100) buckets[0]++;
        else if (s <= 500) buckets[1]++;
        else if (s <= 1000) buckets[2]++;
        else buckets[3]++;
    });
    
    packetSizeChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['0-100 bytes', '101-500 bytes', '501-1000 bytes', '1001+ bytes'],
            datasets: [{
                label: 'Packet Count',
                data: buckets,
                backgroundColor: 'rgba(102, 126, 234, 0.7)',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Number of Packets' } },
                x: { title: { display: true, text: 'Packet Size Range' } }
            }
        }
    });
}

function createTrafficTimeline(fp) {
    const ctx = document.getElementById('trafficTimeline').getContext('2d');
    if (trafficTimeline) trafficTimeline.destroy();
    
    const times = fp.inter_arrival_times || [];
    const perSecond = new Array(12).fill(0);
    let cumulative = 0;
    
    times.forEach(t => {
        cumulative += t;
        const sec = Math.floor(cumulative);
        if (sec < 12) perSecond[sec]++;
    });
    
    trafficTimeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: perSecond.map((_, i) => `${i}s`),
            datasets: [{
                label: 'Packets per second',
                data: perSecond,
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Packets' } },
                x: { title: { display: true, text: 'Time (seconds)' } }
            }
        }
    });
}

function displayComparisonResults(data) {
    document.getElementById('compareResults').style.display = 'block';
    
    displayCompareCards(data.fingerprint1, data.fingerprint2);
    displayDiffTable(data.diff);
    createCompareProtocolChart(data.fingerprint1, data.fingerprint2);
    createCompareTimelineChart(data.fingerprint1, data.fingerprint2);
    
    document.getElementById('compareResults').scrollIntoView({ behavior: 'smooth' });
}

function displayCompareCards(fp1, fp2) {
    const card1 = document.getElementById('compareCard1');
    const card2 = document.getElementById('compareCard2');
    
    const createCard = (fp, title) => {
        const behavior = fp.behavior_label || 'Unknown';
        let badgeClass = 'behavior-unknown';
        if (behavior === 'Streaming') badgeClass = 'behavior-streaming';
        else if (behavior === 'Social Media') badgeClass = 'behavior-social';
        else if (behavior === 'Static Content') badgeClass = 'behavior-static';
        else if (behavior === 'API-Heavy') badgeClass = 'behavior-api-heavy';
        
        return `
            <h3>${title}</h3>
            <div class="summary-item">
                <div class="summary-label">URL</div>
                <div class="summary-value small">${escapeHtml(fp.site_url)}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Behavior</div>
                <span class="behavior-badge ${badgeClass}">${behavior}</span>
            </div>
            <div class="summary-item">
                <div class="summary-label">Confidence</div>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${(fp.confidence || 0) * 100}%"></div>
                </div>
                <div class="confidence-text">${((fp.confidence || 0) * 100).toFixed(0)}%</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Total Packets</div>
                <div class="summary-value">${(fp.total_packets || 0).toLocaleString()}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Total Data</div>
                <div class="summary-value">${formatBytes(fp.total_bytes || 0)}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Unique IPs</div>
                <div class="summary-value">${fp.unique_ips || 0}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Mean Packet Size</div>
                <div class="summary-value">${(fp.mean_packet_size || 0).toFixed(0)} bytes</div>
            </div>
            ${fp.classification_characteristics ? `
            <div class="characteristics">
                <h4>Characteristics:</h4>
                ${fp.classification_characteristics.slice(0, 3).map(c => `<div class="characteristic-item">${escapeHtml(c)}</div>`).join('')}
            </div>
            ` : ''}
        `;
    };
    
    card1.innerHTML = createCard(fp1, 'Website 1');
    card2.innerHTML = createCard(fp2, 'Website 2');
}

function displayDiffTable(diff) {
    const container = document.getElementById('diffContent');
    
    if (!diff) {
        container.innerHTML = '<p>No comparison data available</p>';
        return;
    }
    
    container.innerHTML = `
        <table class="diff-table">
            <thead>
                <tr><th>Metric</th><th>Website 1</th><th>Website 2</th><th>Difference</th></tr>
            </thead>
            <tbody>
                <tr>
                    <td class="metric-name">Total Packets</td>
                    <td>${(diff.total_packets?.site1 || 0).toLocaleString()}</td>
                    <td>${(diff.total_packets?.site2 || 0).toLocaleString()}</td>
                    <td>${Math.abs(diff.total_packets?.difference || 0).toLocaleString()}</td>
                </tr>
                <tr>
                    <td class="metric-name">Total Data</td>
                    <td>${formatBytes(diff.total_bytes?.site1 || 0)}</td>
                    <td>${formatBytes(diff.total_bytes?.site2 || 0)}</td>
                    <td>${formatBytes(Math.abs(diff.total_bytes?.difference || 0))}</td>
                </tr>
                <tr>
                    <td class="metric-name">Unique IPs</td>
                    <td>${diff.unique_ips?.site1 || 0}</td>
                    <td>${diff.unique_ips?.site2 || 0}</td>
                    <td>${Math.abs(diff.unique_ips?.difference || 0)}</td>
                </tr>
                <tr>
                    <td class="metric-name">Mean Packet Size</td>
                    <td>${(diff.mean_packet_size?.site1 || 0).toFixed(0)} bytes</td>
                    <td>${(diff.mean_packet_size?.site2 || 0).toFixed(0)} bytes</td>
                    <td>${Math.abs(diff.mean_packet_size?.difference || 0).toFixed(0)} bytes</td>
                </tr>
                <tr>
                    <td class="metric-name">Behavior</td>
                    <td><strong>${diff.behavior_label?.site1 || 'Unknown'}</strong></td>
                    <td><strong>${diff.behavior_label?.site2 || 'Unknown'}</strong></td>
                    <td>${diff.behavior_label?.match ? 'Same' : 'Different'}</td>
                </tr>
            </tbody>
        </table>
    `;
}

function createCompareProtocolChart(fp1, fp2) {
    const ctx = document.getElementById('compareProtocolChart').getContext('2d');
    if (compareProtocolChart) compareProtocolChart.destroy();
    
    const allProtos = [...new Set([
        ...Object.keys(fp1.protocol_distribution || {}),
        ...Object.keys(fp2.protocol_distribution || {})
    ])];
    
    compareProtocolChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: allProtos,
            datasets: [
                {
                    label: fp1.site_url.substring(0, 40),
                    data: allProtos.map(p => (fp1.protocol_distribution || {})[p] || 0),
                    backgroundColor: 'rgba(102, 126, 234, 0.7)'
                },
                {
                    label: fp2.site_url.substring(0, 40),
                    data: allProtos.map(p => (fp2.protocol_distribution || {})[p] || 0),
                    backgroundColor: 'rgba(245, 87, 108, 0.7)'
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, max: 100, title: { display: true, text: 'Percentage (%)' } }
            }
        }
    });
}

function createCompareTimelineChart(fp1, fp2) {
    const ctx = document.getElementById('compareTimelineChart').getContext('2d');
    if (compareTimelineChart) compareTimelineChart.destroy();
    
    const times1 = fp1.inter_arrival_times || [];
    const times2 = fp2.inter_arrival_times || [];
    
    const pps1 = new Array(12).fill(0);
    const pps2 = new Array(12).fill(0);
    
    let cum1 = 0, cum2 = 0;
    times1.forEach(t => { cum1 += t; const sec = Math.floor(cum1); if (sec < 12) pps1[sec]++; });
    times2.forEach(t => { cum2 += t; const sec = Math.floor(cum2); if (sec < 12) pps2[sec]++; });
    
    compareTimelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: pps1.map((_, i) => `${i}s`),
            datasets: [
                {
                    label: fp1.site_url.substring(0, 40),
                    data: pps1,
                    borderColor: '#667eea',
                    borderWidth: 2,
                    fill: false,
                    tension: 0.3
                },
                {
                    label: fp2.site_url.substring(0, 40),
                    data: pps2,
                    borderColor: '#f5576c',
                    borderWidth: 2,
                    fill: false,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Packets per second' } },
                x: { title: { display: true, text: 'Time (seconds)' } }
            }
        }
    });
}

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showLoading(show, msg) {
    const div = document.getElementById('loading');
    div.style.display = show ? 'block' : 'none';
    if (msg) document.getElementById('loadingMessage').textContent = msg;
}

function showError(msg) {
    const errDiv = document.getElementById('error');
    errDiv.innerHTML = msg;
    errDiv.style.display = 'block';
    errDiv.scrollIntoView({ behavior: 'smooth' });
    setTimeout(() => {
        errDiv.style.display = 'none';
    }, 8000);
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const modeBtns = document.querySelectorAll('.mode-btn');
    modeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            modeBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            switchMode(btn.getAttribute('data-mode'));
        });
    });
    
    document.getElementById('analyzeBtn').addEventListener('click', analyzeSingle);
    document.getElementById('compareBtn').addEventListener('click', analyzeCompare);
    
    document.getElementById('urlInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeSingle();
    });
    document.getElementById('urlInput1').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') document.getElementById('urlInput2').focus();
    });
    document.getElementById('urlInput2').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeCompare();
    });
    
    document.querySelectorAll('[data-example]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.getElementById('urlInput').value = btn.getAttribute('data-example');
            hideInlineError('urlError');
        });
    });
    
    ['urlInput', 'urlInput1', 'urlInput2'].forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('input', () => {
                const errorId = id === 'urlInput' ? 'urlError' : (id + 'Error');
                hideInlineError(errorId);
            });
        }
    });
});