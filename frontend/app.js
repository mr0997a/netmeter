/**
 * NetMeter — Subnet Data Usage Monitor Application Logic
 */

// Application State
const state = {
    devices: [],
    totals: {},
    liveBandwidth: { in_kb: 0, out_kb: 0, total_kb: 0 },
    system: {},
    searchQuery: '',
    currentFilter: 'all',
    currentSort: 'total_bytes_desc',
    wsConnected: false,
    selectedDeviceIp: null,
    // Live chart buffer: 60 data points (1 per second)
    chartPoints: Array.from({ length: 60 }, () => ({ in_kb: 0, out_kb: 0 }))
};

// DOM References
const elements = {
    subnetText: document.getElementById('subnetText'),
    engineMode: document.getElementById('engineMode'),
    engineDot: document.getElementById('engineDot'),
    toggleSimBtn: document.getElementById('toggleSimBtn'),
    wsStatus: document.getElementById('wsStatus'),
    wsDot: document.getElementById('wsDot'),

    totalDownloadVal: document.getElementById('totalDownloadVal'),
    totalDownloadUnit: document.getElementById('totalDownloadUnit'),
    totalDownloadSub: document.getElementById('totalDownloadSub'),
    kpiDownBar: document.getElementById('kpiDownBar'),

    totalUploadVal: document.getElementById('totalUploadVal'),
    totalUploadUnit: document.getElementById('totalUploadUnit'),
    totalUploadSub: document.getElementById('totalUploadSub'),
    kpiUpBar: document.getElementById('kpiUpBar'),

    liveThroughputVal: document.getElementById('liveThroughputVal'),
    liveThroughputUnit: document.getElementById('liveThroughputUnit'),
    liveDownSpeed: document.getElementById('liveDownSpeed'),
    liveUpSpeed: document.getElementById('liveUpSpeed'),

    activeDevCount: document.getElementById('activeDevCount'),
    totalDevCount: document.getElementById('totalDevCount'),

    liveChart: document.getElementById('liveChart'),
    deviceSearch: document.getElementById('deviceSearch'),
    filterBtns: document.querySelectorAll('.filter-btn'),
    countFilterAll: document.getElementById('countFilterAll'),
    countFilterActive: document.getElementById('countFilterActive'),
    sortSelect: document.getElementById('sortSelect'),

    deviceTableBody: document.getElementById('deviceTableBody'),
    emptyState: document.getElementById('emptyState'),

    // Modals
    deviceModal: document.getElementById('deviceModal'),
    closeModalBtn: document.getElementById('closeModalBtn'),
    modalDeviceName: document.getElementById('modalDeviceName'),
    modalDeviceIP: document.getElementById('modalDeviceIP'),
    modalNicknameInput: document.getElementById('modalNicknameInput'),
    modalSaveNameBtn: document.getElementById('modalSaveNameBtn'),
    modalMac: document.getElementById('modalMac'),
    modalVendor: document.getElementById('modalVendor'),
    modalHostname: document.getElementById('modalHostname'),
    modalFirstSeen: document.getElementById('modalFirstSeen'),
    modalProtocolList: document.getElementById('modalProtocolList'),
    modalUsageIn: document.getElementById('modalUsageIn'),
    modalUsageOut: document.getElementById('modalUsageOut'),
    modalUsageSum: document.getElementById('modalUsageSum'),

    inlineRenameModal: document.getElementById('inlineRenameModal'),
    closeInlineRenameBtn: document.getElementById('closeInlineRenameBtn'),
    inlineRenameIP: document.getElementById('inlineRenameIP'),
    inlineRenameInput: document.getElementById('inlineRenameInput'),
    saveInlineRenameBtn: document.getElementById('saveInlineRenameBtn'),

    // AirFiber Scan & Add
    scanAirFiberBtn: document.getElementById('scanAirFiberBtn'),
    addDeviceBtn: document.getElementById('addDeviceBtn'),
    addDeviceModal: document.getElementById('addDeviceModal'),
    closeAddDeviceBtn: document.getElementById('closeAddDeviceBtn'),
    newDeviceIP: document.getElementById('newDeviceIP'),
    newDeviceName: document.getElementById('newDeviceName'),
    newDeviceVendor: document.getElementById('newDeviceVendor'),
    saveNewDeviceBtn: document.getElementById('saveNewDeviceBtn'),

    toastContainer: document.getElementById('toastContainer')
};

// Canvas context
const ctx = elements.liveChart.getContext('2d');

/**
 * Format bytes into human friendly string (Bytes, KB, MB, GB)
 */
function formatBytes(bytes) {
    if (bytes === 0 || !bytes) return { val: '0.00', unit: 'MB' };
    const gb = bytes / (1024 * 1024 * 1024);
    if (gb >= 1.0) {
        return { val: gb.toFixed(2), unit: 'GB' };
    }
    const mb = bytes / (1024 * 1024);
    return { val: mb.toFixed(2), unit: 'MB' };
}

function formatSpeed(kbVal) {
    if (!kbVal || kbVal < 0) return { val: '0.0', unit: 'KB/s' };
    if (kbVal >= 1024) {
        return { val: (kbVal / 1024).toFixed(2), unit: 'MB/s' };
    }
    return { val: kbVal.toFixed(1), unit: 'KB/s' };
}

/**
 * Show temporary toast message
 */
function showToast(message, icon = 'ℹ️') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    elements.toastContainer.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 300);
    }, 3200);
}

/**
 * WebSocket Connection & Live Stream
 */
let ws = null;
function initWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws/live`;

    try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            state.wsConnected = true;
            elements.wsDot.className = 'pulse-indicator pulse-green';
            elements.wsStatus.textContent = 'Live Stream (Active)';
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleLiveUpdate(data);
            } catch (err) {
                console.error("WS Parse error:", err);
            }
        };

        ws.onclose = () => {
            state.wsConnected = false;
            elements.wsDot.className = 'pulse-indicator';
            elements.wsStatus.textContent = 'Reconnecting...';
            setTimeout(initWebSocket, 2000);
        };

        ws.onerror = () => {
            if (ws) ws.close();
        };
    } catch (e) {
        console.warn("WebSocket not available, falling back to HTTP polling", e);
        startHttpPolling();
    }
}

/**
 * HTTP Fallback Polling
 */
function startHttpPolling() {
    setInterval(async () => {
        if (!state.wsConnected) {
            try {
                const [devRes, sumRes] = await Promise.all([
                    fetch('/api/devices').then(r => r.json()),
                    fetch('/api/traffic/summary').then(r => r.json())
                ]);
                handleLiveUpdate({
                    devices: devRes.devices,
                    totals: sumRes.totals,
                    live_bandwidth: {
                        in_kb: sumRes.live_speed.rate_in_kb,
                        out_kb: sumRes.live_speed.rate_out_kb,
                        total_kb: sumRes.live_speed.rate_total_kb
                    },
                    status: sumRes.system
                });
            } catch (err) {
                console.error("Polling error:", err);
            }
        }
    }, 1500);
}

/**
 * Process new telemetry snapshot
 */
function handleLiveUpdate(data) {
    if (data.devices) state.devices = data.devices;
    if (data.totals) state.totals = data.totals;
    if (data.live_bandwidth) state.liveBandwidth = data.live_bandwidth;
    if (data.status) state.system = data.status;

    // Push to chart buffer
    state.chartPoints.shift();
    state.chartPoints.push({
        in_kb: state.liveBandwidth.in_kb || 0,
        out_kb: state.liveBandwidth.out_kb || 0
    });

    renderUI();
}

/**
 * Update UI Panels
 */
function renderUI() {
    // 1. System & Engine bar
    if (state.system.subnet) {
        elements.subnetText.textContent = `${state.system.subnet} (${state.system.local_ip})`;
    }

    if (state.system.mode) {
        if (state.system.simulation_enabled || state.system.mode === 'simulation') {
            elements.engineMode.textContent = 'Mode: ⚡ Synthetic Demo Simulation';
            elements.engineDot.className = 'pulse-indicator';
            elements.engineDot.style.background = '#f59e0b';
            elements.toggleSimBtn.textContent = 'Switch to Live Capture';
        } else if (state.system.mode === 'raw_socket') {
            elements.engineMode.textContent = 'Mode: ● Windows Promiscuous Raw Socket';
            elements.engineDot.className = 'pulse-indicator pulse-green';
            elements.toggleSimBtn.textContent = '⚡ Enable Demo Mode';
        } else {
            elements.engineMode.textContent = `Mode: ${state.system.mode.toUpperCase()}`;
            elements.engineDot.className = 'pulse-indicator pulse-green';
        }
    }

    // 2. KPI Cards
    const downFmt = formatBytes(state.totals.total_bytes_in);
    elements.totalDownloadVal.textContent = downFmt.val;
    elements.totalDownloadUnit.textContent = downFmt.unit;
    elements.totalDownloadSub.textContent = `${(state.totals.total_packets || 0).toLocaleString()} Total Subnet Packets`;

    const upFmt = formatBytes(state.totals.total_bytes_out);
    elements.totalUploadVal.textContent = upFmt.val;
    elements.totalUploadUnit.textContent = upFmt.unit;
    elements.totalUploadSub.textContent = `Monitored on interface`;

    // Dynamic bar ratios
    const sumBytes = (state.totals.total_bytes_in || 1) + (state.totals.total_bytes_out || 1);
    const downPct = Math.round(((state.totals.total_bytes_in || 1) / sumBytes) * 100);
    elements.kpiDownBar.style.width = `${Math.max(10, downPct)}%`;
    elements.kpiUpBar.style.width = `${Math.max(10, 100 - downPct)}%`;

    // Live Speed
    const spd = formatSpeed(state.liveBandwidth.total_kb);
    elements.liveThroughputVal.textContent = spd.val;
    elements.liveThroughputUnit.textContent = spd.unit;
    elements.liveDownSpeed.textContent = (state.liveBandwidth.in_kb || 0).toFixed(1);
    elements.liveUpSpeed.textContent = (state.liveBandwidth.out_kb || 0).toFixed(1);

    // Device counts
    const activeCount = state.devices.filter(d => d.is_active).length;
    elements.activeDevCount.textContent = activeCount;
    elements.totalDevCount.textContent = state.devices.length;
    elements.countFilterAll.textContent = state.devices.length;
    elements.countFilterActive.textContent = activeCount;

    // 3. Render Table
    renderTable();

    // 4. Render Live Chart
    renderChart();
}

/**
 * Filter & Sort Devices
 */
function getFilteredDevices() {
    let list = [...state.devices];

    // Filter by search query
    if (state.searchQuery.trim()) {
        const q = state.searchQuery.toLowerCase();
        list = list.filter(d =>
            d.ip.toLowerCase().includes(q) ||
            (d.custom_name && d.custom_name.toLowerCase().includes(q)) ||
            (d.hostname && d.hostname.toLowerCase().includes(q)) ||
            (d.mac && d.mac.toLowerCase().includes(q)) ||
            (d.vendor && d.vendor.toLowerCase().includes(q))
        );
    }

    // Filter by tab
    if (state.currentFilter === 'active') {
        list = list.filter(d => d.is_active);
    } else if (state.currentFilter === 'heavy') {
        list = list.filter(d => d.total_mb > 50);
    }

    // Sorting
    list.sort((a, b) => {
        switch (state.currentSort) {
            case 'total_bytes_desc':
                return b.total_bytes - a.total_bytes;
            case 'speed_desc':
                return (b.total_rate_kb || 0) - (a.total_rate_kb || 0);
            case 'bytes_in_desc':
                return b.bytes_in - a.bytes_in;
            case 'bytes_out_desc':
                return b.bytes_out - a.bytes_out;
            case 'ip_asc':
                return a.ip.localeCompare(b.ip, undefined, { numeric: true });
            default:
                return b.total_bytes - a.total_bytes;
        }
    });

    return list;
}

/**
 * Render Device Table Rows
 */
function renderTable() {
    const devices = getFilteredDevices();

    if (devices.length === 0) {
        elements.deviceTableBody.innerHTML = '';
        elements.emptyState.style.display = 'block';
        return;
    }
    elements.emptyState.style.display = 'none';

    // Find max usage for comparative micro-bars
    const maxUsage = Math.max(...devices.map(d => d.total_bytes), 1);

    const rowsHtml = devices.map(dev => {
        const isOnline = dev.is_active;
        const statusDot = isOnline 
            ? '<span class="status-indicator-dot status-online" title="Active (communicating in last 2 mins)"></span>'
            : '<span class="status-indicator-dot status-offline" title="Idle / Inactive"></span>';

        const downFmt = formatBytes(dev.bytes_in);
        const upFmt = formatBytes(dev.bytes_out);
        const totalFmt = formatBytes(dev.total_bytes);

        const inBarPct = Math.min(100, Math.round((dev.bytes_in / maxUsage) * 100));
        const outBarPct = Math.min(100, Math.round((dev.bytes_out / maxUsage) * 100));

        const rateIn = (dev.rate_in_kb || 0) > 1024 
            ? `${(dev.rate_in_kb / 1024).toFixed(1)} MB/s` 
            : `${(dev.rate_in_kb || 0).toFixed(0)} KB/s`;
        const rateOut = (dev.rate_out_kb || 0) > 1024 
            ? `${(dev.rate_out_kb / 1024).toFixed(1)} MB/s` 
            : `${(dev.rate_out_kb || 0).toFixed(0)} KB/s`;

        return `
            <tr data-ip="${dev.ip}">
                <td class="col-status">${statusDot}</td>
                <td class="col-device">
                    <div class="device-name-cell">
                        <div class="device-title-row">
                            <span class="device-name-text">${escapeHtml(dev.display_name)}</span>
                            <button class="btn-rename-trigger" title="Rename this device" onclick="openInlineRename('${dev.ip}', '${escapeQuotes(dev.custom_name || '')}')">✏️</button>
                        </div>
                        <span class="device-host-sub">${escapeHtml(dev.hostname || dev.vendor || 'Local Device')}</span>
                    </div>
                </td>
                <td class="col-ip">
                    <span class="ip-badge">${dev.ip}</span>
                </td>
                <td class="col-mac">
                    <div class="mac-cell">
                        <span class="mac-text">${dev.mac}</span>
                        <span class="vendor-badge">${escapeHtml(dev.vendor)}</span>
                    </div>
                </td>
                <td class="col-speed">
                    <div class="speed-pill-cell">
                        <span class="speed-in-rate">↓ ${rateIn}</span>
                        <span class="speed-out-rate">↑ ${rateOut}</span>
                    </div>
                </td>
                <td class="col-usage">
                    <div class="usage-cell">
                        <span class="usage-text-val">${downFmt.val} ${downFmt.unit}</span>
                        <div class="usage-bar-mini">
                            <div class="usage-bar-fill fill-cyan" style="width: ${inBarPct}%;"></div>
                        </div>
                    </div>
                </td>
                <td class="col-usage">
                    <div class="usage-cell">
                        <span class="usage-text-val">${upFmt.val} ${upFmt.unit}</span>
                        <div class="usage-bar-mini">
                            <div class="usage-bar-fill fill-emerald" style="width: ${outBarPct}%;"></div>
                        </div>
                    </div>
                </td>
                <td class="col-total">
                    <div class="total-highlight">${totalFmt.val} ${totalFmt.unit}</div>
                    <div class="total-packets-sub">${(dev.total_packets || 0).toLocaleString()} pkts</div>
                </td>
                <td class="col-actions">
                    <button class="action-btn-inspect" onclick="openDeviceModal('${dev.ip}')">Inspect</button>
                </td>
            </tr>
        `;
    }).join('');

    elements.deviceTableBody.innerHTML = rowsHtml;
}

/**
 * Real-time Canvas Area Chart
 */
function renderChart() {
    const canvas = elements.liveChart;
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;

    // Adjust canvas resolution for crisp lines on Retina/HiDPI
    if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
    }

    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const points = state.chartPoints;
    const count = points.length;

    // Find peak speed for dynamic Y-axis scaling
    let maxVal = 50; // Minimum 50 KB/s ceiling
    for (const p of points) {
        if (p.in_kb > maxVal) maxVal = p.in_kb;
        if (p.out_kb > maxVal) maxVal = p.out_kb;
    }
    maxVal = maxVal * 1.25; // headroom

    // Draw horizontal grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
        const y = height - (height * (i / 4));
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();

        // Label
        ctx.fillStyle = 'rgba(255, 255, 255, 0.25)';
        ctx.font = '10px JetBrains Mono';
        const labelSpeed = (maxVal * (i / 4)).toFixed(0) + ' KB/s';
        ctx.fillText(labelSpeed, 8, y - 4);
    }

    const stepX = width / (count - 1);

    // 1. Draw Download Stream (Cyan Area & Line)
    drawStream(points.map(p => p.in_kb), maxVal, width, height, stepX, '#00f2fe', 'rgba(0, 242, 254, 0.18)');

    // 2. Draw Upload Stream (Emerald Area & Line)
    drawStream(points.map(p => p.out_kb), maxVal, width, height, stepX, '#10b981', 'rgba(16, 185, 129, 0.18)');

    ctx.restore();
}

function drawStream(values, maxVal, width, height, stepX, strokeColor, fillColor) {
    if (values.length < 2) return;

    ctx.beginPath();
    ctx.moveTo(0, height);

    const coords = [];
    for (let i = 0; i < values.length; i++) {
        const x = i * stepX;
        const normalized = Math.min(1, values[i] / maxVal);
        const y = height - (normalized * (height - 20)) - 5;
        coords.push({ x, y });
    }

    // Bezier curve through points
    ctx.lineTo(coords[0].x, coords[0].y);
    for (let i = 0; i < coords.length - 1; i++) {
        const xc = (coords[i].x + coords[i + 1].x) / 2;
        const yc = (coords[i].y + coords[i + 1].y) / 2;
        ctx.quadraticCurveTo(coords[i].x, coords[i].y, xc, yc);
    }
    ctx.lineTo(coords[coords.length - 1].x, coords[coords.length - 1].y);

    // Complete polygon for fill
    ctx.lineTo(width, height);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();

    // Stroke line
    ctx.beginPath();
    ctx.moveTo(coords[0].x, coords[0].y);
    for (let i = 0; i < coords.length - 1; i++) {
        const xc = (coords[i].x + coords[i + 1].x) / 2;
        const yc = (coords[i].y + coords[i + 1].y) / 2;
        ctx.quadraticCurveTo(coords[i].x, coords[i].y, xc, yc);
    }
    ctx.lineTo(coords[coords.length - 1].x, coords[coords.length - 1].y);
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.2;
    ctx.stroke();
}

/**
 * Open Detailed Device Modal
 */
window.openDeviceModal = async function(ip) {
    state.selectedDeviceIp = ip;
    try {
        const res = await fetch(`/api/devices/${ip}`);
        if (!res.ok) throw new Error("Could not load device details");
        const dev = await res.json();

        elements.modalDeviceName.textContent = dev.display_name;
        elements.modalDeviceIP.textContent = dev.ip;
        elements.modalNicknameInput.value = dev.custom_name || '';
        elements.modalMac.textContent = dev.mac || 'Unknown';
        elements.modalVendor.textContent = dev.vendor || 'Generic Device';
        elements.modalHostname.textContent = dev.hostname || 'None reported';
        elements.modalFirstSeen.textContent = new Date(dev.first_seen * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        const inFmt = formatBytes(dev.bytes_in);
        const outFmt = formatBytes(dev.bytes_out);
        const totalFmt = formatBytes(dev.total_bytes);
        elements.modalUsageIn.textContent = `${inFmt.val} ${inFmt.unit}`;
        elements.modalUsageOut.textContent = `${outFmt.val} ${outFmt.unit}`;
        elements.modalUsageSum.textContent = `${totalFmt.val} ${totalFmt.unit}`;

        // Render protocol badges
        const protos = dev.protocols || {};
        const protoEntries = Object.entries(protos);
        if (protoEntries.length === 0) {
            elements.modalProtocolList.innerHTML = '<div style="color: var(--text-muted); font-size: 13px;">No protocol data logged yet.</div>';
        } else {
            elements.modalProtocolList.innerHTML = protoEntries.map(([proto, stats]) => {
                const pClass = `proto-${proto.toLowerCase()}` in { 'proto-https': 1, 'proto-http': 1, 'proto-dns': 1, 'proto-udp': 1, 'proto-tcp': 1 }
                    ? `proto-${proto.toLowerCase()}`
                    : 'proto-other';
                const pFmt = formatBytes(stats.bytes);
                return `
                    <div class="protocol-row">
                        <span class="proto-badge ${pClass}">${proto}</span>
                        <span class="proto-bytes">${pFmt.val} ${pFmt.unit} (${stats.packets.toLocaleString()} pkts)</span>
                    </div>
                `;
            }).join('');
        }

        elements.deviceModal.classList.add('open');
    } catch (err) {
        showToast(`Failed to load device detail: ${err.message}`, '❌');
    }
};

/**
 * Open Inline Rename Modal
 */
window.openInlineRename = function(ip, currentName) {
    state.selectedDeviceIp = ip;
    elements.inlineRenameIP.textContent = ip;
    elements.inlineRenameInput.value = currentName || '';
    elements.inlineRenameModal.classList.add('open');
    setTimeout(() => elements.inlineRenameInput.focus(), 50);
};

/**
 * Save Device Custom Name via API
 */
async function saveDeviceName(ip, newName) {
    try {
        const res = await fetch(`/api/devices/${ip}/rename`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ custom_name: newName })
        });
        if (!res.ok) throw new Error("Server error saving nickname");

        // Update local state
        const target = state.devices.find(d => d.ip === ip);
        if (target) {
            target.custom_name = newName;
            target.display_name = newName || target.hostname || `Device (${ip.split('.').pop()})`;
        }

        renderTable();
        showToast(`Device ${ip} renamed to "${newName || 'Default'}"`, '✅');
    } catch (err) {
        showToast(`Error renaming device: ${err.message}`, '❌');
    }
}

// Event Listeners Setup
function initEventListeners() {
    // Search
    elements.deviceSearch.addEventListener('input', (e) => {
        state.searchQuery = e.target.value;
        renderTable();
    });

    // Filter Chips
    elements.filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            elements.filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.currentFilter = btn.getAttribute('data-filter');
            renderTable();
        });
    });

    // Sort Dropdown
    elements.sortSelect.addEventListener('change', (e) => {
        state.currentSort = e.target.value;
        renderTable();
    });

    // Toggle Simulation Mode
    elements.toggleSimBtn.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/system/toggle-simulation', { method: 'POST' });
            const data = await res.json();
            showToast(data.simulation_active ? "Simulation Mode Enabled" : "Live Packet Sniffer Active", "⚡");
        } catch (e) {
            showToast("Failed to toggle mode", "❌");
        }
    });

    // Modal Close
    elements.closeModalBtn.addEventListener('click', () => {
        elements.deviceModal.classList.remove('open');
    });

    elements.closeInlineRenameBtn.addEventListener('click', () => {
        elements.inlineRenameModal.classList.remove('open');
    });

    // Save from Detail Modal
    elements.modalSaveNameBtn.addEventListener('click', async () => {
        if (!state.selectedDeviceIp) return;
        const name = elements.modalNicknameInput.value.trim();
        await saveDeviceName(state.selectedDeviceIp, name);
        elements.modalDeviceName.textContent = name || state.selectedDeviceIp;
        elements.deviceModal.classList.remove('open');
    });

    // Save from Quick Rename Modal
    elements.saveInlineRenameBtn.addEventListener('click', async () => {
        if (!state.selectedDeviceIp) return;
        const name = elements.inlineRenameInput.value.trim();
        await saveDeviceName(state.selectedDeviceIp, name);
        elements.inlineRenameModal.classList.remove('open');
    });

    // Close modal on outside click
    window.addEventListener('click', (e) => {
        if (e.target === elements.deviceModal) elements.deviceModal.classList.remove('open');
        if (e.target === elements.inlineRenameModal) elements.inlineRenameModal.classList.remove('open');
        if (e.target === elements.addDeviceModal) elements.addDeviceModal.classList.remove('open');
    });

    // AirFiber Scan Subnet Button
    elements.scanAirFiberBtn.addEventListener('click', async () => {
        elements.scanAirFiberBtn.disabled = true;
        elements.scanAirFiberBtn.innerHTML = '⏳ Scanning Subnet...';
        showToast('Scanning 192.168.1.x subnet for all connected AirFiber devices...', '🔍');

        try {
            const res = await fetch('/api/discovery/scan', { method: 'POST' });
            const data = await res.json();
            showToast(`Scan complete! Discovered ${data.devices_found} AirFiber devices.`, '✅');
            // Refresh device list immediately
            const devRes = await fetch('/api/devices');
            const devData = await devRes.json();
            state.devices = devData.devices;
            renderUI();
        } catch (err) {
            showToast(`Subnet scan failed: ${err.message}`, '❌');
        } finally {
            elements.scanAirFiberBtn.disabled = false;
            elements.scanAirFiberBtn.innerHTML = '🔍 Scan AirFiber Devices';
        }
    });

    // Add Device Modal Handlers
    elements.addDeviceBtn.addEventListener('click', () => {
        elements.newDeviceIP.value = '';
        elements.newDeviceName.value = '';
        elements.newDeviceVendor.value = '';
        elements.addDeviceModal.classList.add('open');
        setTimeout(() => elements.newDeviceIP.focus(), 50);
    });

    elements.closeAddDeviceBtn.addEventListener('click', () => {
        elements.addDeviceModal.classList.remove('open');
    });

    elements.saveNewDeviceBtn.addEventListener('click', async () => {
        const ip = elements.newDeviceIP.value.trim();
        const name = elements.newDeviceName.value.trim();
        const vendor = elements.newDeviceVendor.value.trim();

        if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
            showToast('Please enter a valid IPv4 address (e.g. 192.168.1.55)', '⚠️');
            elements.newDeviceIP.focus();
            return;
        }

        try {
            const res = await fetch('/api/devices', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: ip,
                    custom_name: name || undefined,
                    vendor: vendor || 'AirFiber Device'
                })
            });
            if (!res.ok) throw new Error('Failed to register device');

            elements.addDeviceModal.classList.remove('open');
            showToast(`Registered device ${ip} (${name || 'AirFiber Client'})`, '✅');

            // Refresh device list
            const devRes = await fetch('/api/devices');
            const devData = await devRes.json();
            state.devices = devData.devices;
            renderUI();
        } catch (err) {
            showToast(`Error adding device: ${err.message}`, '❌');
        }
    });

    // Window resize for canvas
    window.addEventListener('resize', renderChart);
}

// Helpers
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function escapeQuotes(str) {
    if (!str) return '';
    return str.replace(/'/g, "\\'");
}

// Initial Boot
document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    initWebSocket();
});
