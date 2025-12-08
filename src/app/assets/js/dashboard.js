// --- Toast System ---
function showToast(message, type = 'warning') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `px-4 py-2 rounded shadow-lg text-xs font-mono flex items-center gap-2 transition-all duration-300 transform translate-y-10 opacity-0 ${type === 'warning' ? 'bg-red-500/90 text-white backdrop-blur border border-red-500/50' : 'bg-green-500/90 text-white backdrop-blur border border-green-500/50'
        }`;
    toast.innerHTML = `<i class="fas ${type === 'warning' ? 'fa-exclamation-triangle' : 'fa-check-circle'}"></i> ${message}`;
    container.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
        toast.classList.remove('translate-y-10', 'opacity-0');
    });

    // Remove after 3s
    setTimeout(() => {
        toast.classList.add('translate-y-10', 'opacity-0');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// --- Authentication & Secure Logs ---
let SYSTEM_LOGS = [];

function generateLogs() {
    const logs = [];
    const sources = ['System', 'Firewall', 'IDS', 'Auth', 'Network', 'Kernel', 'Application'];
    const levels = ['INFO', 'WARN', 'CRIT'];
    const messages = [
        'Backup completed successfully',
        'Port 22 access attempt blocked',
        'Signature match: SQL Injection',
        'User login successful: admin',
        'High latency detected on uplink',
        'Package update installed',
        'Connection reset by peer'
    ];

    const now = new Date();
    for (let i = 0; i < 50; i++) {
        const time = new Date(now.getTime() - Math.floor(Math.random() * 48 * 60 * 60 * 1000)); // Last 48h
        const level = levels[Math.floor(Math.random() * levels.length)];
        const source = sources[Math.floor(Math.random() * sources.length)];
        const msg = messages[Math.floor(Math.random() * messages.length)];

        logs.push({
            time: time.toISOString().replace('T', ' ').split('.')[0],
            timestamp: time,
            level,
            source,
            msg
        });
    }
    // Sort by new to old
    logs.sort((a, b) => b.timestamp - a.timestamp);
    SYSTEM_LOGS = logs;
}

// Generate immediately
generateLogs();

function handleLogin(e) {
    e.preventDefault();
    const password = document.getElementById('login-password').value;
    const overlay = document.getElementById('login-overlay');
    const content = document.getElementById('app-content');

    // Hardcoded demo password
    if (password === 'admin' || password === '1234') {
        // Success
        overlay.classList.add('opacity-0', 'pointer-events-none');
        content.classList.remove('opacity-0', 'blur-xl', 'pointer-events-none');

        // Render Logs
        renderSecureLogs();

        showToast('Authentication Successful', 'success');
    } else {
        // Failure
        showToast('Access Denied: Invalid Credentials');
        document.getElementById('login-password').value = '';
        document.getElementById('login-password').focus();

        // Shake animation
        const panel = overlay.querySelector('.panel');
        panel.classList.add('animate-pulse'); // Simple shake replacement
        setTimeout(() => panel.classList.remove('animate-pulse'), 500);
    }
}

async function handleBiometricLogin() {
    if (!window.PublicKeyCredential) {
        showToast('Biometrics not supported on this device');
        return;
    }

    // Check for secure context (required for WebAuthn)
    if (!window.isSecureContext) {
        showToast('Biometrics require HTTPS or Localhost');
        // Fallback for demo/dev if needed, but strictly WebAuthn fails.
        // We'll proceed to try, but it will likely throw.
    }

    try {
        showToast('Place finger on sensor...', 'info');

        // We use 'create' to force a user verification (biometric check) 
        // since we don't have a registered credential ID to 'get'.
        // This effectively asks the OS to "Verify it's you to create a key".
        const publicKey = {
            challenge: new Uint8Array(32), // Random challenge
            rp: { name: "Sentinel Dashboard" },
            user: {
                id: new Uint8Array(16),
                name: "admin",
                displayName: "Administrator"
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: {
                authenticatorAttachment: "platform", // Prefer built-in (TouchID, Windows Hello)
                userVerification: "required" // Force biometric/pin
            },
            timeout: 60000
        };

        // Trigger the browser/OS dialog
        await navigator.credentials.create({ publicKey });

        // If we get here, the user passed the biometric check
        const overlay = document.getElementById('login-overlay');
        const content = document.getElementById('app-content');

        overlay.classList.add('opacity-0', 'pointer-events-none');
        content.classList.remove('opacity-0', 'blur-xl', 'pointer-events-none');

        renderSecureLogs();
        showToast('Biometric Verified', 'success');

    } catch (err) {
        console.error(err);
        if (err.name === 'NotAllowedError') {
            showToast('Biometric Request Cancelled');
        } else {
            showToast('Biometric Auth Failed: ' + err.message);
        }
    }
}

function lockSession() {
    const overlay = document.getElementById('login-overlay');
    const content = document.getElementById('app-content');

    overlay.classList.remove('opacity-0', 'pointer-events-none');
    content.classList.add('opacity-0', 'blur-xl', 'pointer-events-none');

    document.getElementById('login-password').value = '';
    showToast('Session Locked');
}

function renderSecureLogs() {
    const tbody = document.getElementById('logs-body');
    tbody.innerHTML = ''; // Clear existing (if any)

    const timeFilter = document.getElementById('log-filter-time')?.value || 'all';
    const levelFilter = document.getElementById('log-filter-level')?.value || 'all';
    const now = new Date();

    SYSTEM_LOGS.forEach(log => {
        // Filter Level
        if (levelFilter !== 'all' && log.level !== levelFilter) return;

        // Filter Time
        if (timeFilter === '1h') {
            if (now - log.timestamp > 60 * 60 * 1000) return;
        } else if (timeFilter === '24h') {
            if (now - log.timestamp > 24 * 60 * 60 * 1000) return;
        }

        const tr = document.createElement('tr');
        tr.className = 'table-row transition-colors';

        let levelClass = 'font-bold';
        if (log.level === 'WARN') levelClass += ' text-yellow-500';
        if (log.level === 'CRIT') levelClass += ' text-red-500';

        tr.innerHTML = `
            <td class="p-4 opacity-70">${log.time}</td>
            <td class="p-4 ${levelClass}">${log.level}</td>
            <td class="p-4">${log.source}</td>
            <td class="p-4 opacity-80">${log.msg}</td>
            <td class="p-4 text-right"><button class="hover:underline">Details</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// --- Logs Download Logic ---
function toggleLogsDownloadMenu() {
    const menu = document.getElementById('logs-download-menu');
    menu.classList.toggle('hidden');
}

// Close menu when clicking outside
document.addEventListener('click', (e) => {
    const menu = document.getElementById('logs-download-menu');
    if (menu) {
        const btn = menu.previousElementSibling; // The toggle button
        if (!menu.classList.contains('hidden') && !menu.contains(e.target) && !btn.contains(e.target)) {
            menu.classList.add('hidden');
        }
    }
});

// Helper to get currently visible logs based on filters
function getFilteredLogs() {
    const timeFilter = document.getElementById('log-filter-time')?.value || 'all';
    const levelFilter = document.getElementById('log-filter-level')?.value || 'all';
    const now = new Date();

    return SYSTEM_LOGS.filter(log => {
        // Filter Level
        if (levelFilter !== 'all' && log.level !== levelFilter) return false;

        // Filter Time
        if (timeFilter === '1h') {
            if (now - log.timestamp > 60 * 60 * 1000) return false;
        } else if (timeFilter === '24h') {
            if (now - log.timestamp > 24 * 60 * 60 * 1000) return false;
        }
        return true;
    });
}

function downloadLogsCSV() {
    const visibleLogs = getFilteredLogs();

    if (!visibleLogs || visibleLogs.length === 0) {
        showToast('No visible logs to download', 'warning');
        return;
    }

    const headers = ['Timestamp', 'Level', 'Source', 'Message'];
    const rows = visibleLogs.map(log => [
        log.time,
        log.level,
        log.source,
        `"${log.msg.replace(/"/g, '""')}"` // Escape quotes
    ]);

    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `system_logs_${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    toggleLogsDownloadMenu();
    showToast('Logs downloaded as CSV', 'success');
}

async function downloadLogsPDF() {
    const visibleLogs = getFilteredLogs();

    if (!visibleLogs || visibleLogs.length === 0) {
        showToast('No visible logs to download', 'warning');
        return;
    }

    showToast('Generating PDF...', 'info');

    // Reuse the existing report generation endpoint
    // We construct a single-section report
    const headers = ["Timestamp", "Severity", "Source", "Message"];
    const rows = visibleLogs.map(log => [
        log.time,
        log.level,
        log.source,
        log.msg
    ]);

    const reportData = [{
        title: "System Logs",
        type: "table",
        content: { headers, rows }
    }];

    try {
        const response = await fetch('/api/report/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ sections: reportData })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `system_logs_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            showToast('Logs downloaded as PDF', 'success');
        } else {
            throw new Error('Server returned error');
        }
    } catch (error) {
        console.error("PDF generation failed:", error);
        showToast('Failed to generate PDF', 'error');
    }

    toggleLogsDownloadMenu();
}

// --- 3D Background (Three.js) ---
function init3D() {
    const container = document.getElementById('canvas-container');
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });

    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);

    // Inner Core (Shield)
    const geometry = new THREE.IcosahedronGeometry(8, 2);
    const material = new THREE.MeshBasicMaterial({
        color: 0x4ade80, // Greenish for security
        wireframe: true,
        transparent: true,
        opacity: 0.3 // Increased opacity
    });
    const sphere = new THREE.Mesh(geometry, material);
    scene.add(sphere);

    // Outer Shell (Force Field)
    const outerGeo = new THREE.IcosahedronGeometry(14, 1);
    const outerMat = new THREE.MeshBasicMaterial({
        color: 0x888888,
        wireframe: true,
        transparent: true,
        opacity: 0.15 // Increased opacity
    });
    const outerSphere = new THREE.Mesh(outerGeo, outerMat);
    scene.add(outerSphere);

    // Floating Security Objects (Cubes/Locks)
    const securityGroup = new THREE.Group();
    const secGeo = new THREE.BoxGeometry(0.5, 0.5, 0.5);
    const secMat = new THREE.MeshBasicMaterial({ color: 0x4ade80, wireframe: true });

    for (let i = 0; i < 50; i++) {
        const mesh = new THREE.Mesh(secGeo, secMat);
        mesh.position.set(
            (Math.random() - 0.5) * 40,
            (Math.random() - 0.5) * 40,
            (Math.random() - 0.5) * 20
        );
        mesh.rotation.set(Math.random() * Math.PI, Math.random() * Math.PI, 0);
        securityGroup.add(mesh);
    }
    scene.add(securityGroup);

    // Floating Particles
    const particlesGeom = new THREE.BufferGeometry();
    const particlesCount = 1500; // Increased count
    const posArray = new Float32Array(particlesCount * 3);
    for (let i = 0; i < particlesCount * 3; i++) {
        posArray[i] = (Math.random() - 0.5) * 80;
    }
    particlesGeom.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
    const particlesMat = new THREE.PointsMaterial({
        size: 0.08,
        color: 0x888888,
        transparent: true,
        opacity: 0.6
    });
    const particlesMesh = new THREE.Points(particlesGeom, particlesMat);
    scene.add(particlesMesh);

    camera.position.z = 30;

    // Animation Loop
    function animate() {
        requestAnimationFrame(animate);
        sphere.rotation.x += 0.002;
        sphere.rotation.y += 0.002;

        outerSphere.rotation.x -= 0.001;
        outerSphere.rotation.y -= 0.001;

        particlesMesh.rotation.y += 0.0005;
        securityGroup.rotation.y -= 0.001;
        securityGroup.rotation.x += 0.0005;

        // Theme adaptation
        const isDark = document.documentElement.classList.contains('dark');
        const color = isDark ? 0xffffff : 0x000000;
        const shieldColor = isDark ? 0x4ade80 : 0x16a34a; // Green

        material.color.setHex(shieldColor);
        outerMat.color.setHex(color);
        particlesMat.color.setHex(color);
        secMat.color.setHex(shieldColor);

        renderer.render(scene, camera);
    }
    animate();

    // Resize Handler
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

// --- Charts (Chart.js) ---
function initCharts() {
    Chart.defaults.font.family = 'Inter';
    Chart.defaults.color = '#888888';
    Chart.defaults.scale.grid.color = 'rgba(128, 128, 128, 0.1)';

    // Events Chart (Stacked Area - Realtime)
    const ctxEvents = document.getElementById('eventsChart').getContext('2d');

    // Generate initial data
    const initialDataPoints = 60;
    const labels = [];
    const data1 = [];
    const data2 = [];
    const data3 = [];

    let now = new Date();
    for (let i = 0; i < initialDataPoints; i++) {
        const t = new Date(now.getTime() - (initialDataPoints - i) * 1000);
        labels.push(t.getHours().toString().padStart(2, '0') + ':' + t.getMinutes().toString().padStart(2, '0') + ':' + t.getSeconds().toString().padStart(2, '0'));
        data1.push(Math.floor(Math.random() * 30) + 10);
        data2.push(Math.floor(Math.random() * 20) + 5);
        data3.push(Math.floor(Math.random() * 15) + 5);
    }

    const eventsChart = new Chart(ctxEvents, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Web Server',
                    data: data1,
                    borderColor: document.documentElement.classList.contains('dark') ? '#ffffff' : '#000000',
                    borderWidth: 1.5,
                    backgroundColor: (context) => {
                        const ctx = context.chart.ctx;
                        const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                        const color = document.documentElement.classList.contains('dark') ? '255, 255, 255' : '0, 0, 0';
                        gradient.addColorStop(0, `rgba(${color}, 0.2)`);
                        gradient.addColorStop(1, `rgba(${color}, 0)`);
                        return gradient;
                    },
                    tension: 0.4,
                    pointRadius: 0,
                    fill: true
                },
                {
                    label: 'App Server',
                    data: data2,
                    borderColor: '#8b5cf6', // Purple
                    backgroundColor: 'rgba(139, 92, 246, 0.2)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                },
                {
                    label: 'DB Server',
                    data: data3,
                    borderColor: '#10b981', // Emerald
                    backgroundColor: 'rgba(16, 185, 129, 0.2)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false, // Disable default animation for smooth realtime updates
            plugins: {
                legend: { display: true, position: 'top', align: 'end', labels: { boxWidth: 8, usePointStyle: true } },
                tooltip: { mode: 'index', intersect: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    border: { display: false },
                    ticks: { maxTicksLimit: 6, maxRotation: 0 }
                },
                y: {
                    stacked: true,
                    border: { display: false },
                    min: 0,
                    suggestedMax: 100
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });

    // Real-time Update Loop for Events Chart
    setInterval(() => {
        const now = new Date();
        const timeLabel = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0') + ':' + now.getSeconds().toString().padStart(2, '0');

        // Remove oldest
        eventsChart.data.labels.shift();
        eventsChart.data.datasets.forEach(ds => ds.data.shift());

        // Add newest
        eventsChart.data.labels.push(timeLabel);

        eventsChart.data.datasets.forEach(ds => {
            const last = ds.data[ds.data.length - 1];
            // Random walk
            let change = Math.floor(Math.random() * 10) - 4;
            let newVal = last + change;
            if (newVal < 5) newVal = 5;
            if (newVal > 50) newVal = 50;
            ds.data.push(newVal);
        });

        eventsChart.update('none'); // Efficient update
    }, 1000);


    // Alerts Chart (Doughnut)
    const ctxAlerts = document.getElementById('alertsChart').getContext('2d');
    const alertsChart = new Chart(ctxAlerts, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Warning', 'Info'],
            datasets: [{
                data: [5, 15, 80],
                backgroundColor: ['#ef4444', '#eab308', document.documentElement.classList.contains('dark') ? '#333333' : '#e5e5e5'],
                borderWidth: 0,
                hoverOffset: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '75%',
            plugins: {
                legend: { position: 'right', labels: { usePointStyle: true, boxWidth: 6 } }
            }
        }
    });

    // Simulate live updates for Alerts
    setInterval(() => {
        const data = alertsChart.data.datasets[0].data;
        // Randomly fluctuate
        data[0] = Math.max(2, Math.min(10, data[0] + (Math.random() > 0.5 ? 1 : -1))); // Critical
        data[1] = Math.max(10, Math.min(25, data[1] + (Math.random() > 0.5 ? 1 : -1))); // Warning
        data[2] = 100 - data[0] - data[1]; // Info takes the rest
        alertsChart.update();
    }, 2000);

    // MITRE ATT&CK Chart
    const ctxMitre = document.getElementById('mitreChart').getContext('2d');
    const mitreChart = new Chart(ctxMitre, {
        type: 'doughnut',
        data: {
            labels: ['Password Guessing', 'SSH', 'Brute Force', 'Valid Accounts', 'System Binary Proxy', 'Account Access Removal'],
            datasets: [{
                data: [25, 15, 10, 20, 15, 15],
                backgroundColor: [
                    '#3b82f6', // Blue
                    '#60a5fa', // Light Blue
                    '#facc15', // Yellow
                    '#2dd4bf', // Teal
                    '#4ade80', // Green
                    '#c084fc'  // Purple
                ],
                borderWidth: 0,
                hoverOffset: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: { position: 'right', labels: { usePointStyle: true, boxWidth: 6, font: { size: 10 } } }
            }
        }
    });

    // Update charts on theme toggle
    window.updateChartsTheme = () => {
        const isDark = document.documentElement.classList.contains('dark');
        const textColor = isDark ? '#e5e5e5' : '#4b5563';
        const infoColor = isDark ? '#333333' : '#e5e5e5';
        const lineColor = isDark ? '#ffffff' : '#000000';

        // Alerts Chart
        alertsChart.data.datasets[0].backgroundColor[2] = infoColor;
        alertsChart.update();

        // Events Chart
        eventsChart.data.datasets[0].borderColor = lineColor;
        eventsChart.update();
    };
}



// --- Logic ---
function toggleTheme() {
    document.documentElement.classList.toggle('dark');
    if (window.updateChartsTheme) window.updateChartsTheme();
    if (window.updateChartsTheme) window.updateChartsTheme();
}

// --- Chat Logic ---
let chat3dInitialized = false;
let chatBgInitialized = false;

function initChat3D() {
    const container = document.getElementById('chat-3d-container');
    if (!container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });

    renderer.setSize(32, 32); // Fixed size matching w-8 h-8
    container.appendChild(renderer.domElement);

    const geometry = new THREE.IcosahedronGeometry(1, 0);
    const material = new THREE.MeshBasicMaterial({
        color: 0x4ade80,
        wireframe: true
    });
    const mesh = new THREE.Mesh(geometry, material);
    scene.add(mesh);

    camera.position.z = 3;

    function animate() {
        requestAnimationFrame(animate);
        mesh.rotation.x += 0.03;
        mesh.rotation.y += 0.03;
        renderer.render(scene, camera);
    }
    animate();
}

function initChatBg3D() {
    const container = document.getElementById('chat-bg-canvas');
    if (!container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, container.clientWidth / container.clientHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });

    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    // Shield Object
    const geometry = new THREE.IcosahedronGeometry(5, 1);
    const material = new THREE.MeshBasicMaterial({
        color: 0x4ade80,
        wireframe: true,
        transparent: true,
        opacity: 0.15
    });
    const shield = new THREE.Mesh(geometry, material);
    scene.add(shield);

    // Outer Ring
    const ringGeo = new THREE.TorusGeometry(7, 0.2, 16, 100);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x888888, transparent: true, opacity: 0.1 });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    scene.add(ring);

    camera.position.z = 15;

    function animate() {
        requestAnimationFrame(animate);
        shield.rotation.y += 0.005;
        shield.rotation.x += 0.002;
        ring.rotation.x += 0.005;
        ring.rotation.y += 0.005;

        // Theme adaptation
        const isDark = document.documentElement.classList.contains('dark');
        const shieldColor = isDark ? 0x4ade80 : 0x16a34a;
        const ringColor = isDark ? 0x888888 : 0x000000;

        material.color.setHex(shieldColor);
        ringMat.color.setHex(ringColor);

        renderer.render(scene, camera);
    }
    animate();

    // Handle resize for full screen toggle
    const resizeObserver = new ResizeObserver(() => {
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    });
    resizeObserver.observe(container);
}

function toggleChat() {
    const chat = document.getElementById('chat-window');
    chat.classList.toggle('hidden');

    if (!chat.classList.contains('hidden')) {
        if (!chat3dInitialized) {
            initChat3D();
            chat3dInitialized = true;
        }
        if (!chatBgInitialized) {
            // Small delay to ensure container has dimensions
            setTimeout(() => {
                initChatBg3D();
                chatBgInitialized = true;
            }, 100);
        }
    }
}

function toggleChatFullScreen() {
    const chat = document.getElementById('chat-window');
    const icon = document.getElementById('chat-expand-icon');
    const isFull = chat.classList.contains('fixed');

    if (isFull) {
        // Minimize
        chat.classList.remove('fixed', 'inset-0', 'z-[100]', 'rounded-none');
        chat.classList.add('absolute', 'bottom-16', 'right-0', 'w-80', 'h-96', 'rounded-lg');
        icon.classList.replace('fa-compress', 'fa-expand');
    } else {
        // Maximize
        chat.classList.remove('absolute', 'bottom-16', 'right-0', 'w-80', 'h-96', 'rounded-lg');
        chat.classList.add('fixed', 'inset-0', 'z-[100]', 'rounded-none');
        icon.classList.replace('fa-expand', 'fa-compress');
    }
}

function handleChat(e) {
    e.preventDefault();
    const input = document.getElementById('chat-input');
    const container = document.getElementById('chat-messages');
    const msg = input.value.trim();
    if (!msg) return;

    container.innerHTML += `<div class="flex justify-end"><div class="bg-gray-100 dark:bg-white/10 p-3 rounded-lg rounded-tr-none max-w-[85%] text-xs shadow-sm dark:shadow-none">${msg}</div></div>`;
    input.value = '';
    container.scrollTop = container.scrollHeight;

    setTimeout(() => {
        container.innerHTML += `<div class="flex justify-start"><div class="bg-gray-100 dark:bg-white/5 p-3 rounded-lg rounded-tl-none max-w-[85%] text-xs shadow-sm dark:shadow-none">Command received. Processing...</div></div>`;
        container.scrollTop = container.scrollHeight;
    }, 500);
}

// --- Clock & Timezone ---
let currentTimeZone = localStorage.getItem('sentinel_timezone') || 'Asia/Kolkata';

function updateClock() {
    const now = new Date();

    const tzMap = {
        'UTC': 'UTC',
        'Asia/Kolkata': 'IST',
        'America/New_York': 'EST',
        'Europe/London': 'GMT',
        'Asia/Tokyo': 'JST'
    };

    const options = { timeZone: currentTimeZone, hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' };
    const timeString = now.toLocaleTimeString('en-US', options);
    const label = tzMap[currentTimeZone] || 'Local';

    document.getElementById('clock').innerText = `${timeString} ${label}`;
}
setInterval(updateClock, 1000);

function toggleTimeZoneMenu() {
    const menu = document.getElementById('timezone-menu');
    menu.classList.toggle('hidden');
}

function setTimeZone(tz) {
    currentTimeZone = tz;
    localStorage.setItem('sentinel_timezone', tz);
    updateClock();
    toggleTimeZoneMenu();
    showToast(`Timezone set to ${tz}`, 'info');
}

// Close timezone menu when clicking outside
document.addEventListener('click', (e) => {
    const menu = document.getElementById('timezone-menu');
    if (menu) {
        // The button that toggles it is the parent of the clock span, or the button itself
        // We need to be careful not to close it if we just clicked the toggle button
        const toggleBtn = menu.previousElementSibling;
        if (!menu.classList.contains('hidden') && !menu.contains(e.target) && !toggleBtn.contains(e.target)) {
            menu.classList.add('hidden');
        }
    }
});

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    init3D();
    initCharts();
    loadSavedPlugins();

    updateClock();

    // Security: Disable shortcuts & Right Click
    document.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        showToast('Security Alert: Context Menu Disabled');
    });

    document.addEventListener('copy', (e) => {
        e.preventDefault();
        showToast('Security Alert: Copying Disabled');
    });

    document.addEventListener('selectstart', (e) => {
        // e.preventDefault(); // Optional: completely block selection
        // showToast('Security Alert: Selection Disabled'); 
        // Note: selectstart fires on click sometimes, might be too aggressive. 
        // Relying on copy event and user-select:none CSS.
    });

    document.addEventListener('keydown', (e) => {
        // PrintScreen
        if (e.key === 'PrintScreen') {
            showToast('Security Alert: Screenshot Detected');
            // Optional: Blur screen momentarily
            document.body.style.filter = 'blur(20px)';
            setTimeout(() => document.body.style.filter = 'none', 1000);
        }

        // Function Keys (F1-F12)
        if (e.key.startsWith('F') && !isNaN(e.key.substring(1))) {
            e.preventDefault();
            showToast(`Security Alert: Function Key ${e.key} Disabled`);
        }

        // DevTools (Ctrl+Shift+I/J/C) or View Source (Ctrl+U) or Save (Ctrl+S)
        if (
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
            (e.ctrlKey && e.key === 'u') ||
            (e.ctrlKey && e.key === 's')
        ) {
            e.preventDefault();
            showToast('Security Alert: Developer Tools Disabled');
        }
    });

    // Initialize Drag and Drop
    initDragAndDrop();
});

// --- Drag and Drop Logic ---
let draggedItem = null;
let currentDropZone = null;

// Store default layout on load
const defaultLayout = {};

function initDragAndDrop() {
    const draggables = document.querySelectorAll('.draggable-widget');
    const dropZones = document.querySelectorAll('.drop-zone');

    // Capture default layout
    dropZones.forEach(zone => {
        defaultLayout[zone.id] = Array.from(zone.children).map(child => child.id).filter(id => id);
    });

    // Add main container as drop zone for System Logs flexibility
    const mainContainer = document.querySelector('main');
    if (mainContainer) {
        mainContainer.classList.add('drop-zone');
        mainContainer.dataset.zone = 'main-root'; // Use a distinct data-zone for the main container
        defaultLayout['main-root'] = Array.from(mainContainer.children).map(child => child.id).filter(id => id);
    }

    draggables.forEach(draggable => {
        attachDragListeners(draggable);
    });

    // Re-select drop zones including new main
    const allDropZones = document.querySelectorAll('.drop-zone');

    allDropZones.forEach(zone => {
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();

            if (draggedItem && draggedItem.contains(zone)) return;

            const afterElement = getDragAfterElement(zone, e.clientY, e.clientX);

            zone.classList.add('drag-over');

            if (afterElement == null) {
                zone.appendChild(draggedItem);
            } else {
                zone.insertBefore(draggedItem, afterElement);
            }
        });

        zone.addEventListener('dragleave', () => {
            zone.classList.remove('drag-over');
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('drag-over');
            saveLayout();
        });
    });

    loadLayout();
}

function getDragAfterElement(container, y, x) {
    const draggableElements = [...container.querySelectorAll('.draggable-widget:not(.dragging)')];

    return draggableElements.reduce((closest, child) => {
        const box = child.getBoundingClientRect();
        const offsetX = x - (box.left + box.width / 2);
        const offsetY = y - (box.top + box.height / 2);

        const isRow = window.getComputedStyle(container).flexDirection === 'row' ||
            container.classList.contains('grid');

        if (isRow) {
            if (offsetX < 0 && offsetX > closest.offset) {
                return { offset: offsetX, element: child };
            }
        } else {
            if (offsetY < 0 && offsetY > closest.offset) {
                return { offset: offsetY, element: child };
            }
        }
        return closest;
    }, { offset: Number.NEGATIVE_INFINITY }).element;
}

// --- Widget Library Logic ---
const removedWidgets = new Set();
const selectedWidgetsToRestore = new Set();

const widgetNames = {
    'widget-stat-online': 'Online Devices Stat',
    'widget-stat-alerts': 'Critical Alerts Stat',
    'widget-stat-threat': 'Threat Level Stat',
    'widget-stat-load': 'Network Load Stat',
    'widget-chart-events': 'Event Velocity Chart',
    'widget-table-devices': 'Discovered Devices Table',
    'widget-integrations': 'Integrations Panel',
    'widget-stats-auth': 'Auth Statistics',
    'widget-chart-alerts': 'Alert Distribution Chart',
    'widget-chart-mitre': 'MITRE ATT&CK Chart',
    'widget-list-hardware': 'Hardware Detection List',
    'widget-table-logs': 'System Logs Table'
};

function toggleWidgetLibrary() {
    const modal = document.getElementById('widget-library');
    modal.classList.toggle('hidden');
    selectedWidgetsToRestore.clear(); // Clear selection on open/close
    renderWidgetLibrary();
}

function removeWidget(id) {
    const widget = document.getElementById(id);
    if (widget) {
        widget.style.display = 'none';
        removedWidgets.add(id);
        showToast('Widget Removed');
        saveLayout();
    }
}

function toggleWidgetSelection(id) {
    if (selectedWidgetsToRestore.has(id)) {
        selectedWidgetsToRestore.delete(id);
    } else {
        selectedWidgetsToRestore.add(id);
    }
    renderWidgetLibrary();
}

function restoreSelectedWidgets() {
    if (selectedWidgetsToRestore.size === 0) {
        showToast('No widgets selected', 'warning');
        return;
    }

    selectedWidgetsToRestore.forEach(id => {
        const widget = document.getElementById(id);
        if (widget) {
            widget.style.display = '';
            removedWidgets.delete(id);

            // Add highlight animation
            widget.classList.add('ring', 'ring-green-500');
            setTimeout(() => widget.classList.remove('ring', 'ring-green-500'), 1000);
        }
    });

    showToast(`${selectedWidgetsToRestore.size} Widgets Restored`, 'success');
    selectedWidgetsToRestore.clear();
    toggleWidgetLibrary();
    saveLayout();
}

function renderWidgetLibrary() {
    const container = document.getElementById('removed-widgets-list');
    container.innerHTML = '';

    if (removedWidgets.size === 0) {
        container.innerHTML = `
            <div class="col-span-2 text-center py-8 opacity-40 italic flex flex-col items-center gap-2">
                <i class="fas fa-check-circle text-2xl"></i>
                <span>All widgets are currently active.</span>
            </div>`;
        return;
    }

    removedWidgets.forEach(id => {
        const name = widgetNames[id] || 'Unknown Widget';
        const isSelected = selectedWidgetsToRestore.has(id);

        const el = document.createElement('div');
        el.className = `panel p-4 rounded border ${isSelected ? 'border-green-500 bg-green-500/10' : 'border-white/10'} flex justify-between items-center hover:bg-white/5 transition-colors group cursor-pointer select-none`;
        el.onclick = () => toggleWidgetSelection(id);
        el.innerHTML = `
            <div class="flex items-center gap-3">
                <div class="w-4 h-4 rounded border ${isSelected ? 'border-green-500 bg-green-500' : 'border-white/30'} flex items-center justify-center transition-colors">
                    ${isSelected ? '<i class="fas fa-check text-[10px] text-black"></i>' : ''}
                </div>
                <span class="font-mono text-xs font-bold ${isSelected ? 'text-green-500' : ''}">${name}</span>
            </div>
        `;
        container.appendChild(el);
    });
}

// --- Persistence & Reset ---
function saveLayout() {
    const layout = {};
    document.querySelectorAll('.drop-zone').forEach(zone => {
        const key = zone.id || zone.dataset.zone;
        if (key) { // Ensure key exists
            layout[key] = Array.from(zone.children)
                .filter(child => child.classList.contains('draggable-widget'))
                .map(child => child.id);
        }
    });
    layout.removed = Array.from(removedWidgets);
    localStorage.setItem('sentinel_layout', JSON.stringify(layout));
}

function loadLayout() {
    const saved = localStorage.getItem('sentinel_layout');
    if (!saved) return;

    try {
        const layout = JSON.parse(saved);

        // Restore Removed Widgets
        if (layout.removed) {
            removedWidgets.clear();
            layout.removed.forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    el.style.display = 'none';
                    removedWidgets.add(id);
                }
            });
        }

        // Re-add widgets to their respective zones in order
        Object.keys(layout).forEach(zoneId => {
            if (zoneId === 'removed') return;

            let zone;
            if (zoneId === 'main-root') {
                zone = document.querySelector('main');
            } else {
                zone = document.getElementById(zoneId);
            }

            if (zone && Array.isArray(layout[zoneId])) {
                layout[zoneId].forEach(widgetId => {
                    const widget = document.getElementById(widgetId);
                    if (widget) {
                        // Ensure widget is visible if it's being placed (unless it's in removed set, which we handled above?
                        // Actually if it's in removed set, display is none.
                        // But if it's in the zone list, it implies it should be there.
                        // Conflict: A widget might be in 'removed' list AND in 'zone' list if save logic was weird.
                        // Priority: If it is in removedWidgets, keep it hidden.

                        if (!removedWidgets.has(widgetId)) {
                            widget.style.display = '';
                            zone.appendChild(widget);
                        }
                    }
                });
            }
        });
    } catch (e) {
        console.error('Failed to load layout', e);
        // Optionally, clear corrupted layout
        localStorage.removeItem('sentinel_layout');
    }
}

function resetLayout() {
    // 1. Clear Local Storage
    localStorage.removeItem('sentinel_layout');

    // 2. Restore Removed Widgets
    removedWidgets.forEach(id => {
        const widget = document.getElementById(id);
        if (widget) widget.style.display = '';
    });
    removedWidgets.clear();
    selectedWidgetsToRestore.clear(); // Clear selection list

    // 3. Move widgets back to default zones in default order
    Object.keys(defaultLayout).forEach(zoneId => {
        let zone;
        if (zoneId === 'main-root') {
            zone = document.querySelector('main');
        } else {
            zone = document.getElementById(zoneId);
        }

        if (zone && defaultLayout[zoneId]) {
            defaultLayout[zoneId].forEach(widgetId => {
                const widget = document.getElementById(widgetId);
                if (widget) {
                    zone.appendChild(widget);
                }
            });
        }
    });

    showToast('Layout Reset to Default', 'success');

    // Close modal immediately
    const modal = document.getElementById('widget-library');
    if (modal) {
        modal.classList.add('hidden');
    }
    updateResetButtonState();
}

// --- Plugin Upload Logic (Hybrid: Local + Server) ---
function triggerPluginUpload() {
    document.getElementById('plugin-upload-input').click();
}

async function handlePluginUpload(input) {
    const file = input.files[0];
    if (!file) return;

    const isPython = file.name.endsWith('.py');

    // 1. Immediate Local Load (Frontend) - ONLY FOR HTML
    if (!isPython) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const content = e.target.result;
            const existing = document.querySelector(`[data-plugin-name="${file.name}"]`);
            if (!existing) {
                addPluginToDashboard(content, file.name);
            }
        };
        reader.readAsText(file);
    }

    // 2. Upload to Server (Backend Persistence)
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/plugins/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) throw new Error('Upload failed');

        const data = await response.json();

        if (data.type === 'backend') {
            // addBackendPluginToDashboard(data.name); // Wait for socket event to get actual plugin name
            showToast('Backend Plugin Uploaded. Initializing...', 'success');
        } else {
            showToast('Plugin Uploaded & Saved', 'success');
        }
    } catch (error) {
        console.error(error);
        if (isPython) {
            showToast('Upload failed. Backend plugins require server connection.', 'error');
        } else {
            showToast('Local load only (Server upload failed)', 'warning');
        }
    }

    input.value = ''; // Reset
}

// --- Socket.IO Integration for Plugins ---

const socket = io();

socket.on('plugin_added', (data) => {
    console.log("New Plugin Received:", data.name);

    // Check if we already have this widget to avoid duplicates
    const existing = document.querySelector(`[data-plugin-name="${data.name}"]`);
    if (!existing) {
        addPluginToDashboard(data.content, data.name);
    }
});

// --- Load Saved Plugins on Startup ---
// --- Load Saved Plugins on Startup ---
async function loadSavedPlugins() {
    // 1. Load HTML Plugins (Frontend)
    try {
        const response = await fetch('/api/plugins/list');
        const plugins = await response.json();

        plugins.forEach(plugin => {
            setTimeout(() => {
                const existing = document.querySelector(`[data-plugin-name="${plugin.name}"]`);
                if (!existing) {
                    addPluginToDashboard(plugin.content, plugin.name);
                }
            }, 100);
        });
    } catch (e) {
        console.error("Could not load HTML plugins:", e);
    }

    // 2. Load Python Plugins (Backend)
    try {
        const response = await fetch('/api/plugins/backend/list');
        const plugins = await response.json();

        plugins.forEach(plugin => {
            addBackendPluginToDashboard(plugin.name);
        });
    } catch (e) {
        console.error("Could not load backend plugins:", e);
    }
}

socket.on('backend_plugin_added', (data) => {
    console.log("New Backend Plugin:", data.name);
    addBackendPluginToDashboard(data.name);
    showToast(`Backend Plugin Loaded: ${data.name}`, 'success');
});

function attachDragListeners(draggable) {
    draggable.addEventListener('dragstart', (e) => {
        draggedItem = draggable;
        e.stopPropagation();
        setTimeout(() => draggable.classList.add('dragging'), 0);
    });

    draggable.addEventListener('dragend', () => {
        draggable.classList.remove('dragging');
        draggedItem = null;
        document.querySelectorAll('.drop-zone').forEach(zone => zone.classList.remove('drag-over'));
        saveLayout();
    });
}

function addBackendPluginToDashboard(name) {
    const integrationsGrid = document.getElementById('integrations-grid');
    if (!integrationsGrid) return;

    // Check for duplicates
    const existing = Array.from(integrationsGrid.children).find(child => child.innerText.includes(name));
    if (existing) return;

    const item = document.createElement('div');
    item.className = 'panel bg-white/5 border border-white/10 p-4 rounded-lg flex flex-col items-center gap-3 group cursor-pointer hover:bg-white/10 transition-all relative overflow-hidden';
    item.innerHTML = `
        <div class="absolute top-2 right-2 w-2 h-2 rounded-full bg-yellow-500"></div>
        <i class="fab fa-python text-3xl opacity-80 group-hover:opacity-100 group-hover:scale-110 transition-all"></i>
        <span class="text-xs font-mono font-bold">${name}</span>
    `;
    integrationsGrid.appendChild(item);
}

function addPluginToDashboard(content, fileName) {
    // 0. Check if this plugin was previously removed
    // We look for any widget that has data-plugin-name == fileName AND is in removedWidgets
    const existingRemovedId = Array.from(removedWidgets).find(id => {
        const el = document.getElementById(id);
        return el && el.dataset.pluginName === fileName;
    });

    if (existingRemovedId) {
        // Restore the existing one
        const widget = document.getElementById(existingRemovedId);
        widget.style.display = '';
        removedWidgets.delete(existingRemovedId);

        // Move to below integrations tile if possible
        const integrationsTile = document.getElementById('widget-integrations');
        const container = document.getElementById('main-left-col');

        if (integrationsTile && container && container.contains(integrationsTile)) {
            // Insert after integrationsTile
            container.insertBefore(widget, integrationsTile.nextSibling);
        } else if (container) {
            container.appendChild(widget);
        }

        // Update selection in library if it was selected
        selectedWidgetsToRestore.delete(existingRemovedId);

        // Highlight it
        widget.classList.add('ring', 'ring-green-500');
        setTimeout(() => widget.classList.remove('ring', 'ring-green-500'), 1000);

        // Scroll to it
        setTimeout(() => {
            widget.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 100);

        showToast('Plugin Restored', 'success');
        saveLayout();
        updateResetButtonState();
        return;
    }

    // 1. Create Widget
    const widgetId = 'widget-plugin-' + Date.now();
    const widget = document.createElement('div');
    widget.id = widgetId;
    widget.dataset.pluginName = fileName; // Store filename for restoration check
    widget.className = 'panel p-6 rounded-lg draggable-widget relative group mb-6';
    widget.draggable = true;

    widget.innerHTML = `
        <div class="widget-remove-btn" onclick="removeWidget('${widgetId}')"><i class="fas fa-times"></i></div>
        <div class="mb-4">
            <h3 class="font-display font-bold text-lg">${fileName.replace('.html', '')}</h3>
            <p class="text-xs opacity-60">Custom Plugin</p>
        </div>
        <div class="plugin-content">
            ${content}
        </div>
    `;

    // Attach listeners
    attachDragListeners(widget);

    // Append to Left Column (at the bottom)
    const container = document.getElementById('main-left-col');
    if (container) {
        container.appendChild(widget);
        // Scroll to the new widget
        setTimeout(() => {
            widget.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 100);
    }

    // 2. Add to Integrations Panel
    const integrationsGrid = document.getElementById('integrations-grid');
    if (integrationsGrid) {
        const item = document.createElement('div');
        item.className = 'panel bg-white/5 border border-white/10 p-4 rounded-lg flex flex-col items-center gap-3 group cursor-pointer hover:bg-white/10 transition-all relative overflow-hidden';
        item.innerHTML = `
            <div class="absolute top-2 right-2 w-2 h-2 rounded-full bg-blue-500"></div>
            <i class="fas fa-puzzle-piece text-3xl opacity-80 group-hover:opacity-100 group-hover:scale-110 transition-all"></i>
            <span class="text-xs font-mono font-bold">${fileName.replace('.html', '')}</span>
        `;
        integrationsGrid.appendChild(item);
    }

    showToast('Plugin Added Successfully', 'success');
    saveLayout();
    updateResetButtonState();
}

// --- Report Generation Logic ---

function openReportModal() {
    const modal = document.getElementById('report-modal');
    const list = document.getElementById('report-component-list');
    list.innerHTML = '';

    // Find all widgets
    const widgets = document.querySelectorAll('.draggable-widget');
    widgets.forEach(widget => {
        const id = widget.id;
        // Try to find a title
        let title = id;
        const titleEl = widget.querySelector('h3, .text-xs.uppercase, .font-display');
        if (titleEl) title = titleEl.innerText.trim();

        const item = document.createElement('label');
        item.className = 'flex items-center gap-3 p-3 rounded bg-white/5 hover:bg-white/10 cursor-pointer transition';
        item.innerHTML = `
        <input type="checkbox" class="report-checkbox accent-blue-500" value="${id}" checked>
        <span class="text-sm font-mono truncate">${title}</span>
    `;
        list.appendChild(item);
    });

    modal.classList.remove('hidden');
}

function closeReportModal() {
    document.getElementById('report-modal').classList.add('hidden');
}

function toggleAllReportItems(checked) {
    document.querySelectorAll('.report-checkbox').forEach(cb => cb.checked = checked);
}

async function submitReportRequest() {
    const btn = document.getElementById('btn-download-pdf');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    btn.disabled = true;

    try {
        const selectedIds = Array.from(document.querySelectorAll('.report-checkbox:checked')).map(cb => cb.value);
        const reportData = [];

        for (const id of selectedIds) {
            const widget = document.getElementById(id);
            if (!widget) continue;

            // Extract Title
            let title = "Untitled Component";
            const titleEl = widget.querySelector('h3, .text-xs.uppercase, .font-display');
            if (titleEl) title = titleEl.innerText.trim();

            const entry = {
                title: title,
                type: 'text',
                content: ''
            };

            // --- Specialized Scrapers ---

            // 1. Logs Table (widget-table-logs)
            if (id === 'widget-table-logs') {
                entry.type = 'table';
                const headers = ["Timestamp", "Severity", "Source", "Message"];
                const rows = [];
                // Scrape the visible rows
                const trs = widget.querySelectorAll('tbody tr');
                trs.forEach(tr => {
                    const tds = tr.querySelectorAll('td');
                    if (tds.length >= 4) {
                        rows.push([
                            tds[0].innerText.trim(),
                            tds[1].innerText.trim(),
                            tds[2].innerText.trim(),
                            tds[3].innerText.trim()
                        ]);
                    }
                });
                entry.content = { headers, rows };
            }
            // 2. Hardware List (widget-list-hardware)
            else if (id === 'widget-list-hardware') {
                entry.type = 'table';
                const headers = ["Device", "Type", "Details", "Status"];
                const rows = [];
                // The hardware list uses divs, not a table. We need to parse the divs.
                // Structure: .flex.items-center... -> h4 (Name), span (Type), p (Details)
                const items = widget.querySelectorAll('.overflow-y-auto > div');
                items.forEach(item => {
                    const name = item.querySelector('h4')?.innerText.trim() || '-';
                    const type = item.querySelector('span')?.innerText.trim() || '-';
                    const details = item.querySelector('p')?.innerText.trim() || '-';
                    const status = item.querySelector('.bg-green-500') ? 'Active' : 'Idle'; // Simple heuristic
                    rows.push([name, type, details, status]);
                });
                entry.content = { headers, rows };
            }
            // 3. Discovered Devices (widget-table-devices) - Standard Table
            else if (id === 'widget-table-devices') {
                entry.type = 'table';
                const table = widget.querySelector('table');
                if (table) {
                    const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.innerText.trim());
                    const rows = Array.from(table.querySelectorAll('tbody tr')).map(tr => {
                        return Array.from(tr.querySelectorAll('td')).map(td => td.innerText.trim());
                    });
                    entry.content = { headers, rows };
                }
            }
            // 4. Charts (Canvas)
            else if (widget.querySelector('canvas')) {
                entry.type = 'image';
                const canvas = widget.querySelector('canvas');
                entry.content = canvas.toDataURL('image/png');
            }
            // 5. Stats
            else if (widget.querySelector('.text-3xl')) {
                entry.type = 'stat';
                // Extract Value (e.g., "142")
                const valEl = widget.querySelector('.text-3xl');
                let value = valEl ? valEl.innerText.trim().replace(/\n/g, '') : 'N/A';

                // Extract Subtext (e.g., "12%") - usually in the div below value
                const subEl = widget.querySelector('.text-3xl + div');
                let subtext = subEl ? subEl.innerText.trim().replace(/\n/g, ' ') : '';

                // Cleanup for specific widgets if needed
                if (id === 'widget-stat-load') {
                    // For load, value might be "45Mbps", we want to keep it clean
                    // The HTML is 45<span>Mbps</span>. innerText gives "45Mbps". That's fine.
                }

                entry.content = { value, subtext };
            }
            // 6. Integrations & Plugins List (widget-integrations)
            else if (id === 'widget-integrations') {
                entry.type = 'table';
                const headers = ["Integration Name", "Status", "Type"];
                const rows = [];

                // Scrape the grid items
                const grid = widget.querySelector('#integrations-grid');
                if (grid) {
                    const items = grid.querySelectorAll('.panel');
                    items.forEach(item => {
                        const name = item.querySelector('span')?.innerText.trim() || 'Unknown';
                        const isPython = item.querySelector('.fa-python');
                        const isPlugin = item.querySelector('.fa-puzzle-piece');

                        let type = "Standard Integration";
                        if (isPython) type = "Backend Plugin (Python)";
                        else if (isPlugin) type = "Frontend Plugin (HTML)";

                        // Check for status dot
                        const dot = item.querySelector('.rounded-full');
                        let status = "Active";
                        if (dot) {
                            if (dot.classList.contains('bg-green-500')) status = "Online";
                            else if (dot.classList.contains('bg-yellow-500')) status = "Loading/Warning";
                            else if (dot.classList.contains('bg-blue-500')) status = "Loaded";
                        }

                        rows.push([name, status, type]);
                    });
                }
                entry.content = { headers, rows };
            }
            // 7. Custom Plugins (widget-plugin-...)
            else if (id.startsWith('widget-plugin-')) {
                // Try to find a table first
                const table = widget.querySelector('table');
                if (table) {
                    entry.type = 'table';
                    const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.innerText.trim());
                    const rows = Array.from(table.querySelectorAll('tbody tr')).map(tr => {
                        return Array.from(tr.querySelectorAll('td')).map(td => td.innerText.trim());
                    });
                    entry.content = { headers, rows };
                }
                // Try to find a list
                else if (widget.querySelector('ul') || widget.querySelector('ol')) {
                    entry.type = 'text';
                    entry.content = widget.querySelector('.plugin-content').innerText.trim();
                }
                // Fallback to text
                else {
                    entry.type = 'text';
                    const contentEl = widget.querySelector('.plugin-content');
                    entry.content = contentEl ? contentEl.innerText.trim() : widget.innerText.trim();
                }
            }
            // 8. Default Text Fallback
            else {
                entry.content = widget.innerText.replace(title, '').trim();
            }

            reportData.push(entry);
        }

        // Send to backend
        const response = await fetch('/api/report/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ sections: reportData })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `sentinel_report_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            closeReportModal();
        } else {
            throw new Error('Server returned error');
        }

    } catch (error) {
        console.error("Report generation failed:", error);
        alert("Failed to generate report. See console for details.");
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Hook up the main button
function generateReport() {
    openReportModal();
}
