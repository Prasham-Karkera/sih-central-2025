class DecryptReportManager {
    constructor() {
        this.file = null;
        this.csvData = [];
        this.jsonData = [];
        this.currentPage = 0;
        this.rowsPerPage = 20;
    }

    handleFileSelect(input) {
        const file = input.files[0];
        if (!file) return;
        this.file = file;

        const statusDiv = document.getElementById('decrypt-status');
        const filenameEl = document.getElementById('decrypt-filename');
        const statusText = document.getElementById('decrypt-status-text');
        const progress = document.getElementById('decrypt-progress');
        const actions = document.getElementById('decrypt-actions');

        statusDiv.classList.remove('hidden');
        actions.classList.add('hidden');
        filenameEl.innerText = file.name;
        statusText.innerText = 'Ready to Decrypt';
        statusText.className = 'text-xs font-bold text-blue-500';
        progress.style.width = '0%';

        actions.classList.remove('hidden');
    }

    async processDecryption() {
        const keyInput = document.getElementById('decrypt-key-input');
        const statusText = document.getElementById('decrypt-status-text');
        const progress = document.getElementById('decrypt-progress');
        const contentDiv = document.getElementById('decrypted-content');

        const keyHex = keyInput.value.trim();

        if (!this.file || !keyHex) {
            showToast("Please provide file and key", "warning");
            return;
        }

        statusText.innerText = 'Decrypting...';
        progress.style.width = '50%';

        try {
            const arrayBuffer = await this.file.arrayBuffer();

            if (arrayBuffer.byteLength < 28) throw new Error("Invalid file format (too short)");

            const iv = new Uint8Array(arrayBuffer.slice(0, 12));
            const data = new Uint8Array(arrayBuffer.slice(12));

            const keyBuffer = this.hex2buf(keyHex);

            const key = await window.crypto.subtle.importKey(
                "raw",
                keyBuffer,
                { name: "AES-GCM" },
                true,
                ["decrypt"]
            );

            const decrypted = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                data
            );

            const dec = new TextDecoder();
            const decodedString = dec.decode(decrypted);

            statusText.innerText = 'Rendering Report...';
            progress.style.width = '80%';

            try {
                const jsonData = JSON.parse(decodedString);

                // Check for new Array format
                if (Array.isArray(jsonData)) {
                    this.jsonData = jsonData; // Store for pagination
                    this.currentPage = 0;
                    this.renderJSONTable(contentDiv);
                    this.finishSuccess(statusText, progress);
                    return;
                }

                // Legacy format
                if (jsonData.sections) {
                    this.renderContent(jsonData, contentDiv);
                    this.finishSuccess(statusText, progress);
                    return;
                }
            } catch (e) {
                console.error("JSON Parse Error", e);
            }

            throw new Error("Invalid data format (expected JSON)");

        } catch (e) {
            console.error(e);
            statusText.innerText = 'Decryption Failed';
            statusText.className = 'text-xs font-bold text-red-500';
            progress.style.width = '0%';
            if (e.name === 'OperationError') {
                showToast("Incorrect Key or Corrupted File", "error");
            } else {
                showToast("Decryption Failed: " + e.message, "error");
            }
        }
    }

    finishSuccess(statusText, progress) {
        statusText.innerText = 'Complete';
        statusText.className = 'text-xs font-bold text-green-500';
        progress.style.width = '100%';
        showToast("Report Decrypted Successfully", "success");
    }

    parseCSV(text) {
        const lines = text.trim().split(/\r?\n/);
        if (lines.length < 2) return [];

        const headers = this.parseCSVLine(lines[0]);
        const rows = [];

        for (let i = 1; i < lines.length; i++) {
            const row = this.parseCSVLine(lines[i]);
            if (row.length === headers.length) {
                const obj = {};
                headers.forEach((h, index) => obj[h] = row[index]);
                rows.push(obj);
            }
        }
        return { headers, rows };
    }

    parseCSVLine(line) {
        const result = [];
        let current = '';
        let inQuotes = false;

        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            if (char === '"') {
                if (inQuotes && line[i + 1] === '"') {
                    current += '"';
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (char === ',' && !inQuotes) {
                result.push(current);
                current = '';
            } else {
                current += char;
            }
        }
        result.push(current);
        return result;
    }

    renderJSONTable(container) {
        container.innerHTML = '';
        container.classList.remove('hidden');

        let rows = this.jsonData;

        // If no data, use dummy data
        if (!rows || rows.length === 0) {
            rows = this.generateDummyData();
            this.jsonData = rows; // Update reference for pagination
            showToast("No data found. Showing dummy data for demonstration.", "info");
        }

        const totalPages = Math.ceil(rows.length / this.rowsPerPage);

        const start = this.currentPage * this.rowsPerPage;
        const end = Math.min(start + this.rowsPerPage, rows.length);
        const currentRows = rows.slice(start, end);

        // Define headers based on first object keys or fixed list
        const headers = ['id', 'title', 'description', 'severity', 'resolved', 'hostname', 'triggered_at'];

        const tableHtml = `
            <div class="panel p-6 rounded-lg border border-white/5">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="font-display font-bold text-lg">Decrypted Alerts Data</h3>
                    <div class="text-xs font-mono opacity-60">
                        Showing ${start + 1}-${end} of ${rows.length}
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-white/5 border-b border-white/10">
                            <tr>
                                ${headers.map(h => `<th class="p-3 text-left opacity-60 font-mono text-xs uppercase whitespace-nowrap">${h.replace(/_/g, ' ')}</th>`).join('')}
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-white/5">
                            ${currentRows.map(row => {
            const safeDesc = (row.description || '').replace(/"/g, '&quot;');
            return `
                                <tr class="hover:bg-white/5 transition">
                                    <td class="p-3 text-sm whitespace-nowrap opacity-60">#${row.id}</td>
                                    <td class="p-3 text-sm font-bold">${row.title}</td>
                                    <td class="p-3 text-sm opacity-80 max-w-[200px] truncate" title="${safeDesc}">${row.description}</td>
                                    <td class="p-3 text-sm">
                                        <span class="${row.severity === 'high' || row.severity === 'critical' ? 'text-red-500' : row.severity === 'medium' || row.severity === 'warning' ? 'text-orange-500' : 'text-blue-500'} font-bold uppercase text-xs">
                                            ${row.severity}
                                        </span>
                                    </td>
                                    <td class="p-3 text-sm">
                                        <span class="${row.resolved ? 'text-green-500' : 'text-red-500'} font-bold uppercase text-xs">
                                            ${row.resolved ? 'Resolved' : 'Active'}
                                        </span>
                                    </td>
                                    <td class="p-3 text-sm font-mono opacity-60">${row.hostname || '-'}</td>
                                    <td class="p-3 text-sm font-mono opacity-60">${row.triggered_at || '-'}</td>
                                </tr>
                            `}).join('')}
                        </tbody>
                    </table>
                </div>
                <div class="flex justify-between items-center mt-4 border-t border-white/10 pt-4">
                    <button onclick="decryptReportManager.changePage(-1)" ${this.currentPage === 0 ? 'disabled' : ''} class="px-3 py-1 rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 text-xs font-bold">Previous</button>
                    <span class="text-xs font-mono opacity-60">Page ${this.currentPage + 1} of ${totalPages}</span>
                    <button onclick="decryptReportManager.changePage(1)" ${this.currentPage >= totalPages - 1 ? 'disabled' : ''} class="px-3 py-1 rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 text-xs font-bold">Next</button>
                </div>
            </div>
        `;

        container.innerHTML = tableHtml;
    }

    generateDummyData() {
        return [
            {
                id: 1001,
                title: "Brute Force Attack Detected",
                description: "Multiple failed login attempts from IP 192.168.1.50",
                severity: "critical",
                resolved: false,
                hostname: "auth-server-01",
                triggered_at: new Date().toISOString()
            },
            {
                id: 1002,
                title: "High CPU Usage",
                description: "CPU usage exceeded 90% for 5 minutes",
                severity: "warning",
                resolved: true,
                hostname: "db-node-02",
                triggered_at: new Date(Date.now() - 3600000).toISOString()
            },
            {
                id: 1003,
                title: "Port Scan Detected",
                description: "Port scan activity detected from external IP",
                severity: "high",
                resolved: false,
                hostname: "firewall-01",
                triggered_at: new Date(Date.now() - 7200000).toISOString()
            },
            {
                id: 1004,
                title: "Service Stopped",
                description: "Nginx service stopped unexpectedly",
                severity: "medium",
                resolved: true,
                hostname: "web-proxy-01",
                triggered_at: new Date(Date.now() - 10800000).toISOString()
            },
            {
                id: 1005,
                title: "Disk Space Low",
                description: "Free disk space below 10% on /var/log",
                severity: "low",
                resolved: false,
                hostname: "log-server-01",
                triggered_at: new Date(Date.now() - 14400000).toISOString()
            }
        ];
    }

    changePage(delta) {
        const rows = this.jsonData;
        const totalPages = Math.ceil(rows.length / this.rowsPerPage);

        this.currentPage += delta;
        if (this.currentPage < 0) this.currentPage = 0;
        if (this.currentPage >= totalPages) this.currentPage = totalPages - 1;

        const container = document.getElementById('decrypted-content');
        this.renderJSONTable(container);
    }

    // Legacy JSON Render Support
    renderContent(jsonData, container) {
        container.innerHTML = '';
        container.classList.remove('hidden');

        if (jsonData.sections && Array.isArray(jsonData.sections)) {
            jsonData.sections.forEach(section => {
                const sectionEl = document.createElement('div');
                sectionEl.className = 'panel p-6 rounded-lg border border-white/5';

                let contentHtml = '';

                if (section.type === 'table') {
                    const headers = section.content.headers.map(h => `<th class="p-3 text-left opacity-60 font-mono text-xs uppercase">${h}</th>`).join('');
                    const rows = section.content.rows.map(row => {
                        return `<tr class="border-b border-white/5 last:border-0 hover:bg-white/5 transition">
                            ${row.map(cell => `<td class="p-3 text-sm">${cell}</td>`).join('')}
                        </tr>`;
                    }).join('');
                    contentHtml = `
                        <div class="overflow-x-auto">
                            <table class="w-full">
                                <thead class="bg-white/5 border-b border-white/10"><tr>${headers}</tr></thead>
                                <tbody>${rows}</tbody>
                            </table>
                        </div>
                    `;
                } else if (section.type === 'image') {
                    contentHtml = `<img src="${section.content}" class="w-full rounded border border-white/10 bg-black/20 p-2">`;
                } else if (section.type === 'stat') {
                    contentHtml = `
                        <div class="flex flex-col items-center justify-center py-4">
                            <span class="text-4xl font-bold font-display text-blue-500">${section.content.value}</span>
                            <span class="text-sm opacity-60 mt-2 text-center">${section.content.subtext}</span>
                        </div>
                    `;
                } else {
                    contentHtml = `<p class="text-sm opacity-80 whitespace-pre-wrap">${section.content}</p>`;
                }

                sectionEl.innerHTML = `
                    <h3 class="font-display font-bold text-lg mb-4 border-b border-white/10 pb-2">${section.title}</h3>
                    ${contentHtml}
                `;
                container.appendChild(sectionEl);
            });
        }
    }

    hex2buf(hex) {
        if (!hex) return new Uint8Array(0);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }
}

const decryptReportManager = new DecryptReportManager();

// Global hooks
function handleDecryptFileSelect(input) {
    decryptReportManager.handleFileSelect(input);
}

function processDecryption() {
    decryptReportManager.processDecryption();
}
