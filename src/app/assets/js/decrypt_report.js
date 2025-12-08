class DecryptReportManager {
    constructor() {
        this.fileContent = null;
        this.fileName = null;
    }

    handleFileSelect(input) {
        const file = input.files[0];
        if (!file) return;

        this.fileName = file.name;
        document.getElementById('decrypt-filename').innerText = file.name;
        document.getElementById('decrypt-dropzone').classList.add('hidden');
        document.getElementById('decrypt-status').classList.remove('hidden');

        // Simulate upload/read progress
        const progressBar = document.getElementById('decrypt-progress');
        progressBar.style.width = '0%';

        const reader = new FileReader();
        reader.onload = (e) => {
            this.fileContent = e.target.result; // This is the binary/text content
            progressBar.style.width = '100%';
            document.getElementById('decrypt-status-text').innerText = 'Ready to Decrypt';
            document.getElementById('decrypt-status-text').classList.replace('text-yellow-500', 'text-green-500');
            document.getElementById('decrypt-actions').classList.remove('hidden');
        };
        reader.readAsText(file);
    }

    async processDecryption() {
        const key = document.getElementById('decrypt-key-input').value.trim();
        if (!key) {
            alert('Please enter the decryption key');
            return;
        }

        const btn = document.querySelector('#decrypt-actions button');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Decrypting...';
        btn.disabled = true;

        try {
            const res = await fetch('/api/alerts/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    encrypted_data: this.fileContent,
                    key: key
                })
            });

            if (res.ok) {
                const data = await res.json();
                if (data.success && data.alerts) {
                    this.renderDecryptedTable(data.alerts);
                    document.getElementById('decrypt-actions').classList.add('hidden');
                    document.getElementById('decrypt-status').classList.add('hidden');
                    document.getElementById('decrypted-content').classList.remove('hidden');
                } else {
                    alert('Decryption failed: Invalid data returned');
                }
            } else {
                const err = await res.json();
                alert('Decryption failed: ' + (err.detail || 'Unknown error'));
            }
        } catch (e) {
            console.error(e);
            alert('Error processing decryption');
        }

        btn.innerHTML = originalText;
        btn.disabled = false;
    }

    renderDecryptedTable(alerts) {
        const container = document.getElementById('decrypted-content');

        if (!alerts || alerts.length === 0) {
            container.innerHTML = '<div class="text-center opacity-50 p-8">No alerts found in decrypted file.</div>';
            return;
        }

        // Sort by severity
        const severityOrder = { 'critical': 0, 'high': 0, 'warning': 1, 'medium': 1, 'info': 2, 'low': 2 };
        alerts.sort((a, b) => {
            const sevA = a.severity ? a.severity.toLowerCase() : 'low';
            const sevB = b.severity ? b.severity.toLowerCase() : 'low';
            return (severityOrder[sevA] ?? 2) - (severityOrder[sevB] ?? 2);
        });

        const html = `
            <div class="flex justify-between items-center mb-4">
                <h3 class="font-bold text-lg text-green-500"><i class="fas fa-unlock mr-2"></i> Decrypted Alerts (${alerts.length})</h3>
                <button onclick="location.reload()" class="text-xs bg-white/10 px-3 py-1 rounded hover:bg-white/20">Clear & Reset</button>
            </div>
            <div class="overflow-auto custom-scrollbar bg-black/20 rounded border border-white/5 max-h-[600px]">
                <table class="w-full text-left text-sm">
                    <thead class="table-header font-mono uppercase sticky top-0 z-10 bg-gray-100 dark:bg-[#0a0a0a] border-b border-gray-200 dark:border-white/10">
                        <tr>
                            <th class="p-4 w-16">ID</th>
                            <th class="p-4">Title</th>
                            <th class="p-4">Description</th>
                            <th class="p-4 w-24">Severity</th>
                            <th class="p-4 w-32">Time</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-white/5 font-mono">
                        ${alerts.map(alert => {
            let severity = alert.severity ? alert.severity.toLowerCase() : 'info';
            let severityClass = 'text-blue-500';
            if (severity === 'critical' || severity === 'high') severityClass = 'text-red-500';
            else if (severity === 'warning' || severity === 'medium') severityClass = 'text-orange-500';

            return `
                                <tr class="hover:bg-white/5 transition-colors">
                                    <td class="p-4 opacity-60">#${alert.id}</td>
                                    <td class="p-4 font-bold">${alert.title}</td>
                                    <td class="p-4 opacity-80 text-xs">${alert.description}</td>
                                    <td class="p-4 font-bold uppercase text-xs ${severityClass}">${severity}</td>
                                    <td class="p-4 opacity-60 text-xs">${alert.triggered_at ? new Date(alert.triggered_at).toLocaleString() : '-'}</td>
                                </tr>
                            `;
        }).join('')}
                    </tbody>
                </table>
            </div>
        `;

        container.innerHTML = html;
    }
}

const decryptReportManager = new DecryptReportManager();

// Global functions for HTML event handlers
function handleDecryptFileSelect(input) {
    decryptReportManager.handleFileSelect(input);
}

function processDecryption() {
    decryptReportManager.processDecryption();
}
