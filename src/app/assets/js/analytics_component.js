class AnalyticsComponent {
    constructor() {
        this.modalId = 'analytics-modal';
        this.chartInstances = [];
    }

    open(serverId, hostname, serverType) {
        this.close(); // Close existing if any
        this.createModal(serverId, hostname);
        this.fetchData(hostname, serverType);
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
    }

    close() {
        const modal = document.getElementById(this.modalId);
        if (modal) {
            modal.remove();
            this.chartInstances.forEach(chart => chart.destroy());
            this.chartInstances = [];
            document.body.style.overflow = '';
        }
    }

    createModal(serverId, hostname) {
        const modal = document.createElement('div');
        modal.id = this.modalId;
        modal.className = 'fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm';
        modal.style.animation = 'fadeIn 0.3s ease-out';

        modal.innerHTML = `
            <div class="bg-[#0a0a0a] border border-white/10 w-[95%] h-[90%] rounded-xl shadow-2xl flex flex-col overflow-hidden relative">
                <!-- Header -->
                <div class="p-6 border-b border-white/10 flex justify-between items-center bg-white/5">
                    <div class="flex items-center gap-4">
                        <div class="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center text-blue-500">
                            <i class="fas fa-chart-pie text-xl"></i>
                        </div>
                        <div>
                            <h2 class="font-display font-bold text-2xl text-white">Device Analytics</h2>
                            <p class="text-sm font-mono text-white/60">Server: <span class="text-blue-400">${hostname || serverId}</span></p>
                        </div>
                    </div>
                    <button id="close-analytics-btn" class="w-8 h-8 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center text-white/60 hover:text-white transition-colors">
                        <i class="fas fa-times"></i>
                    </button>
                </div>

                <!-- Content -->
                <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">
                    <!-- Top Stats -->
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-6" id="analytics-stats-row">
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">Total Logs</div>
                            <div class="text-2xl font-display font-bold text-green-500" id="stat-total-logs">-</div>
                        </div>
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">Total Alerts</div>
                            <div class="text-2xl font-display font-bold text-blue-500" id="stat-total-alerts">-</div>
                        </div>
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">Active Alerts</div>
                            <div class="text-2xl font-display font-bold text-purple-500" id="stat-active-alerts">-</div>
                        </div>
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">Last Seen</div>
                            <div class="text-lg font-display font-bold text-orange-500" id="stat-last-seen">-</div>
                        </div>
                    </div>

                    <!-- Data Table -->
                    <div class="p-6 rounded-lg bg-white/5 border border-white/5">
                        <h3 class="font-bold mb-4 text-sm uppercase tracking-wider opacity-80">Server Data</h3>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left text-xs font-mono">
                                <thead class="border-b border-white/10 text-white/40">
                                    <tr>
                                        <th class="p-3">Hostname</th>
                                        <th class="p-3">IP Address</th>
                                        <th class="p-3">Type</th>
                                        <th class="p-3">Status</th>
                                        <th class="p-3 text-right">Logs</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-white/5 text-white/80" id="analytics-table-body">
                                    <tr><td colspan="5" class="p-4 text-center opacity-50">Loading data...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Event Listeners
        document.getElementById('close-analytics-btn').addEventListener('click', () => this.close());
        modal.addEventListener('click', (e) => {
            if (e.target === modal) this.close();
        });
    }

    async fetchData(hostname, serverType) {
        try {
            // Construct URL as requested
            const url = `http://localhost:8000/api/servers/?search=${encodeURIComponent(hostname)}&server_type=${encodeURIComponent(serverType)}&limit=50&offset=0`;
            console.log("Fetching analytics data from:", url);

            const response = await fetch(url);
            if (response.ok) {
                const data = await response.json();
                this.updateModalWithData(data);
            } else {
                console.error("Failed to fetch analytics data");
                document.getElementById('analytics-table-body').innerHTML = '<tr><td colspan="5" class="p-4 text-center text-red-500">Failed to load data</td></tr>';
            }
        } catch (error) {
            console.error("Error fetching analytics data:", error);
            document.getElementById('analytics-table-body').innerHTML = '<tr><td colspan="5" class="p-4 text-center text-red-500">Error connecting to server</td></tr>';
        }
    }

    updateModalWithData(data) {
        // Handle response format: could be { servers: [...] } or just [...] or single object
        let servers = [];
        if (Array.isArray(data)) {
            servers = data;
        } else if (data.servers && Array.isArray(data.servers)) {
            servers = data.servers;
        } else if (data.id && data.hostname) {
            servers = [data]; // Single object
        }

        // Update Stats (using the first server if available)
        if (servers.length > 0) {
            const server = servers[0];
            if (server.stats) {
                document.getElementById('stat-total-logs').innerText = (server.stats.total_logs || 0).toLocaleString();
                document.getElementById('stat-total-alerts').innerText = (server.stats.total_alerts || 0).toLocaleString();
                document.getElementById('stat-active-alerts').innerText = (server.stats.active_alerts || 0).toLocaleString();

                const lastSeen = server.stats.last_seen ? new Date(server.stats.last_seen).toLocaleString() : 'Never';
                document.getElementById('stat-last-seen').innerText = lastSeen;
            }
        }

        // Update Table
        const tbody = document.getElementById('analytics-table-body');
        if (servers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center opacity-50">No matching servers found</td></tr>';
            return;
        }

        tbody.innerHTML = servers.map(server => `
            <tr class="hover:bg-white/5 transition-colors">
                <td class="p-3 font-bold text-white">${server.hostname}</td>
                <td class="p-3 opacity-80">${server.ip_address}</td>
                <td class="p-3 opacity-80 capitalize">${server.server_type}</td>
                <td class="p-3">
                    <span class="${server.status === 'online' ? 'text-green-500' : 'text-red-500'} font-bold text-[10px] uppercase tracking-wider">
                        ${server.status}
                    </span>
                </td>
                <td class="p-3 text-right font-mono">${(server.stats?.total_logs || 0).toLocaleString()}</td>
            </tr>
        `).join('');
    }
}

// Global instance
window.analyticsComponent = new AnalyticsComponent();
