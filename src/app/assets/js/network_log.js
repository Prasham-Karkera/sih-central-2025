class NetworkLogComponent {
    constructor() {
        this.containerId = 'view-network-log';
        this.initialized = false;
    }

    init() {
        if (this.initialized) return;
        this.render();
        this.initialized = true;
    }

    render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        container.innerHTML = `
            <div class="panel p-6 rounded-lg h-[calc(100vh-8rem)] flex flex-col animate-fade-in">
                <div class="flex justify-between items-center mb-6">
                    <div class="flex items-center gap-4">
                        <div class="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center text-purple-500">
                            <i class="fas fa-network-wired text-xl"></i>
                        </div>
                        <div>
                            <h2 class="font-display font-bold text-2xl">Network Logs</h2>
                            <p class="text-sm font-mono opacity-60">Real-time Network Traffic Analysis</p>
                        </div>
                    </div>
                    <div class="flex gap-2">
                         <div class="relative">
                            <i class="fas fa-search absolute left-3 top-1/2 transform -translate-y-1/2 opacity-40"></i>
                            <input type="text" placeholder="Search IP, Port, Protocol..." class="bg-black/20 border border-white/10 rounded-lg py-2 pl-10 pr-4 outline-none focus:border-purple-500/50 transition-all font-mono text-xs w-64">
                        </div>
                        <button onclick="window.networkLogComponent.refresh()" class="px-4 py-2 rounded bg-white/10 hover:bg-white/20 text-white text-xs font-bold transition-colors">
                            <i class="fas fa-sync mr-2"></i> Refresh
                        </button>
                    </div>
                </div>

                <!-- Stats Row -->
                <div class="grid grid-cols-4 gap-4 mb-6">
                    <div class="panel p-4 rounded bg-white/5 border border-white/5 flex flex-col gap-1">
                        <span class="text-[10px] font-mono uppercase opacity-60">Total Requests</span>
                        <span class="text-xl font-display font-bold">24,592</span>
                    </div>
                    <div class="panel p-4 rounded bg-white/5 border border-white/5 flex flex-col gap-1">
                        <span class="text-[10px] font-mono uppercase opacity-60">Inbound Traffic</span>
                        <span class="text-xl font-display font-bold text-blue-400">1.2 GB</span>
                    </div>
                    <div class="panel p-4 rounded bg-white/5 border border-white/5 flex flex-col gap-1">
                        <span class="text-[10px] font-mono uppercase opacity-60">Outbound Traffic</span>
                        <span class="text-xl font-display font-bold text-green-400">840 MB</span>
                    </div>
                    <div class="panel p-4 rounded bg-white/5 border border-white/5 flex flex-col gap-1">
                        <span class="text-[10px] font-mono uppercase opacity-60">Blocked</span>
                        <span class="text-xl font-display font-bold text-red-400">142</span>
                    </div>
                </div>

                <!-- Table -->
                <div class="flex-1 overflow-auto custom-scrollbar bg-black/20 rounded border border-white/5 relative">
                    <table class="w-full text-left text-xs font-mono">
                        <thead class="sticky top-0 z-10 bg-[#111] border-b border-white/10 uppercase tracking-wider text-white/40">
                            <tr>
                                <th class="p-3 w-24">Time</th>
                                <th class="p-3 w-32">Source IP</th>
                                <th class="p-3 w-32">Dest IP</th>
                                <th class="p-3 w-20">Proto</th>
                                <th class="p-3 w-20">Port</th>
                                <th class="p-3">Info</th>
                                <th class="p-3 w-24 text-right">Status</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-white/5 text-white/80" id="network-logs-body">
                            <!-- Logs will be injected here -->
                        </tbody>
                    </table>
                </div>
                
                <!-- Pagination -->
                 <div class="mt-4 flex justify-between items-center border-t border-white/10 pt-4">
                    <span class="text-xs opacity-60 font-mono">Showing 1-15 of 24592</span>
                    <div class="flex gap-2">
                        <button class="px-3 py-1.5 rounded bg-white/5 hover:bg-white/10 text-xs font-bold transition disabled:opacity-30" disabled>Previous</button>
                        <button class="px-3 py-1.5 rounded bg-white/5 hover:bg-white/10 text-xs font-bold transition">Next</button>
                    </div>
                </div>
            </div>
        `;

        this.loadDummyData();
    }

    refresh() {
        const tbody = document.getElementById('network-logs-body');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center opacity-40">Refreshing...</td></tr>';
            setTimeout(() => this.loadDummyData(), 500);
        }
    }

    loadDummyData() {
        const tbody = document.getElementById('network-logs-body');
        if (!tbody) return;

        const protos = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
        const statuses = ['Allowed', 'Blocked', 'Filtered'];
        const rows = [];

        for (let i = 0; i < 15; i++) {
            const time = new Date().toLocaleTimeString();
            const src = `192.168.1.${Math.floor(Math.random() * 255)}`;
            const dst = `10.0.0.${Math.floor(Math.random() * 255)}`;
            const proto = protos[Math.floor(Math.random() * protos.length)];
            const port = Math.floor(Math.random() * 65535);
            const status = statuses[Math.floor(Math.random() * statuses.length)];

            let statusColor = 'text-green-500';
            if (status === 'Blocked') statusColor = 'text-red-500';
            if (status === 'Filtered') statusColor = 'text-yellow-500';

            rows.push(`
                <tr class="hover:bg-white/5 transition-colors">
                    <td class="p-3 opacity-60">${time}</td>
                    <td class="p-3 text-blue-400">${src}</td>
                    <td class="p-3 text-purple-400">${dst}</td>
                    <td class="p-3 opacity-80">${proto}</td>
                    <td class="p-3 opacity-80">${port}</td>
                    <td class="p-3 opacity-60 truncate max-w-xs">Packet length: ${Math.floor(Math.random() * 1500)} bytes, TTL: ${Math.floor(Math.random() * 128)}</td>
                    <td class="p-3 text-right font-bold ${statusColor}">${status}</td>
                </tr>
            `);
        }

        tbody.innerHTML = rows.join('');
    }
}

window.networkLogComponent = new NetworkLogComponent();
