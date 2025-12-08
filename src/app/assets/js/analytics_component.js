
class AnalyticsComponent {
    constructor() {
        this.modalId = 'analytics-modal';
        this.chartInstances = [];
    }

    open(serverId) {
        this.close(); // Close existing if any
        this.createModal(serverId);
        this.renderCharts(serverId);
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

    createModal(serverId) {
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
                            <p class="text-sm font-mono text-white/60">Server ID: <span class="text-blue-400">${serverId}</span></p>
                        </div>
                    </div>
                    <button id="close-analytics-btn" class="w-8 h-8 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center text-white/60 hover:text-white transition-colors">
                        <i class="fas fa-times"></i>
                    </button>
                </div>

                <!-- Content -->
                <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">
                    <!-- Top Stats -->
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">Uptime</div>
                            <div class="text-2xl font-display font-bold text-green-500">99.9%</div>
                        </div>
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">CPU Usage</div>
                            <div class="text-2xl font-display font-bold text-blue-500">45%</div>
                        </div>
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">Memory</div>
                            <div class="text-2xl font-display font-bold text-purple-500">8.2 GB</div>
                        </div>
                        <div class="p-4 rounded-lg bg-white/5 border border-white/5">
                            <div class="text-xs font-mono uppercase opacity-60 mb-2">Network I/O</div>
                            <div class="text-2xl font-display font-bold text-orange-500">1.2 Gbps</div>
                        </div>
                    </div>

                    <!-- Charts Row -->
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 h-96">
                        <div class="p-6 rounded-lg bg-white/5 border border-white/5 flex flex-col">
                            <h3 class="font-bold mb-4 text-sm uppercase tracking-wider opacity-80">Traffic Analysis</h3>
                            <div class="flex-1 relative">
                                <canvas id="analytics-traffic-chart"></canvas>
                            </div>
                        </div>
                        <div class="p-6 rounded-lg bg-white/5 border border-white/5 flex flex-col">
                            <h3 class="font-bold mb-4 text-sm uppercase tracking-wider opacity-80">Resource Utilization</h3>
                            <div class="flex-1 relative">
                                <canvas id="analytics-resource-chart"></canvas>
                            </div>
                        </div>
                    </div>

                    <!-- Logs Preview -->
                    <div class="p-6 rounded-lg bg-white/5 border border-white/5">
                        <h3 class="font-bold mb-4 text-sm uppercase tracking-wider opacity-80">Recent Activity</h3>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left text-xs font-mono">
                                <thead class="border-b border-white/10 text-white/40">
                                    <tr>
                                        <th class="p-3">Timestamp</th>
                                        <th class="p-3">Event</th>
                                        <th class="p-3">Severity</th>
                                        <th class="p-3 text-right">Status</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-white/5 text-white/80">
                                    <tr>
                                        <td class="p-3 opacity-60">2023-10-27 10:45:12</td>
                                        <td class="p-3">SSH Login Successful</td>
                                        <td class="p-3 text-green-500">INFO</td>
                                        <td class="p-3 text-right">Success</td>
                                    </tr>
                                    <tr>
                                        <td class="p-3 opacity-60">2023-10-27 10:42:05</td>
                                        <td class="p-3">Port Scan Detected</td>
                                        <td class="p-3 text-orange-500">WARNING</td>
                                        <td class="p-3 text-right">Blocked</td>
                                    </tr>
                                    <tr>
                                        <td class="p-3 opacity-60">2023-10-27 10:30:00</td>
                                        <td class="p-3">System Update</td>
                                        <td class="p-3 text-blue-500">INFO</td>
                                        <td class="p-3 text-right">Completed</td>
                                    </tr>
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

    renderCharts(serverId) {
        // Traffic Chart
        const ctxTraffic = document.getElementById('analytics-traffic-chart').getContext('2d');
        const trafficChart = new Chart(ctxTraffic, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'Inbound',
                    data: [12, 19, 3, 5, 2, 3].map(x => x * Math.random() * 10),
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Outbound',
                    data: [8, 11, 13, 9, 12, 15].map(x => x * Math.random() * 10),
                    borderColor: '#a855f7',
                    backgroundColor: 'rgba(168, 85, 247, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#fff' }
                    }
                },
                scales: {
                    y: {
                        grid: { color: 'rgba(255,255,255,0.1)' },
                        ticks: { color: 'rgba(255,255,255,0.5)' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: 'rgba(255,255,255,0.5)' }
                    }
                }
            }
        });
        this.chartInstances.push(trafficChart);

        // Resource Chart
        const ctxResource = document.getElementById('analytics-resource-chart').getContext('2d');
        const resourceChart = new Chart(ctxResource, {
            type: 'doughnut',
            data: {
                labels: ['CPU', 'Memory', 'Disk', 'Network'],
                datasets: [{
                    data: [45, 25, 15, 15],
                    backgroundColor: [
                        '#3b82f6',
                        '#a855f7',
                        '#22c55e',
                        '#f97316'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#fff' }
                    }
                }
            }
        });
        this.chartInstances.push(resourceChart);
    }
}

// Global instance
window.analyticsComponent = new AnalyticsComponent();
