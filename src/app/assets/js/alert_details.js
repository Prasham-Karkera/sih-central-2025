
class AlertDetailsManager {
    constructor() {
        this.currentPage = 0;
        this.limit = 20;
        this.currentFilter = 'all'; // all, critical, warning, info
        this.alertsCache = [];
    }

    init() {
        this.fetchAlerts();
        this.setupListeners();
    }

    setupListeners() {
        // Filter buttons
        document.querySelectorAll('.alert-filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                // Update active state
                document.querySelectorAll('.alert-filter-btn').forEach(b => {
                    b.classList.remove('bg-white/10', 'text-white', 'shadow');
                    b.classList.add('opacity-60');
                });
                e.currentTarget.classList.remove('opacity-60');
                e.currentTarget.classList.add('bg-white/10', 'text-white', 'shadow');

                this.currentFilter = e.currentTarget.dataset.filter;
                this.currentPage = 0;
                this.fetchAlerts();
            });
        });
    }

    setFilter(filter) {
        // Find the button for this filter
        const btn = document.querySelector(`.alert-filter-btn[data-filter="${filter}"]`);
        if (btn) {
            btn.click();
        }
    }

    async fetchAlerts() {
        const tbody = document.getElementById('alerts-table-body');

        if (!tbody) return;

        tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center opacity-50"><i class="fas fa-circle-notch fa-spin mr-2"></i> Loading alerts...</td></tr>';

        try {
            let url = `/api/alerts/?limit=${this.limit}&offset=${this.currentPage * this.limit}`;

            // Map UI filter (critical, warning, info) to API severity (high, medium, low)
            if (this.currentFilter !== 'all') {
                let apiSeverity = this.currentFilter;
                if (this.currentFilter === 'critical') apiSeverity = 'high';
                else if (this.currentFilter === 'warning') apiSeverity = 'medium';
                else if (this.currentFilter === 'info') apiSeverity = 'low';

                url += `&severity=${apiSeverity}`;
            }

            const res = await fetch(url);
            if (res.ok) {
                const data = await res.json();

                // Sort alerts: Critical/High > Warning/Medium > Info/Low
                const severityOrder = {
                    'critical': 0, 'high': 0,
                    'warning': 1, 'medium': 1,
                    'info': 2, 'low': 2
                };

                if (data.alerts && Array.isArray(data.alerts)) {
                    data.alerts.sort((a, b) => {
                        const sevA = a.severity ? a.severity.toLowerCase() : 'low';
                        const sevB = b.severity ? b.severity.toLowerCase() : 'low';
                        return (severityOrder[sevA] ?? 2) - (severityOrder[sevB] ?? 2);
                    });
                }

                this.alertsCache = data.alerts || [];
                this.renderTable(this.alertsCache, data.total || 0);
            } else {
                tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center text-red-500">Failed to load alerts</td></tr>';
            }
        } catch (e) {
            console.error(e);
            tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center text-red-500">Error connecting to server</td></tr>';
        }
    }

    renderTable(alerts, total) {
        const tbody = document.getElementById('alerts-table-body');
        const paginationInfo = document.getElementById('alerts-pagination-info');
        const btnPrev = document.getElementById('btn-prev-alerts');
        const btnNext = document.getElementById('btn-next-alerts');

        if (!tbody) return;

        if (!alerts || alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center opacity-50">No alerts found</td></tr>';
            if (paginationInfo) paginationInfo.innerText = 'Showing 0-0 of 0';
            if (btnPrev) btnPrev.disabled = true;
            if (btnNext) btnNext.disabled = true;
            return;
        }

        tbody.innerHTML = alerts.map(alert => {
            // Robust data extraction
            const id = alert.id || '-';
            const title = alert.title || 'Untitled';
            const description = alert.description || '';
            let severity = alert.severity ? alert.severity.toLowerCase() : 'info';
            const resolved = !!alert.resolved;
            const hostname = alert.server ? alert.server.hostname : 'Unknown';

            // Map severity to display values
            if (severity === 'low') severity = 'info';
            else if (severity === 'high') severity = 'critical';
            else if (severity === 'medium') severity = 'warning';

            // False Positives extraction
            let falsePositives = '-';
            if (alert.metadata && alert.metadata.false_positives) {
                const fp = alert.metadata.false_positives;
                falsePositives = Array.isArray(fp) ? fp.join(', ') : String(fp);
            }

            // Styling
            let severityClass = 'text-blue-500';
            if (severity === 'critical') severityClass = 'text-red-500';
            else if (severity === 'warning') severityClass = 'text-orange-500';

            const statusClass = resolved ? 'text-green-500' : 'text-red-500';
            const statusText = resolved ? 'Resolved' : 'Active';

            return `
                <tr class="table-row transition-colors hover:bg-white/5 group">
                    <td class="p-4 border-b border-white/5 text-xs opacity-60">#${id}</td>
                    <td class="p-4 border-b border-white/5 font-bold text-sm">${title}</td>
                    <td class="p-4 border-b border-white/5 text-xs opacity-80 max-w-[300px] truncate" title="${description.replace(/"/g, '&quot;')}">${description}</td>
                    <td class="p-4 border-b border-white/5">
                        <button onclick="alertDetailsManager.setFilter('${severity}')" class="font-bold uppercase text-xs ${severityClass} hover:opacity-80 transition-opacity">
                            ${severity}
                        </button>
                    </td>
                    <td class="p-4 border-b border-white/5">
                        <span class="font-bold uppercase text-xs ${statusClass}">
                            ${statusText}
                        </span>
                    </td>
                    <td class="p-4 border-b border-white/5 text-xs opacity-60">${falsePositives}</td>
                    <td class="p-4 border-b border-white/5 text-xs font-mono opacity-80">${hostname}</td>
                </tr>
            `;
        }).join('');

        // Pagination
        if (paginationInfo) {
            const start = this.currentPage * this.limit + 1;
            const end = Math.min((this.currentPage + 1) * this.limit, total);
            paginationInfo.innerText = `Showing ${start}-${end} of ${total}`;
        }

        if (btnPrev) btnPrev.disabled = this.currentPage === 0;
        if (btnNext) btnNext.disabled = (this.currentPage + 1) * this.limit >= total;
    }

    changePage(delta) {
        this.currentPage += delta;
        if (this.currentPage < 0) this.currentPage = 0;
        this.fetchAlerts();
    }
}

const alertDetailsManager = new AlertDetailsManager();
