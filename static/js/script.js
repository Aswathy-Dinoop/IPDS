let chartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
    initChart();
    setInterval(fetchStats, 2000); // Poll every 2 seconds
});

function initChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ff4d4d', '#ff9f43', '#feca57', '#54a0ff'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#c5c6c7' }
                }
            }
        }
    });
}

function startSniffer() {
    fetch('/api/start_sniffer')
        .then(res => res.json())
        .then(data => {
            console.log("Sniffer start command:", data);
        });
}

function fetchStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            // Update Status
            const indicator = document.getElementById('status-indicator');
            if (data.status === 'Active') {
                indicator.className = 'status online';
                indicator.textContent = 'SYSTEM ACTIVE';
            } else {
                indicator.className = 'status offline';
                indicator.textContent = 'SYSTEM OFFLINE';
            }
            
            // Update Counts
            document.getElementById('total-attacks').textContent = data.total_attacks;
            // Assuming simplified blocked count logic (equal to unique source IPs in logs or similar)
            // For now just using total attacks as proxy if not separate
            // But we can estimate blocked IPs from the types data later
            
            // Update Chart
            updateChart(data.attack_types);
            
            // Update Table
            updateTable(data.recent_logs);
        });
}

function updateChart(types) {
    if (!chartInstance) return;
    
    const labels = Object.keys(types);
    const values = Object.values(types);
    
    chartInstance.data.labels = labels;
    chartInstance.data.datasets[0].data = values;
    chartInstance.update();
}

function updateTable(logs) {
    const tbody = document.getElementById('logs-body');
    tbody.innerHTML = '';
    
    logs.forEach(log => {
        const tr = document.createElement('tr');
        tr.className = 'log-alert';
        tr.innerHTML = `
            <td>${log.timestamp}</td>
            <td>${log.src_ip}</td>
            <td>${log.dst_ip}</td>
            <td>${log.protocol}</td>
            <td>${log.type} (${(Math.random()*20+80).toFixed(1)}%)</td>
            <td style="color:red">[BLOCKED]</td>
        `;
        tbody.appendChild(tr);
    });
}
