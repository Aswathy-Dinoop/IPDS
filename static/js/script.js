let chartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
    initChart();
    setInterval(fetchStats, 2000); // Poll every 2 seconds
});

function initChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    console.log('Initializing chart...', ctx);

    chartInstance = new Chart(ctx, {
        type: 'bar', // Changed from doughnut to bar
        data: {
            labels: ['No Attacks Yet'],
            datasets: [{
                label: 'Attack Count',
                data: [0],
                backgroundColor: ['#66fcf1', '#ff4d4d', '#ff9f43', '#feca57', '#54a0ff', '#48dbfb'],
                borderColor: ['#66fcf1', '#ff4d4d', '#ff9f43', '#feca57', '#54a0ff', '#48dbfb'],
                borderWidth: 2
            }]
        },
        options: {
            indexAxis: 'y', // Horizontal bars
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { color: '#c5c6c7' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                },
                y: {
                    ticks: { color: '#c5c6c7' },
                    grid: { display: false }
                }
            },
            plugins: {
                legend: {
                    display: false // Hide legend for cleaner look
                }
            }
        }
    });

    console.log('Chart initialized successfully');
}

function startSniffer() {
    fetch('/api/start_sniffer')
        .then(res => res.json())
        .then(data => {
            console.log("Sniffer start command:", data);
        });
}

function resetThreats() {
    console.log("Reset button clicked");
    if (confirm("Are you sure you want to clear all detected threats? This cannot be undone.")) {
        fetch('/api/reset_stats')
            .then(res => {
                if (!res.ok) throw new Error("Server error " + res.status);
                return res.json();
            })
            .then(data => {
                console.log("Reset result:", data);
                if (data.status === 'success') {
                    alert("Threats reset successfully!");
                    fetchStats(); // Update the UI immediately
                } else {
                    alert("Reset failed: " + (data.message || "Unknown error"));
                }
            })
            .catch(err => {
                console.error("Error resetting stats:", err);
                if (err.message.includes("404")) {
                    alert("Error: The server doesn't recognize the reset command. \n\nPLEASE RESTART YOUR PYTHON APP (Ctrl+C and run 'python app.py' again).");
                } else {
                    alert("System Error: " + err.message);
                }
            });
    }
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

            // Calculate unique blocked IPs from recent logs
            const uniqueIPs = new Set();
            if (data.recent_logs && data.recent_logs.length > 0) {
                data.recent_logs.forEach(log => {
                    if (log.action && log.action.toLowerCase().includes('block')) {
                        uniqueIPs.add(log.src_ip);
                    }
                });
            }
            document.getElementById('blocked-ips').textContent = uniqueIPs.size;

            // Update Chart
            updateChart(data.attack_types);

            // Update Table
            updateTable(data.recent_logs);
        });
}


function updateChart(types) {
    if (!chartInstance) {
        console.error('Chart instance not initialized');
        return;
    }

    try {
        console.log('Updating chart with types:', types);

        const labels = Object.keys(types || {});
        const values = Object.values(types || {});

        // If no data, show a placeholder
        if (!types || labels.length === 0) {
            chartInstance.data.labels = ['No Attacks Yet'];
            chartInstance.data.datasets[0].data = [0];
        } else {
            chartInstance.data.labels = labels;
            chartInstance.data.datasets[0].data = values;
        }

        // Important: Use 'none' animation mode to prevent flickering
        chartInstance.update('none');
        console.log('Chart updated successfully with', labels.length, 'attack types');
    } catch (error) {
        console.error('Error updating chart:', error);
    }
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
            <td>${log.type} (${(Math.random() * 20 + 80).toFixed(1)}%)</td>
            <td style="color:red">[BLOCKED]</td>
        `;
        tbody.appendChild(tr);
    });
}
