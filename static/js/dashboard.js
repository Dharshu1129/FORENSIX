document.addEventListener('DOMContentLoaded', function () {
    const evCanvas = document.getElementById('chart-evidence-types');
    const sevCanvas = document.getElementById('chart-findings-severity');
    const artCanvas = document.getElementById('chart-artifact-dist');

    if (!evCanvas || !sevCanvas || !artCanvas) return;

    // Common Chart Config Defaults
    Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
    Chart.defaults.color = "#94A3B8";

    fetch('/api/dashboard/charts')
        .then(response => response.json())
        .then(data => {
            // 1. Evidence Types Chart
            new Chart(evCanvas, {
                type: 'doughnut',
                data: {
                    labels: data.evidence_types.labels,
                    datasets: [{
                        data: data.evidence_types.data,
                        backgroundColor: ['#0EA5E9', '#06B6D4', '#6366F1', '#8B5CF6', '#EC4899', '#F59E0B'],
                        borderWidth: 2,
                        borderColor: '#0D1322',
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#94A3B8', font: { size: 11, weight: '500' }, padding: 15 } }
                    }
                }
            });

            // 2. Findings Severity Chart
            new Chart(sevCanvas, {
                type: 'bar',
                data: {
                    labels: data.findings_severity.labels,
                    datasets: [{
                        label: 'Findings Count',
                        data: data.findings_severity.data,
                        backgroundColor: ['#EF4444', '#F97316', '#F59E0B', '#3B82F6'],
                        borderRadius: 6,
                        barThickness: 28
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { ticks: { color: '#94A3B8', font: { weight: '600' } }, grid: { display: false } },
                        y: { ticks: { color: '#64748B', precision: 0 }, grid: { color: 'rgba(30, 41, 61, 0.5)' } }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });

            // 3. Artifact Distribution Chart
            new Chart(artCanvas, {
                type: 'pie',
                data: {
                    labels: data.artifact_distribution.labels,
                    datasets: [{
                        data: data.artifact_distribution.data,
                        backgroundColor: ['#10B981', '#F59E0B', '#6366F1', '#EC4899', '#14B8A6'],
                        borderWidth: 2,
                        borderColor: '#0D1322'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#94A3B8', font: { size: 11, weight: '500' }, padding: 15 } }
                    }
                }
            });
        })
        .catch(err => console.error("Error loading dashboard chart data:", err));
});
