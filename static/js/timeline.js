document.addEventListener('DOMContentLoaded', function () {
    const timelineCanvas = document.getElementById('chart-timeline-events');
    const caseSelect = document.getElementById('timeline-case-select');
    const typeFilter = document.getElementById('filter-artifact-type');
    const severityFilter = document.getElementById('filter-severity');
    const searchInput = document.getElementById('timeline-search');

    if (!caseSelect) return;

    let chartInstance = null;

    function loadTimelineData() {
        const caseId = caseSelect.value;
        if (!caseId) return;

        const type = typeFilter ? typeFilter.value : 'ALL';
        const severity = severityFilter ? severityFilter.value : 'ALL';
        const q = searchInput ? searchInput.value : '';

        const url = `/api/timeline/${caseId}?type=${encodeURIComponent(type)}&severity=${encodeURIComponent(severity)}&q=${encodeURIComponent(q)}`;

        fetch(url)
            .then(res => res.json())
            .then(data => {
                renderTimelineChart(data.events);
            })
            .catch(err => console.error("Error fetching timeline events:", err));
    }

    function renderTimelineChart(events) {
        if (!timelineCanvas) return;

        const ctx = timelineCanvas.getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(14, 165, 233, 0.4)');
        gradient.addColorStop(1, 'rgba(14, 165, 233, 0.0)');

        // Aggregate events by date
        const dateCounts = {};
        events.forEach(e => {
            if (!e.timestamp) return;
            const dateStr = e.timestamp.split('T')[0];
            dateCounts[dateStr] = (dateCounts[dateStr] || 0) + 1;
        });

        const sortedDates = Object.keys(dateCounts).sort();
        const counts = sortedDates.map(d => dateCounts[d]);

        if (chartInstance) {
            chartInstance.destroy();
        }

        chartInstance = new Chart(timelineCanvas, {
            type: 'line',
            data: {
                labels: sortedDates,
                datasets: [{
                    label: 'Forensic Events',
                    data: counts,
                    borderColor: '#38BDF8',
                    borderWidth: 3,
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 4,
                    pointHoverRadius: 7,
                    pointBackgroundColor: '#06B6D4',
                    pointBorderColor: '#FFFFFF',
                    pointBorderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#94A3B8' }, grid: { color: 'rgba(30, 41, 61, 0.4)' } },
                    y: { ticks: { color: '#64748B', precision: 0 }, grid: { color: 'rgba(30, 41, 61, 0.4)' } }
                },
                plugins: {
                    legend: { labels: { color: '#94A3B8', font: { weight: '600' } } }
                }
            }
        });
    }

    if (caseSelect) caseSelect.addEventListener('change', loadTimelineData);
    if (typeFilter) typeFilter.addEventListener('change', loadTimelineData);
    if (severityFilter) severityFilter.addEventListener('change', loadTimelineData);
    if (searchInput) searchInput.addEventListener('keyup', loadTimelineData);

    // Initial load
    loadTimelineData();
});
