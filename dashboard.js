/**
 * Cybersecurity Defensive Log Analyzer - Interactive Frontend Engine
 * BUILDERS Phase 2
 */

// Toast notification helper
function showToast(message, type = 'info') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'cyber-toast';
  
  let borderColor = '#06b6d4';
  if (type === 'success') borderColor = '#10b981';
  if (type === 'danger' || type === 'error') borderColor = '#ef4444';
  if (type === 'warning') borderColor = '#f59e0b';
  
  toast.style.borderLeftColor = borderColor;
  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Chart.js helper references
let outcomeChartInstance = null;
let timelineChartInstance = null;
let usersChartInstance = null;
let ipsChartInstance = null;

// Initialize Dashboard Charts
function initDashboardCharts(chartData) {
  if (typeof Chart === 'undefined') return;

  // 1. Outcome Doughnut Chart
  const outcomeCanvas = document.getElementById('outcomeChart');
  if (outcomeCanvas && chartData.outcome) {
    if (outcomeChartInstance) outcomeChartInstance.destroy();
    outcomeChartInstance = new Chart(outcomeCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Successful Logins', 'Failed Logins', 'Malformed Records'],
        datasets: [{
          data: [chartData.outcome.success, chartData.outcome.failed, chartData.outcome.malformed || 0],
          backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
          borderColor: '#0b0f19',
          borderWidth: 2,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#94a3b8', font: { family: 'inherit', size: 12 } }
          }
        },
        cutout: '70%'
      }
    });
  }

  // 2. Timeline Activity Chart
  const timelineCanvas = document.getElementById('timelineChart');
  if (timelineCanvas && chartData.timeline) {
    if (timelineChartInstance) timelineChartInstance.destroy();
    timelineChartInstance = new Chart(timelineCanvas, {
      type: 'line',
      data: {
        labels: chartData.timeline.labels,
        datasets: [
          {
            label: 'Failed Logins',
            data: chartData.timeline.failed_series,
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            fill: true,
            tension: 0.3,
            borderWidth: 2,
            pointBackgroundColor: '#ef4444',
          },
          {
            label: 'Successful Logins',
            data: chartData.timeline.success_series,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            fill: true,
            tension: 0.3,
            borderWidth: 2,
            pointBackgroundColor: '#10b981',
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', font: { size: 11 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', font: { size: 11 } }
          }
        },
        plugins: {
          legend: {
            position: 'top',
            labels: { color: '#94a3b8' }
          }
        }
      }
    });
  }

  // 3. Top Attacked User Accounts Chart (Horizontal Bar)
  const usersCanvas = document.getElementById('topUsersChart');
  if (usersCanvas && chartData.top_users) {
    if (usersChartInstance) usersChartInstance.destroy();
    usersChartInstance = new Chart(usersCanvas, {
      type: 'bar',
      data: {
        labels: chartData.top_users.map(u => u.username),
        datasets: [{
          label: 'Failed Authentication Attempts',
          data: chartData.top_users.map(u => u.failed_count),
          backgroundColor: 'rgba(239, 68, 68, 0.75)',
          borderColor: '#ef4444',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b' }
          },
          y: {
            grid: { display: false },
            ticks: { color: '#cbd5e1', font: { weight: 600 } }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  // 4. Top Malicious Source IPs Chart (Horizontal Bar)
  const ipsCanvas = document.getElementById('topIpsChart');
  if (ipsCanvas && chartData.top_ips) {
    if (ipsChartInstance) ipsChartInstance.destroy();
    ipsChartInstance = new Chart(ipsCanvas, {
      type: 'bar',
      data: {
        labels: chartData.top_ips.map(i => i.source_ip),
        datasets: [{
          label: 'Failed Requests',
          data: chartData.top_ips.map(i => i.failed_count),
          backgroundColor: 'rgba(6, 182, 212, 0.75)',
          borderColor: '#06b6d4',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b' }
          },
          y: {
            grid: { display: false },
            ticks: { color: '#cbd5e1', font: { family: 'monospace' } }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

// Interactive Live Test Suite Runner
function runAutomatedTests() {
  const btn = document.getElementById('runTestsBtn');
  const summaryBox = document.getElementById('testSummaryBox');
  const testList = document.getElementById('testCasesContainer');

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = 'Executing Test Assertions...';
  }

  fetch('/api/run-tests', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      showToast(`Test suite execution complete: ${data.passed_tests}/${data.total_tests} passed in ${data.total_duration_ms}ms`, 'success');

      // Update Summary Header
      if (summaryBox) {
        summaryBox.innerHTML = `
          <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
            <div>
              <span class="badge ${data.all_passed ? 'badge-success' : 'badge-danger'}" style="font-size: 0.95rem; padding: 0.4rem 0.9rem;">
                ${data.all_passed ? 'ALL TESTS PASSED (100%)' : 'TESTS FAILED'}
              </span>
              <span style="margin-left: 1rem; color: var(--text-muted); font-size: 0.88rem;">
                Duration: <strong style="color: #fff;">${data.total_duration_ms} ms</strong> | Executed: ${data.executed_at}
              </span>
            </div>
            <div>
              <span style="font-size: 1.1rem; font-weight: 700; color: #34d399;">${data.passed_tests} Passed</span>
              <span style="color: var(--text-dim); margin: 0 0.5rem;">/</span>
              <span style="font-size: 1.1rem; font-weight: 700; color: ${data.failed_tests > 0 ? '#f87171' : 'var(--text-muted)'};">${data.failed_tests} Failed</span>
            </div>
          </div>
        `;
      }

      // Re-render Test Cards
      if (testList && data.test_results) {
        testList.innerHTML = data.test_results.map(t => `
          <div class="cyber-card" style="margin-bottom: 1.25rem; border-left: 4px solid ${t.status === 'PASSED' ? 'var(--green-success)' : 'var(--red-danger)'};">
            <div style="display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 0.75rem;">
              <div>
                <span class="badge badge-info" style="margin-right: 0.5rem;">${t.id}</span>
                <span style="font-weight: 700; font-size: 1.05rem; color: #fff;">${t.name}</span>
                <span class="badge badge-gray" style="margin-left: 0.5rem;">${t.category}</span>
              </div>
              <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 0.8rem; color: var(--text-dim); font-family: monospace;">${t.duration_ms} ms</span>
                <span class="badge ${t.status === 'PASSED' ? 'badge-success' : 'badge-danger'}">${t.status}</span>
              </div>
            </div>
            <p style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 0.85rem;">${t.details}</p>
            <div style="background: rgba(0, 0, 0, 0.3); border-radius: var(--radius-sm); padding: 0.75rem 1rem; border: 1px solid var(--border-subtle);">
              <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); font-weight: 700; margin-bottom: 0.4rem;">Verified Assertions (${t.assertions_checked})</div>
              <ul style="list-style: none; padding-left: 0; display: flex; flex-direction: column; gap: 0.25rem;">
                ${t.assertions_details.map(a => `
                  <li style="font-size: 0.82rem; font-family: monospace; display: flex; align-items: center; gap: 0.5rem; color: ${a.endsWith('PASS') ? '#a7f3d0' : '#fca5a5'};">
                    <span>${a.endsWith('PASS') ? '✔' : '✖'}</span>
                    <span>${a}</span>
                  </li>
                `).join('')}
              </ul>
            </div>
          </div>
        `).join('');
      }
    })
    .catch(err => {
      showToast('Error executing automated test suite: ' + err, 'error');
    })
    .finally(() => {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = 'Run Test Suite Again';
      }
    });
}

// Quick Sample Log Loader
function loadSampleLogs(fileType = 'txt') {
  fetch('/api/load-sample', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file_type: fileType })
  })
    .then(r => r.json())
    .then(data => {
      showToast(`Loaded ${data.filename}: ${data.summary.valid_records_count} valid records parsed.`, 'success');
      setTimeout(() => {
        window.location.reload();
      }, 1000);
    })
    .catch(err => {
      showToast('Failed to load sample log: ' + err, 'error');
    });
}

// Client-side Log Search & Filter
function filterLogsTable() {
  const searchInput = document.getElementById('logSearchInput');
  const statusFilter = document.getElementById('statusFilterSelect');
  const serviceFilter = document.getElementById('serviceFilterSelect');
  const table = document.getElementById('logsTable');

  if (!table) return;

  const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
  const status = statusFilter ? statusFilter.value.toUpperCase() : 'ALL';
  const service = serviceFilter ? serviceFilter.value.toUpperCase() : 'ALL';

  const rows = table.querySelectorAll('tbody tr');
  let visibleCount = 0;

  rows.forEach(row => {
    const text = row.innerText.toLowerCase();
    const rowStatus = row.getAttribute('data-status') || '';
    const rowService = row.getAttribute('data-service') || '';

    const matchesQuery = !query || text.includes(query);
    const matchesStatus = status === 'ALL' || rowStatus === status;
    const matchesService = service === 'ALL' || rowService === service;

    if (matchesQuery && matchesStatus && matchesService) {
      row.style.display = '';
      visibleCount++;
    } else {
      row.style.display = 'none';
    }
  });

  const countBadge = document.getElementById('filteredCountBadge');
  if (countBadge) {
    countBadge.innerText = `Showing ${visibleCount} records`;
  }
}
