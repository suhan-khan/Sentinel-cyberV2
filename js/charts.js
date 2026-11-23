/**
 * Sentinel Cyber — Chart.js Visualization Engine
 * SOC Theme: Deep Navy, Electric Blue & Cyber Cyan
 * Renders real-time telemetry, model prediction metrics, and longitudinal analytics.
 */

window.Charts = {
  instances: {},

  getChartColors() {
    return {
      cyan: '#00E5FF',
      blue: '#3B82F6',
      purple: '#8B5CF6',
      pink: '#EC4899',
      green: '#10B981',
      yellow: '#F59E0B',
      orange: '#F97316',
      red: '#EF4444',
      cardBg: '#10192E',
      textPrimary: '#F1F5F9',
      textMuted: '#94A3B8',
      gridColor: 'rgba(255, 255, 255, 0.06)'
    };
  },

  getDefaultOptions(overrides = {}) {
    const c = this.getChartColors();

    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: c.textMuted,
            font: { family: "'Inter', sans-serif", size: 12 },
            boxWidth: 12,
            usePointStyle: true
          }
        },
        tooltip: {
          backgroundColor: 'rgba(12, 18, 34, 0.95)',
          titleColor: c.cyan,
          bodyColor: c.textPrimary,
          borderColor: '#1E2D4A',
          borderWidth: 1,
          cornerRadius: 8,
          padding: 10
        }
      },
      scales: {
        x: {
          grid: { color: c.gridColor },
          ticks: { color: c.textMuted }
        },
        y: {
          grid: { color: c.gridColor },
          ticks: { color: c.textMuted }
        }
      },
      ...overrides
    };
  },

  destroyChart(canvasId) {
    if (this.instances[canvasId]) {
      this.instances[canvasId].destroy();
      delete this.instances[canvasId];
    }
  },

  destroyAll() {
    Object.keys(this.instances).forEach(id => this.destroyChart(id));
  },

  createTrafficOverviewChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();
    const ctx = el.getContext('2d');

    const gradNormal = ctx.createLinearGradient(0, 0, 0, 300);
    gradNormal.addColorStop(0, 'rgba(0, 229, 255, 0.25)');
    gradNormal.addColorStop(1, 'rgba(0, 229, 255, 0.00)');

    const gradThreat = ctx.createLinearGradient(0, 0, 0, 300);
    gradThreat.addColorStop(0, 'rgba(239, 68, 68, 0.30)');
    gradThreat.addColorStop(1, 'rgba(239, 68, 68, 0.00)');

    this.instances[canvasId] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels || [],
        datasets: [
          {
            label: 'Normal Traffic',
            data: data.normal || [],
            borderColor: c.cyan,
            backgroundColor: gradNormal,
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: c.cyan
          },
          {
            label: 'Suspicious / Malicious',
            data: data.suspicious || [],
            borderColor: c.red,
            backgroundColor: gradThreat,
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: c.red
          }
        ]
      },
      options: this.getDefaultOptions()
    });
  },

  createThreatDistributionChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();

    this.instances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: data.labels || [],
        datasets: [{
          data: data.values || [],
          backgroundColor: data.colors || [c.green, c.red, c.orange, c.blue, c.purple, c.pink],
          borderWidth: 0,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: c.textMuted,
              font: { size: 11 },
              usePointStyle: true
            }
          },
          tooltip: {
            backgroundColor: 'rgba(12, 18, 34, 0.95)',
            titleColor: c.cyan,
            bodyColor: c.textPrimary,
            borderColor: '#1E2D4A',
            borderWidth: 1
          }
        },
        cutout: '70%'
      }
    });
  },

  createAttackTypesChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();

    this.instances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels: data.labels || [],
        datasets: [{
          label: 'Detected Incidents',
          data: data.values || [],
          backgroundColor: [c.red, c.orange, c.blue, c.purple, c.pink],
          borderRadius: 4
        }]
      },
      options: {
        ...this.getDefaultOptions(),
        indexAxis: 'y',
        plugins: { legend: { display: false } }
      }
    });
  },

  createThreatSeverityChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();

    this.instances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          label: 'Count',
          data: data.values || [0, 0, 0, 0],
          backgroundColor: [c.red, c.orange, c.yellow, c.green],
          borderRadius: 6
        }]
      },
      options: {
        ...this.getDefaultOptions(),
        plugins: { legend: { display: false } }
      }
    });
  },

  createProtocolDistributionChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();

    this.instances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: data.labels || [],
        datasets: [{
          data: data.values || [],
          backgroundColor: data.colors || [c.cyan, c.blue, c.green, c.orange, c.purple, c.pink],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: c.textMuted, usePointStyle: true }
          }
        },
        cutout: '65%'
      }
    });
  },

  createTrafficTrendChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();

    this.instances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'line',
      data: {
        labels: data.labels || [],
        datasets: [
          {
            label: 'Normal Records',
            data: data.normal || [],
            borderColor: c.green,
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            borderWidth: 2,
            tension: 0.3,
            fill: true
          },
          {
            label: 'Malicious Records',
            data: data.suspicious || [],
            borderColor: c.red,
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            borderWidth: 2,
            tension: 0.3,
            fill: true
          }
        ]
      },
      options: this.getDefaultOptions()
    });
  },

  createNormalVsMaliciousChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();

    this.instances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels: data.labels || ['Current Analysis'],
        datasets: [
          {
            label: 'Normal Flow Records',
            data: data.normal || [],
            backgroundColor: c.cyan,
            borderRadius: 4
          },
          {
            label: 'Malicious Flow Records',
            data: data.malicious || [],
            backgroundColor: c.red,
            borderRadius: 4
          }
        ]
      },
      options: this.getDefaultOptions()
    });
  },

  createDetectionStatsChart(canvasId, data) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;

    this.destroyChart(canvasId);
    const c = this.getChartColors();

    this.instances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels: data.labels || [],
        datasets: [{
          label: 'Detected Threats',
          data: data.values || [],
          backgroundColor: c.blue,
          borderRadius: 6
        }]
      },
      options: {
        ...this.getDefaultOptions(),
        plugins: { legend: { display: false } }
      }
    });
  },

  updateFromPredictions(predictions) {
    if (!Array.isArray(predictions) || predictions.length === 0) return;

    const normal = predictions.filter(item =>
      ['normal', 'benign'].includes(String(item.classification || '').toLowerCase())
    ).length;

    const malicious = predictions.length - normal;
    const severityLabels = ['Critical', 'High', 'Medium', 'Low'];

    const severityCounts = severityLabels.map(severity =>
      predictions.filter(item =>
        String(item.severity || '').toLowerCase() === severity.toLowerCase()
      ).length
    );

    const normalMaliciousCanvas = document.getElementById('normal-vs-malicious-chart');
    if (normalMaliciousCanvas) {
      this.createNormalVsMaliciousChart('normal-vs-malicious-chart', {
        labels: ['Current Analysis'],
        normal: [normal],
        malicious: [malicious]
      });
    }

    const severityCanvas = document.getElementById('threat-severity-chart');
    if (severityCanvas) {
      this.createThreatSeverityChart('threat-severity-chart', { values: severityCounts });
    }
  }
};
