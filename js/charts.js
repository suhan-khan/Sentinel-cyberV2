
/**
 * Sentinel Cyber V2 — Chart.js Visualization Engine
 * SOC Theme: Dark Purple, Violet & Lavender
 * Renders real-time telemetry, model prediction metrics, and longitudinal analytics.
 *
 * NOTE:
 * - Existing chart methods and canvas IDs are preserved.
 * - Existing prediction calculations are preserved.
 * - Visual styling only; no backend or API changes.
 */

window.Charts = {
  instances: {},

  getChartColors() {
    return {
      // Primary brand palette
      cyan: '#C084FC',
      blue: '#8B5CF6',
      purple: '#A855F7',
      pink: '#D946EF',
      lavender: '#DDD6FE',

      // Semantic status colors
      green: '#10B981',
      yellow: '#F59E0B',
      orange: '#F97316',
      red: '#EF4444',

      // Dark dashboard surfaces
      cardBg: '#15111F',
      tooltipBg: 'rgba(16, 11, 25, 0.97)',

      // Typography
      textPrimary: '#F5F3FF',
      textMuted: '#A89BB9',

      // Chart grid
      gridColor: 'rgba(192, 132, 252, 0.09)',
      borderColor: 'rgba(192, 132, 252, 0.22)'
    };
  },

  getDefaultOptions(overrides = {}) {
    const c = this.getChartColors();

    return {
      responsive: true,
      maintainAspectRatio: false,

      interaction: {
        intersect: false,
        mode: 'index'
      },

      animation: {
        duration: 650,
        easing: 'easeOutQuart'
      },

      plugins: {
        legend: {
          display: true,
          labels: {
            color: c.textMuted,
            font: {
              family: "'Inter', sans-serif",
              size: 11,
              weight: '500'
            },
            boxWidth: 9,
            boxHeight: 9,
            padding: 16,
            usePointStyle: true,
            pointStyle: 'circle'
          }
        },

        tooltip: {
          enabled: true,
          backgroundColor: c.tooltipBg,
          titleColor: c.cyan,
          bodyColor: c.textPrimary,
          borderColor: c.borderColor,
          borderWidth: 1,
          cornerRadius: 9,
          padding: 12,
          displayColors: true,
          titleFont: {
            family: "'Inter', sans-serif",
            size: 12,
            weight: '600'
          },
          bodyFont: {
            family: "'Inter', sans-serif",
            size: 11
          },
          boxPadding: 5,
          usePointStyle: true
        }
      },

      scales: {
        x: {
          border: {
            display: false
          },
          grid: {
            color: c.gridColor,
            drawTicks: false
          },
          ticks: {
            color: c.textMuted,
            font: {
              family: "'Inter', sans-serif",
              size: 10
            },
            padding: 9
          }
        },

        y: {
          border: {
            display: false
          },
          grid: {
            color: c.gridColor,
            drawTicks: false
          },
          ticks: {
            color: c.textMuted,
            font: {
              family: "'Inter', sans-serif",
              size: 10
            },
            padding: 9
          },
          beginAtZero: true
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
    gradNormal.addColorStop(0, 'rgba(168, 85, 247, 0.30)');
    gradNormal.addColorStop(1, 'rgba(168, 85, 247, 0.00)');

    const gradThreat = ctx.createLinearGradient(0, 0, 0, 300);
    gradThreat.addColorStop(0, 'rgba(239, 68, 68, 0.25)');
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
            borderWidth: 2.5,
            tension: 0.4,
            fill: true,
            pointRadius: 2,
            pointHoverRadius: 6,
            pointBackgroundColor: c.cyan,
            pointBorderColor: c.cardBg,
            pointBorderWidth: 2
          },

          {
            label: 'Suspicious / Malicious',
            data: data.suspicious || [],
            borderColor: c.red,
            backgroundColor: gradThreat,
            borderWidth: 2.2,
            tension: 0.4,
            fill: true,
            pointRadius: 2,
            pointHoverRadius: 6,
            pointBackgroundColor: c.red,
            pointBorderColor: c.cardBg,
            pointBorderWidth: 2
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

          backgroundColor: data.colors || [
            c.green,
            c.red,
            c.orange,
            c.blue,
            c.purple,
            c.pink
          ],

          // No dark outlines between doughnut segments
          borderWidth: 0,
          spacing: 2,
          hoverOffset: 8,
          hoverBorderWidth: 0
        }]
      },

      options: {
        responsive: true,
        maintainAspectRatio: false,

        animation: {
          duration: 750,
          easing: 'easeOutQuart'
        },

        plugins: {
          legend: {
            position: 'right',

            labels: {
              color: c.textMuted,
              font: {
                family: "'Inter', sans-serif",
                size: 10
              },
              padding: 12,
              boxWidth: 9,
              boxHeight: 9,
              usePointStyle: true,
              pointStyle: 'circle'
            }
          },

          tooltip: {
            backgroundColor: c.tooltipBg,
            titleColor: c.cyan,
            bodyColor: c.textPrimary,
            borderColor: c.borderColor,
            borderWidth: 1,
            cornerRadius: 9,
            padding: 12,
            displayColors: true,
            usePointStyle: true
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

          backgroundColor: [
            c.red,
            c.orange,
            c.blue,
            c.purple,
            c.pink
          ],

          borderRadius: 6,
          borderSkipped: false,
          maxBarThickness: 26,
          hoverBackgroundColor: c.lavender
        }]
      },

      options: {
        ...this.getDefaultOptions(),

        indexAxis: 'y',

        plugins: {
          legend: {
            display: false
          }
        },

        scales: {
          x: {
            border: {
              display: false
            },
            grid: {
              color: c.gridColor,
              drawTicks: false
            },
            ticks: {
              color: c.textMuted,
              font: {
                size: 10
              }
            },
            beginAtZero: true
          },

          y: {
            border: {
              display: false
            },
            grid: {
              display: false
            },
            ticks: {
              color: c.textMuted,
              font: {
                size: 10
              }
            }
          }
        }
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

          backgroundColor: [
            c.red,
            c.orange,
            c.yellow,
            c.green
          ],

          borderRadius: 7,
          borderSkipped: false,
          maxBarThickness: 48
        }]
      },

      options: {
        ...this.getDefaultOptions(),

        plugins: {
          legend: {
            display: false
          }
        }
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

          backgroundColor: data.colors || [
            c.cyan,
            c.blue,
            c.green,
            c.orange,
            c.purple,
            c.pink
          ],

          borderWidth: 0,
          spacing: 2,
          hoverOffset: 7,
          hoverBorderWidth: 0
        }]
      },

      options: {
        responsive: true,
        maintainAspectRatio: false,

        animation: {
          duration: 750,
          easing: 'easeOutQuart'
        },

        plugins: {
          legend: {
            position: 'right',

            labels: {
              color: c.textMuted,
              font: {
                family: "'Inter', sans-serif",
                size: 10
              },
              padding: 12,
              boxWidth: 9,
              boxHeight: 9,
              usePointStyle: true,
              pointStyle: 'circle'
            }
          },

          tooltip: {
            backgroundColor: c.tooltipBg,
            titleColor: c.cyan,
            bodyColor: c.textPrimary,
            borderColor: c.borderColor,
            borderWidth: 1,
            cornerRadius: 9,
            padding: 12
          }
        },

        cutout: '68%'
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
            backgroundColor: 'rgba(16, 185, 129, 0.10)',
            borderWidth: 2.3,
            tension: 0.4,
            fill: true,
            pointRadius: 2,
            pointHoverRadius: 5,
            pointBackgroundColor: c.green,
            pointBorderColor: c.cardBg,
            pointBorderWidth: 2
          },

          {
            label: 'Malicious Records',
            data: data.suspicious || [],
            borderColor: c.red,
            backgroundColor: 'rgba(239, 68, 68, 0.10)',
            borderWidth: 2.3,
            tension: 0.4,
            fill: true,
            pointRadius: 2,
            pointHoverRadius: 5,
            pointBackgroundColor: c.red,
            pointBorderColor: c.cardBg,
            pointBorderWidth: 2
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
            borderRadius: 6,
            borderSkipped: false,
            maxBarThickness: 55
          },

          {
            label: 'Malicious Flow Records',
            data: data.malicious || [],
            backgroundColor: c.red,
            borderRadius: 6,
            borderSkipped: false,
            maxBarThickness: 55
          }
        ]
      },

      options: {
        ...this.getDefaultOptions(),

        scales: {
          x: {
            border: {
              display: false
            },
            grid: {
              display: false
            },
            ticks: {
              color: c.textMuted
            }
          },

          y: {
            border: {
              display: false
            },
            grid: {
              color: c.gridColor,
              drawTicks: false
            },
            ticks: {
              color: c.textMuted
            },
            beginAtZero: true
          }
        }
      }
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

          backgroundColor: c.purple,
          hoverBackgroundColor: c.cyan,

          borderRadius: 7,
          borderSkipped: false,
          maxBarThickness: 42
        }]
      },

      options: {
        ...this.getDefaultOptions(),

        plugins: {
          legend: {
            display: false
          }
        }
      }
    });
  },

  updateFromPredictions(predictions) {
    if (!Array.isArray(predictions) || predictions.length === 0) return;

    const normal = predictions.filter(item =>
      ['normal', 'benign'].includes(
        String(item.classification || '').toLowerCase()
      )
    ).length;

    const malicious = predictions.length - normal;

    const severityLabels = [
      'Critical',
      'High',
      'Medium',
      'Low'
    ];

    const severityCounts = severityLabels.map(severity =>
      predictions.filter(item =>
        String(item.severity || '').toLowerCase() === severity.toLowerCase()
      ).length
    );

    const normalMaliciousCanvas = document.getElementById(
      'normal-vs-malicious-chart'
    );

    if (normalMaliciousCanvas) {
      this.createNormalVsMaliciousChart(
        'normal-vs-malicious-chart',
        {
          labels: ['Current Analysis'],
          normal: [normal],
          malicious: [malicious]
        }
      );
    }

    const severityCanvas = document.getElementById(
      'threat-severity-chart'
    );

    if (severityCanvas) {
      this.createThreatSeverityChart(
        'threat-severity-chart',
        {
          values: severityCounts
        }
      );
    }
  }
};
