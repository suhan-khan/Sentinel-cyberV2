
/**
 * Sentinel Cyber V2 — Dashboard Overview Controller
 * Manages overview KPIs, live host telemetry streams, security alerts feed,
 * subsystem health diagnostics, and Chart.js visualizations.
 */

window.Dashboard = {
  currentRange: '24h',
  livePredictions: [],
  liveStats: null,
  sensorPollTimer: null,
  lastTelemetry: null,

  init() {
    const isLive = window.ApiService
      ? window.ApiService.isLiveMode()
      : false;

    if (this.livePredictions.length > 0) {
      this.updateStats(this.liveStats);
      this.renderAlerts(this.getAlertsFromPredictions());
    } else if (!isLive) {
      this.updateStats(window.DemoData?.overviewStats);
      this.renderAlerts(window.DemoData?.recentAlerts);
    } else {
      this.updateStats({
        totalConnections: 0,
        maliciousDetected: 0,
        normalConnections: 0,
        detectionRate: 0
      });

      this.renderAlerts([]);
    }

    this.renderCharts();
    this.setupTimeFilters();
    this.setupTelemetrySyncBtn();

    // Initial subsystem health is rendered by SentinelApp.
    // Live sensor status is exclusively controlled by telemetry polling.
    this.startSensorPolling();
  },

  startSensorPolling() {
    if (this.sensorPollTimer) {
      clearInterval(this.sensorPollTimer);
    }

    this.fetchSensorTelemetry();

    this.sensorPollTimer = setInterval(() => {
      this.fetchSensorTelemetry();
    }, 3000);
  },

  async fetchSensorTelemetry() {
    if (!window.ApiService) return;

    try {
      const telemetry = await window.ApiService.getSensorTelemetry();

      this.lastTelemetry = telemetry;
      this.updateSensorUI(telemetry);
    } catch (err) {
      console.warn('[Dashboard] Failed to poll telemetry:', err);

      this.updateSensorUI({
        status: 'offline',
        connected: false,
        connections: {}
      });
    }
  },

  /**
   * Live telemetry is the single source of truth for sensor status.
   */
  updateSensorUI(telemetry) {
    if (!telemetry) return;

    const status = telemetry.status || 'offline';

    const isOnline = status === 'online';
    const isStale = status === 'stale';
    const isDemo = status === 'demo';

    const statusBadge =
      document.getElementById('sensor-status-badge');

    const statusDot =
      document.getElementById('sensor-status-dot');

    const statusText =
      document.getElementById('sensor-status-text');

    const lastUpdated =
      document.getElementById('sensor-last-updated');

    if (statusBadge) {
      statusBadge.className =
        `telemetry-badge ${isDemo ? 'stale' : status}`;
    }

    if (statusDot) {
      statusDot.className =
        `status-dot ${isDemo ? 'stale' : status}`;
    }

    if (statusText) {
      if (isOnline) {
        statusText.innerText = 'Sensor Active';
      } else if (isStale) {
        statusText.innerText =
          `Sensor Stale (${telemetry.age_seconds ?? '?'}s)`;
      } else if (isDemo) {
        statusText.innerText = 'Simulated Stream';
      } else {
        statusText.innerText = 'Sensor Offline';
      }
    }

    if (lastUpdated) {
      if (telemetry.last_seen) {
        const lastSeenDate = new Date(telemetry.last_seen);

        const timeStr = Number.isNaN(lastSeenDate.getTime())
          ? 'Unknown'
          : lastSeenDate.toLocaleTimeString();

        const age = telemetry.age_seconds != null
          ? `${telemetry.age_seconds}s ago`
          : 'just now';

        lastUpdated.innerText =
          `Last heartbeat: ${timeStr} (${age})`;
      } else {
        lastUpdated.innerText =
          'No telemetry received yet. Run sensor on Windows.';
      }
    }

    // Device and interface.
    const devEl =
      document.getElementById('sensor-device');

    const ifaceEl =
      document.getElementById('sensor-interface');

    if (devEl) {
      devEl.innerText = telemetry.device || '--';
    }

    if (ifaceEl) {
      ifaceEl.innerText = telemetry.interface
        ? `NIC: ${telemetry.interface}`
        : 'No active interface';
    }

    // Throughput.
    const formatSpeed = (kbps) => {
      const val = Number(kbps) || 0;

      if (val >= 1024) {
        return `${(val / 1024).toFixed(2)} MB/s`;
      }

      return `${val.toFixed(2)} KB/s`;
    };

    const formatBytes = (bytes) => {
      const val = Number(bytes) || 0;

      if (val >= 1024 * 1024 * 1024) {
        return `${(val / (1024 * 1024 * 1024)).toFixed(2)} GB total`;
      }

      if (val >= 1024 * 1024) {
        return `${(val / (1024 * 1024)).toFixed(1)} MB total`;
      }

      return `${Math.round(val / 1024)} KB total`;
    };

    const upSpeedEl =
      document.getElementById('sensor-upload-speed');

    const downSpeedEl =
      document.getElementById('sensor-download-speed');

    const bytesSentEl =
      document.getElementById('sensor-bytes-sent');

    const bytesRecvEl =
      document.getElementById('sensor-bytes-recv');

    if (upSpeedEl) {
      upSpeedEl.innerText =
        formatSpeed(telemetry.upload_kbps);
    }

    if (downSpeedEl) {
      downSpeedEl.innerText =
        formatSpeed(telemetry.download_kbps);
    }

    if (bytesSentEl) {
      bytesSentEl.innerText =
        formatBytes(telemetry.bytes_sent_total);
    }

    if (bytesRecvEl) {
      bytesRecvEl.innerText =
        formatBytes(telemetry.bytes_received_total);
    }

    // Socket statistics.
    const conns = telemetry.connections || {
      total: 0,
      tcp: 0,
      udp: 0,
      established: 0
    };

    const totalConnsEl =
      document.getElementById('sensor-total-conns');

    const breakdownEl =
      document.getElementById('sensor-conn-breakdown');

    const estConnsEl =
      document.getElementById('sensor-est-conns');

    const errorsEl =
      document.getElementById('sensor-errors');

    if (totalConnsEl) {
      totalConnsEl.innerText =
        Number(conns.total || 0).toLocaleString();
    }

    if (breakdownEl) {
      breakdownEl.innerText =
        `TCP: ${conns.tcp || 0} | UDP: ${conns.udp || 0}`;
    }

    if (estConnsEl) {
      estConnsEl.innerText =
        Number(conns.established || 0).toLocaleString();
    }

    if (errorsEl) {
      errorsEl.innerText =
        `Errors: ${telemetry.errors_in || 0} in / ${telemetry.errors_out || 0} out`;
    }

    // Update the sensor health item from telemetry only.
    const healthSensorEl =
      document.getElementById('health-sensor-status');

    if (healthSensorEl) {
      const healthLabel = isOnline
        ? `Active (${telemetry.interface || 'NIC'})`
        : isStale
          ? 'Stale Stream'
          : isDemo
            ? 'Simulated Stream'
            : 'Disconnected';

      const healthClass = isOnline
        ? 'online'
        : isStale || isDemo
          ? 'stale'
          : 'offline';

      const healthColor = isOnline
        ? 'var(--text-primary)'
        : isStale || isDemo
          ? 'var(--color-warning)'
          : 'var(--color-danger)';

      healthSensorEl.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <span style="color:var(--text-secondary);font-size:0.78rem;">
            Live Network Sensor
          </span>

          <span class="status-dot ${healthClass}"></span>
        </div>

        <div style="font-weight:600;font-size:0.88rem;margin-top:4px;color:${healthColor};">
          ${this.escapeHTML(healthLabel)}
        </div>
      `;
    }
  },

  setupTelemetrySyncBtn() {
    const btn =
      document.getElementById('btn-refresh-telemetry');

    if (btn) {
      btn.addEventListener('click', async () => {
        btn.disabled = true;

        try {
          await this.fetchSensorTelemetry();

          if (window.SentinelApp?.showNotification) {
            window.SentinelApp.showNotification(
              'Telemetry stream synchronized.',
              'info'
            );
          }
        } finally {
          setTimeout(() => {
            btn.disabled = false;
          }, 1000);
        }
      });
    }
  },

  loadLiveAnalysis(predictions, stats) {
    if (!Array.isArray(predictions)) return;

    this.livePredictions = predictions;
    this.liveStats = stats || null;

    const total = predictions.length;

    const normal = predictions.filter(
      item => this.isNormal(item)
    ).length;

    const malicious = total - normal;

    const detectionRate = total > 0
      ? (malicious / total) * 100
      : 0;

    this.updateStats({
      totalConnections: stats?.total ?? total,
      maliciousDetected: stats?.malicious ?? malicious,
      normalConnections: stats?.normal ?? normal,
      detectionRate
    });

    this.renderAlerts(this.getAlertsFromPredictions());

    const badge =
      document.getElementById('alerts-status-badge');

    if (badge) {
      badge.className = 'badge badge-critical';
      badge.innerText = `${malicious} Attacks Flagged`;
    }
  },

  isNormal(item) {
    const classification =
      String(item.classification || '').toLowerCase();

    return classification === 'normal' ||
      classification === 'benign';
  },

  getAlertsFromPredictions() {
    return this.livePredictions
      .filter(item => !this.isNormal(item))
      .slice(0, 10)
      .map((item, index) => ({
        id: item.id ?? index + 1,
        timestamp: item.timestamp || new Date().toISOString(),
        srcIp: item.srcIp || 'N/A',
        dstIp: item.dstIp || 'N/A',
        classification: item.classification || 'ATTACK',
        severity: item.severity || 'Medium'
      }));
  },

  updateStats(stats) {
    if (!stats) return;

    this.animateValue(
      'stat-total-value',
      0,
      Number(stats.totalConnections) || 0,
      700
    );

    this.animateValue(
      'stat-malicious-value',
      0,
      Number(stats.maliciousDetected) || 0,
      700
    );

    this.animateValue(
      'stat-normal-value',
      0,
      Number(stats.normalConnections) || 0,
      700
    );

    this.animateValue(
      'stat-rate-value',
      0,
      Number(stats.detectionRate) || 0,
      700,
      '%'
    );
  },

  animateValue(elementId, start, end, duration, suffix = '') {
    const obj = document.getElementById(elementId);

    if (!obj) return;

    let startTimestamp = null;

    const isFloat = Number(end) % 1 !== 0;

    const step = (timestamp) => {
      if (!startTimestamp) {
        startTimestamp = timestamp;
      }

      const progress = Math.min(
        (timestamp - startTimestamp) / duration,
        1
      );

      const current =
        progress * (end - start) + start;

      if (isFloat) {
        obj.innerText = current.toFixed(1) + suffix;
      } else {
        obj.innerText =
          Math.floor(current).toLocaleString() + suffix;
      }

      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        obj.innerText = (
          isFloat
            ? Number(end).toFixed(1)
            : Math.floor(end).toLocaleString()
        ) + suffix;
      }
    };

    window.requestAnimationFrame(step);
  },

  renderCharts() {
    if (!window.Charts) return;

    const trafficData =
      this.getFilteredTrafficData(this.currentRange);

    window.Charts.createTrafficOverviewChart(
      'traffic-overview-chart',
      trafficData
    );

    const attackDist =
      window.DemoData?.analyticsData?.attackDistribution;

    if (attackDist) {
      window.Charts.createThreatDistributionChart(
        'threat-distribution-chart',
        attackDist
      );
    }
  },

  setupTimeFilters() {
    const buttons =
      document.querySelectorAll('.time-filter-btn');

    buttons.forEach(btn => {
      btn.addEventListener('click', () => {
        buttons.forEach(button => {
          button.classList.remove('active');
        });

        btn.classList.add('active');

        const range =
          btn.getAttribute('data-range') || '24h';

        this.handleTimeFilter(range);
      });
    });
  },

  handleTimeFilter(range) {
    this.currentRange = range;

    if (!window.Charts) return;

    const trafficData =
      this.getFilteredTrafficData(range);

    window.Charts.createTrafficOverviewChart(
      'traffic-overview-chart',
      trafficData
    );
  },

  getFilteredTrafficData(range) {
    const analytics =
      window.DemoData?.analyticsData;

    const base = analytics?.trafficTrend || {
      labels: [],
      normal: [],
      suspicious: []
    };

    if (range === '1h') {
      return {
        labels: [
          '14:00',
          '14:10',
          '14:20',
          '14:30',
          '14:40',
          '14:50'
        ],
        normal: [420, 480, 510, 460, 490, 530],
        suspicious: [28, 35, 22, 19, 31, 24]
      };
    }

    if (range === '6h') {
      return {
        labels: [
          '09:00',
          '10:00',
          '11:00',
          '12:00',
          '13:00',
          '14:00'
        ],
        normal: [2100, 2600, 2750, 2900, 3100, 2850],
        suspicious: [130, 160, 145, 185, 210, 165]
      };
    }

    if (range === '7d') {
      return {
        labels: [
          'Nov 17',
          'Nov 18',
          'Nov 19',
          'Nov 20',
          'Nov 21',
          'Nov 22',
          'Nov 23'
        ],
        normal: [
          21400,
          22100,
          20800,
          24500,
          23900,
          24100,
          23554
        ],
        suspicious: [
          1120,
          1080,
          950,
          1310,
          1260,
          1340,
          1293
        ]
      };
    }

    return base;
  },

  renderAlerts(alerts) {
    const tbody =
      document.getElementById('alerts-table-body');

    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center text-muted" style="padding:28px;font-size:0.85rem;">
            No active threat alerts in this session. Upload a packet capture CSV or click "Load Included Sample Dataset" to run intrusion detection.
          </td>
        </tr>
      `;

      return;
    }

    tbody.innerHTML = alerts.map(alert => {
      const severity =
        String(alert.severity || 'Medium');

      const allowedSeverities = [
        'critical',
        'high',
        'medium',
        'low'
      ];

      const severityClass =
        allowedSeverities.includes(severity.toLowerCase())
          ? `badge-${severity.toLowerCase()}`
          : 'badge-medium';

      const timestamp =
        alert.timestamp ? new Date(alert.timestamp) : null;

      const timeStr =
        timestamp && !Number.isNaN(timestamp.getTime())
          ? timestamp.toLocaleTimeString()
          : 'N/A';

      const classification =
        alert.classification || 'ATTACK';

      const classificationClass =
        this.isNormal(alert)
          ? 'badge-normal'
          : 'badge-critical';

      const alertId = Number(alert.id) || 1;

      return `
        <tr>
          <td style="font-family:monospace;color:var(--text-muted);">
            ${this.escapeHTML(timeStr)}
          </td>

          <td style="font-family:monospace;color:var(--accent-purple);">
            ${this.escapeHTML(alert.srcIp || 'N/A')}
          </td>

          <td style="font-family:monospace;">
            ${this.escapeHTML(alert.dstIp || 'N/A')}
          </td>

          <td>
            <span class="badge ${classificationClass}">
              ${this.escapeHTML(classification)}
            </span>
          </td>

          <td>
            <span class="badge ${severityClass}">
              ${this.escapeHTML(severity)}
            </span>
          </td>

          <td>
            <button
              class="btn btn-secondary btn-sm"
              onclick="window.SentinelApp.showNotification('Alert incident ${alertId} flagged for review.', 'info')">
              Investigate
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[char]);
  },

  renderSystemHealth(health) {
    if (!health) return;

    const setHealthItem = (id, data, fallbackLabel) => {
      const el = document.getElementById(id);

      if (!el) return;

      const isOnline =
        data && (
          data.status === 'online' ||
          data.status === 'ready'
        );

      const isStale =
        data && data.status === 'stale';

      el.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <span style="color:var(--text-secondary);font-size:0.78rem;">
            ${this.escapeHTML(data?.label || fallbackLabel)}
          </span>

          <span class="status-dot ${
            isOnline ? 'online' : isStale ? 'stale' : 'offline'
          }"></span>
        </div>

        <div style="font-weight:600;font-size:0.88rem;margin-top:4px;color:${
          isOnline
            ? 'var(--text-primary)'
            : isStale
              ? 'var(--color-warning)'
              : 'var(--color-danger)'
        };">
          ${this.escapeHTML(data?.detail || 'Offline')}
        </div>
      `;
    };

    setHealthItem(
      'health-model-status',
      health.model,
      'Random Forest ML Model'
    );

    setHealthItem(
      'health-api-status',
      health.api,
      'FastAPI Connection'
    );

    setHealthItem(
      'health-dataset-status',
      health.dataset,
      'Dataset Processor'
    );

    // The sensor indicator is updated only by updateSensorUI().
  }
};
