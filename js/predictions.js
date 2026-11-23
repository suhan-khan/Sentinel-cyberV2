
/**
 * Sentinel Cyber — Predictions & History Controller
 * Supports backend predictions, filtering, sorting, pagination,
 * live chart updates, and persistent analysis history.
 */

window.Predictions = {
  currentData: [],
  filteredData: [],
  currentPage: 1,
  rowsPerPage: 15,
  currentSort: { field: null, direction: 'asc' },

  init() {
    this.currentData = [
      ...(window.DemoData?.predictionResults || [])
    ];

    this.filteredData = [...this.currentData];

    this.setupListeners();
    this.renderPredictions();
    this.renderHistory();
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

  isNormal(item) {
    const classification = String(
      item.classification || ''
    ).toLowerCase();

    return ['normal', 'benign'].includes(classification);
  },

  setupListeners() {
    const filterSelect = document.getElementById('predictions-filter');

    if (filterSelect) {
      filterSelect.addEventListener('change', () => {
        this.applyFilters();
      });
    }

    const searchInput = document.getElementById('predictions-search');

    if (searchInput) {
      searchInput.addEventListener('input', () => {
        this.applyFilters();
      });
    }

    const prevBtn = document.getElementById('pred-prev-btn');
    const nextBtn = document.getElementById('pred-next-btn');

    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        if (this.currentPage > 1) {
          this.currentPage--;
          this.renderTableOnly();
        }
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        const totalPages = Math.ceil(
          this.filteredData.length / this.rowsPerPage
        ) || 1;

        if (this.currentPage < totalPages) {
          this.currentPage++;
          this.renderTableOnly();
        }
      });
    }

    const sortHeaders = document.querySelectorAll(
      '#predictions-table th.sortable'
    );

    sortHeaders.forEach(th => {
      th.addEventListener('click', () => {
        const field = th.getAttribute('data-sort');
        if (field) this.sortPredictions(field);
      });
    });
  },

  loadCustomData(records) {
    if (!Array.isArray(records)) {
      console.error('[Predictions] Invalid prediction data.');
      return;
    }

    this.currentData = [...records];
    this.filteredData = [...records];
    this.currentPage = 1;

    // Reset existing filters when a new analysis is loaded.
    const filterSelect = document.getElementById('predictions-filter');
    const searchInput = document.getElementById('predictions-search');

    if (filterSelect) filterSelect.value = 'all';
    if (searchInput) searchInput.value = '';

    this.renderPredictions();

    // Update charts with the latest backend predictions.
    if (window.Charts?.updateFromPredictions) {
      window.Charts.updateFromPredictions(this.currentData);
    }

    console.log(
      `[Predictions] Loaded ${records.length} prediction records.`
    );
  },

  applyFilters() {
    const filterSelect = document.getElementById('predictions-filter');
    const searchInput = document.getElementById('predictions-search');

    const filterVal = filterSelect
      ? filterSelect.value.toLowerCase()
      : 'all';

    const query = searchInput
      ? searchInput.value.trim().toLowerCase()
      : '';

    this.filteredData = this.currentData.filter(item => {
      const normal = this.isNormal(item);

      let matchesFilter = true;

      if (filterVal === 'normal') {
        matchesFilter = normal;
      } else if (filterVal === 'malicious') {
        matchesFilter = !normal;
      }

      const searchableValues = [
        item.srcIp,
        item.dstIp,
        item.protocol,
        item.classification,
        item.severity
      ];

      const matchesSearch = !query ||
        searchableValues.some(value =>
          String(value ?? '').toLowerCase().includes(query)
        );

      return matchesFilter && matchesSearch;
    });

    this.currentPage = 1;
    this.renderPredictions();
  },

  sortPredictions(field) {
    if (this.currentSort.field === field) {
      this.currentSort.direction =
        this.currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
      this.currentSort.field = field;
      this.currentSort.direction = 'asc';
    }

    const factor =
      this.currentSort.direction === 'asc' ? 1 : -1;

    this.filteredData.sort((a, b) => {
      const valA = a[field];
      const valB = b[field];

      if (typeof valA === 'number' && typeof valB === 'number') {
        return (valA - valB) * factor;
      }

      return String(valA ?? '').localeCompare(
        String(valB ?? ''),
        undefined,
        { numeric: true }
      ) * factor;
    });

    this.renderTableOnly();
  },

  renderPredictions() {
    const totalCount = this.currentData.length;

    const normalCount = this.currentData.filter(
      item => this.isNormal(item)
    ).length;

    const maliciousCount = totalCount - normalCount;

    const validConfidence = this.currentData
      .map(item => Number(item.confidence))
      .filter(value =>
        Number.isFinite(value) && value >= 0 && value <= 1
      );

    const avgConfidence = validConfidence.length > 0
      ? (
          validConfidence.reduce((sum, value) => sum + value, 0) /
          validConfidence.length * 100
        ).toFixed(1)
      : 'N/A';

    const setEl = (id, value) => {
      const el = document.getElementById(id);
      if (el) el.innerText = value;
    };

    setEl('pred-total-value', totalCount.toLocaleString());
    setEl('pred-normal-value', normalCount.toLocaleString());
    setEl('pred-malicious-value', maliciousCount.toLocaleString());
    setEl(
      'pred-confidence-value',
      avgConfidence === 'N/A' ? avgConfidence : avgConfidence + '%'
    );

    this.renderTableOnly();
  },

  renderTableOnly() {
    const tbody = document.getElementById('predictions-table-body');
    if (!tbody) return;

    const totalPages = Math.ceil(
      this.filteredData.length / this.rowsPerPage
    ) || 1;

    this.currentPage = Math.min(this.currentPage, totalPages);

    const startIndex = (this.currentPage - 1) * this.rowsPerPage;

    const pageItems = this.filteredData.slice(
      startIndex,
      startIndex + this.rowsPerPage
    );

    if (pageItems.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center text-muted"
              style="padding: 24px;">
            No predictions match the active filter criteria.
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = pageItems.map(item => {
        const isNormal = this.isNormal(item);

        const confidence = Number(item.confidence);

        const validConfidence =
          Number.isFinite(confidence) &&
          confidence >= 0 &&
          confidence <= 1;

        const confPct = validConfidence
          ? Math.round(confidence * 100)
          : null;

        let confColor = 'var(--color-success)';

        if (confPct !== null && confPct < 75) {
          confColor = 'var(--color-danger)';
        } else if (confPct !== null && confPct < 90) {
          confColor = 'var(--color-warning)';
        }

        const severity = String(
          item.severity || (isNormal ? 'Low' : 'Unknown')
        );

        const safeSeverity = this.escapeHTML(severity);
        const safeClassification = this.escapeHTML(
          item.classification || 'Unknown'
        );

        const severityClass = severity
          .toLowerCase()
          .replace(/[^a-z0-9_-]/g, '');

        return `
          <tr>
            <td style="color: var(--text-muted); font-family: monospace;">
              #${this.escapeHTML(item.id)}
            </td>

            <td>
              <span style="font-family: monospace; color: var(--accent-cyan);">
                ${this.escapeHTML(item.srcIp || 'N/A')}
              </span>
            </td>

            <td>
              <span style="font-family: monospace;">
                ${this.escapeHTML(item.dstIp || 'N/A')}
              </span>
            </td>

            <td>
              <span class="badge badge-info">
                ${this.escapeHTML(item.protocol || 'Unknown')}
              </span>
            </td>

            <td>
              <span class="badge ${isNormal ? 'badge-normal' : 'badge-critical'}">
                ${safeClassification}
              </span>
            </td>

            <td>
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-weight: 600; color: ${confColor}; font-size: 0.85rem;">
                  ${confPct === null ? 'N/A' : confPct + '%'}
                </span>

                <div style="width: 50px; height: 5px; background: #374151; border-radius: 3px; overflow: hidden;">
                  <div style="width: ${confPct ?? 0}%; height: 100%; background: ${confColor};"></div>
                </div>
              </div>
            </td>

            <td>
              <span class="badge badge-${severityClass}">
                ${safeSeverity}
              </span>
            </td>
          </tr>
        `;
      }).join('');
    }

    const pageInfo = document.getElementById('pred-page-info');

    if (pageInfo) {
      pageInfo.innerText =
        `Page ${this.currentPage} of ${totalPages} (${this.filteredData.length} total)`;
    }

    const prevBtn = document.getElementById('pred-prev-btn');
    const nextBtn = document.getElementById('pred-next-btn');

    if (prevBtn) prevBtn.disabled = this.currentPage <= 1;
    if (nextBtn) nextBtn.disabled = this.currentPage >= totalPages;
  },

  renderHistory() {
    const tbody = document.getElementById('history-table-body');
    const emptyState = document.getElementById('history-empty-state');

    if (!tbody) return;

    let historyList = [];

    const stored = localStorage.getItem('sentinel_analysis_history');

    if (stored) {
      try {
        historyList = JSON.parse(stored);
        if (!Array.isArray(historyList)) historyList = [];
      } catch (error) {
        historyList = [];
      }
    }

    if (historyList.length === 0 && window.DemoData) {
      historyList = window.DemoData.analysisHistory || [];
    }

    if (historyList.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      tbody.innerHTML = '';
      return;
    }

    if (emptyState) emptyState.style.display = 'none';

    tbody.innerHTML = historyList.map(item => {
      const dateStr = String(item.date || 'Unknown')
        .replace('T', ' ')
        .slice(0, 16);

      const malicious = Number(item.malicious) || 0;
      const records = Number(item.records) || 0;

      return `
        <tr>
          <td>
            <span style="font-family: monospace; font-weight: 600; color: var(--accent-cyan);">
              ${this.escapeHTML(item.id)}
            </span>
          </td>

          <td>
            <span style="font-weight: 500;">
              ${this.escapeHTML(item.filename)}
            </span>
          </td>

          <td style="color: var(--text-muted); font-size: 0.85rem;">
            ${this.escapeHTML(dateStr)}
          </td>

          <td>
            <span style="font-family: monospace;">
              ${records.toLocaleString()}
            </span>
          </td>

          <td>
            <span class="badge ${malicious > 0 ? 'badge-critical' : 'badge-normal'}">
              ${malicious.toLocaleString()} detected
            </span>
          </td>

          <td>
            <span class="badge badge-normal">
              ${this.escapeHTML(item.status || 'Completed')}
            </span>
          </td>

          <td>
            <button class="btn btn-secondary btn-sm"
                    data-analysis-id="${this.escapeHTML(item.id)}">
              View Details
            </button>
          </td>
        </tr>
      `;
    }).join('');

    tbody.querySelectorAll('[data-analysis-id]').forEach(button => {
      button.addEventListener('click', () => {
        this.viewAnalysisDetails(
          button.getAttribute('data-analysis-id')
        );
      });
    });
  },

  viewAnalysisDetails(analysisId) {
    if (window.SentinelApp) {
      window.SentinelApp.showNotification(
        `Loaded historical session details for ${analysisId}`,
        'info'
      );

      window.SentinelApp.navigateTo('predictions');
    }
  },

  addToHistory(entry) {
    let historyList = [];

    const stored = localStorage.getItem('sentinel_analysis_history');

    if (stored) {
      try {
        historyList = JSON.parse(stored);
        if (!Array.isArray(historyList)) historyList = [];
      } catch (error) {
        historyList = [];
      }
    }

    if (historyList.length === 0 && window.DemoData) {
      historyList = [...(window.DemoData.analysisHistory || [])];
    }

    historyList.unshift(entry);

    localStorage.setItem(
      'sentinel_analysis_history',
      JSON.stringify(historyList)
    );

    this.renderHistory();
  },

  clearHistory() {
    localStorage.removeItem('sentinel_analysis_history');

    this.renderHistory();

    if (window.SentinelApp) {
      window.SentinelApp.showNotification(
        'Historical analysis sessions cleared.',
        'warning'
      );
    }
  }
};
