
/**
 * Sentinel Cyber V2 — Dataset Upload & Ingestion Engine
 * Handles drag-and-drop, CSV validation, 74-feature benchmark loading,
 * preview parsing, and Random Forest inference execution.
 */

window.Upload = {
  selectedFile: null,
  selectedDatasetId: null,
  parsedData: null,

  init() {
    const dropZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');
    const removeBtn = document.getElementById('upload-remove-btn');
    const analyzeBtn = document.getElementById('btn-analyze');
    const sampleBtn = document.getElementById('btn-load-sample-dataset');

    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, e => {
        e.preventDefault();
        e.stopPropagation();
      }, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => {
        dropZone.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => {
        dropZone.classList.remove('dragover');
      }, false);
    });

    dropZone.addEventListener('drop', e => {
      const files = e.dataTransfer.files;

      if (files && files.length > 0) {
        this.handleFile(files[0]);
      }
    });

    if (browseBtn) {
      browseBtn.addEventListener('click', () => fileInput.click());
    }

    fileInput.addEventListener('change', e => {
      if (e.target.files && e.target.files.length > 0) {
        this.handleFile(e.target.files[0]);
      }
    });

    if (removeBtn) {
      removeBtn.addEventListener('click', () => this.reset());
    }

    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', () => this.startAnalysis());
    }

    if (sampleBtn) {
      sampleBtn.addEventListener('click', () => this.loadBenchmarkDataset());
    }
  },

  /**
   * Load the built-in 74-feature benchmark dataset.
   */
  async loadBenchmarkDataset() {
    this.clearError();

    const statusEl = document.getElementById('upload-status');

    if (statusEl) {
      statusEl.innerText = 'Loading benchmark dataset from backend...';
    }

    try {
      if (!window.ApiService) {
        throw new Error('API service unavailable.');
      }

      const result = await window.ApiService.getSampleDataset();

      if (!result || typeof result !== 'object') {
        throw new Error('Backend returned an invalid dataset response.');
      }

      const datasetId = result.datasetId || result.dataset_id;

      if (!datasetId) {
        throw new Error('Backend did not return a valid sample dataset ID.');
      }

      this.selectedDatasetId = datasetId;

      this.selectedFile = {
        name: result.filename || 'sample_test.csv',
        size: result.size || 1686
      };

      this.parsedData = null;

      const fileInfo = document.getElementById('upload-file-info');
      const fileNameEl = document.getElementById('upload-filename');
      const fileSizeEl = document.getElementById('upload-filesize');

      if (fileInfo) fileInfo.classList.remove('hidden');

      if (fileNameEl) {
        fileNameEl.innerText =
          `${this.selectedFile.name} (CIC-IDS2017 Benchmark - 74 Features)`;
      }

      if (fileSizeEl) {
        fileSizeEl.innerText = this.formatFileSize(this.selectedFile.size);
      }

      const headers = Array.isArray(result.columns)
        ? result.columns
        : [];

      const previewRows = Array.isArray(result.preview)
        ? result.preview.map(row => {
            if (Array.isArray(row)) {
              return row;
            }

            return headers.map(header => row?.[header] ?? '');
          })
        : [];

      this.showPreview(
        headers,
        previewRows.length
          ? previewRows
          : [headers.map(() => '0')]
      );

      const analyzeBtn = document.getElementById('btn-analyze');

      if (analyzeBtn) {
        analyzeBtn.removeAttribute('disabled');
      }

      if (statusEl) {
        statusEl.innerText = 'Benchmark dataset ready for ML analysis.';
      }

      if (window.SentinelApp) {
        window.SentinelApp.showNotification(
          'Loaded CIC-IDS2017 benchmark dataset! Click "Run AI Random Forest Inference" to analyze.',
          'success'
        );
      }

    } catch (err) {
      this.showError(
        `Failed to load benchmark dataset: ${err.message}`
      );
    }
  },

  handleFile(file) {
    this.clearError();

    if (!file) return;

    this.selectedDatasetId = null;
    this.parsedData = null;

    const filename = file.name.toLowerCase();

    if (!filename.endsWith('.csv')) {
      this.showError(
        'Invalid file format. Please upload a CSV network traffic flow dataset.'
      );
      return;
    }

    const maxSize = 50 * 1024 * 1024;

    if (file.size > maxSize) {
      this.showError(
        'File exceeds the maximum allowable size of 50MB.'
      );
      return;
    }

    this.selectedFile = file;

    const fileInfo = document.getElementById('upload-file-info');
    const fileNameEl = document.getElementById('upload-filename');
    const fileSizeEl = document.getElementById('upload-filesize');

    if (fileInfo) fileInfo.classList.remove('hidden');

    if (fileNameEl) {
      fileNameEl.innerText = file.name;
    }

    if (fileSizeEl) {
      fileSizeEl.innerText = this.formatFileSize(file.size);
    }

    const preview = document.getElementById('upload-preview');

    if (preview) {
      preview.classList.add('hidden');
    }

    const analyzeBtn = document.getElementById('btn-analyze');

    if (analyzeBtn) {
      analyzeBtn.setAttribute('disabled', 'true');
    }

    const reader = new FileReader();

    reader.onload = e => {
      try {
        const parsed = this.parseCSV(e.target.result);

        if (parsed.rows.length === 0) {
          throw new Error('CSV file contains no valid records.');
        }

        this.parsedData = parsed;

        this.showPreview(parsed.headers, parsed.rows);

        if (analyzeBtn) {
          analyzeBtn.removeAttribute('disabled');
        }

      } catch (err) {
        this.showError('Failed to parse CSV data: ' + err.message);
      }
    };

    reader.onerror = () => {
      this.showError('Error reading uploaded CSV file.');
    };

    reader.readAsText(file);
  },

  /**
   * Parse CSV rows, including escaped quotation marks.
   */
  parseCSV(text) {
    const lines = String(text)
      .split(/\r?\n/)
      .filter(line => line.trim().length > 0);

    if (lines.length < 2) {
      throw new Error(
        'Dataset must contain a header row and at least one data record.'
      );
    }

    const parseLine = line => {
      const values = [];
      let current = '';
      let inQuotes = false;

      for (let i = 0; i < line.length; i++) {
        const char = line[i];

        if (char === '"') {
          if (inQuotes && line[i + 1] === '"') {
            current += '"';
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (char === ',' && !inQuotes) {
          values.push(current.trim());
          current = '';
        } else {
          current += char;
        }
      }

      if (inQuotes) {
        throw new Error('CSV contains an unclosed quoted field.');
      }

      values.push(current.trim());

      return values;
    };

    const headers = parseLine(lines[0]);

    if (headers.length === 0 || headers.every(header => !header)) {
      throw new Error('CSV header row is empty.');
    }

    const rows = [];

    for (let i = 1; i < Math.min(lines.length, 500); i++) {
      const row = parseLine(lines[i]);

      if (row.length === headers.length) {
        rows.push(row);
      }
    }

    return {
      headers,
      rows
    };
  },

  showPreview(headers, rows) {
    const previewContainer = document.getElementById('upload-preview');
    const rowCountEl = document.getElementById('upload-row-count');
    const colCountEl = document.getElementById('upload-col-count');
    const thead = document.getElementById('preview-table-head');
    const tbody = document.getElementById('preview-table-body');

    if (!previewContainer || !thead || !tbody) return;

    previewContainer.classList.remove('hidden');

    if (rowCountEl) {
      rowCountEl.innerText = rows.length.toLocaleString();
    }

    if (colCountEl) {
      colCountEl.innerText = headers.length.toString();
    }

    thead.innerHTML =
      '<tr>' +
      headers.slice(0, 15)
        .map(header => `<th>${this.escapeHTML(header)}</th>`)
        .join('') +
      (headers.length > 15
        ? `<th>+${headers.length - 15} more</th>`
        : '') +
      '</tr>';

    tbody.innerHTML = rows.slice(0, 8).map(row => {
      return (
        '<tr>' +
        row.slice(0, 15).map(value =>
          `<td><span style="font-family:monospace;font-size:0.8rem;">${this.escapeHTML(value)}</span></td>`
        ).join('') +
        (row.length > 15 ? '<td>...</td>' : '') +
        '</tr>'
      );
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

  showError(message) {
    const errorEl = document.getElementById('upload-error');
    const errorText = document.getElementById('upload-error-text');

    if (errorEl) {
      if (errorText) {
        errorText.innerText = message;
      } else {
        errorEl.innerText = message;
      }

      errorEl.classList.remove('hidden');
    }

    if (window.SentinelApp) {
      window.SentinelApp.showNotification(message, 'error');
    }
  },

  clearError() {
    const errorEl = document.getElementById('upload-error');

    if (errorEl) {
      errorEl.classList.add('hidden');
    }
  },

  async startAnalysis() {
    const analyzeBtn = document.getElementById('btn-analyze');
    const progressContainer = document.getElementById('upload-progress');
    const statusEl = document.getElementById('upload-status');

    if (!this.selectedFile) {
      this.showError('Please select or load a CSV dataset first.');
      return;
    }

    if (analyzeBtn) {
      analyzeBtn.setAttribute('disabled', 'true');
    }

    if (progressContainer) {
      progressContainer.classList.remove('hidden');
    }

    this.clearError();

    try {
      if (!window.ApiService) {
        throw new Error('API service is unavailable.');
      }

      let datasetId = this.selectedDatasetId;

      // STEP 1: Upload dataset if not already registered.
      if (!datasetId) {
        this.updateProgress(
          20,
          'Uploading CSV dataset to backend...'
        );

        if (statusEl) {
          statusEl.innerText =
            'Uploading dataset to FastAPI backend...';
        }

        const uploadResponse =
          await window.ApiService.uploadDataset(this.selectedFile);

        datasetId =
          uploadResponse?.datasetId ||
          uploadResponse?.dataset_id;

        if (!datasetId) {
          throw new Error(
            'Backend did not return a valid dataset ID.'
          );
        }
      }

      // STEP 2: Run Random Forest inference.
      this.updateProgress(
        50,
        'Executing Random Forest inference (74 features)...'
      );

      if (statusEl) {
        statusEl.innerText =
          'Evaluating flow vectors against CIC-IDS2017 decision trees...';
      }

      const predictionResponse =
        await window.ApiService.predict(datasetId);

      if (
        !predictionResponse ||
        !Array.isArray(predictionResponse.predictions)
      ) {
        throw new Error(
          'Backend returned an unexpected prediction payload.'
        );
      }

      // STEP 3: Update predictions and history.
      this.updateProgress(
        75,
        'Processing and classifying intrusion anomalies...'
      );

      if (window.Predictions) {
        window.Predictions.loadCustomData(
          predictionResponse.predictions
        );

        const totalRecords =
          predictionResponse.stats?.total ??
          predictionResponse.predictions.length;

        const malicious =
          predictionResponse.stats?.malicious ??
          predictionResponse.predictions.filter(p =>
            !['normal', 'benign'].includes(
              String(p.classification || '').toLowerCase()
            )
          ).length;

        window.Predictions.addToHistory({
          id:
            'ANA-' +
            new Date().toISOString().slice(0, 10).replace(/-/g, '') +
            '-' +
            Math.floor(100 + Math.random() * 900),

          filename: this.selectedFile.name,
          date: new Date().toISOString(),
          records: totalRecords,
          malicious: malicious,
          status: 'Completed'
        });
      }

      // STEP 4: Update dashboard.
      if (window.Dashboard) {
        window.Dashboard.loadLiveAnalysis(
          predictionResponse.predictions,
          predictionResponse.stats
        );
      }

      // STEP 5: Refresh backend health diagnostics.
      if (
        window.Dashboard &&
        window.ApiService.isLiveMode()
      ) {
        const health = await window.ApiService.checkHealth();

        window.Dashboard.renderSystemHealth(health);
      }

      // STEP 6: Complete and navigate to predictions.
      this.updateProgress(
        100,
        'ML inference completed successfully!'
      );

      if (statusEl) {
        statusEl.innerText =
          'Analysis finished. Redirecting to predictions...';
      }

      if (window.SentinelApp) {
        const threatCount =
          predictionResponse.stats?.malicious ??
          predictionResponse.predictions.filter(p =>
            !['normal', 'benign'].includes(
              String(p.classification || '').toLowerCase()
            )
          ).length;

        window.SentinelApp.showNotification(
          `Analysis finished: ${threatCount} threats identified.`,
          'success'
        );

        window.SentinelApp.navigateTo('predictions');
      }

      setTimeout(() => this.reset(), 800);

    } catch (error) {
      console.error('[Upload] Analysis failed:', error);

      let message = error.message;

      if (error.data?.detail) {
        const detail = error.data.detail;

        if (
          typeof detail === 'object' &&
          detail.missing_columns
        ) {
          message =
            `Dataset lacks required features: Missing ${detail.missing_columns.length} of ${detail.expected_count || 74} CIC-IDS2017 features. Click 'Load Included Sample Dataset' to test with compliant benchmark data.`;
        } else {
          message =
            typeof detail === 'string'
              ? detail
              : JSON.stringify(detail);
        }
      }

      this.showError(
        message || 'Prediction failed. Check model artifacts.'
      );

      if (statusEl) {
        statusEl.innerText = 'Analysis halted due to an error.';
      }

      if (progressContainer) {
        progressContainer.classList.add('hidden');
      }

      if (analyzeBtn) {
        analyzeBtn.removeAttribute('disabled');
      }
    }
  },

  updateProgress(percent, text) {
    const fill = document.getElementById('upload-progress-fill');
    const label = document.getElementById('upload-progress-text');

    if (fill) {
      fill.style.width = percent + '%';
    }

    if (label) {
      label.innerText = `${percent}% — ${text}`;
    }
  },

  formatFileSize(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) {
      return '0 Bytes';
    }

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];

    const i = Math.min(
      Math.floor(Math.log(bytes) / Math.log(k)),
      sizes.length - 1
    );

    return (
      parseFloat((bytes / Math.pow(k, i)).toFixed(1)) +
      ' ' +
      sizes[i]
    );
  },

  reset() {
    this.selectedFile = null;
    this.selectedDatasetId = null;
    this.parsedData = null;

    const fileInput = document.getElementById('file-input');

    if (fileInput) {
      fileInput.value = '';
    }

    const fileInfo = document.getElementById('upload-file-info');

    if (fileInfo) {
      fileInfo.classList.add('hidden');
    }

    const preview = document.getElementById('upload-preview');

    if (preview) {
      preview.classList.add('hidden');
    }

    const progress = document.getElementById('upload-progress');

    if (progress) {
      progress.classList.add('hidden');
    }

    const analyzeBtn = document.getElementById('btn-analyze');

    if (analyzeBtn) {
      analyzeBtn.setAttribute('disabled', 'true');
    }

    const statusEl = document.getElementById('upload-status');

    if (statusEl) {
      statusEl.innerText = '';
    }

    this.clearError();
  }
};
