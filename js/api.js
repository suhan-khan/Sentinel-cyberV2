/**
 * Sentinel Cyber — API Service Adapter
 * Seamlessly bridges the frontend to either local FastAPI (http://localhost:8000)
 * or production Render HTTPS API (https://sentinel-cyber.onrender.com)
 * with robust error handling and high-fidelity Demo Mode fallback.
 */

window.ApiService = {
  /**
   * Determine appropriate API base URL dynamically based on environment.
   */
  getDefaultApiUrl() {
    // 1. Explicit user override in localStorage takes priority
    const savedUrl = localStorage.getItem('sentinel_api_url');
    if (savedUrl && savedUrl.trim()) {
      return savedUrl.trim().replace(/\/+$/, '');
    }

    // 2. Window config injection (useful for custom CI/CD or Vercel config)
    if (window.__SENTINEL_CONFIG__ && window.__SENTINEL_CONFIG__.API_BASE_URL) {
      return window.__SENTINEL_CONFIG__.API_BASE_URL.replace(/\/+$/, '');
    }

    // 3. Localhost & file:// detection: default to local FastAPI backend
    const host = window.location.hostname;
    if (
      !host ||
      host === 'localhost' ||
      host === '127.0.0.1' ||
      window.location.protocol === 'file:'
    ) {
      return 'http://localhost:8000';
    }

    // 4. Production web deployment (e.g. Vercel): default to deployed Render API
    return 'https://sentinel-cyber.onrender.com';
  },

  API_BASE_URL: '',
  isLive: false,
  lastHealthResponse: null,

  init() {
    this.API_BASE_URL = this.getDefaultApiUrl();
    console.log(`[ApiService] Initialized with backend target: ${this.API_BASE_URL}`);
  },

  /**
   * Check connection and readiness of the FastAPI backend.
   * Endpoint: GET /api/health
   */
  async checkHealth() {
    if (!this.API_BASE_URL) this.init();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8s timeout

    try {
      const response = await fetch(`${this.API_BASE_URL}/api/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`Health endpoint returned HTTP ${response.status}`);
      }

      const data = await response.json();
      this.isLive = true;
      this.lastHealthResponse = data;

      return {
        status: 'online',
        isLive: true,
        model: data.model || {
          status: 'online',
          label: 'Random Forest',
          detail: 'Inference Active'
        },
        api: {
          status: 'online',
          label: 'API Connection',
          detail: 'FastAPI Operational'
        },
        dataset: data.dataset || {
          status: 'ready',
          label: 'Dataset Processor',
          detail: 'Pipeline Ready'
        },
        sensor: data.sensor || {
          status: 'offline',
          label: 'Live Network Sensor',
          detail: 'Waiting for stream'
        },
        modelReady: data.model_ready ?? true,
        featureCount: data.feature_count ?? 74,
        threshold: data.threshold ?? 0.05,
        lastAnalysis: data.last_analysis || null
      };

    } catch (err) {
      clearTimeout(timeoutId);
      this.isLive = false;
      this.lastHealthResponse = null;

      console.warn(`[ApiService] Health check to ${this.API_BASE_URL} failed (${err.name === 'AbortError' ? 'Timeout' : err.message}). Fallback to Demo Mode.`);

      return {
        status: 'offline',
        isLive: false,
        model: {
          status: 'offline',
          label: 'Random Forest',
          detail: 'Backend Unreachable'
        },
        api: {
          status: 'offline',
          label: 'API Connection',
          detail: 'Disconnected (Demo Mode)'
        },
        dataset: {
          status: 'ready',
          label: 'Dataset Processor',
          detail: 'Local Parser Active'
        },
        sensor: {
          status: 'offline',
          label: 'Live Network Sensor',
          detail: 'Backend Offline'
        },
        lastAnalysis: null,
        error: err.message
      };
    }
  },

  /**
   * Retrieve safe, sanitized live network telemetry from the Windows sensor.
   * Endpoint: GET /api/sensor/telemetry
   * Note: This does NOT require or expose the secret sensor authentication token!
   */
  async getSensorTelemetry() {
    if (!this.isLive) {
      return {
        status: 'demo',
        connected: false,
        device: 'DEMO-WORKSTATION',
        interface: 'Wi-Fi (Simulated)',
        upload_kbps: Math.round(180 + Math.random() * 90),
        download_kbps: Math.round(850 + Math.random() * 450),
        connections: {
          total: 42,
          tcp: 32,
          udp: 10,
          established: 21
        },
        last_seen: new Date().toISOString(),
        age_seconds: 1.0,
        history: [],
        disclaimer: 'Simulated interface counters (Demo Mode). Connect FastAPI and run Windows Sensor for live monitoring.'
      };
    }

    try {
      return await this._request('GET', '/api/sensor/telemetry');
    } catch (err) {
      console.warn('[ApiService] Failed to fetch sensor telemetry:', err.message);
      return {
        status: 'offline',
        connected: false,
        upload_kbps: 0,
        download_kbps: 0,
        connections: { total: 0, tcp: 0, udp: 0, established: 0 },
        disclaimer: 'Unable to reach sensor telemetry endpoint.'
      };
    }
  },

  /**
   * Load the 74-feature CIC-IDS2017 sample dataset from the backend for instant testing.
   * Endpoint: GET /api/sample-dataset
   */
  async getSampleDataset() {
    if (this.isLive) {
      return await this._request('GET', '/api/sample-dataset');
    }

    return {
      datasetId: 'DS-SAMPLE-DEMO',
      filename: 'sample_test.csv',
      rows: 3,
      columns: window.DemoData?.sampleHeaders || [],
      status: 'ready',
      preview: []
    };
  },

  /**
   * Upload dataset CSV to backend.
   * Endpoint: POST /api/upload
   */
  async uploadDataset(file) {
    if (this.isLive) {
      const formData = new FormData();
      formData.append('file', file);
      return await this._request('POST', '/api/upload', formData, false);
    }

    // Demo Mode fallback simulation
    await new Promise(resolve => setTimeout(resolve, 500));
    return {
      datasetId: 'DS-' + Date.now().toString().slice(-6),
      filename: file.name,
      size: file.size,
      status: 'uploaded',
      rows: 15,
      columns: []
    };
  },

  /**
   * Trigger ML prediction on an uploaded dataset ID.
   * Endpoint: POST /api/predict
   */
  async predict(datasetId) {
    if (this.isLive) {
      return await this._request(
        'POST',
        '/api/predict',
        JSON.stringify({ dataset_id: datasetId }),
        true
      );
    }

    // Demo Mode fallback simulation
    await new Promise(resolve => setTimeout(resolve, 800));
    const results = window.DemoData?.predictionResults || [];
    return {
      predictions: results,
      stats: {
        total: results.length,
        normal: results.filter(p => (p.classification || '').toLowerCase() === 'normal').length,
        malicious: results.filter(p => (p.classification || '').toLowerCase() !== 'normal').length,
        avgConfidence: 0.94,
        threatRate: 26.7
      }
    };
  },

  /**
   * Fetch historical analysis sessions.
   * Endpoint: GET /api/history
   */
  async getHistory() {
    if (this.isLive) {
      try {
        const liveHistory = await this._request('GET', '/api/history');
        if (Array.isArray(liveHistory) && liveHistory.length > 0) {
          return liveHistory;
        }
      } catch (err) {
        console.warn('[ApiService] Could not fetch live history:', err.message);
      }
    }

    // Stored or fallback history
    const stored = localStorage.getItem('sentinel_analysis_history');
    if (stored) {
      try {
        return JSON.parse(stored);
      } catch (err) {
        console.warn('Could not parse stored history:', err);
      }
    }

    return window.DemoData?.analysisHistory || [];
  },

  /**
   * Fetch SOC analytics data.
   * Endpoint: GET /api/analytics
   */
  async getAnalytics() {
    if (this.isLive) {
      try {
        const liveAnalytics = await this._request('GET', '/api/analytics');
        if (liveAnalytics && Object.keys(liveAnalytics).length > 0) {
          return liveAnalytics;
        }
      } catch (err) {
        console.warn('[ApiService] Could not fetch live analytics:', err.message);
      }
    }

    return window.DemoData?.analyticsData || null;
  },

  setLiveMode(bool) {
    this.isLive = bool;
  },

  isLiveMode() {
    return this.isLive;
  },

  /**
   * Configure backend URL in runtime and persist to localStorage.
   */
  setApiUrl(url) {
    const cleanUrl = (url || '').trim().replace(/\/+$/, '');
    this.API_BASE_URL = cleanUrl;
    localStorage.setItem('sentinel_api_url', cleanUrl);
    console.log(`[ApiService] Updated API_BASE_URL to: ${cleanUrl}`);
  },

  resetToDefaultUrl() {
    localStorage.removeItem('sentinel_api_url');
    this.API_BASE_URL = this.getDefaultApiUrl();
    return this.API_BASE_URL;
  },

  /**
   * Internal request wrapper with timeout and JSON/FormData handling.
   */
  async _request(method, endpoint, body = null, isJson = true) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout for heavy inference

    const headers = {};
    if (isJson && body && typeof body === 'string') {
      headers['Content-Type'] = 'application/json';
    }

    try {
      const response = await fetch(`${this.API_BASE_URL}${endpoint}`, {
        method,
        headers,
        body,
        signal: controller.signal
      });

      if (!response.ok) {
        let errData;
        try {
          errData = await response.json();
        } catch {
          errData = await response.text();
        }

        const errorObj = new Error(
          typeof errData === 'object' && errData.detail
            ? (typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail))
            : `API Error ${response.status}: ${JSON.stringify(errData)}`
        );
        errorObj.status = response.status;
        errorObj.data = errData;
        throw errorObj;
      }

      return await response.json();

    } catch (err) {
      if (err.name === 'AbortError') {
        throw new Error(`Request to ${endpoint} timed out.`);
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }
};

// Initialize immediately on script evaluation
window.ApiService.init();
