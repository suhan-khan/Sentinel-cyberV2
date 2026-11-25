
window.ApiService = {
  /**
   * Determine the API URL based on the environment.
   */
  getDefaultApiUrl() {
    const savedUrl = localStorage.getItem('sentinel_api_url');

    if (savedUrl && savedUrl.trim()) {
      return savedUrl.trim().replace(/\/+$/, '');
    }

    if (
      window.__SENTINEL_CONFIG__ &&
      window.__SENTINEL_CONFIG__.API_BASE_URL
    ) {
      return window.__SENTINEL_CONFIG__.API_BASE_URL.replace(/\/+$/, '');
    }

    const host = window.location.hostname;

    if (
      !host ||
      host === 'localhost' ||
      host === '127.0.0.1' ||
      window.location.protocol === 'file:'
    ) {
      return 'http://localhost:8000';
    }

    return 'https://sentinel-cyber-backend-jntd.onrender.com';
  },

  API_BASE_URL: '',
  isLive: false,
  lastHealthResponse: null,

  init() {
    this.API_BASE_URL = this.getDefaultApiUrl();

    console.log(
      `[ApiService] Initialized with backend: ${this.API_BASE_URL}`
    );
  },

  async checkHealth() {
    if (!this.API_BASE_URL) this.init();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    try {
      const response = await fetch(`${this.API_BASE_URL}/api/health`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal
      });

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
      this.isLive = false;
      this.lastHealthResponse = null;

      const errorMessage =
        err.name === 'AbortError' ? 'Timeout' : err.message;

      console.warn(
        `[ApiService] Health check failed: ${errorMessage}.`
      );

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

    } finally {
      clearTimeout(timeoutId);
    }
  },

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

        disclaimer:
          'Simulated interface counters (Demo Mode). Connect FastAPI and run Windows Sensor for live monitoring.'
      };
    }

    try {
      return await this._request('GET', '/api/sensor/telemetry');

    } catch (err) {
      console.warn(
        '[ApiService] Failed to fetch sensor telemetry:',
        err.message
      );

      return {
        status: 'offline',
        connected: false,
        upload_kbps: 0,
        download_kbps: 0,

        connections: {
          total: 0,
          tcp: 0,
          udp: 0,
          established: 0
        },

        disclaimer: 'Unable to reach sensor telemetry endpoint.'
      };
    }
  },

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

  async uploadDataset(file) {
    if (this.isLive) {
      const formData = new FormData();
      formData.append('file', file);

      return await this._request(
        'POST',
        '/api/upload',
        formData,
        false
      );
    }

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

  async predict(datasetId) {
    if (this.isLive) {
      return await this._request(
        'POST',
        '/api/predict',
        JSON.stringify({ dataset_id: datasetId }),
        true
      );
    }

    await new Promise(resolve => setTimeout(resolve, 800));

    const results = window.DemoData?.predictionResults || [];

    return {
      predictions: results,

      stats: {
        total: results.length,

        normal: results.filter(
          p => (p.classification || '').toLowerCase() === 'normal'
        ).length,

        malicious: results.filter(
          p => (p.classification || '').toLowerCase() !== 'normal'
        ).length,

        avgConfidence: 0.94,
        threatRate: 26.7
      }
    };
  },

  async getHistory() {
    if (this.isLive) {
      try {
        const liveHistory = await this._request(
          'GET',
          '/api/history'
        );

        if (Array.isArray(liveHistory) && liveHistory.length > 0) {
          return liveHistory;
        }

      } catch (err) {
        console.warn(
          '[ApiService] Could not fetch live history:',
          err.message
        );
      }
    }

    const stored = localStorage.getItem(
      'sentinel_analysis_history'
    );

    if (stored) {
      try {
        return JSON.parse(stored);

      } catch (err) {
        console.warn('Could not parse stored history:', err);
      }
    }

    return window.DemoData?.analysisHistory || [];
  },

  async getAnalytics() {
    if (this.isLive) {
      try {
        const liveAnalytics = await this._request(
          'GET',
          '/api/analytics'
        );

        if (
          liveAnalytics &&
          typeof liveAnalytics === 'object' &&
          Object.keys(liveAnalytics).length > 0
        ) {
          return liveAnalytics;
        }

      } catch (err) {
        console.warn(
          '[ApiService] Could not fetch live analytics:',
          err.message
        );
      }
    }

    return window.DemoData?.analyticsData || null;
  },

  /**
   * Send a message to Sentinel AI Assistant.
   * Limits conversation history to prevent backend validation errors.
   */
  async sendAssistantMessage(message, history = []) {
    if (!this.API_BASE_URL) {
      this.init();
    }

    if (typeof message !== 'string' || !message.trim()) {
      throw new Error('Please enter a valid message.');
    }

    if (message.trim().length > 2000) {
      throw new Error('Your message exceeds the 2,000-character limit.');
    }

    const normalizedHistory = (Array.isArray(history) ? history : [])
      .filter(turn =>
        turn &&
        ['user', 'model'].includes(turn.role) &&
        typeof turn.content === 'string' &&
        turn.content.trim().length > 0
      )
      .slice(-8)
      .map(turn => ({
        role: turn.role,
        content: turn.content.trim().slice(0, 1800)
      }));

    return await this._request(
      'POST',
      '/api/assistant/chat',
      JSON.stringify({
        message: message.trim(),
        history: normalizedHistory
      }),
      true
    );
  },

  setLiveMode(bool) {
    this.isLive = Boolean(bool);
  },

  isLiveMode() {
    return this.isLive;
  },

  setApiUrl(url) {
    const cleanUrl = (url || '').trim().replace(/\/+$/, '');

    this.API_BASE_URL = cleanUrl;

    localStorage.setItem('sentinel_api_url', cleanUrl);

    this.isLive = false;
    this.lastHealthResponse = null;

    console.log(
      `[ApiService] Updated API_BASE_URL to: ${cleanUrl}`
    );
  },

  resetToDefaultUrl() {
    localStorage.removeItem('sentinel_api_url');

    this.API_BASE_URL = this.getDefaultApiUrl();
    this.isLive = false;
    this.lastHealthResponse = null;

    return this.API_BASE_URL;
  },

  /**
   * Centralized HTTP request handler.
   */
  async _request(method, endpoint, body = null, isJson = true) {
    if (!this.API_BASE_URL) {
      this.init();
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      60000
    );

    const headers = {
      Accept: 'application/json'
    };

    if (isJson && body && typeof body === 'string') {
      headers['Content-Type'] = 'application/json';
    }

    try {
      const response = await fetch(
        `${this.API_BASE_URL}${endpoint}`,
        {
          method,
          headers,
          body,
          signal: controller.signal
        }
      );

      if (!response.ok) {
        let errData;

        try {
          errData = await response.json();

        } catch {
          errData = await response.text();
        }

        const errorMessage =
          typeof errData === 'object' && errData?.detail
            ? (
                typeof errData.detail === 'string'
                  ? errData.detail
                  : JSON.stringify(errData.detail)
              )
            : `API Error ${response.status}: ${
                typeof errData === 'string'
                  ? errData
                  : JSON.stringify(errData)
              }`;

        const errorObj = new Error(errorMessage);

        errorObj.status = response.status;
        errorObj.data = errData;

        throw errorObj;
      }

      // Handle endpoints that return no response body.
      if (response.status === 204) {
        return null;
      }

      const contentType = response.headers.get('content-type') || '';

      if (contentType.includes('application/json')) {
        return await response.json();
      }

      const responseText = await response.text();

      if (!responseText.trim()) {
        return null;
      }

      try {
        return JSON.parse(responseText);
      } catch {
        return responseText;
      }

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

// Initialize immediately
window.ApiService.init();
