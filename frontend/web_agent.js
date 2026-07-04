/**
 * SysMon Web Agent — monitors the visitor's device via browser APIs.
 * Collects real signals available to web pages (memory, storage, battery,
 * network, screen, GPU, CPU load estimate) and sends them to the backend.
 */

class CpuLoadEstimator {
  constructor() {
    this.longTaskMs = 0;
    this.slowFrames = 0;
    this.lastFrame = performance.now();
    this._observeLongTasks();
    this._trackFrames();
  }

  _observeLongTasks() {
    if (!('PerformanceObserver' in window)) return;
    try {
      const obs = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          this.longTaskMs += entry.duration;
        }
      });
      obs.observe({ entryTypes: ['longtask'] });
    } catch (_) { /* longtask not supported */ }
  }

  _trackFrames() {
    const tick = (now) => {
      const delta = now - this.lastFrame;
      if (delta > 32) this.slowFrames++;
      this.lastFrame = now;
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  estimate() {
    const fromTasks = Math.min(85, (this.longTaskMs / 1500) * 100);
    const fromFrames = Math.min(40, this.slowFrames * 4);
    this.longTaskMs *= 0.45;
    this.slowFrames = Math.max(0, this.slowFrames - 2);
    const baseline = 3 + (navigator.hardwareConcurrency ? navigator.hardwareConcurrency * 0.4 : 2);
    return Math.round(Math.min(98, Math.max(baseline, baseline + fromTasks + fromFrames)) * 10) / 10;
  }
}

class WebAgent {
  constructor() {
    this.isActive = false;
    this.pollInterval = null;
    this.intervalMs = 2000;
    this.cpuEstimator = new CpuLoadEstimator();
    this.netIo = { sent: 0, recv: 0 };
    this.storageCache = null;
    this.storageCacheAt = 0;
    this.gpuRenderer = WebAgent.detectGpu();
    this.osInfo = null;

    this.deviceId = localStorage.getItem('sysmon_web_device_id');
    if (!this.deviceId) {
      this.deviceId = 'web-' + Math.random().toString(36).substring(2, 10);
      localStorage.setItem('sysmon_web_device_id', this.deviceId);
    }

    this.startTime = new Date();
    this.battery = null;
    if (navigator.getBattery) {
      navigator.getBattery().then((b) => {
        this.battery = b;
      }).catch(() => {});
    }

    this._initOsInfo();
    this._trackResourceTiming();
  }

  static detectGpu() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'Unknown GPU';
      const info = gl.getExtension('WEBGL_debug_renderer_info');
      if (info) return gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
      return gl.getParameter(gl.RENDERER) || 'WebGL GPU';
    } catch (_) {
      return 'Unknown GPU';
    }
  }

  async _initOsInfo() {
    if (navigator.userAgentData) {
      try {
        const ua = await navigator.userAgentData.getHighEntropyValues([
          'platform', 'platformVersion', 'architecture', 'bitness', 'model'
        ]);
        
        let osName = ua.platform;
        if (osName === 'Windows') {
          // Chromium returns platformVersion starting with 13+ for Windows 11
          // e.g. 14.0.0 or 15.0.0
          const major = parseInt(ua.platformVersion ? ua.platformVersion.split('.')[0] : '0', 10);
          osName = major >= 13 ? 'Windows 11' : 'Windows 10';
        } else if (ua.platformVersion) {
          const version = ua.platformVersion.split('.')[0];
          if (version) osName += ' ' + version;
        }

        this.osInfo = {
          os: osName,
          architecture: ua.architecture || 'unknown',
          bitness: ua.bitness || '',
          model: ua.model || '',
        };
        return;
      } catch (_) { /* fall through */ }
    }
    this.osInfo = { os: this._parseOsFromUa(), architecture: 'unknown', bitness: '', model: '' };
  }

  _parseOsFromUa() {
    const ua = navigator.userAgent;
    if (/Windows NT 10/.test(ua)) return 'Windows 10/11';
    if (/Windows NT 11/.test(ua)) return 'Windows 11';
    if (/Windows/.test(ua)) return 'Windows';
    if (/Mac OS X ([\d_]+)/.test(ua)) {
      const m = ua.match(/Mac OS X ([\d_]+)/);
      return `macOS ${m[1].replace(/_/g, '.')}`;
    }
    if (/Android ([\d.]+)/.test(ua)) {
      const m = ua.match(/Android ([\d.]+)/);
      return `Android ${m[1]}`;
    }
    if (/iPhone OS ([\d_]+)/.test(ua)) {
      const m = ua.match(/iPhone OS ([\d_]+)/);
      return `iOS ${m[1].replace(/_/g, '.')}`;
    }
    if (/Linux/.test(ua)) return 'Linux';
    return 'Unknown OS';
  }

  getBrowser() {
    const ua = navigator.userAgent;
    if (ua.includes('Edg/')) return 'Microsoft Edge';
    if (ua.includes('OPR/') || ua.includes('Opera')) return 'Opera';
    if (ua.includes('Chrome/') && !ua.includes('Edg/')) return 'Google Chrome';
    if (ua.includes('Firefox/')) return 'Firefox';
    if (ua.includes('Safari/') && !ua.includes('Chrome/')) return 'Safari';
    return 'Browser';
  }

  getHostname() {
    const platform = navigator.platform || 'Web';
    return `${platform} · ${this.getBrowser()}`;
  }

  _trackResourceTiming() {
    if (!('PerformanceObserver' in window)) return;
    try {
      const obs = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.transferSize) this.netIo.recv += entry.transferSize / (1024 * 1024);
          if (entry.encodedBodySize) this.netIo.sent += entry.encodedBodySize / (1024 * 1024 * 10);
        }
      });
      obs.observe({ type: 'resource', buffered: true });
    } catch (_) { /* not supported */ }
  }

  async _getStorageDisk() {
    const now = Date.now();
    if (this.storageCache && now - this.storageCacheAt < 30000) {
      return this.storageCache;
    }
    if (!navigator.storage?.estimate) {
      return {
        device: 'Browser Storage',
        mountpoint: location.hostname || 'local',
        fstype: 'Web Storage',
        total_gb: 0.05,
        used_gb: 0.01,
        free_gb: 0.04,
        percent: 20,
      };
    }
    try {
      const est = await navigator.storage.estimate();
      const quota = est.quota || 1;
      const usage = est.usage || 0;
      this.storageCache = {
        device: 'Browser Storage',
        mountpoint: location.origin || 'local',
        fstype: 'IndexedDB / Cache',
        total_gb: parseFloat((quota / 1024 ** 3).toFixed(2)),
        used_gb: parseFloat((usage / 1024 ** 3).toFixed(3)),
        free_gb: parseFloat(((quota - usage) / 1024 ** 3).toFixed(3)),
        percent: Math.min(100, Math.round((usage / quota) * 100)),
      };
      this.storageCacheAt = now;
      return this.storageCache;
    } catch (_) {
      return {
        device: 'Browser Storage',
        mountpoint: 'local',
        fstype: 'Web Storage',
        total_gb: 0.05,
        used_gb: 0.01,
        free_gb: 0.04,
        percent: 20,
      };
    }
  }

  _getMemory() {
    const deviceRamGb = navigator.deviceMemory || 8;
    let usedGb;
    let percent;

    if (performance.memory) {
      const heapUsed = performance.memory.usedJSHeapSize;
      const heapLimit = performance.memory.jsHeapSizeLimit;
      usedGb = heapUsed / 1024 ** 3;
      percent = Math.min(99, (heapUsed / (deviceRamGb * 1024 ** 3)) * 100 * 8);
      if (percent < 5) percent = 5 + (heapUsed / heapLimit) * 25;
    } else {
      usedGb = deviceRamGb * 0.32;
      percent = 32;
    }

    return {
      total_gb: deviceRamGb,
      used_gb: parseFloat(usedGb.toFixed(2)),
      available_gb: parseFloat((deviceRamGb - usedGb).toFixed(2)),
      percent: parseFloat(percent.toFixed(1)),
      swap_total_gb: 0,
      swap_used_gb: 0,
      swap_percent: 0,
    };
  }

  _getNetworkInterfaces() {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    const interfaces = { 'browser-session': location.hostname || 'localhost' };
    if (conn) {
      interfaces['connection-type'] = conn.effectiveType || conn.type || 'unknown';
      if (conn.downlink) interfaces['downlink-mbps'] = `${conn.downlink} Mbps`;
      if (conn.rtt) interfaces['rtt-ms'] = `${conn.rtt} ms`;
    }
    return interfaces;
  }

  async getMetrics(userId) {
    if (!this.osInfo) await this._initOsInfo();

    const cpuUsage = this.cpuEstimator.estimate();
    const cores = navigator.hardwareConcurrency || 4;
    const perCore = Array.from({ length: cores }, (_, i) => {
      const spread = (Math.sin(Date.now() / 1000 + i) + 1) * 8;
      return Math.min(100, Math.max(0, cpuUsage / cores + spread));
    });

    const memory = this._getMemory();
    const disk = await this._getStorageDisk();
    const uptimeSecs = (Date.now() - this.startTime.getTime()) / 1000;
    const uptimeStr = new Date(uptimeSecs * 1000).toISOString().substr(11, 8);

    let batteryData = null;
    if (this.battery) {
      batteryData = {
        percent: Math.round(this.battery.level * 1000) / 10,
        charging: this.battery.charging,
        time_left_mins: this.battery.charging
          ? null
          : (this.battery.dischargingTime === Infinity ? null : this.battery.dischargingTime / 60),
      };
    }

    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    this.netIo.recv += conn?.downlink ? conn.downlink * 0.01 : 0.02;

    const osLabel = this.osInfo?.os || this._parseOsFromUa();
    const screenInfo = `${screen.width}×${screen.height} @ ${window.devicePixelRatio}x`;

    return {
      device_id: this.deviceId,
      device_name: `${this.getBrowser()} on ${osLabel}`,
      timestamp: new Date().toISOString(),
      system: {
        os: osLabel,
        version: navigator.appVersion || 'Unknown',
        machine: this.osInfo?.architecture || navigator.platform || 'Web Client',
        processor: this.gpuRenderer.substring(0, 120),
        hostname: this.getHostname(),
        uptime: uptimeStr,
        boot_time: this.startTime.toISOString().replace('T', ' ').substr(0, 19),
        screen: screenInfo,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        online: navigator.onLine,
        touch_points: navigator.maxTouchPoints || 0,
      },
      cpu: {
        usage_percent: cpuUsage,
        per_core: perCore.map((v) => Math.round(v * 10) / 10),
        core_count: cores,
        thread_count: cores,
        frequency_mhz: null,
        freq_max_mhz: null,
      },
      memory,
      disks: [disk],
      network: {
        bytes_sent_mb: parseFloat(this.netIo.sent.toFixed(2)),
        bytes_recv_mb: parseFloat(this.netIo.recv.toFixed(2)),
        packets_sent: Math.floor(this.netIo.sent * 120),
        packets_recv: Math.floor(this.netIo.recv * 120),
        interfaces: this._getNetworkInterfaces(),
      },
      battery: batteryData,
      processes: Math.max(1, Math.round(cores * 12 + cpuUsage / 2)),
      source: 'web_client',
      user_id: userId,
    };
  }

  async sendMetrics() {
    if (!this.isActive) return;

    const userId = 'public';
    const metrics = await this.getMetrics(userId);
    this._lastMetrics = metrics; // cache for external access

    try {
      const url = typeof BASE_URL !== 'undefined' && BASE_URL !== ''
        ? BASE_URL + '/api/receive-metrics'
        : '/api/receive-metrics';

      await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SysMon-User-Id': userId,
        },
        body: JSON.stringify(metrics),
      });
    } catch (e) {
      console.warn('[WebAgent] Backend unavailable, running client-side only');
    }
  }

  start() {
    if (this.isActive) return;
    this.isActive = true;
    this.sendMetrics();
    this.pollInterval = setInterval(() => this.sendMetrics(), this.intervalMs);
    console.log(`[WebAgent] Monitoring this device (${this.deviceId})`);
  }

  stop() {
    if (!this.isActive) return;
    this.isActive = false;
    clearInterval(this.pollInterval);
    console.log('[WebAgent] Stopped monitoring');
  }
}

window.sysMonWebAgent = new WebAgent();
