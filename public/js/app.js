/**
 * Salt-GUI Frontend Application
 *
 * Vanilla JavaScript - No frameworks, no build step
 *
 * @author Samuel Brucker
 * @version 1.0.0
 */

(function() {
  'use strict';

  // ============================================================
  // Configuration
  // ============================================================

  const API_BASE = window.location.origin;
  const HEALTH_CHECK_INTERVAL = 30000;
  const DEVICE_REFRESH_INTERVAL = 60000;

  // ============================================================
  // Application State
  // ============================================================

  const state = {
    authenticated: false,
    user: null,
    devices: [],
    selectedDevices: new Set(),
    scripts: [],
    selectedScript: null,
    currentView: 'devices'
  };

  // ============================================================
  // API Helper
  // ============================================================

  async function api(endpoint, options = {}) {
    const url = API_BASE + endpoint;
    const defaultOptions = {
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    };

    try {
      const response = await fetch(url, { ...defaultOptions, ...options });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      return data;
    } catch (error) {
      if (error.name === 'TypeError') {
        throw new Error('Network error - server may be unreachable');
      }
      throw error;
    }
  }

  // ============================================================
  // Toast Notifications
  // ============================================================

  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 5000);
  }

  // ============================================================
  // Modal Helper
  // ============================================================

  function showConfirmModal(title, message, onConfirm) {
    const modal = document.getElementById('confirm-modal');
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-message').textContent = message;

    const confirmBtn = document.getElementById('modal-confirm');
    const cancelBtn = document.getElementById('modal-cancel');

    modal.classList.remove('hidden');

    const cleanup = () => {
      modal.classList.add('hidden');
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
    };

    confirmBtn.onclick = () => {
      cleanup();
      onConfirm();
    };

    cancelBtn.onclick = cleanup;
  }

  // ============================================================
  // Utility Functions
  // ============================================================

  function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleString();
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  // ============================================================
  // Authentication
  // ============================================================

  async function checkAuth() {
    try {
      const result = await api('/api/auth/status');
      state.authenticated = result.authenticated;
      state.user = result.user;
      return result.authenticated;
    } catch (error) {
      state.authenticated = false;
      state.user = null;
      return false;
    }
  }

  async function checkSetupRequired() {
    try {
      const result = await api('/api/auth/setup-required');
      return result.required;
    } catch (error) {
      return false;
    }
  }

  function showLoginScreen(setupRequired = false) {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('app-screen').classList.add('hidden');

    const loginForm = document.getElementById('login-form');
    const setupForm = document.getElementById('setup-form');

    if (setupRequired) {
      loginForm.classList.add('hidden');
      setupForm.classList.remove('hidden');
    } else {
      loginForm.classList.remove('hidden');
      setupForm.classList.add('hidden');
    }
  }

  function showAppScreen() {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app-screen').classList.remove('hidden');

    if (state.user) {
      document.getElementById('current-user').textContent = state.user.username;
    }

    loadDevices();
    checkSaltConnection();
  }

  async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');

    try {
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      errorEl.classList.add('hidden');
      await checkAuth();
      showAppScreen();
      showToast('Login successful', 'success');
    } catch (error) {
      errorEl.textContent = error.message;
      errorEl.classList.remove('hidden');
    }
  }

  async function handleSetup(e) {
    e.preventDefault();
    const username = document.getElementById('setup-username').value;
    const password = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm').value;
    const errorEl = document.getElementById('setup-error');

    if (password !== confirm) {
      errorEl.textContent = 'Passwords do not match';
      errorEl.classList.remove('hidden');
      return;
    }

    try {
      await api('/api/auth/setup', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      errorEl.classList.add('hidden');
      showToast('Admin user created', 'success');

      // Now login
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      await checkAuth();
      showAppScreen();
    } catch (error) {
      errorEl.textContent = error.message;
      errorEl.classList.remove('hidden');
    }
  }

  async function handleLogout() {
    try {
      await api('/api/auth/logout', { method: 'POST' });
      state.authenticated = false;
      state.user = null;
      showLoginScreen();
      showToast('Logged out', 'success');
    } catch (error) {
      showToast('Logout failed: ' + error.message, 'error');
    }
  }

  // ============================================================
  // Connection Status
  // ============================================================

  async function checkSaltConnection() {
    const statusEl = document.getElementById('connection-status');

    try {
      const health = await api('/api/health');

      if (health.salt.status === 'connected') {
        statusEl.textContent = 'Connected';
        statusEl.className = 'status-badge status-connected';
      } else {
        statusEl.textContent = 'Disconnected';
        statusEl.className = 'status-badge status-disconnected';
      }
    } catch (error) {
      statusEl.textContent = 'Error';
      statusEl.className = 'status-badge status-disconnected';
    }
  }

  // ============================================================
  // Navigation
  // ============================================================

  function switchView(viewName) {
    state.currentView = viewName;

    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === viewName);
    });

    // Show/hide views
    document.querySelectorAll('.view').forEach(view => {
      view.classList.toggle('active', view.id === `view-${viewName}`);
      view.classList.toggle('hidden', view.id !== `view-${viewName}`);
    });

    // Load view-specific data
    switch (viewName) {
      case 'devices':
        loadDevices();
        break;
      case 'scripts':
        loadScripts();
        break;
      case 'audit':
        loadAuditLog();
        break;
      case 'settings':
        loadSettings();
        break;
      case 'services':
        populateSingleDeviceSelects();
        break;
      case 'processes':
        populateSingleDeviceSelects();
        break;
      case 'passwords':
        break;
      case 'keys':
        loadKeys();
        break;
    }
  }

  // ============================================================
  // Devices
  // ============================================================

  async function loadDevices(forceRefresh = false) {
    const listEl = document.getElementById('device-list');
    listEl.innerHTML = '<div class="loading">Loading devices...</div>';

    try {
      const url = forceRefresh ? '/api/devices?refresh=true' : '/api/devices';
      const result = await api(url);
      state.devices = result.devices || [];

      renderDeviceList();
      updateDeviceCounts();
    } catch (error) {
      listEl.innerHTML = `<div class="no-devices">Failed to load devices: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderDeviceList() {
    const listEl = document.getElementById('device-list');
    const filter = document.getElementById('device-filter').value.toLowerCase();

    const filteredDevices = state.devices.filter(d =>
      d.id.toLowerCase().includes(filter) ||
      d.os.toLowerCase().includes(filter) ||
      d.ip.toLowerCase().includes(filter)
    );

    if (filteredDevices.length === 0) {
      listEl.innerHTML = '<div class="no-devices">No devices found</div>';
      return;
    }

    listEl.innerHTML = filteredDevices.map(device => `
      <div class="device-item ${state.selectedDevices.has(device.id) ? 'selected' : ''}" data-id="${escapeHtml(device.id)}">
        <input type="checkbox" class="device-checkbox" ${state.selectedDevices.has(device.id) ? 'checked' : ''}>
        <span class="device-name">${escapeHtml(device.id)}</span>
        <span class="device-os">${escapeHtml(device.os)}</span>
        <span class="device-ip">${escapeHtml(device.ip)}</span>
        <span class="device-status ${device.status}">${device.status}</span>
      </div>
    `).join('');

    // Add click handlers
    listEl.querySelectorAll('.device-item').forEach(item => {
      item.addEventListener('click', (e) => {
        if (e.target.classList.contains('device-checkbox')) return;
        toggleDeviceSelection(item.dataset.id);
      });

      item.querySelector('.device-checkbox').addEventListener('change', (e) => {
        toggleDeviceSelection(item.dataset.id);
      });
    });
  }

  function toggleDeviceSelection(deviceId) {
    if (state.selectedDevices.has(deviceId)) {
      state.selectedDevices.delete(deviceId);
    } else {
      state.selectedDevices.add(deviceId);
    }
    renderDeviceList();
    updateDeviceCounts();
  }

  function selectAllDevices() {
    state.devices.forEach(d => state.selectedDevices.add(d.id));
    renderDeviceList();
    updateDeviceCounts();
  }

  function selectLinuxDevices() {
    state.devices.forEach(d => {
      if (d.kernel === 'Linux') {
        state.selectedDevices.add(d.id);
      }
    });
    renderDeviceList();
    updateDeviceCounts();
  }

  function selectWindowsDevices() {
    state.devices.forEach(d => {
      if (d.kernel === 'Windows') {
        state.selectedDevices.add(d.id);
      }
    });
    renderDeviceList();
    updateDeviceCounts();
  }

  function clearDeviceSelection() {
    state.selectedDevices.clear();
    renderDeviceList();
    updateDeviceCounts();
  }

  function updateDeviceCounts() {
    document.getElementById('device-count').textContent = `${state.devices.length} devices`;
    document.getElementById('selected-count').textContent = `${state.selectedDevices.size} selected`;
  }

  // ============================================================
  // Commands
  // ============================================================

  function getCommandTargets() {
    const targetType = document.getElementById('cmd-target-type').value;

    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        throw new Error('No devices selected');
      }
      return Array.from(state.selectedDevices);
    } else if (targetType === 'all') {
      return '*';
    } else {
      const custom = document.getElementById('cmd-custom-target').value.trim();
      if (!custom) {
        throw new Error('Custom target pattern is required');
      }
      return custom;
    }
  }

  async function executeCommand() {
    const command = document.getElementById('cmd-input').value.trim();
    const outputEl = document.getElementById('cmd-output');
    const shell = document.getElementById('cmd-shell').value;
    const timeout = document.getElementById('cmd-timeout').value;

    if (!command) {
      showToast('Please enter a command', 'warning');
      return;
    }

    let targets;
    try {
      targets = getCommandTargets();
    } catch (error) {
      showToast(error.message, 'warning');
      return;
    }

    outputEl.textContent = 'Executing command...';

    try {
      const result = await api('/api/commands/run', {
        method: 'POST',
        body: JSON.stringify({
          targets,
          command,
          shell: shell === 'auto' ? undefined : shell,
          timeout: parseInt(timeout)
        })
      });

      let output = '';
      for (const [minion, data] of Object.entries(result.results)) {
        output += `-- ${minion} -----------------------------------------------\n`;
        if (data.error) {
          output += `ERROR: ${data.output}\n`;
        } else {
          output += `${data.output}\n`;
        }
        output += '\n';
      }

      output += `\n[${result.summary.success}/${result.summary.total} succeeded in ${result.execution_time_ms}ms]`;
      outputEl.textContent = output;

      showToast(`Command executed on ${result.summary.total} devices`, 'success');
    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Command execution failed', 'error');
    }
  }

  // ============================================================
  // Scripts
  // ============================================================

  async function loadScripts() {
    const treeEl = document.getElementById('scripts-tree');
    treeEl.innerHTML = '<div class="loading">Loading scripts...</div>';

    try {
      const result = await api('/api/scripts/tree');
      renderScriptTree(result.tree);
    } catch (error) {
      treeEl.innerHTML = `<div class="loading">Failed to load scripts: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderScriptTree(tree, filter = 'all') {
    const treeEl = document.getElementById('scripts-tree');

    function renderNode(node, path = '') {
      if (node.type === 'directory') {
        const fullPath = path ? `${path}/${node.name}` : node.name;

        // Skip if filtering by OS
        if (filter !== 'all' && node.name !== filter && path === 'scripts') {
          return '';
        }

        const children = node.children.map(child => renderNode(child, fullPath)).join('');
        if (!children && node.children.length === 0) return '';

        return `
          <div class="script-folder expanded">
            <div class="script-folder-name">${escapeHtml(node.name)}</div>
            <div class="script-folder-contents">${children}</div>
          </div>
        `;
      } else {
        const fullPath = `${path}/${node.name}`.replace(/^scripts\//, '');
        return `
          <div class="script-file" data-path="${escapeHtml(fullPath)}">${escapeHtml(node.name)}</div>
        `;
      }
    }

    const html = tree.children.map(child => renderNode(child, 'scripts')).join('');
    treeEl.innerHTML = html || '<div class="loading">No scripts found</div>';

    // Add event listeners
    treeEl.querySelectorAll('.script-folder-name').forEach(el => {
      el.addEventListener('click', () => {
        el.parentElement.classList.toggle('expanded');
      });
    });

    treeEl.querySelectorAll('.script-file').forEach(el => {
      el.addEventListener('click', () => {
        loadScriptContent(el.dataset.path);
        treeEl.querySelectorAll('.script-file').forEach(f => f.classList.remove('selected'));
        el.classList.add('selected');
      });
    });
  }

  async function loadScriptContent(scriptPath) {
    const infoEl = document.getElementById('script-info');
    const contentEl = document.getElementById('script-content');
    const executeBtn = document.getElementById('script-execute-btn');

    state.selectedScript = scriptPath;

    try {
      const result = await api(`/api/scripts/content/${encodeURIComponent(scriptPath)}`);
      const script = result.script;

      infoEl.innerHTML = `
        <div class="script-info-grid">
          <div class="script-info-item">
            <span class="script-info-label">Name</span>
            <span class="script-info-value">${escapeHtml(script.name)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">OS</span>
            <span class="script-info-value">${escapeHtml(script.os)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Shell</span>
            <span class="script-info-value">${escapeHtml(script.shell)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Size</span>
            <span class="script-info-value">${formatBytes(script.size)}</span>
          </div>
        </div>
      `;

      contentEl.textContent = script.content;
      executeBtn.disabled = false;
    } catch (error) {
      infoEl.innerHTML = `<p class="placeholder-text">Failed to load script: ${escapeHtml(error.message)}</p>`;
      contentEl.textContent = '';
      executeBtn.disabled = true;
    }
  }

  async function executeScript() {
    if (!state.selectedScript) {
      showToast('Please select a script', 'warning');
      return;
    }

    const outputEl = document.getElementById('script-output');
    const argsEl = document.getElementById('script-args');
    const targetType = document.getElementById('script-target-type').value;

    let targets;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'all') {
      targets = '*';
    } else {
      targets = document.getElementById('script-custom-target').value.trim();
      if (!targets) {
        showToast('Custom target pattern is required', 'warning');
        return;
      }
    }

    const args = argsEl.value.trim().split(/\s+/).filter(a => a);

    outputEl.textContent = 'Executing script...';

    try {
      const result = await api('/api/scripts/run', {
        method: 'POST',
        body: JSON.stringify({
          targets,
          script: state.selectedScript,
          args
        })
      });

      let output = '';
      for (const [minion, data] of Object.entries(result.results)) {
        output += `-- ${minion} -----------------------------------------------\n`;
        if (data.error) {
          output += `ERROR: ${data.output}\n`;
        } else {
          output += `${data.output}\n`;
        }
        output += '\n';
      }

      output += `\n[${result.summary.success}/${result.summary.total} succeeded in ${result.execution_time_ms}ms]`;
      outputEl.textContent = output;

      showToast(`Script executed on ${result.summary.total} devices`, 'success');
    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Script execution failed', 'error');
    }
  }

  // ============================================================
  // Audit Log
  // ============================================================

  async function loadAuditLog() {
    const listEl = document.getElementById('audit-list');
    const actionFilter = document.getElementById('audit-action-filter').value;
    const userFilter = document.getElementById('audit-user-filter').value;
    const limit = document.getElementById('audit-limit').value;

    listEl.innerHTML = '<div class="loading">Loading audit log...</div>';

    try {
      let url = `/api/audit?limit=${limit}`;
      if (actionFilter) url += `&action=${encodeURIComponent(actionFilter)}`;
      if (userFilter) url += `&user=${encodeURIComponent(userFilter)}`;

      const result = await api(url);

      if (result.entries.length === 0) {
        listEl.innerHTML = '<div class="loading">No audit entries found</div>';
        return;
      }

      listEl.innerHTML = result.entries.map(entry => `
        <div class="audit-item">
          <div class="audit-header">
            <span class="audit-timestamp">${formatDate(entry.timestamp)}</span>
            <span class="audit-action">${escapeHtml(entry.action)}</span>
            <span class="audit-user">${escapeHtml(entry.user || 'system')}</span>
          </div>
          ${entry.details ? `<div class="audit-details">${escapeHtml(JSON.stringify(entry.details, null, 2))}</div>` : ''}
        </div>
      `).join('');

      // Load filter options
      loadAuditFilters();
    } catch (error) {
      listEl.innerHTML = `<div class="loading">Failed to load audit log: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadAuditFilters() {
    try {
      const [actions, users] = await Promise.all([
        api('/api/audit/actions'),
        api('/api/audit/users')
      ]);

      const actionSelect = document.getElementById('audit-action-filter');
      const userSelect = document.getElementById('audit-user-filter');

      // Preserve current values
      const currentAction = actionSelect.value;
      const currentUser = userSelect.value;

      actionSelect.innerHTML = '<option value="">All Actions</option>' +
        actions.actions.map(a => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join('');

      userSelect.innerHTML = '<option value="">All Users</option>' +
        users.users.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('');

      actionSelect.value = currentAction;
      userSelect.value = currentUser;
    } catch (error) {
      // Ignore filter loading errors
    }
  }

  // ============================================================
  // Settings
  // ============================================================

  async function loadSettings() {
    try {
      const result = await api('/api/settings');
      const settings = result.settings;

      if (settings.salt.api) {
        document.getElementById('salt-url').value = settings.salt.api.url || '';
        document.getElementById('salt-username').value = settings.salt.api.username || '';
        document.getElementById('salt-eauth').value = settings.salt.api.eauth || 'pam';
      }

      // Load system status
      loadSystemStatus();
    } catch (error) {
      showToast('Failed to load settings: ' + error.message, 'error');
    }
  }

  async function loadSystemStatus() {
    const statusEl = document.getElementById('system-status');

    try {
      const result = await api('/api/settings/status');
      const status = result.status;

      statusEl.innerHTML = `
        <div class="status-grid">
          <div class="status-item">
            <span class="status-label">Uptime</span>
            <span class="status-value">${Math.floor(status.server.uptime / 60)} min</span>
          </div>
          <div class="status-item">
            <span class="status-label">Node.js</span>
            <span class="status-value">${escapeHtml(status.server.nodeVersion)}</span>
          </div>
          <div class="status-item">
            <span class="status-label">Salt API</span>
            <span class="status-value ${status.salt.connected ? 'text-success' : 'text-error'}">
              ${status.salt.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div class="status-item">
            <span class="status-label">Minions</span>
            <span class="status-value">
              ${status.salt.minions ? `${status.salt.minions.online} online / ${status.salt.minions.offline} offline` : 'N/A'}
            </span>
          </div>
        </div>
      `;
    } catch (error) {
      statusEl.innerHTML = `<div class="loading">Failed to load status</div>`;
    }
  }

  async function testSaltConnection() {
    const resultEl = document.getElementById('salt-test-result');
    resultEl.className = 'test-result';
    resultEl.classList.remove('hidden');
    resultEl.textContent = 'Testing connection...';

    const url = document.getElementById('salt-url').value;
    const username = document.getElementById('salt-username').value;
    const password = document.getElementById('salt-password').value;
    const eauth = document.getElementById('salt-eauth').value;

    try {
      const result = await api('/api/settings/salt/test', {
        method: 'POST',
        body: JSON.stringify({ url, username, password, eauth })
      });

      if (result.connected) {
        resultEl.className = 'test-result success';
        resultEl.textContent = `Connected! Response time: ${result.details.responseTime}ms`;
      } else {
        resultEl.className = 'test-result error';
        resultEl.textContent = result.message || 'Connection failed';
      }
    } catch (error) {
      resultEl.className = 'test-result error';
      resultEl.textContent = error.message;
    }
  }

  async function saveSaltSettings(e) {
    e.preventDefault();

    const url = document.getElementById('salt-url').value;
    const username = document.getElementById('salt-username').value;
    const password = document.getElementById('salt-password').value;
    const eauth = document.getElementById('salt-eauth').value;

    try {
      await api('/api/settings/salt', {
        method: 'POST',
        body: JSON.stringify({ url, username, password, eauth })
      });

      showToast('Settings saved', 'success');
      checkSaltConnection();
    } catch (error) {
      showToast('Failed to save settings: ' + error.message, 'error');
    }
  }

  async function changePassword(e) {
    e.preventDefault();
    const resultEl = document.getElementById('password-result');

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-new-password').value;

    if (newPassword !== confirmPassword) {
      resultEl.className = 'test-result error';
      resultEl.classList.remove('hidden');
      resultEl.textContent = 'New passwords do not match';
      return;
    }

    try {
      await api('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword })
      });

      resultEl.className = 'test-result success';
      resultEl.classList.remove('hidden');
      resultEl.textContent = 'Password changed successfully';

      // Clear form
      document.getElementById('change-password-form').reset();
    } catch (error) {
      resultEl.className = 'test-result error';
      resultEl.classList.remove('hidden');
      resultEl.textContent = error.message;
    }
  }

  // ============================================================
  // Emergency Actions
  // ============================================================

  function initiateLockdown() {
    const targetType = document.getElementById('emergency-target-type').value;
    let targets;

    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'all') {
      targets = '*';
    } else {
      targets = document.getElementById('emergency-custom-target').value.trim();
      if (!targets) {
        showToast('Custom target pattern is required', 'warning');
        return;
      }
    }

    const targetDesc = Array.isArray(targets) ? targets.join(', ') : targets;

    showConfirmModal(
      'Confirm Lockdown',
      `This will lock down the following targets: ${targetDesc}\n\nAll non-essential services will be stopped and firewall rules will be applied. Only Salt connectivity will be preserved. Are you sure?`,
      async () => {
        showToast('Lockdown initiated...', 'warning');

        try {
          const result = await api('/api/emergency/lockdown', {
            method: 'POST',
            body: JSON.stringify({
              targets,
              confirm: 'LOCKDOWN'
            })
          });

          let message = `Lockdown complete: ${result.summary.success}/${result.summary.total} succeeded`;
          if (result.summary.failed > 0) {
            showToast(message, 'warning');
          } else {
            showToast(message, 'success');
          }
        } catch (error) {
          showToast('Lockdown failed: ' + error.message, 'error');
        }
      }
    );
  }

  // ============================================================
  // Key Management
  // ============================================================

  async function loadKeys() {
    try {
      const result = await api('/api/devices/keys/all');
      renderKeys(result.keys, result.counts);
    } catch (error) {
      showToast('Failed to load keys: ' + error.message, 'error');
    }
  }

  function renderKeys(keys, counts) {
    // Update counts
    document.getElementById('pending-count').textContent = counts.pending;
    document.getElementById('accepted-count').textContent = counts.accepted;
    document.getElementById('rejected-count').textContent = counts.rejected;
    document.getElementById('denied-count').textContent = counts.denied;

    // Render pending keys
    const pendingList = document.getElementById('pending-keys-list');
    if (keys.pending.length === 0) {
      pendingList.innerHTML = '<div class="keys-empty">No pending keys</div>';
    } else {
      pendingList.innerHTML = keys.pending.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-accept" onclick="acceptKey('${escapeHtml(key)}')">Accept</button>
            <button class="btn btn-reject" onclick="rejectKey('${escapeHtml(key)}')">Reject</button>
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }

    // Render accepted keys
    const acceptedList = document.getElementById('accepted-keys-list');
    if (keys.accepted.length === 0) {
      acceptedList.innerHTML = '<div class="keys-empty">No accepted keys</div>';
    } else {
      acceptedList.innerHTML = keys.accepted.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }

    // Render rejected keys
    const rejectedList = document.getElementById('rejected-keys-list');
    if (keys.rejected.length === 0) {
      rejectedList.innerHTML = '<div class="keys-empty">No rejected keys</div>';
    } else {
      rejectedList.innerHTML = keys.rejected.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-accept" onclick="acceptKey('${escapeHtml(key)}')">Accept</button>
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }

    // Render denied keys
    const deniedList = document.getElementById('denied-keys-list');
    if (keys.denied.length === 0) {
      deniedList.innerHTML = '<div class="keys-empty">No denied keys</div>';
    } else {
      deniedList.innerHTML = keys.denied.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-accept" onclick="acceptKey('${escapeHtml(key)}')">Accept</button>
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }
  }

  async function acceptKey(minionId) {
    try {
      await api('/api/devices/keys/accept', {
        method: 'POST',
        body: JSON.stringify({ minionId })
      });
      showToast(`Key accepted for ${minionId}`, 'success');
      loadKeys();
      // Also refresh devices list
      loadDevices(true);
    } catch (error) {
      showToast('Failed to accept key: ' + error.message, 'error');
    }
  }

  async function rejectKey(minionId) {
    try {
      await api('/api/devices/keys/reject', {
        method: 'POST',
        body: JSON.stringify({ minionId })
      });
      showToast(`Key rejected for ${minionId}`, 'success');
      loadKeys();
    } catch (error) {
      showToast('Failed to reject key: ' + error.message, 'error');
    }
  }

  async function deleteKey(minionId) {
    showConfirmModal(
      'Delete Minion Key',
      `Are you sure you want to delete the key for "${minionId}"? This will remove the minion from Salt.`,
      async () => {
        try {
          await api(`/api/devices/keys/${encodeURIComponent(minionId)}`, {
            method: 'DELETE'
          });
          showToast(`Key deleted for ${minionId}`, 'success');
          loadKeys();
          loadDevices(true);
        } catch (error) {
          showToast('Failed to delete key: ' + error.message, 'error');
        }
      }
    );
  }

  async function acceptAllKeys() {
    showConfirmModal(
      'Accept All Pending Keys',
      'Are you sure you want to accept all pending minion keys?',
      async () => {
        try {
          const result = await api('/api/devices/keys/accept-all', {
            method: 'POST'
          });
          showToast(`Accepted ${result.accepted.length} keys`, 'success');
          loadKeys();
          loadDevices(true);
        } catch (error) {
          showToast('Failed to accept keys: ' + error.message, 'error');
        }
      }
    );
  }

  // Expose key functions to window for onclick handlers
  window.acceptKey = acceptKey;
  window.rejectKey = rejectKey;
  window.deleteKey = deleteKey;

  // ============================================================
  // Services Management
  // ============================================================

  function populateSingleDeviceSelects() {
    const selects = [
      document.getElementById('svc-single-target'),
      document.getElementById('proc-single-target')
    ];

    selects.forEach(select => {
      if (!select) return;
      const currentValue = select.value;
      select.innerHTML = '<option value="">Select device...</option>' +
        state.devices.map(d => `<option value="${escapeHtml(d.id)}">${escapeHtml(d.id)}</option>`).join('');
      select.value = currentValue;
    });
  }

  async function loadServices() {
    const outputEl = document.getElementById('svc-output');
    const listEl = document.getElementById('services-list');
    const targetType = document.getElementById('svc-target-type').value;

    let target;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      if (state.selectedDevices.size > 1) {
        showToast('Select a single device to list services', 'warning');
        return;
      }
      target = Array.from(state.selectedDevices)[0];
    } else {
      target = document.getElementById('svc-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
    }

    listEl.innerHTML = '<div class="loading">Loading services...</div>';

    try {
      const result = await api(`/api/services/${encodeURIComponent(target)}`);
      const services = result.services?.[target] || [];

      if (services.length === 0) {
        listEl.innerHTML = '<div class="loading">No services found</div>';
        return;
      }

      listEl.innerHTML = services.map(svc =>
        `<div class="service-item" data-name="${escapeHtml(svc)}">${escapeHtml(svc)}</div>`
      ).join('');

      // Click to select
      listEl.querySelectorAll('.service-item').forEach(item => {
        item.addEventListener('click', () => {
          listEl.querySelectorAll('.service-item').forEach(i => i.classList.remove('selected'));
          item.classList.add('selected');
          document.getElementById('svc-name').value = item.dataset.name;
        });
      });

    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function serviceAction(action) {
    const service = document.getElementById('svc-name').value.trim();
    const outputEl = document.getElementById('svc-output');
    const targetType = document.getElementById('svc-target-type').value;

    if (!service) {
      showToast('Enter a service name', 'warning');
      return;
    }

    let targets;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else {
      const target = document.getElementById('svc-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    }

    outputEl.textContent = `${action}ing service ${service}...`;

    try {
      const result = await api(`/api/services/${action}`, {
        method: 'POST',
        body: JSON.stringify({ targets, service })
      });

      let output = `Action: ${action}\nService: ${service}\n\n`;
      for (const [minion, data] of Object.entries(result.results || {})) {
        output += `-- ${minion} --\n`;
        output += typeof data === 'boolean' ? (data ? 'Success' : 'Failed') : JSON.stringify(data, null, 2);
        output += '\n\n';
      }
      outputEl.textContent = output;
      showToast(`Service ${action} completed`, 'success');

    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast(`Service ${action} failed`, 'error');
    }
  }

  // ============================================================
  // Process Management
  // ============================================================

  async function loadProcesses() {
    const outputEl = document.getElementById('proc-output');
    const listEl = document.getElementById('processes-list');
    const targetType = document.getElementById('proc-target-type').value;
    const limit = document.getElementById('proc-limit').value;

    let target;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      if (state.selectedDevices.size > 1) {
        showToast('Select a single device to list processes', 'warning');
        return;
      }
      target = Array.from(state.selectedDevices)[0];
    } else {
      target = document.getElementById('proc-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
    }

    listEl.innerHTML = '<div class="loading">Loading processes...</div>';

    try {
      const result = await api(`/api/processes/${encodeURIComponent(target)}?limit=${limit}`);
      const processes = result.processes?.[target];

      if (!processes) {
        listEl.innerHTML = '<div class="loading">No process data</div>';
        return;
      }

      // Format process list
      let html = '<div class="process-header">PID | CPU% | MEM% | COMMAND</div>';
      if (Array.isArray(processes)) {
        processes.forEach(p => {
          const pid = p.pid || p.PID || '?';
          const cpu = p.cpu_percent || p.cpu || '?';
          const mem = p.mem_percent || p.mem || '?';
          const cmd = p.name || p.cmdline || p.command || '?';
          html += `<div class="process-item" data-pid="${pid}">${pid} | ${cpu} | ${mem} | ${escapeHtml(String(cmd).substring(0, 80))}</div>`;
        });
      } else {
        html += `<pre>${escapeHtml(JSON.stringify(processes, null, 2))}</pre>`;
      }

      listEl.innerHTML = html;

      // Click to select PID
      listEl.querySelectorAll('.process-item').forEach(item => {
        item.addEventListener('click', () => {
          listEl.querySelectorAll('.process-item').forEach(i => i.classList.remove('selected'));
          item.classList.add('selected');
          document.getElementById('proc-pid').value = item.dataset.pid;
        });
      });

    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function killProcess() {
    const pid = document.getElementById('proc-pid').value.trim();
    const outputEl = document.getElementById('proc-output');
    const targetType = document.getElementById('proc-target-type').value;

    if (!pid) {
      showToast('Enter a PID', 'warning');
      return;
    }

    let targets;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else {
      const target = document.getElementById('proc-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    }

    outputEl.textContent = `Killing process ${pid}...`;

    try {
      const result = await api('/api/processes/kill', {
        method: 'POST',
        body: JSON.stringify({ targets, pid: parseInt(pid), signal: 9 })
      });

      outputEl.textContent = JSON.stringify(result.results, null, 2);
      showToast('Kill signal sent', 'success');

    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Kill failed', 'error');
    }
  }

  async function pkillProcess() {
    const pattern = document.getElementById('proc-pattern').value.trim();
    const outputEl = document.getElementById('proc-output');
    const targetType = document.getElementById('proc-target-type').value;

    if (!pattern) {
      showToast('Enter a process name pattern', 'warning');
      return;
    }

    let targets;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else {
      const target = document.getElementById('proc-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    }

    showConfirmModal(
      'Confirm Kill',
      `Kill all processes matching "${pattern}"?`,
      async () => {
        outputEl.textContent = `Killing processes matching ${pattern}...`;

        try {
          const result = await api('/api/processes/pkill', {
            method: 'POST',
            body: JSON.stringify({ targets, pattern, signal: 9 })
          });

          outputEl.textContent = JSON.stringify(result.results, null, 2);
          showToast('Kill signal sent', 'success');

        } catch (error) {
          outputEl.textContent = `Error: ${error.message}`;
          showToast('Kill failed', 'error');
        }
      }
    );
  }

  // ============================================================
  // Password Management
  // ============================================================

  async function changeRemotePassword() {
    const targetType = document.getElementById('pwd-target-type').value;
    const username = document.getElementById('pwd-username').value.trim();
    const password = document.getElementById('pwd-password').value;
    const confirm = document.getElementById('pwd-confirm').value;
    const outputEl = document.getElementById('pwd-output');

    if (!username || !password) {
      showToast('Enter username and password', 'warning');
      return;
    }

    if (password !== confirm) {
      showToast('Passwords do not match', 'error');
      return;
    }

    if (password.length < 8) {
      showToast('Password must be at least 8 characters', 'warning');
      return;
    }

    let targets;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'all') {
      targets = '*';
    } else {
      targets = document.getElementById('pwd-custom-target').value.trim();
      if (!targets) {
        showToast('Enter custom target pattern', 'warning');
        return;
      }
    }

    const targetDesc = Array.isArray(targets) ? targets.join(', ') : targets;

    showConfirmModal(
      'Confirm Password Change',
      `Change password for user "${username}" on: ${targetDesc}?`,
      async () => {
        outputEl.textContent = 'Changing password...';

        try {
          const result = await api('/api/passwords/change', {
            method: 'POST',
            body: JSON.stringify({ targets, username, password })
          });

          let output = `Password change for: ${username}\n`;
          output += `Total: ${result.summary.total}, Success: ${result.summary.success}, Failed: ${result.summary.failed}\n\n`;

          for (const [minion, data] of Object.entries(result.results)) {
            output += `-- ${minion} --\n`;
            output += data.success ? 'SUCCESS' : `FAILED: ${data.error || 'Unknown error'}`;
            output += '\n\n';
          }

          outputEl.textContent = output;
          showToast(`Password changed on ${result.summary.success}/${result.summary.total} devices`, result.summary.failed > 0 ? 'warning' : 'success');

          // Clear password fields
          document.getElementById('pwd-password').value = '';
          document.getElementById('pwd-confirm').value = '';

        } catch (error) {
          outputEl.textContent = `Error: ${error.message}`;
          showToast('Password change failed', 'error');
        }
      }
    );
  }

  // ============================================================
  // Event Listeners Setup
  // ============================================================

  function setupEventListeners() {
    // Login/Setup forms
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('setup-form').addEventListener('submit', handleSetup);

    // Logout
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        if (item.dataset.view) {
          switchView(item.dataset.view);
        }
      });
    });

    // Devices
    document.getElementById('select-all-btn').addEventListener('click', selectAllDevices);
    document.getElementById('select-linux-btn').addEventListener('click', selectLinuxDevices);
    document.getElementById('select-windows-btn').addEventListener('click', selectWindowsDevices);
    document.getElementById('clear-selection-btn').addEventListener('click', clearDeviceSelection);
    document.getElementById('refresh-devices-btn').addEventListener('click', () => loadDevices(true));
    document.getElementById('device-filter').addEventListener('input', renderDeviceList);

    // Commands
    document.getElementById('cmd-execute-btn').addEventListener('click', executeCommand);
    document.getElementById('cmd-clear-btn').addEventListener('click', () => {
      document.getElementById('cmd-output').textContent = 'No output yet.';
    });
    document.getElementById('cmd-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('cmd-output').textContent);
      showToast('Output copied to clipboard', 'success');
    });
    document.getElementById('cmd-target-type').addEventListener('change', (e) => {
      document.getElementById('cmd-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
    });

    // Scripts
    document.getElementById('refresh-scripts-btn').addEventListener('click', loadScripts);
    document.getElementById('script-execute-btn').addEventListener('click', executeScript);
    document.getElementById('script-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('script-output').textContent);
      showToast('Output copied to clipboard', 'success');
    });
    document.getElementById('script-target-type').addEventListener('change', (e) => {
      document.getElementById('script-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
    });
    document.getElementById('scripts-os-filter').addEventListener('change', (e) => {
      // Reload with filter
      loadScripts();
    });

    // Audit
    document.getElementById('refresh-audit-btn').addEventListener('click', loadAuditLog);
    document.getElementById('audit-action-filter').addEventListener('change', loadAuditLog);
    document.getElementById('audit-user-filter').addEventListener('change', loadAuditLog);
    document.getElementById('audit-limit').addEventListener('change', loadAuditLog);

    // Settings
    document.getElementById('salt-settings-form').addEventListener('submit', saveSaltSettings);
    document.getElementById('test-salt-btn').addEventListener('click', testSaltConnection);
    document.getElementById('change-password-form').addEventListener('submit', changePassword);

    // Emergency
    document.getElementById('lockdown-btn').addEventListener('click', initiateLockdown);
    document.getElementById('emergency-target-type').addEventListener('change', (e) => {
      document.getElementById('emergency-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
    });

    // Services
    document.getElementById('svc-load-btn').addEventListener('click', loadServices);
    document.getElementById('svc-start-btn').addEventListener('click', () => serviceAction('start'));
    document.getElementById('svc-stop-btn').addEventListener('click', () => serviceAction('stop'));
    document.getElementById('svc-restart-btn').addEventListener('click', () => serviceAction('restart'));
    document.getElementById('svc-enable-btn').addEventListener('click', () => serviceAction('enable'));
    document.getElementById('svc-disable-btn').addEventListener('click', () => serviceAction('disable'));
    document.getElementById('svc-target-type').addEventListener('change', (e) => {
      document.getElementById('svc-single-target').classList.toggle('hidden', e.target.value !== 'single');
    });

    // Processes
    document.getElementById('proc-load-btn').addEventListener('click', loadProcesses);
    document.getElementById('proc-kill-btn').addEventListener('click', killProcess);
    document.getElementById('proc-pkill-btn').addEventListener('click', pkillProcess);
    document.getElementById('proc-target-type').addEventListener('change', (e) => {
      document.getElementById('proc-single-target').classList.toggle('hidden', e.target.value !== 'single');
    });

    // Passwords
    document.getElementById('pwd-change-btn').addEventListener('click', changeRemotePassword);
    document.getElementById('pwd-target-type').addEventListener('change', (e) => {
      document.getElementById('pwd-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
    });

    // Keys
    document.getElementById('refresh-keys-btn').addEventListener('click', loadKeys);
    document.getElementById('accept-all-keys-btn').addEventListener('click', acceptAllKeys);

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      // Ctrl+Enter to execute command
      if (e.ctrlKey && e.key === 'Enter') {
        if (state.currentView === 'commands') {
          executeCommand();
        } else if (state.currentView === 'scripts') {
          executeScript();
        }
      }
    });
  }

  // ============================================================
  // Initialization
  // ============================================================

  async function init() {
    setupEventListeners();

    // Check if setup is required
    const setupRequired = await checkSetupRequired();

    if (setupRequired) {
      showLoginScreen(true);
      return;
    }

    // Check if already authenticated
    const isAuthenticated = await checkAuth();

    if (isAuthenticated) {
      showAppScreen();
    } else {
      showLoginScreen(false);
    }

    // Periodic health checks
    setInterval(checkSaltConnection, HEALTH_CHECK_INTERVAL);
  }

  // Start the application
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
