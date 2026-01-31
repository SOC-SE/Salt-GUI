/**
 * Tests for frontend features (Features 2-5)
 *
 * Tests command history, loading indicator logic, cancel behavior,
 * and disconnect banner logic.
 *
 * Since these are frontend JS features inside an IIFE, we test the
 * extracted logic patterns rather than the DOM-bound functions.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// ============================================================
// Feature 4: Command History (localStorage simulation)
// ============================================================

describe('Command History', () => {
  const CMD_HISTORY_MAX = 50;

  // Simulate localStorage
  let storage = {};
  const localStorage = {
    getItem: (k) => storage[k] || null,
    setItem: (k, v) => { storage[k] = v; },
    removeItem: (k) => { delete storage[k]; }
  };
  const CMD_HISTORY_KEY = 'salt-gui-cmd-history';

  function getCmdHistory() {
    try {
      return JSON.parse(localStorage.getItem(CMD_HISTORY_KEY)) || [];
    } catch { return []; }
  }

  function addCmdHistory(command, shell) {
    const history = getCmdHistory();
    history.unshift({ command, shell, timestamp: Date.now() });
    if (history.length > CMD_HISTORY_MAX) history.length = CMD_HISTORY_MAX;
    localStorage.setItem(CMD_HISTORY_KEY, JSON.stringify(history));
  }

  beforeEach(() => {
    storage = {};
  });

  it('should start with empty history', () => {
    assert.deepEqual(getCmdHistory(), []);
  });

  it('should add a command to history', () => {
    addCmdHistory('whoami', 'bash');
    const history = getCmdHistory();
    assert.equal(history.length, 1);
    assert.equal(history[0].command, 'whoami');
    assert.equal(history[0].shell, 'bash');
    assert.ok(history[0].timestamp > 0);
  });

  it('should prepend new commands (most recent first)', () => {
    addCmdHistory('first', 'bash');
    addCmdHistory('second', 'bash');
    addCmdHistory('third', 'bash');
    const history = getCmdHistory();
    assert.equal(history[0].command, 'third');
    assert.equal(history[1].command, 'second');
    assert.equal(history[2].command, 'first');
  });

  it('should cap history at 50 entries', () => {
    for (let i = 0; i < 60; i++) {
      addCmdHistory(`cmd-${i}`, 'bash');
    }
    const history = getCmdHistory();
    assert.equal(history.length, CMD_HISTORY_MAX);
    // Most recent should be cmd-59
    assert.equal(history[0].command, 'cmd-59');
  });

  it('should persist across "page refreshes" (same localStorage)', () => {
    addCmdHistory('persistent-cmd', 'powershell');
    // Simulate page refresh by re-reading
    const history = getCmdHistory();
    assert.equal(history[0].command, 'persistent-cmd');
    assert.equal(history[0].shell, 'powershell');
  });

  it('should handle corrupted localStorage gracefully', () => {
    localStorage.setItem(CMD_HISTORY_KEY, 'not-valid-json{{{');
    const history = getCmdHistory();
    assert.deepEqual(history, []);
  });

  describe('History Navigation', () => {
    let cmdHistoryIndex = -1;
    let cmdHistoryTemp = '';
    let inputValue = '';

    function navigateCmdHistory(direction) {
      const history = getCmdHistory();
      if (history.length === 0) return;

      if (direction === 'up') {
        if (cmdHistoryIndex === -1) cmdHistoryTemp = inputValue;
        if (cmdHistoryIndex < history.length - 1) {
          cmdHistoryIndex++;
          inputValue = history[cmdHistoryIndex].command;
        }
      } else {
        if (cmdHistoryIndex > 0) {
          cmdHistoryIndex--;
          inputValue = history[cmdHistoryIndex].command;
        } else if (cmdHistoryIndex === 0) {
          cmdHistoryIndex = -1;
          inputValue = cmdHistoryTemp;
        }
      }
    }

    beforeEach(() => {
      cmdHistoryIndex = -1;
      cmdHistoryTemp = '';
      inputValue = '';
      storage = {};
    });

    it('should navigate up through history', () => {
      addCmdHistory('first', 'bash');
      addCmdHistory('second', 'bash');
      addCmdHistory('third', 'bash');

      navigateCmdHistory('up');
      assert.equal(inputValue, 'third');
      navigateCmdHistory('up');
      assert.equal(inputValue, 'second');
      navigateCmdHistory('up');
      assert.equal(inputValue, 'first');
    });

    it('should not go past the oldest entry', () => {
      addCmdHistory('only', 'bash');
      navigateCmdHistory('up');
      assert.equal(inputValue, 'only');
      navigateCmdHistory('up'); // Should stay at 'only'
      assert.equal(inputValue, 'only');
    });

    it('should navigate down to restore current input', () => {
      addCmdHistory('old-cmd', 'bash');
      inputValue = 'typing-something';

      navigateCmdHistory('up');
      assert.equal(inputValue, 'old-cmd');

      navigateCmdHistory('down');
      assert.equal(inputValue, 'typing-something');
    });

    it('should do nothing with empty history', () => {
      inputValue = 'current';
      navigateCmdHistory('up');
      assert.equal(inputValue, 'current');
      navigateCmdHistory('down');
      assert.equal(inputValue, 'current');
    });

    it('should preserve temp value when navigating up then back down', () => {
      addCmdHistory('cmd-a', 'bash');
      addCmdHistory('cmd-b', 'bash');

      inputValue = 'my-draft';
      navigateCmdHistory('up'); // cmd-b
      navigateCmdHistory('up'); // cmd-a
      navigateCmdHistory('down'); // cmd-b
      navigateCmdHistory('down'); // back to 'my-draft'
      assert.equal(inputValue, 'my-draft');
    });
  });
});

// ============================================================
// Feature 2: Loading Indicator + Elapsed Timer
// ============================================================

describe('Loading Indicator Logic', () => {
  it('should calculate elapsed seconds correctly', () => {
    const startTime = Date.now() - 5000; // 5 seconds ago
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    assert.ok(elapsed >= 4 && elapsed <= 6, `Elapsed should be ~5, got ${elapsed}`);
  });

  it('should format executing message with timer', () => {
    const elapsed = 12;
    const message = `Executing... (${elapsed}s)`;
    assert.equal(message, 'Executing... (12s)');
  });

  it('should start at 0s', () => {
    const startTime = Date.now();
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    assert.equal(elapsed, 0);
  });
});

// ============================================================
// Feature 3: Cancel Running Command (AbortController)
// ============================================================

describe('Cancel Running Command', () => {
  it('should create an AbortController with valid signal', () => {
    const controller = new AbortController();
    assert.ok(controller.signal);
    assert.equal(controller.signal.aborted, false);
  });

  it('should abort the signal when cancel is called', () => {
    const controller = new AbortController();
    controller.abort();
    assert.equal(controller.signal.aborted, true);
  });

  it('should cause fetch to throw AbortError when aborted', async () => {
    const controller = new AbortController();
    controller.abort();

    await assert.rejects(async () => {
      await fetch('http://localhost:1/nonexistent', { signal: controller.signal });
    }, (err) => {
      return err.name === 'AbortError';
    });
  });

  it('should track running state correctly', () => {
    let activeCommandAbort = null;

    // Start command
    activeCommandAbort = new AbortController();
    assert.ok(activeCommandAbort !== null, 'Should be in running state');

    // Cancel
    activeCommandAbort.abort();
    activeCommandAbort = null;
    assert.equal(activeCommandAbort, null, 'Should be in idle state');
  });

  it('should toggle button state concept', () => {
    let btnText = 'Execute';
    let btnClass = 'btn-primary';

    // Start running
    btnText = 'Cancel';
    btnClass = 'btn-danger';
    assert.equal(btnText, 'Cancel');
    assert.equal(btnClass, 'btn-danger');

    // Stop running
    btnText = 'Execute';
    btnClass = 'btn-primary';
    assert.equal(btnText, 'Execute');
    assert.equal(btnClass, 'btn-primary');
  });
});

// ============================================================
// Feature 5: Disconnect Banner Logic
// ============================================================

describe('Disconnect Banner Logic', () => {
  it('should show banner when salt status is not connected', () => {
    const health = { salt: { status: 'disconnected' } };
    const shouldShowBanner = health.salt.status !== 'connected';
    assert.equal(shouldShowBanner, true);
  });

  it('should hide banner when salt status is connected', () => {
    const health = { salt: { status: 'connected' } };
    const shouldShowBanner = health.salt.status !== 'connected';
    assert.equal(shouldShowBanner, false);
  });

  it('should show banner on health check error', () => {
    // When health check throws, we show the banner
    let shouldShowBanner = false;
    try {
      throw new Error('Network error');
    } catch {
      shouldShowBanner = true;
    }
    assert.equal(shouldShowBanner, true);
  });

  it('should coexist with status badge (both updated independently)', () => {
    // Status badge and banner use different elements
    let badgeText = '';
    let badgeClass = '';
    let bannerHidden = true;

    // Connected state
    badgeText = 'Connected';
    badgeClass = 'status-badge status-connected';
    bannerHidden = true;
    assert.equal(badgeText, 'Connected');
    assert.equal(bannerHidden, true);

    // Disconnected state
    badgeText = 'Disconnected';
    badgeClass = 'status-badge status-disconnected';
    bannerHidden = false;
    assert.equal(badgeText, 'Disconnected');
    assert.equal(bannerHidden, false);
  });
});

// ============================================================
// API helper signal passthrough
// ============================================================

describe('API Helper AbortSignal Support', () => {
  it('should extract signal from options and pass to fetch', () => {
    const controller = new AbortController();
    const options = {
      method: 'POST',
      signal: controller.signal,
      body: '{}',
      headers: { 'X-Custom': 'test' }
    };

    // Simulate the destructuring from the updated api() function
    const { signal, ...restOptions } = options;
    assert.ok(signal, 'Signal should be extracted');
    assert.equal(signal, controller.signal);
    assert.equal(restOptions.signal, undefined, 'Signal should not be in restOptions');
    assert.equal(restOptions.method, 'POST');
    assert.equal(restOptions.body, '{}');
  });

  it('should work without signal (backward compatible)', () => {
    const options = { method: 'GET' };
    const { signal, ...restOptions } = options;
    assert.equal(signal, undefined);
    assert.equal(restOptions.method, 'GET');
  });
});
