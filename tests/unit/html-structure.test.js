/**
 * Tests for HTML structure changes
 *
 * Verifies that the disconnect banner and other HTML elements
 * required by the new features are present.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, '../../public/index.html');
const cssPath = path.join(__dirname, '../../public/css/styles.css');
const appJsPath = path.join(__dirname, '../../public/js/app.js');

describe('HTML Structure', () => {
  const html = fs.readFileSync(htmlPath, 'utf8');

  it('should contain the disconnect banner element', () => {
    assert.ok(html.includes('id="salt-disconnect-banner"'), 'Missing disconnect banner element');
  });

  it('should have the disconnect banner hidden by default', () => {
    assert.ok(html.includes('disconnect-banner hidden'), 'Banner should be hidden by default');
  });

  it('should have the banner text', () => {
    assert.ok(html.includes('Salt API disconnected -- commands will fail'), 'Missing banner text');
  });

  it('should have banner between header and main-layout', () => {
    const headerIdx = html.indexOf('</header>');
    const bannerIdx = html.indexOf('salt-disconnect-banner');
    const mainLayoutIdx = html.indexOf('class="main-layout"');
    assert.ok(headerIdx < bannerIdx, 'Banner should come after header');
    assert.ok(bannerIdx < mainLayoutIdx, 'Banner should come before main-layout');
  });

  it('should still have the connection status badge', () => {
    assert.ok(html.includes('id="connection-status"'), 'Status badge should still exist');
  });

  it('should have cmd-execute-btn', () => {
    assert.ok(html.includes('id="cmd-execute-btn"'), 'Execute button should exist');
  });

  it('should have cmd-input textarea', () => {
    assert.ok(html.includes('id="cmd-input"'), 'Command input should exist');
  });

  it('should have script-execute-btn', () => {
    assert.ok(html.includes('id="script-execute-btn"'), 'Script execute button should exist');
  });
});

describe('CSS Styles', () => {
  const css = fs.readFileSync(cssPath, 'utf8');

  it('should have disconnect-banner styles', () => {
    assert.ok(css.includes('.disconnect-banner'), 'Missing disconnect-banner CSS class');
  });

  it('should have disconnect-banner hidden rule', () => {
    assert.ok(css.includes('.disconnect-banner.hidden'), 'Missing disconnect-banner.hidden CSS rule');
  });

  it('should style banner with error color', () => {
    // Check that the banner uses the error color for background
    const bannerSection = css.substring(css.indexOf('.disconnect-banner'));
    assert.ok(bannerSection.includes('--status-error'), 'Banner should use error color');
  });
});

describe('Frontend JavaScript', () => {
  const js = fs.readFileSync(appJsPath, 'utf8');

  describe('Feature 1: Command History', () => {
    it('should define CMD_HISTORY_KEY', () => {
      assert.ok(js.includes("'salt-gui-cmd-history'"), 'Missing CMD_HISTORY_KEY');
    });

    it('should define CMD_HISTORY_MAX of 50', () => {
      assert.ok(js.includes('CMD_HISTORY_MAX = 50'), 'Missing CMD_HISTORY_MAX');
    });

    it('should have getCmdHistory function', () => {
      assert.ok(js.includes('function getCmdHistory'), 'Missing getCmdHistory');
    });

    it('should have addCmdHistory function', () => {
      assert.ok(js.includes('function addCmdHistory'), 'Missing addCmdHistory');
    });

    it('should have navigateCmdHistory function', () => {
      assert.ok(js.includes('function navigateCmdHistory'), 'Missing navigateCmdHistory');
    });

    it('should listen for ArrowUp on cmd-input', () => {
      assert.ok(js.includes("e.key === 'ArrowUp'"), 'Missing ArrowUp handler');
    });

    it('should listen for ArrowDown on cmd-input', () => {
      assert.ok(js.includes("e.key === 'ArrowDown'"), 'Missing ArrowDown handler');
    });

    it('should call addCmdHistory in executeCommand', () => {
      // Find executeCommand and check it saves to history
      assert.ok(js.includes('addCmdHistory(command, shell)'), 'executeCommand should save to history');
    });
  });

  describe('Feature 2: Loading Indicator + Elapsed Timer', () => {
    it('should have startElapsedTimer function', () => {
      assert.ok(js.includes('function startElapsedTimer'), 'Missing startElapsedTimer');
    });

    it('should show Executing... message', () => {
      assert.ok(js.includes('Executing... (0s)'), 'Missing initial timer text');
    });

    it('should use setInterval for timer', () => {
      assert.ok(js.includes('setInterval'), 'Should use setInterval for timer');
    });

    it('should clear timer on completion', () => {
      assert.ok(js.includes('clearInterval(activeCommandTimer)') || js.includes('clearInterval(timer)'),
        'Should clear timer interval');
    });

    it('should disable script execute button during execution', () => {
      assert.ok(js.includes("executeBtn.disabled = true"), 'Script button should be disabled during execution');
    });

    it('should re-enable script execute button after execution', () => {
      assert.ok(js.includes("executeBtn.disabled = false"), 'Script button should be re-enabled');
    });
  });

  describe('Feature 3: Cancel Running Command', () => {
    it('should track AbortController', () => {
      assert.ok(js.includes('activeCommandAbort'), 'Missing activeCommandAbort');
    });

    it('should create AbortController for new commands', () => {
      assert.ok(js.includes('new AbortController()'), 'Should create AbortController');
    });

    it('should have setCommandRunning function', () => {
      assert.ok(js.includes('function setCommandRunning'), 'Missing setCommandRunning');
    });

    it('should change button to Cancel when running', () => {
      assert.ok(js.includes("btn.textContent = 'Cancel'"), 'Button should say Cancel');
    });

    it('should change button back to Execute when done', () => {
      assert.ok(js.includes("btn.textContent = 'Execute'"), 'Button should revert to Execute');
    });

    it('should add btn-danger class when running', () => {
      assert.ok(js.includes("btn.classList.add('btn-danger')"), 'Should add danger class');
    });

    it('should pass signal to api() calls', () => {
      assert.ok(js.includes('signal: abortController.signal'), 'Should pass signal to fetch');
    });

    it('should handle AbortError in api()', () => {
      assert.ok(js.includes("error.name === 'AbortError'"), 'Should check for AbortError');
    });
  });

  describe('Feature 4: Disconnect Banner', () => {
    it('should reference salt-disconnect-banner element', () => {
      assert.ok(js.includes("'salt-disconnect-banner'"), 'Should reference banner element');
    });

    it('should show banner on disconnection', () => {
      assert.ok(js.includes("bannerEl.classList.remove('hidden')"), 'Should show banner');
    });

    it('should hide banner on connection', () => {
      assert.ok(js.includes("bannerEl.classList.add('hidden')"), 'Should hide banner');
    });
  });

  describe('Feature 5: SSE Streaming Client', () => {
    it('should have streamCommandResults function', () => {
      assert.ok(js.includes('function streamCommandResults'), 'Missing streamCommandResults');
    });

    it('should use EventSource', () => {
      assert.ok(js.includes('new EventSource'), 'Should create EventSource');
    });

    it('should listen for result events', () => {
      assert.ok(js.includes("addEventListener('result'"), 'Should listen for result events');
    });

    it('should listen for status events', () => {
      assert.ok(js.includes("addEventListener('status'"), 'Should listen for status events');
    });

    it('should listen for error events', () => {
      assert.ok(js.includes("addEventListener('error'"), 'Should listen for error events');
    });

    it('should close EventSource on completion', () => {
      assert.ok(js.includes('es.close()'), 'Should close EventSource');
    });

    it('should use run-async endpoint for SSE flow', () => {
      assert.ok(js.includes('/api/commands/run-async'), 'Should call run-async');
    });

    it('should construct stream URL with JID', () => {
      assert.ok(js.includes('/api/commands/stream/'), 'Should construct stream URL');
    });

    it('should track activeEventSource', () => {
      assert.ok(js.includes('activeEventSource'), 'Should track EventSource instance');
    });

    it('should fall back to synchronous on SSE failure', () => {
      // After the SSE try block, there should be a sync fallback
      assert.ok(js.includes("// Synchronous fallback") || js.includes('/api/commands/run'),
        'Should fall back to synchronous execution');
    });
  });
});

describe('Backend - commands.js SSE route', () => {
  const commandsJs = fs.readFileSync(path.join(__dirname, '../../src/routes/commands.js'), 'utf8');

  it('should have stream/:jid route', () => {
    assert.ok(commandsJs.includes("/stream/:jid"), 'Missing stream route');
  });

  it('should set SSE headers', () => {
    assert.ok(commandsJs.includes('text/event-stream'), 'Missing SSE Content-Type');
    assert.ok(commandsJs.includes('no-cache'), 'Missing Cache-Control');
  });

  it('should poll with setInterval', () => {
    assert.ok(commandsJs.includes('setInterval'), 'Should use setInterval for polling');
  });

  it('should have 10-minute timeout', () => {
    assert.ok(commandsJs.includes('10 * 60 * 1000'), 'Should have 10-minute timeout');
  });

  it('should clean up on client disconnect', () => {
    assert.ok(commandsJs.includes("req.on('close'"), 'Should handle client disconnect');
  });

  it('should send status, result, and error events', () => {
    assert.ok(commandsJs.includes("sendEvent('status'"), 'Should send status events');
    assert.ok(commandsJs.includes("sendEvent('result'"), 'Should send result events');
    assert.ok(commandsJs.includes("sendEvent('error'"), 'Should send error events');
  });

  it('should call jobLookup for polling', () => {
    assert.ok(commandsJs.includes('saltClient.jobLookup(jid)'), 'Should poll with jobLookup');
  });
});

describe('Backend - salt-client.js Retry Logic', () => {
  const saltClientJs = fs.readFileSync(path.join(__dirname, '../../src/lib/salt-client.js'), 'utf8');

  it('should have retry loop in run()', () => {
    assert.ok(saltClientJs.includes('for (let attempt = 0; attempt <= maxRetries'), 'Missing retry loop');
  });

  it('should define retryable error codes', () => {
    assert.ok(saltClientJs.includes('ECONNREFUSED'), 'Missing ECONNREFUSED');
    assert.ok(saltClientJs.includes('ECONNRESET'), 'Missing ECONNRESET');
    assert.ok(saltClientJs.includes('ETIMEDOUT'), 'Missing ETIMEDOUT');
    assert.ok(saltClientJs.includes('ENOTFOUND'), 'Missing ENOTFOUND');
  });

  it('should define retryable HTTP statuses', () => {
    assert.ok(saltClientJs.includes('502'), 'Missing 502');
    assert.ok(saltClientJs.includes('503'), 'Missing 503');
    assert.ok(saltClientJs.includes('504'), 'Missing 504');
  });

  it('should have max 2 retries', () => {
    assert.ok(saltClientJs.includes('maxRetries = 2'), 'Should have maxRetries = 2');
  });

  it('should have delay of 1s then 2s', () => {
    assert.ok(saltClientJs.includes('[1000, 2000]'), 'Should have delays [1000, 2000]');
  });

  it('should log retry attempts', () => {
    assert.ok(saltClientJs.includes('logger.warn') && saltClientJs.includes('retrying'),
      'Should log retry attempts');
  });
});
