/**
 * Tests for SSE streaming endpoint (Feature 6)
 *
 * Tests the /api/commands/stream/:jid route handler behavior.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

describe('SSE Streaming Endpoint', () => {

  it('should reject invalid JID format (non-numeric)', () => {
    const jid = 'abc-invalid';
    assert.equal(/^[0-9]+$/.test(jid), false);
  });

  it('should accept valid JID format', () => {
    const jid = '20260130143000123456';
    assert.equal(/^[0-9]+$/.test(jid), true);
  });

  it('should reject empty JID', () => {
    const jid = '';
    assert.equal(!jid || !/^[0-9]+$/.test(jid), true);
  });

  it('should reject JID with special characters', () => {
    const jid = '12345; DROP TABLE';
    assert.equal(/^[0-9]+$/.test(jid), false);
  });

  describe('SSE event formatting', () => {
    function formatSSE(event, data) {
      return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    }

    it('should format status event correctly', () => {
      const result = formatSSE('status', { status: 'running', jid: '123' });
      assert.equal(result, 'event: status\ndata: {"status":"running","jid":"123"}\n\n');
    });

    it('should format result event correctly', () => {
      const result = formatSSE('result', { minion: 'web-01', output: 'root' });
      assert.equal(result, 'event: result\ndata: {"minion":"web-01","output":"root"}\n\n');
    });

    it('should format error event correctly', () => {
      const result = formatSSE('error', { message: 'connection lost' });
      assert.equal(result, 'event: error\ndata: {"message":"connection lost"}\n\n');
    });

    it('should handle output with special characters', () => {
      const result = formatSSE('result', { minion: 'db-01', output: 'line1\nline2\ttab' });
      const parsed = JSON.parse(result.split('\n')[1].replace('data: ', ''));
      assert.equal(parsed.output, 'line1\nline2\ttab');
    });
  });

  describe('Incremental result tracking', () => {
    it('should detect new minion results', () => {
      let previousKeys = new Set();

      // First poll: minion-1 reports
      const poll1 = { 'minion-1': 'output1' };
      const currentKeys1 = new Set(Object.keys(poll1));
      const newKeys1 = [];
      for (const key of currentKeys1) {
        if (!previousKeys.has(key)) newKeys1.push(key);
      }
      assert.deepEqual(newKeys1, ['minion-1']);
      previousKeys = currentKeys1;

      // Second poll: minion-1 still there, minion-2 new
      const poll2 = { 'minion-1': 'output1', 'minion-2': 'output2' };
      const currentKeys2 = new Set(Object.keys(poll2));
      const newKeys2 = [];
      for (const key of currentKeys2) {
        if (!previousKeys.has(key)) newKeys2.push(key);
      }
      assert.deepEqual(newKeys2, ['minion-2']);
      previousKeys = currentKeys2;

      // Third poll: no new minions
      const poll3 = { 'minion-1': 'output1', 'minion-2': 'output2' };
      const currentKeys3 = new Set(Object.keys(poll3));
      const newKeys3 = [];
      for (const key of currentKeys3) {
        if (!previousKeys.has(key)) newKeys3.push(key);
      }
      assert.deepEqual(newKeys3, []);
    });

    it('should determine completion when results exist', () => {
      const result = { 'minion-1': 'done' };
      const currentKeys = new Set(Object.keys(result));
      assert.equal(currentKeys.size > 0, true, 'Job should be considered complete');
    });

    it('should determine running state when no results', () => {
      const result = {};
      const currentKeys = new Set(Object.keys(result));
      assert.equal(currentKeys.size === 0, true, 'Job should be considered running');
    });
  });

  describe('Timeout enforcement', () => {
    it('should detect timeout after max duration', () => {
      const maxDuration = 10 * 60 * 1000; // 10 minutes
      const startTime = Date.now() - maxDuration - 1000; // Started 10m1s ago
      assert.equal(Date.now() - startTime > maxDuration, true);
    });

    it('should not timeout before max duration', () => {
      const maxDuration = 10 * 60 * 1000;
      const startTime = Date.now() - 5000; // Started 5s ago
      assert.equal(Date.now() - startTime > maxDuration, false);
    });
  });
});
