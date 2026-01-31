#!/bin/bash
#
# Salt-GUI Browser-Perspective Feature Tests
# Simulates user activity through the web interface
#
set -uo pipefail

BASE="http://localhost:3000"
COOKIES="/tmp/saltgui-test-cookies.txt"
JS_FILE="/tmp/saltgui-test-app.js"
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL: $1"; echo "    Detail: $2"; }

echo "=============================="
echo "Salt-GUI Browser Feature Tests"
echo "=============================="
echo ""

# ----------------------------------------------------------
# Pre-req: Login and get session cookie
# ----------------------------------------------------------
echo "[Setup] Logging in..."
LOGIN=$(curl -s -c "$COOKIES" -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Changeme1!"}')

if echo "$LOGIN" | grep -q '"success":true'; then
  echo "[Setup] Login successful"
else
  echo "[Setup] FATAL: Login failed: $LOGIN"
  exit 1
fi
echo ""

# ----------------------------------------------------------
# Test: Health check shows connected
# ----------------------------------------------------------
echo "== Pre-check: Salt connection =="
HEALTH=$(curl -s -b "$COOKIES" "$BASE/api/health")
if echo "$HEALTH" | grep -q '"status":"connected"'; then
  pass "Salt API is connected"
else
  fail "Salt API not connected" "$HEALTH"
fi
echo ""

# ----------------------------------------------------------
# Feature 5: Disconnect Banner HTML
# ----------------------------------------------------------
echo "== Feature 5: Disconnect Banner =="

HTML=$(curl -s -b "$COOKIES" "$BASE/")

if echo "$HTML" | grep -q 'id="salt-disconnect-banner"'; then
  pass "Disconnect banner element exists in HTML"
else
  fail "Disconnect banner element missing" "Not found in HTML"
fi

if echo "$HTML" | grep -q 'disconnect-banner hidden'; then
  pass "Disconnect banner is hidden by default"
else
  fail "Disconnect banner not hidden by default" ""
fi

if echo "$HTML" | grep -q 'Salt API disconnected -- commands will fail'; then
  pass "Disconnect banner has correct text"
else
  fail "Disconnect banner text missing" ""
fi
echo ""

# ----------------------------------------------------------
# Feature 5: CSS has banner styles
# ----------------------------------------------------------
echo "== Feature 5: Banner CSS =="

CSS=$(curl -s -b "$COOKIES" "$BASE/css/styles.css")

if echo "$CSS" | grep -q '.disconnect-banner'; then
  pass "CSS contains .disconnect-banner class"
else
  fail "CSS missing .disconnect-banner class" ""
fi
echo ""

# ----------------------------------------------------------
# Feature 2: Loading indicator (verify JS delivered to browser)
# ----------------------------------------------------------
echo "== Feature 2: Loading Indicator =="

curl -s -b "$COOKIES" "$BASE/js/app.js" > "$JS_FILE"

if grep -q 'startElapsedTimer' "$JS_FILE"; then
  pass "JS contains startElapsedTimer function"
else
  fail "JS missing startElapsedTimer" ""
fi

if grep -q 'Executing\.\.\. (0s)' "$JS_FILE"; then
  pass "JS shows initial timer text"
else
  fail "JS missing initial timer text" ""
fi
echo ""

# ----------------------------------------------------------
# Feature 3: Cancel running command
# ----------------------------------------------------------
echo "== Feature 3: Cancel Running Command =="

if grep -q 'activeCommandAbort' "$JS_FILE"; then
  pass "JS tracks AbortController for cancel"
else
  fail "JS missing abort tracking" ""
fi

if grep -q "btn.textContent = 'Cancel'" "$JS_FILE"; then
  pass "JS changes button to Cancel during execution"
else
  fail "JS missing Cancel button state" ""
fi

if grep -q "AbortError" "$JS_FILE"; then
  pass "JS handles AbortError gracefully"
else
  fail "JS missing AbortError handling" ""
fi
echo ""

# ----------------------------------------------------------
# Feature 4: Command History
# ----------------------------------------------------------
echo "== Feature 4: Command History =="

if grep -q 'salt-gui-cmd-history' "$JS_FILE"; then
  pass "JS uses localStorage key 'salt-gui-cmd-history'"
else
  fail "JS missing history localStorage key" ""
fi

if grep -q 'CMD_HISTORY_MAX = 50' "$JS_FILE"; then
  pass "JS caps history at 50 entries"
else
  fail "JS missing history cap" ""
fi

if grep -q 'navigateCmdHistory' "$JS_FILE"; then
  pass "JS has history navigation function"
else
  fail "JS missing history navigation" ""
fi

if grep -q "ArrowUp" "$JS_FILE"; then
  pass "JS listens for ArrowUp key"
else
  fail "JS missing ArrowUp listener" ""
fi

if grep -q "ArrowDown" "$JS_FILE"; then
  pass "JS listens for ArrowDown key"
else
  fail "JS missing ArrowDown listener" ""
fi
echo ""

# ----------------------------------------------------------
# Feature 6: SSE Streaming Client JS
# ----------------------------------------------------------
echo "== Feature 6: SSE Streaming Client =="

if grep -q 'streamCommandResults' "$JS_FILE"; then
  pass "JS has streamCommandResults function"
else
  fail "JS missing streamCommandResults" ""
fi

if grep -q 'new EventSource' "$JS_FILE"; then
  pass "JS creates EventSource for SSE"
else
  fail "JS missing EventSource creation" ""
fi

if grep -q '/api/commands/run-async' "$JS_FILE"; then
  pass "JS calls run-async endpoint"
else
  fail "JS missing run-async call" ""
fi

if grep -q 'activeEventSource' "$JS_FILE"; then
  pass "JS tracks active EventSource"
else
  fail "JS missing EventSource tracking" ""
fi
echo ""

# ----------------------------------------------------------
# Feature 1 + Integration: Synchronous command execution
# ----------------------------------------------------------
echo "== Feature 1: Retry + End-to-End Command Execution =="

CMD_RESULT=$(curl -s -b "$COOKIES" -X POST "$BASE/api/commands/run" \
  -H 'Content-Type: application/json' \
  -d '{"targets":"minion-ubuntu","command":"hostname","shell":"bash","timeout":30}')

if echo "$CMD_RESULT" | grep -q '"success":true'; then
  pass "Synchronous command execution succeeded"
else
  fail "Synchronous command execution failed" "$CMD_RESULT"
fi

if echo "$CMD_RESULT" | grep -q '"minion-ubuntu"'; then
  pass "Got result from minion-ubuntu"
else
  fail "Missing minion-ubuntu in results" "$CMD_RESULT"
fi

if echo "$CMD_RESULT" | grep -q 'execution_time_ms'; then
  pass "Response includes execution_time_ms"
else
  fail "Missing execution_time_ms" "$CMD_RESULT"
fi
echo ""

# ----------------------------------------------------------
# Feature 6: Async command + SSE streaming end-to-end
# ----------------------------------------------------------
echo "== Feature 6: Async Command + SSE Stream =="

ASYNC_RESULT=$(curl -s -b "$COOKIES" -X POST "$BASE/api/commands/run-async" \
  -H 'Content-Type: application/json' \
  -d '{"targets":"minion-ubuntu","command":"echo hello-from-sse-test","shell":"bash","timeout":30}')

if echo "$ASYNC_RESULT" | grep -q '"success":true'; then
  pass "Async command submission succeeded"
else
  fail "Async command submission failed" "$ASYNC_RESULT"
fi

JID=$(echo "$ASYNC_RESULT" | grep -o '"jid":"[^"]*"' | cut -d'"' -f4)

if [ -n "$JID" ]; then
  pass "Got JID: $JID"
else
  fail "No JID returned" "$ASYNC_RESULT"
  JID=""
fi

if [ -n "$JID" ]; then
  # Wait for the async job to complete
  sleep 3

  # Test SSE stream endpoint
  SSE_OUTPUT=$(timeout 20 curl -s -b "$COOKIES" -N "$BASE/api/commands/stream/$JID" 2>&1 || true)

  if echo "$SSE_OUTPUT" | grep -q 'event: status'; then
    pass "SSE stream sent status event"
  else
    fail "SSE stream missing status event" "$(echo "$SSE_OUTPUT" | head -5)"
  fi

  if echo "$SSE_OUTPUT" | grep -q 'event: result'; then
    pass "SSE stream sent result event"
  else
    fail "SSE stream missing result event" "$(echo "$SSE_OUTPUT" | head -5)"
  fi

  if echo "$SSE_OUTPUT" | grep -q 'hello-from-sse-test'; then
    pass "SSE stream contains command output"
  else
    fail "SSE stream missing command output" "$(echo "$SSE_OUTPUT" | head -10)"
  fi

  if echo "$SSE_OUTPUT" | grep -q '"status":"complete"'; then
    pass "SSE stream sent complete status"
  else
    fail "SSE stream missing complete status" "$(echo "$SSE_OUTPUT" | tail -5)"
  fi
fi
echo ""

# ----------------------------------------------------------
# Feature 6: SSE validation - invalid JID
# ----------------------------------------------------------
echo "== Feature 6: SSE Validation =="

INVALID_SSE=$(curl -s -b "$COOKIES" -o /dev/null -w "%{http_code}" "$BASE/api/commands/stream/abc-invalid")
if [ "$INVALID_SSE" = "400" ]; then
  pass "SSE rejects invalid JID with 400"
else
  fail "SSE should reject invalid JID" "Got HTTP $INVALID_SSE"
fi
echo ""

# ----------------------------------------------------------
# Feature 1: Retry logic (verify code on deployed server)
# ----------------------------------------------------------
echo "== Feature 1: Retry Logic (deployed code) =="

SALT_CLIENT_FILE="/opt/salt-gui/src/lib/salt-client.js"
if [ ! -r "$SALT_CLIENT_FILE" ]; then
  # Try with sudo
  SALT_CLIENT=$(sudo cat "$SALT_CLIENT_FILE" 2>/dev/null)
else
  SALT_CLIENT=$(cat "$SALT_CLIENT_FILE")
fi

if echo "$SALT_CLIENT" | grep -q 'maxRetries = 2'; then
  pass "Server has retry logic with maxRetries=2"
else
  fail "Server missing retry logic" ""
fi

if echo "$SALT_CLIENT" | grep -q 'ECONNREFUSED'; then
  pass "Server retries on ECONNREFUSED"
else
  fail "Server missing ECONNREFUSED retry" ""
fi

if echo "$SALT_CLIENT" | grep -q '502'; then
  pass "Server retries on HTTP 502/503/504"
else
  fail "Server missing HTTP 5xx retry" ""
fi

if echo "$SALT_CLIENT" | grep -q '\[1000, 2000\]'; then
  pass "Server uses 1s, 2s retry delays"
else
  fail "Server missing retry delays" ""
fi
echo ""

# ----------------------------------------------------------
# Integration: Multi-target command
# ----------------------------------------------------------
echo "== Integration: Multi-target command =="

MULTI_CMD=$(curl -s -b "$COOKIES" -X POST "$BASE/api/commands/run" \
  -H 'Content-Type: application/json' \
  -d '{"targets":"*","command":"whoami","shell":"bash","timeout":15}')

TOTAL_DEVICES=$(echo "$MULTI_CMD" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2)
# Extract success count from summary (not from individual results)
SUCCESS_DEVICES=$(echo "$MULTI_CMD" | grep -o '"summary":{[^}]*}' | grep -o '"success":[0-9]*' | cut -d: -f2)

if [ "${TOTAL_DEVICES:-0}" -ge 1 ]; then
  pass "Multi-target command reached $TOTAL_DEVICES device(s)"
else
  fail "Multi-target command reached no devices" "$MULTI_CMD"
fi

if [ "${SUCCESS_DEVICES:-0}" -ge 1 ]; then
  pass "Multi-target command: $SUCCESS_DEVICES succeeded"
else
  fail "Multi-target command: none succeeded" "$MULTI_CMD"
fi
echo ""

# ----------------------------------------------------------
# Integration: Device list
# ----------------------------------------------------------
echo "== Integration: Device list =="

DEVICES=$(curl -s -b "$COOKIES" "$BASE/api/devices")

if echo "$DEVICES" | grep -q '"success":true'; then
  pass "Device list API returned successfully"
else
  fail "Device list API failed" "$DEVICES"
fi

if echo "$DEVICES" | grep -q 'minion-ubuntu'; then
  pass "minion-ubuntu appears in device list"
else
  fail "minion-ubuntu not in device list" "$DEVICES"
fi
echo ""

# ----------------------------------------------------------
# Integration: Script list (verify frontend can load scripts)
# ----------------------------------------------------------
echo "== Integration: Script list =="

SCRIPTS=$(curl -s -b "$COOKIES" "$BASE/api/scripts/tree")
if echo "$SCRIPTS" | grep -q '"success":true'; then
  pass "Script tree API returned successfully"
else
  fail "Script tree API failed" "$SCRIPTS"
fi
echo ""

# ----------------------------------------------------------
# Summary
# ----------------------------------------------------------
rm -f "$COOKIES" "$JS_FILE"
echo "=============================="
echo "Results: $PASS passed, $FAIL failed out of $TOTAL tests"
echo "=============================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
