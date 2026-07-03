// Solo-mode circuit breaker (pure decision logic, unit-testable).
//
// The wild Mad Dog loop, on a crash, sleeps 10s and blindly respawns forever.
// Solo replaces that with a bounded breaker: count consecutive failed cycles,
// reset on any success, and once the count hits the threshold, signal STOP so
// the caller can hard-exit instead of thrashing. Keeping the decision pure (no
// git, no process.exit, no clock) lets test/solo/breaker.test.js exercise every
// transition without spawning a daemon.

// Advance the breaker by one cycle result. Returns the new state plus whether
// the caller should trip (stop the process).
//   state: { consecutiveFailures }
//   ok:    did the cycle succeed?
//   maxConsecutiveFailures: threshold (>=1)
function step(state, ok, maxConsecutiveFailures) {
  const max = Math.max(1, maxConsecutiveFailures | 0);
  const prev = (state && state.consecutiveFailures) || 0;
  const consecutiveFailures = ok ? 0 : prev + 1;
  return {
    state: { consecutiveFailures },
    tripped: !ok && consecutiveFailures >= max,
  };
}

module.exports = { step };
