'use strict';

// FNV-1a 32-bit hash — shared implementation used across gep modules.
// Returns an 8-char lowercase hex string.
function stableHash(input) {
  const s = String(input || '');
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

module.exports = { stableHash };
