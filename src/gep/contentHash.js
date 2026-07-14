// Content-addressable hashing for GEP assets.
//
// As of v1.84.0 the protocol primitives (SCHEMA_VERSION, canonicalize,
// computeAssetId, verifyAssetId) live in @evomap/gep-sdk. This module
// is a thin CommonJS facade so the ~13 internal callsites that
// `require('./contentHash')` keep working unchanged.
//
// Why move them out: every implementation that participates in GEP
// (this engine, gep-mcp-server, evox-Rust, the Hub backend) needs an
// authoritative copy of the canonicalize / computeAssetId algorithm.
// Hand-maintaining four copies caused the v1.80.8 "explore" enum
// drift incident; consolidating into the SDK makes that class of bug
// structurally impossible. If you find yourself wanting to inline the
// algorithm here again, stop -- bump @evomap/gep-sdk instead.
//
// Implementation note: @evomap/gep-sdk is published as ESM
// (`"type": "module"`). Node 22 supports `require()` of synchronous
// ESM packages, but only on 22.12.0 and later (the
// `--experimental-require-module` flag was unflagged in that
// release). `package.json#engines.node` is therefore pinned to
// `>=22.12` so the call below works in every supported runtime.

const { SCHEMA_VERSION, canonicalize, computeAssetId, verifyAssetId } = require('@evomap/gep-sdk');

module.exports = {
  SCHEMA_VERSION,
  canonicalize,
  computeAssetId,
  verifyAssetId,
};
