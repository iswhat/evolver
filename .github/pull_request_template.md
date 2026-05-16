## Summary

Short 1-2 sentence summary of the change.

## What changed

- Bullet list of changes

## How to test

1. Copy commands
2. Expected output

## Risk

Low / Medium / High -- note if it touches infra or public API.

## Self-check

Tick only the boxes that apply, but every applicable box must be ticked. Bugbot
reads the project rules and will request changes if anything below is missing.

- [ ] If this PR adds a new source file under `src/`, it is registered in
      `public.manifest.json` consistently with its sibling files (e.g. listed
      in `obfuscate` when the rest of the directory is). Build verification
      passed: `node scripts/build_public.js` succeeded and the new file shows
      up in `dist-public/` in the expected (obfuscated or plain) form.
- [ ] If this PR adds or modifies a schema factory under `src/gep/schemas/`,
      the corresponding `validate*` function is invoked at every write and
      every publish call site (not just defined).
- [ ] If this PR uses `Object.assign({}, DEFAULTS, partial)` to build an
      object, every reference-typed field (arrays, sub-objects) on the result
      is sliced or cloned -- not held by reference to either source.
- [ ] If this PR introduces a new module-level constant initialized from
      `process.env.X`, the owning module is loaded after the entry point's
      dotenv configuration step (or the constant is migrated to the lazy
      env helpers in `src/config.js`).
- [ ] No new runtime dependencies added without a clear justification in the
      "What changed" section above.
- [ ] Tests added or updated to cover the new behavior; full suite passes
      locally (`node --test test/*.test.js`).

## Related

Closes #NN
