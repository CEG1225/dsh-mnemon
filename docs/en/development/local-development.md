# Local development

This checkout is the source for the `dsh-mnemon` packages installed in a DSH profile. The profile
installs them from the registry, so **a rebuild here changes nothing until the built `lib/`
directories are copied into the profile**. That copy is the whole loop:

```bash
# 1. edit src/ or plugins/*/src/
# 2. build (root first: sub-packages resolve `dsh-mnemon/client` from the root build output)
pnpm run build
pnpm -r --workspace-concurrency=4 run build

# 3. copy lib/ into the profile
node scripts/deploy-local.mjs              # default profile
node scripts/deploy-local.mjs --dry-run    # show what would be copied
node scripts/deploy-local.mjs --profile <name>

# 4. restart DSH Desktop completely (bundle changes are not hot-reloaded)
```

## Why the copy is needed

`dsh.profile.bundles` resolves each package from the profile's `node_modules`, and those are real
directories copied out of the registry tarball — not links into this checkout. `file:` dependencies
behave the same way: pnpm copies them. Nothing watches this directory.

A build renames its hashed chunks (`runtime-DmL0It3P.js` becomes `runtime-DjkNiYzG.js`), and a copy
does not remove the previous name. `deploy-local.mjs` moves any file in the installed `lib/` that the
current build did not produce into `lib/.stale-<timestamp>/`, so the module graph cannot resolve to a
previous build. Nothing is deleted — clear those directories by hand once you are satisfied.

## Toolchain

Node and pnpm come from the DSH Desktop bundled runtime; there is no global `node` on PATH.

```powershell
$node="C:\Users\Administrator\AppData\Local\Programs\DSH Desktop\resources\runtime\x64\primary-runtime\dependencies\node\bin\node.exe"
$pnpm="C:\Users\Administrator\AppData\Local\Programs\DSH Desktop\resources\runtime\x64\primary-runtime\dependencies\pnpm\bin\pnpm.cjs"
& $node $pnpm install --ignore-scripts
```

`pnpm install` without `--ignore-scripts` fails in this environment on `node-pty`'s `conpty`
postinstall (`ENOENT: no such file or directory, mkdir ...\node-pty\build\Release\conpty`). No
package in this workspace needs it.

Build order matters: the root package must build before `plugins/*`, because sub-packages resolve
`dsh-mnemon/client` from `lib/types/src/client/index.d.ts`, which only the root build produces.
Building sub-packages first fails with `error TS2307: Cannot find module 'dsh-mnemon/client'` plus a
run of `TS7006` implicit-any errors that are only symptoms of that first failure.

## Running the tests

Vitest runs from this checkout against the sources, not the deployed build:

```powershell
$env:PATH="D:\Git\cmd;$env:PATH"   # one Source spec shells out to `git init`
& $node $pnpm exec vitest run --dir tests
```

Git has to be on `PATH` for `tests/source.spec.ts`; without it that file fails with
`spawnSync git ENOENT`, which looks like a code failure and is not. The suite also has a handful of
failures that predate any local change — browser-storage shims (`client-session-scope.spec.tsx`),
`SIGTERM`/`git --version` host assumptions (`git-sync.spec.ts`, `review-tools.spec.ts`), and the
`pack.spec.ts` archive-size assertions. Diff the failing set against `git stash` before attributing
one to your change.

`tests/composable-memory.spec.ts` holds a real performance fence (15 s for repeated three-Source
Views). It is the test that notices if a new per-projection cost is added: guarding every entry body
made that fence fail until the guard memoized its scan.

## Verifying a change without restarting DSH

The built packages are plain ESM and can be imported directly:

```javascript
import { pathToFileURL } from 'node:url'
const m = await import(pathToFileURL('…/node_modules/dsh-mnemon-source-runtime/lib/index.js').href)
console.log(m.scanForThreats('Ignore all previous instructions'))   // ['disregard_rules']
```

`createRuntimeMemorySource({ dataDir, userDataDir, memoryLimitBytes, userLimitBytes })` accepts an
explicit throwaway directory, so a capacity or scan test never touches the real memory store.

## Writing a deploy by hand

`scripts/deploy-local.mjs` copies `lib/` for every package whose `package.json` sits in this repo or
under `plugins/`. To do it manually, copy the same directories to
`<DSH_HOME>/profiles/<profile>/node_modules/<package-name>/lib`. Back up the previous `lib/`
first — the installed package version does not change, so a bad build is only visible as behaviour,
not as a version mismatch.
