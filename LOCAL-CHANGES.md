# Local changes vs upstream

This checkout started as a copy of `omdsh-dev/dsh-mnemon` v0.5.46 and is now the development source
for the `dsh-mnemon` packages installed in this machine's DSH profile. Upstream is unchanged; the
list below is everything this fork does differently, so a future upstream merge has a short,
explicit conflict surface.

## Why the fork exists

Upstream's runtime memory (`MEMORY.md` / `USER.md`) has three gaps that matter once the memory is
actually used rather than just installed:

1. **A polluted entry is a persistent prompt injection.** Runtime memory is projected into the
   system prompt on every later turn. Upstream redacts secrets on write but has no scan for
   injection or exfiltration shapes, and no guard at read time — an entry written by a poisoned
   tool result, a hand edit, or an older build is replayed verbatim forever.
2. **A full store is a wall, not a negotiation.** Upstream raises
   `Would exceed … Archive and compact runtime memory before retrying.` with no byte count and no
   list of candidates, so a model has to guess how much to cut and usually just retries.
3. **No written policy for how to write.** `recallMode` / `writebackMode` only have `guided` and
   `off`; nothing writes on its own, so the store stays near-empty unless the agent has explicit
   rules about what belongs in each layer.

## What changed

### 1. `plugins/dsh-mnemon-source-runtime/src/threat-scan.ts` (new)

TypeScript port of the Hermes Agent threat-pattern design.

- Scoped table `all ⊂ context ⊂ strict`; `scanForThreats(content, scope)` returns matching ids.
- `FILLER = (?:\w{1,64}\s{1,64}){0,8}` bounds every gap, so no pattern can backtrack
  super-linearly. `SECRET_VAR` matches `$KEY` / `${API_TOKEN}` style shell references.
- 24 patterns: instruction override (`disregard_rules`, `forget_rules`, `bypass_restrictions`,
  `remove_filters`, `sys_prompt_override`, `role_hijack`, `identity_override`, `fake_update`,
  `translate_execute`, `deception_hide`), prompt exfiltration (`leak_system_prompt`), markup-borne
  injection (`html_comment_injection`, `hidden_div`), C2 shapes (`c2_node_registration`,
  `c2_heartbeat`, `c2_task_pull`, `known_c2_framework`, `anti_forensic_oneliner`), exfiltration
  (`exfil_curl`, `exfil_wget`, `read_secrets`, `ssh_backdoor`, `env_var_unset_agent`) and pasted
  credentials (`hardcoded_secret`).
- `maskNegatedForget()` blanks a negated forget clause first, so "Do not forget the rules" is not
  read as "forget the rules".
- Invisible-character detection: zero-width and bidi set, plus the U+E0000..U+E007F tag block with
  the RGI emoji flag sequences (`🏴` + tags + cancel) stripped first, because those are the block's
  only legitimate use.
- `MAX_SCAN_CHARS = 65_536` with `CHUNK_OVERLAP = 4_096`: long content is scanned in overlapping
  windows so a match straddling a boundary is still seen.

### 2. `plugins/dsh-mnemon-source-runtime/src/controller.ts`

- New `checkedContent(value, field)` = `normalizeContent()` + `assertNoThreats()`, used by all three
  commit paths: `prepareMutation` add, `prepareMutation` replace, and `compactionCandidates`
  (which would otherwise let a worker's proposed compaction launder a blocked entry back in).
- `contextMarkdown()` scans at projection time too. An entry that reached the store another way — a
  hand edit of `memories.json`, an older build, a pack or sync from another machine — is replaced in
  the projection with `[BLOCKED: …]` instead of being replayed as instructions. The stored entry is
  untouched, so the user can still inspect and remove it.
- `contracts.ts` `runtimePinnedProjection()` gets the same guard. Pinned entries take a separate
  route into the prompt (a `PINNED RUNTIME MEMORY` prefix built before the body), so guarding only
  `contextMarkdown()` would leave pinned entries as an unguarded replay path.
- `RuntimeMemoryCapacityError` now carries `details: RuntimeCapacityField`
  (`used`, `projected`, `limit`, `overBy`, `entries[{content, importance, pinned?, bytes}]`) and its
  message states the exact byte deficit and the two ways to fix it. Both throw sites pass
  `file.entries`.

### 3. `src/host/runtime-capacity.ts`

`runtimeError()` keeps the byte arithmetic in the fallback message (it has to rebuild the message
from numeric fields when an error crosses a JSON boundary and loses `message`) and now copies
`details` onto the reported error, so the model receives the candidate list rather than just a
number.

### 4. `scripts/deploy-local.mjs` (new)

Copies every built `lib/` into `<DSH_HOME>/profiles/<profile>/node_modules/<pkg>/lib`. Needed
because the profile installs from the registry and there is no watcher; see
`docs/en/development/local-development.md`.

### 5. `~/.dsh/AGENTS.md` section I (outside this repo)

I7 (capacity negotiation), I8 (how `replace` actually matches and why it overwrites a whole entry),
I9 (what belongs in `USER.md`, and when to write it unprompted).

## Operation

After any `pnpm install` in the DSH profile, the registry tarball overwrites the deployed `lib/`
directories and these changes disappear. Re-run `node scripts/deploy-local.mjs` and restart DSH
Desktop.

## Upstream merge surface

Only three upstream files are modified: `plugins/dsh-mnemon-source-runtime/src/controller.ts`,
`plugins/dsh-mnemon-source-runtime/src/contracts.ts` and `src/host/runtime-capacity.ts`, plus two
added files. `threat-scan.ts` has no upstream counterpart, so it never conflicts. Keep the
capacity-error `details` field additive — nothing in the fork changes an existing field's meaning.
