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
- `SECRET_VAR` matches `$KEY` / `${API_TOKEN}` style shell references. Gaps are `\s+` rather than
  `\s{1,64}` chains: a bounded-but-wide repetition in five places re-enumerated tens of millions of
  positions per anchor, and normalizing whitespace first is what actually keeps the cost linear.
- 24 patterns: instruction override (`disregard_rules`, `forget_rules`, `bypass_restrictions`,
  `remove_filters`, `sys_prompt_override`, `role_hijack`, `identity_override`, `fake_update`,
  `translate_execute`, `deception_hide`), prompt exfiltration (`leak_system_prompt`), markup-borne
  injection (`html_comment_injection`, `hidden_div`), C2 shapes (`c2_node_registration`,
  `c2_heartbeat`, `c2_task_pull`, `known_c2_framework`, `anti_forensic_oneliner`), exfiltration
  (`exfil_curl`, `exfil_wget`, `read_secrets`, `ssh_backdoor`, `env_var_unset_agent`) and pasted
  credentials (`hardcoded_secret`).
- `html_comment_injection` anchors both sides to `(?:[^-]|-(?!->))` so an unterminated `<!--` cannot
  re-enumerate 512×512 positions: the `-->` must be reachable forward.
- Negated forget clauses are recorded as ranges and skipped by match position, not blanked out.
  Blanking rewrote the very text being scanned: `do not act as DAN forget your rules` lost the
  payload along with the negator, so both the jailbreak shape and the forget shape went unseen.
  Only `forget_rules` and `disregard_rules` consult those ranges.
- Invisible-character detection: zero-width and bidi set, plus the U+E0000..U+E007F tag block.
  RGI emoji flag sequences and legitimate ZWJ emoji sequences (🧑‍💻, 👨‍👩‍👧) are stripped first,
  because refusing them would block ordinary text; a bare ZWJ outside an emoji is still flagged.
- `MAX_SCAN_CHARS = 65_536` with `CHUNK_OVERLAP = 4_096`: long content is scanned in overlapping
  windows so a match straddling a boundary is still seen, and `MAX_MATCH_SPAN = 2_048` is asserted
  below the overlap at module load so that assumption cannot rot. Every window gets a leading
  newline, which lets `fake_update` stay line-anchored without `^` matching mid-line in a slice.

### 2. `plugins/dsh-mnemon-source-runtime/src/controller.ts`

- New `checkedContent(value, field)` = `normalizeContent()` + `assertNoThreats()`, used by all three
  commit paths: `prepareMutation` add, `prepareMutation` replace, and `compactionCandidates`
  (which would otherwise let a worker's proposed compaction launder a blocked entry back in).
- `contextMarkdown()` scans at projection time too. An entry that reached the store another way — a
  hand edit of `memories.json`, an older build, a pack or sync from another machine — is replaced in
  the projection with `[BLOCKED: …]` instead of being replayed as instructions. The stored entry is
  untouched, so the user can still inspect and remove it.
- `parseEntry()` enforces `RUNTIME_ENTRY_MAX_BYTES`, the same ceiling the write path and the pack
  importer use. Without it a hand edit could put an arbitrarily long entry on disk, and that entry
  would be re-scanned into every later prompt.
- `contracts.ts` exports `guardedEntryBody(content)` as the single guard, and every site that puts
  entry text into a prompt calls it: `contextMarkdown()`, `runtimePinnedProjection()`,
  `runtimeSnapshotContext()` (the maintenance and USER.md compaction prompts) and
  `runtimeRouteChunks()` (the archive routing prompt). The last two matter most: they feed a
  subagent that rewrites memory, so unguarded text there is worse than in the main projection.
  Results are memoized per process by content, because one View composes the same entries many
  times and the scan is a full regex sweep.
- Pinned entries take a separate route into the prompt (a `PINNED RUNTIME MEMORY` prefix built
  before the body), so guarding only `contextMarkdown()` would leave pinned entries as an unguarded
  replay path.
- `RuntimeMemoryCapacityError` now carries `details: RuntimeCapacityField`
  (`used`, `projected`, `limit`, `overBy`, `entries[{content, importance, pinned?, bytes}]`) and its
  message states the exact byte deficit and the two ways to fix it. Both throw sites pass
  `file.entries`.

### 3. `src/host/runtime-capacity.ts`

`runtimeError()` keeps the byte arithmetic in the fallback message (it has to rebuild the message
from numeric fields when an error crosses a JSON boundary and loses `message`) and now copies
`details` onto the reported error, so the model receives the candidate list rather than just a
number. The same copy happens when the capacity error and a failed automatic maintenance are merged
into one message: without it the model sees "maintenance failed" with no way to act. The fallback
wording only promises "one of the entries below" when `details` is actually attached.

`runtimeRouteChunks()` guards each entry before truncating it: the scan needs the whole entry, and a
cut in the middle of a payload would let the shape slip past the excerpt.

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
`plugins/dsh-mnemon-source-runtime/src/contracts.ts` and `src/host/runtime-capacity.ts`, plus three
added or lightly touched files (`src/host/subagent-prompts.ts` changes one call site). `threat-scan.ts`
has no upstream counterpart, so it never conflicts. Keep the capacity-error `details` field
additive — nothing in the fork changes an existing field's meaning.
