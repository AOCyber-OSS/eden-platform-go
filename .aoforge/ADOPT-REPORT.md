# Adopt report — Project

**Adopted:** 2026-11-18 · **AOForge:** v3.1.0 · **Branch:** `aoforge/adopt` (from `tmp/adopt-base-eden-platform-go-wt-adopt` @ `7791383`) · **Pushed:** no · **Mode:** migrate

## Migration

| Change | From | To | How |
| --- | --- | --- | --- |
| Planning tree | .planning | .aoforge | git mv, 46 files |
| Ignore line | .gitignore:41 /.planning/.awareness-cache.json | /.aoforge/.awareness-cache.json | rewritten |
| Ignore line | .gitignore:42 /.planning/.skill-active | /.aoforge/.skill-active | rewritten |

## Needs review

| # | Item | Inferred | Confidence | Evidence |
|---|---|---|---|---|
| 1 | adopt changed no planning content beyond the stamp key | the findings above come from the project's own files, not from the move | priority | compare the planning files with the base branch: every moved file is a 100% rename |
| 2 | validate health warning W001 | PROJECT.md missing section: ## What This Is | low | Add section manually |
| 3 | validate health warning W001 | PROJECT.md missing section: ## Core Value | low | Add section manually |
| 4 | validate health warning W003 | config.json not found | low | Run /aoforge:status check --repair to create with defaults |
| 5 | validate health warning W005 | Objective directory "140-builders-automation-keystone-contracts" doesn't follow NN-name format | low | Rename to match pattern (e.g., 01-setup) |
| 6 | validate health warning W005 | Objective directory "entitlements-bootstrap-by-identity" doesn't follow NN-name format | low | Rename to match pattern (e.g., 01-setup) |
| 7 | validate health warning W005 | Objective directory "platform-identity-context" doesn't follow NN-name format | low | Rename to match pattern (e.g., 01-setup) |
| 8 | validate health warning W005 | Objective directory "platform-identity-issuer" doesn't follow NN-name format | low | Rename to match pattern (e.g., 01-setup) |
| 9 | validate health warning W007 | Objective 140 exists on disk but not in ROADMAP.md | low | Add to roadmap or remove directory |
| 10 | validate health warning W007 | Objective 16 exists on disk but not in ROADMAP.md | low | Add to roadmap or remove directory |
| 11 | validate health warning W007 | Objective 21 exists on disk but not in ROADMAP.md | low | Add to roadmap or remove directory |
| 12 | validate health warning W009 | state.json sidecar not found. Machine-readable state fields use slower markdown parsing. | low | Run /aoforge:status check --repair to create state.json from existing STATE.md |
| 13 | validate health warning W040 | project-behind: stamped never, AOForge v3.1.0; 3 pending, 1 need confirmation | low | Run `aof-tools upgrade --apply` (or /aoforge:status check --migrate) |
| 14 | 3 automatic upgrade migrations pending (0001, 0003, 0004) | applied by the next session start, or by aof-tools upgrade --apply | low | aof-tools upgrade --check |
| 15 | 1 upgrade migration needs confirmation (0006) | a confirm-level migration is never applied unattended | low | /aoforge:status check --migrate |

## What adopt did

- Moved 1 tree with `git mv` (history is kept).
- Renamed the config stamp key in 0 files, the CLAUDE.md block markers in 0 files, and rewrote 2 ignore lines.
- Backed up each planning directory and CLAUDE.md before converting: `~/.claude/aoforge/backups/<local>` (operator machine).
- Wrote nothing else: no PROJECT.md, STATE.md, ROADMAP.md or STACK.md, no new CLAUDE.md block, and no upgrade migration was applied.

## Next steps

1. Work through **Needs review**; the findings come from the project's own files.
2. When satisfied: `git switch tmp/adopt-base-eden-platform-go-wt-adopt && git merge aoforge/adopt`. Nothing was pushed.
3. Bring the project up to date: `aof-tools upgrade --check`, then the next session start applies the automatic migrations, or run `aof-tools upgrade --apply`.
4. Other branches of this repository still on the old layout move when they merge this one, or by running /aoforge:adopt there.
