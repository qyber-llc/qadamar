# Code review runbook

How to run a whole-repository review of Qadamar without exhausting the reviewing session's context, and the root-cause analysis of the 2026-11-12 failure that led to this runbook.

## Incident: autocompact thrashing during the seven-zone review (2026-11-12)

### What happened

A long-running maintenance session launched a seven-zone review of Qadamar (engine and Lean, authn and sessions, storage and audit, admin plane, gateway and SDK, console, CI/deploy/docs) as seven parallel forked reviewers at 04:51Z. Between 04:53Z and 07:18Z the session auto-compacted 28 times, roughly every three minutes, and stopped twice with `Autocompact is thrashing: the context refilled to the limit within 3 turns of the previous compact, 3 times in a row`. The forked core-engine reviewer stopped with the same error at 05:00Z. No review findings were written.

### Root cause

The model was switched (`/model claude-fable-5-2`, 04:48Z) from a model with a 1M-token window to one with a ~200K window, in a session whose **fixed per-request floor was about 150K tokens**. Compaction can only shrink the conversation; it cannot shrink the floor. After every compaction the very first request was already near the auto-compact threshold, so two or three ordinary tool calls tripped it again.

Evidence, from the session transcript (measured with `jq`, never loaded whole):

| Measure | Before the switch | After the switch |
|---|---|---|
| Tokens at auto-compact (`preTokens`) | 274K to 967K | 165K to 188K |
| Interval between compactions | hours | about 3 minutes |
| First request after a compaction (07:08:53Z) | n/a | 157K input tokens (63K cached + 94K written) |

What made up the floor on each request after the switch:

| Component | Size per request |
|---|---|
| Tool schemas: 103 tools (80 MCP tools, of which 49 were loaded earlier via ToolSearch and re-loaded after every compaction) | 277K chars, about 70K tokens |
| System prompt | 37K chars, about 9K tokens |
| Re-injected after each compaction: skill listing, CLAUDE.md and rules, deferred-tool names, agent listing, invoked skills, MCP instructions, output style | about 190K chars, about 48K tokens |
| Compaction summary | 37K to 58K chars, 10K to 15K tokens |

What did **not** cause it: tool output. The 120 tool results in the failing period totalled 420K chars over 28 cycles (median 1.4K chars, largest 23.7K chars), about 3K tokens per cycle. Reviewer reports never came back; the reviewers failed first.

Contributing factors:

- **Forked reviewers.** A fork inherits the parent's whole context, so each of the seven reviewers started at the same ~150K floor and thrashed too.
- **Hook echo.** A PostToolUse output filter re-emits each filtered Bash output as a hook message, so filtered output reaches the context twice (41 such messages, 107K chars, in the failing period).
- **Tool sprawl.** Tools loaded for unrelated work (video, image and audio generation, computer use) stayed loaded for the rest of the session.

### Fix

1. Start a review in a **fresh session** with few connectors, not in a long-lived session that has loaded dozens of tools. Do not switch to a smaller-window model mid-session.
2. Reviewers are **fresh subagents with a small tool set** (Read, Grep, Glob, Bash), never forks.
3. Reviewers **write findings to files** and return at most 1,500 characters.
4. One zone at a time, at most 10 files per chunk, progress written after each chunk (procedure below).

## Review procedure

1. Scratch space: `tmp/review/` (gitignored). Progress file: `tmp/review/PROGRESS.md`, one line per chunk: zone, chunk, status, counts.
2. Zones, in order: engine and Lean; authn and sessions; storage and audit; admin plane; gateway and SDK; console; CI, deploy and docs. Split a zone larger than about 15 files into chunks of at most 10 files.
3. One reviewer per chunk. It writes `tmp/review/<zone>-<n>.md` and returns counts plus CRITICAL/HIGH lines with `file:line`, at most 1,500 characters.
4. The orchestrating session never reads a whole log, report, diff or file over 400 lines; it uses `rg`, `head`, `sed -n` ranges.
5. After each zone: verify every CRITICAL/HIGH against the code, fix real ones with a regression test, run the relevant test subset, commit the zone on its own.
6. At about 60% context: write PROGRESS and the remaining plan, stop. A new session resumes from `PROGRESS.md`.
7. At the end: full suite (`pnpm typecheck`, `pnpm test`, `formal/check.sh`, console unit and e2e checks per [docs/CI.md](../../CI.md)), then push.
