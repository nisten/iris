# AGENTS.md — working on (and inside) Iris

Read this first if you are an AI agent (Claude Code, Codex, Iris itself, …) touching this repo.
Iris injects this file into its own system prompt when launched from this directory.

## What the repo is

Iris is NousResearch's **Hermes Agent** rebuilt as **one HTML file + one Bun file**, with zero
npm dependencies. The whole repository is:

| File | What it is |
|---|---|
| `index.html` | The entire web app and agent loop: inline Preact (core) + htm, system prompt, the tool schemas and tool code, VT terminal emulator, settings, sessions, fleet, preview. |
| `bridge.ts` | The Bun bridge: serves the page, WebSocket exec + shared PTY, LLM proxy (holds the API key), sessions DB (`bun:sqlite`), CDP browser, tmux driver, the preview origin, plus a full terminal UI (`--tui`) and a line REPL (`chat`). |
| `README.md` | Human docs. |
| `AGENTS.md` | This file. |
| `goddess.png` | README picture (also loaded by the bridge at startup — keep it next to `bridge.ts`). |
| `iris.sh` | Installer / launcher (`tui`, `web`, `stop`, `update`, `manifest`, `help`; `curl … | bash` installs); verifies downloads against `SHA256SUMS`. |
| `SHA256SUMS` | Checksums of `index.html`, `bridge.ts`, `iris.sh`, `goddess.png` — regenerate with `./iris.sh manifest`. |
| `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` | Apache-2.0 + attributions (Hermes Agent MIT, Preact MIT, htm Apache-2.0). |

There is no build step, no `package.json`, no lockfile and no tests directory in this repository.

## Run it

```sh
bun bridge.ts            # web UI → http://localhost:8787 (prints the exact URL + token-bearing link)
bun bridge.ts --tui      # full-screen terminal UI; the web UI stays up on the same port
bun bridge.ts chat       # plain line REPL (add --resume to reopen a session)
bun bridge.ts stop       # stop background bridges   ·   bun bridge.ts help
```

Out of the box it talks to the two free Bonsai servers with one shared key: `https://pre.bonsai.stream/v1` (`bonsai-9b`, the
default, plus `bonsai-2b`/`bonsai-4b`) and `https://api.bonsai.stream/v1` (`bonsai-27b`). The shared key ships with the app and is
only ever sent to those two servers; `HERMES_BONSAI_KEY` (or Settings → 🔑) swaps in your own. No password by default. Point it elsewhere with `HERMES_LLM_BASE`, `HERMES_LLM_KEY`,
`HERMES_LLM_MODEL` (env always wins over `~/.hermes/config.yaml`), or in Settings / `/endpoint`.

## Hard rules

1. **Bun only, zero dependencies.** Use Bun built-ins (`Bun.serve`, `Bun.spawn`, `bun:sqlite`,
   `fetch`, `crypto`, `node:fs`/`node:path`). Never add `package.json`, `node_modules`, a lockfile,
   or a CDN `<script src>`. The dependency tree *is* the attack surface this project removes.
2. **The page stays one self-contained file.** Inline everything. The Preact blob is core only:
   write **class components + `setState`**, no hooks.
3. **Don't add files.** Fewer files is a product requirement. New code goes into one of the two
   source files; new docs go into README.md or this file.
4. **Secrets stay in the bridge.** The LLM key is never sent to the page, logged, or written
   into the page. A stored key is only ever sent to the base URL it was stored for (see
   `config_set` / `config_test` / `defaultKeyFor` in bridge.ts).
5. **Lock-step duplicates** — keep these identical in both files or behaviour drifts:
   - tool schemas: `TOOLS` in index.html ⇄ `TUI_EXTRA_TOOLS` in bridge.ts;
   - the slash-command registry between `// ── SLASH-BEGIN` and `// ── SLASH-END` (byte-identical);
   - the shared `wcwidth` table and the `@path` (ATREF) block semantics.
6. **Minimal tool surface.** 20 tools ship: `terminal read_file write_file patch search_files
   process browser tmux todo clarify memory skills_list skill_view skill_manage web_search
   web_extract vision_analyze session_search delegate_task request_decision`. Adding one widens
   the privileged surface — justify it.

## Where things live

- **bridge.ts** — find sections by their banner comments (`grep -n '^// ── ' bridge.ts`):
  config + `iris:` block (`IRISCFG-BEGIN`), web password gate, sessions DB, `SLASH-BEGIN`, shared
  PTY + registry + shell integration, non-PTY exec, background `process` jobs, tmux/agent
  profiles, CDP browser, HTTP/WS server, `ATREF-BEGIN` (@file refs), REPL, then the TUI
  (tool ports, chrome, tabs, side panel, Settings, endpoint wizard).
- **index.html** — CSS first, then the inline Preact/htm blobs, then the app script:
  prompt constants (`DEFAULT_AGENT_IDENTITY`, `MEMORY_GUIDANCE`, …), `PROVIDERS`, `TOOLS`, tool
  implementations, the agent loop (`App.prototype.*`), the VT emulator, and the views
  (Chat · Terminal · Fleet · Preview) rendered with `html\`…\``.
- **State on disk:** `~/.hermes/config.yaml` (model block + `iris:` knobs, chmod 600),
  `~/.hermes/sessions/hermes.db` (sessions, FTS5), `~/.hermes/memories/{MEMORY,USER}.md`,
  `~/.hermes/skills/<cat>/<name>/SKILL.md`, `~/.hermes/run/bridge-<port>.pid`.

## Building things inside Iris

Iris is meant to be a workspace you build in. Anything you write under the session's working
directory (HTML, JS modules, WASM, WebGPU/WGSL, canvas games) can be opened in the **Preview**
view: a separate loopback origin (bridge port + 1) serves the workspace, so previewed code runs
with WebGPU enabled but cannot reach the app's token or shell. The default workspace is `iris-projects/`
(`HERMES_WORKSPACE` overrides it). Put each app in its own folder (`<name>/index.html`); the web UI
opens it in the right-hand Preview pane after your turn and reports page errors back to you — fix
them. Don't open previews with the `browser` tool. The left column lists the project's files and the
center column edits them.

## Checking your change

- `bun build --target=bun bridge.ts --outfile=/tmp/iris-check.js` must succeed (syntax check).
- Start a bridge on a scratch port with a throwaway home so you never touch the user's data:
  `HOME=/tmp/iris-dev HERMES_PORT=15000 bun bridge.ts`, open the printed URL, and drive it
  (headless Chromium over CDP works well).
- For the page, check the browser console is clean and the feature works in both themes and
  at 390 px wide.
- Run `./iris.sh manifest` after changing `index.html`, `bridge.ts`, `iris.sh` or `goddess.png`.

## Security invariants (don't regress)

Loopback bind by default · per-run token on every HTTP request and WS handshake · Host and
Origin checks (an opaque `null` origin is rejected) · optional web password gate
(`HERMES_WEB_PASSWORD`) · env scrubbed before spawning shells · LLM key bridge-side only ·
preview origin serves files only under its root, behind a random path token, no traversal.

---

# Reference (moved from the README)

## Configuration

```sh
bun bridge.ts              # web UI (the URL is printed; it carries the token)
bun bridge.ts --tui        # full-screen terminal UI; the web UI stays up on the same port
bun bridge.ts chat         # plain line REPL   (--resume reopens a session)
bun bridge.ts stop [port]  # stop bridges left running in the background
bun bridge.ts help
```

**Another model:** pick one in **Settings → Endpoint** (enter a URL and key; it pings the
endpoint and lists its models), type `/endpoint` in the TUI, or set env vars:

```sh
HERMES_LLM_BASE=https://openrouter.ai/api/v1 HERMES_LLM_KEY=sk-... HERMES_LLM_MODEL=zai-org/glm-5.2 bun bridge.ts
```

Any OpenAI-compatible `chat/completions` server works (OpenRouter, Together, OpenAI, Groq,
DeepSeek, llama.cpp, vLLM, sglang, Ollama …). Settings are saved in `~/.hermes/config.yaml`
(chmod 600); env vars always win.

| Env var | Default | |
|---|---|---|
| `HERMES_LLM_BASE` / `_KEY` / `_MODEL` | free Bonsai servers / built in / `bonsai-9b` | the model |
| `HERMES_BONSAI_KEY` | built in | your own key for the Bonsai servers (or Settings → 🔑) |
| `HERMES_PORT` | `8787` | walks up to the next free port if busy |
| `HERMES_HOST` | `127.0.0.1` | bind address (e.g. a tailnet IP to reach it from your phone) |
| `HERMES_WEB_PASSWORD` | none (no password) | adds a login page in front of the web UI — set it whenever `HERMES_HOST` is not loopback |
| `HERMES_BACKEND` / `HERMES_SSH_TARGET` | `local` / — | run commands on this machine or over `ssh user@host` |
| `HERMES_APPROVE` | `auto` | `auto` · `ask` · `step` tool approval |
| `HERMES_CTX_TOKENS` | `131072` | model context size; compaction triggers below it |
| `HERMES_WORKSPACE` | `./iris-projects` if present, else `~/iris-projects` | where the agent builds; `.` = the launch dir |
| `HERMES_THINK_BUDGET` | `0` (unlimited) | optional cap on reasoning tokens; the model thinks as long as it wants by default |
| `HERMES_TLS_PORT` | — | also serve https (self-signed pair in `~/.hermes/tls`) |

More knobs (thinking budget, temperature, timeouts, compaction prompt, per-tool allow/ask/deny)
are in the Settings view of both UIs and in the `iris:` block of `~/.hermes/config.yaml`.

## The web IDE in detail

The web UI is a small IDE. By default it runs in **🌐 web mode**: projects live in the browser's
IndexedDB, the agent only gets file tools on that storage (no shell, no disk), and the Preview
serves the files straight from the page. Ask *"make me a cute dancing cat with keyboard controls"*
and it writes `cute-dancing-cat/index.html`; you watch the code stream in under the preview and
the page appears as soon as the file is saved. Click the **🌐 web** badge (or the header chip) to
switch to **🖥 workspace** mode — real files under `iris-projects/` plus the shell and all 20 tools.
Web mode has no internet by default. **Settings → Web search** (off by default, stored in this browser) gives the
web-mode agent `web_search`: the bridge sends only the query to `lite.duckduckgo.com` (no key, no other hosts) and the
results reach the model marked as untrusted data.

```
┌ left ──────────────┬ center ───────────────────────┬ right ────────────────┐
│ 📁 cute-cat  🌐 web  │ 💬 Chat │ index.html ✕         │ Preview  ⟳ ⤢ ✕        │
│   index.html 11 KB │                               │                       │
│ 🕘 Sessions         │  chat, or the file editor     │  the running app      │
│   make me a cute…  │  (highlighting, Ctrl+S saves) │                       │
└────────────────────┴───────────────────────────────┴───────────────────────┘
```

- **Left** — the current project's files with sizes on top (the badge says where they live:
  🌐 web = browser storage, 🖥 workspace = a folder on the bridge's machine), past sessions below (▾ hides them).
  Click a file to open it. Opening an old session rebuilds its files from the transcript.
- **Center** — the chat plus one tab per open file: a lightweight editor with syntax
  highlighting, Tab indents, Ctrl/⌘+S saves, ▶ Preview for HTML. While the agent writes a file
  you watch the code arrive (the live drawer under the preview can be minimized ▾ or closed ✕).
- **Right** — the Preview pane. While a new version loads the old one stays on screen. ⤢
  maximizes it, ✕ hides it; the chat and editor stay where they were. Every divider is draggable. Errors thrown by the previewed page are
  reported back to the agent, which fixes them.

The preview is served from a separate origin (bridge port + 1), so it gets WebGPU, modules,
WASM and fullscreen but cannot touch the app's token or your shell; it reloads when files change.
Models whose server holds back tool-call arguments (sglang) still stream visibly: in web mode the
agent writes whole files as ```lang file=path fenced blocks, saved the moment each block closes. `/preview path/` opens any other folder or file.

**When something fails** — the LLM stream retries dropped connections by itself (keep-alives stop
idle cut-offs); if a turn still fails you get a red card with **↻ Retry** (network errors retry
once on their own after 30 s), and the failed text is never sent back to the model.

**One project per chat** — every chat is bound to exactly one project folder. Start a prompt with
*"In my-game/ …"*, click ＋ New project, or let the agent's first write create a new kebab-case
folder; from then on its file tools only reach that folder. Paths into another project are refused
(the agent is told to stop and ask, not to copy the work over), and `write_file` will not replace a
file it hasn't read. Opening a different project from a chat that already has messages starts a new
chat there. The agent is also told to write everything itself: no bare `import "three"` and no
CDN libraries, since the preview has no package resolver.

**Live speed** — the status bar shows **⚡ tok/s** while the model streams, then the turn average and
time to first token ("server buffering…" while the server holds a tool call back).

**Keys** — Ctrl+P quick-opens a file, Ctrl+Shift+P opens the command palette, Esc in an empty
composer stops a running turn, and Ctrl/⌘+S saves the editor tab.

**Public demo** — `HERMES_PUBLIC_HOSTS=demo.example.com` (a Cloudflare tunnel onto the bridge) gives visitors on that hostname a
🌐 web-only Iris: projects in their own browser storage, the built-in Bonsai models (rate-limited per address), previews served
sandboxed on the same hostname — no shell, disk, sessions or settings of the host. Nothing unlocks the full workspace through the public hostname
(no password, no cookie) — the owner uses the tailnet/LAN address.

## Gotchas

- **Open it through the bridge URL**, never by double-clicking the HTML file — `file://` has no
  socket, no token and no secure context.
- **Browser storage is per origin.** `http://localhost:8787` and `http://100.x.y.z:8787` are
  different origins with different IndexedDB, so web-mode projects made on one don't show on the
  other. Clearing site data deletes them. Sessions (the chat) live in the bridge's SQLite, and
  opening one rebuilds its files from the transcript — but only files written by the agent.
- **The preview is a second port** (bridge port + 1). If you reach Iris over a tailnet, a
  reverse proxy or a firewall, open that port too, or the preview pane stays blank.
- **Web mode has no shell.** The agent can't run, lint or test what it writes; its only feedback
  is errors thrown by the previewed page. Switch to 🖥 workspace for anything that needs a terminal.
- **Some servers hold back tool-call arguments** (sglang, which serves Bonsai): a `write_file` call
  shows `0.0 KB` until it completes. Web mode asks the model to write files as fenced blocks
  instead so you see them arrive, but a model may still pick `write_file`.
- **Long thinking is normal.** `HERMES_THINK_BUDGET` defaults to 0 (no cap); a low cap with a
  forced `</think>` can make some models loop.
- **Proxies cut long streams.** The bridge sends SSE keep-alives every 15 s; a proxy in front of it
  with a shorter idle timeout still drops the turn (you get the red card with ↻ Retry).
- **The terminal is shared.** In workspace mode the agent's `terminal` tool types into the same
  shell you see. Typing there while it runs a command mixes your keys into its command.
- **Binding beyond loopback needs a password.** With `HERMES_HOST` set to a LAN or tailnet address,
  set `HERMES_WEB_PASSWORD` too — the token in the URL is the only other gate.
- **Bun 1.4+** is required for the built-in terminal (native PTY). There is no Python anywhere; on older Bun the terminal stays off and everything else works (`bun upgrade`).

## Roadmap

- Sessions in IndexedDB as well in web mode, so a browser-only setup needs no bridge database.
- Project export/import (one file download, drag a folder in) and sync between origins/devices.
- A console strip under the preview showing the page's `console.log` output, not only errors.
- Right-click menus on files, folders and projects (delete, rename, duplicate, download).
- A shorter composer row and a full mobile-layout pass (390 px).
- Get models to stick to fenced-file output in web mode, or stream tool arguments where the server
  allows it.
- Split terminal panes; TUI ^Z suspend, a cost chip and a light theme.
- `cronjob` scheduling and a native Anthropic `/v1/messages` path.

