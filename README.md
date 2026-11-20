# GitHub Forge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/abtravels/github-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/abtravels/github-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single file. Built for the [github-core-clone-01](https://make.fun/bounty/github-core-clone-01) bounty on [make.fun](https://make.fun/).

## What it does

One process (`main.ts`, Node 22, standard library only) serves, from an
in-memory store:

- **Git smart HTTP** at `/{owner}/{repo}.git` — upload-pack protocol v2
  (ls-refs, fetch, shallow/deepen, tags) and receive-pack v0
  (report-status, side-band-64k, delete-refs, fast-forward enforcement).
- **REST v3** under `/api/v3` — repos, branches, commits, contents,
  labels, issues, pull requests (including squash merge with real
  three-way merge and conflict detection).
- **GraphQL** at `/api/graphql` — viewer, repository, issues, pull
  requests, node/global ids, introspection, mutations, batched
  operations.
- **MCP** at `/mcp` — JSON-RPC 2.0 over Streamable HTTP, modern
  `server/discover` (revision 2026-07-28) and legacy `initialize`
  handshakes, with `create_repo`, `get_repo`, `create_issue`,
  `list_issues`, `create_pull_request` and `merge_pull_request` tools
  acting on the same store as REST.

State is fully deterministic: sequential counters for ids, fixed
timestamps for server-created commits — replays produce the same state
export byte for byte.

## Run

```sh
MAKEFUN_SHOP_TOKEN=<token> node main.ts
```

With `$MAKEFUN_ENV_URL` set, the server binds an ephemeral port,
registers with the trial env, polls `/done`, and exits 0 when the
trial finishes. Without it, it serves standalone on an ephemeral port.

## Practice score

Local kit trial (practice instance): **976/1000** — feature 600/600
(120/120 conformance checks), agent 200/200 (15/15 MCP), performance
176/200 (push 38, clone 42, read 50, write 46).

## License

MIT — see [LICENSE](LICENSE).
