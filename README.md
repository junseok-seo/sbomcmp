# sbomcmp

Run every SBOM generator you have, compare what they found, explain where they disagree, weight the disagreements with vulnerability data, and get a recommendation you can defend.

```
$ sbomcmp scan ./my-repo

[syft]    ok: 164 components (cyclonedx-1.6) in 2.1s
[cdxgen]  ok: 171 components (cyclonedx-1.6) in 6.4s
[trivy]   ok:  98 components (cyclonedx-1.7) in 1.3s
union 180 components across 3 tools
found 3 MCP server reference(s) — not covered by any generator
enriching with vulnerability data (osv)…
vuln: osv — 41 queried, 6 with findings

Recommendation: cdxgen + syft
  • cdxgen covers 95% of the union (171 of 180 components).
  • 12 components were found only by cdxgen.
  • Of those, 3 carry known vulnerabilities (1 critical/high) that the other tools would have missed.
  • Pair with syft: it adds 7 components cdxgen misses.
  ⚠ 3 MCP server(s) are configured in this project. No SBOM generator lists them — this is a shared blind spot.
```

Then `sbomcmp ui` opens the matrix in your browser, and `sbomcmp report` prints Markdown for a PR comment.

![Verdict: which tool to use, with evidence and per-tool coverage bars](docs/viewer-verdict.png)

![Matrix: one row per component, one dot per tool, risk and the reason tools disagree](docs/viewer-matrix.png)

The verdict panel states the recommendation and the evidence behind it. The matrix shows every component, which tools found it (a hollow dot means that tool reported a different version), the highest known severity, and a one-word reason for each disagreement. Filters narrow it to disagreements, single-tool findings, vulnerable rows or registry signals.

## Why

Different generators produce different SBOMs for the same code, and that is not a bug. They read different inputs (manifest vs lockfile vs filesystem), apply different scope policies (dev, optional, transitive), cover different ecosystems, and emit identifiers in slightly different shapes. Today, deciding which tool to standardize on means running them by hand and eyeballing counts.

sbomcmp automates the comparison and, more importantly, the explanation. "cdxgen found 38 more" is trivia. "Of those 38, three have known CVEs and one is critical" is a decision.

## Install

```sh
go install github.com/junseok-seo/sbomcmp@latest
```

`go install` puts the binary in `$(go env GOPATH)/bin` (usually `~/go/bin`). If `sbomcmp` is not found afterwards, that directory is not on your `PATH`:

```sh
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

Or download a binary from [Releases](https://github.com/junseok-seo/sbomcmp/releases) and put it somewhere on your `PATH`:

```sh
curl -sSfL https://github.com/junseok-seo/sbomcmp/releases/latest/download/sbomcmp_darwin_arm64 -o /usr/local/bin/sbomcmp && chmod +x /usr/local/bin/sbomcmp
```

(Pick `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64` or `windows_amd64.exe`.) Or clone and `make build` (Go 1.24+). There are no runtime dependencies beyond the generators themselves.

Install whichever generators you want compared; sbomcmp detects them on `PATH` and skips the rest:

| Generator | Install | Notes |
|---|---|---|
| [syft](https://github.com/anchore/syft) | `brew install syft` | strongest on container images and OS packages |
| [cdxgen](https://github.com/CycloneDX/cdxgen) | `npm i -g @cyclonedx/cdxgen` | widest language coverage, resolves transitives |
| [trivy](https://github.com/aquasecurity/trivy) | `brew install trivy` | needs lockfiles for most language ecosystems |
| [osv-scanner](https://github.com/google/osv-scanner) | `brew install osv-scanner` | OSV-Scalibr front end |

`sbomcmp generators` lists the adapters built in.

## Usage

```sh
sbomcmp scan ./repo                       # source tree
sbomcmp scan image:nginx:1.27             # container image
sbomcmp scan --only syft,cdxgen ./repo    # subset
sbomcmp scan --ui ./repo                  # open the viewer when done

sbomcmp ui                                # viewer for ./sbomcmp.json
sbomcmp report --format md                # Markdown (PR comments, CI logs)
sbomcmp report --format json              # the full result
sbomcmp report --fail-on refuse           # CI gate: exit 3 when VDB-only findings need a decision
sbomcmp push --watch                      # hand the winning SBOM to VDB for monitoring
```

Output: `sbomcmp.json` (the comparison) and `sbomcmp.raw/<tool>.cdx.json` (each tool's untouched SBOM, so nothing is lost).

### Vulnerability weighting

Disagreement rows (components not every tool found) are checked against a vulnerability database so the recommendation can say which tool's extra findings actually matter. Components every tool agrees on are not sent unless you pass `--vuln-all`. Offline or blocked? The scan still completes, and the recommendation notes that scores reflect coverage only.

| `--vuln-source` | What happens |
|---|---|
| `auto` (default) | `vdb` when `VDB_API_KEY` is set, otherwise `osv` |
| `osv` | [OSV](https://osv.dev) batch query plus per-advisory details (CVSS v3 and v4 scored locally; a server-side `vdb_severity` rating is preferred when present). No account needed. `--osv-api` points at any OSV-compatible server, including a VDB deployment (`--osv-api https://vdb.ai.kr` with `VDB_API_KEY`). Details are fetched for up to 600 distinct advisories per scan (`--vuln-details N`, 0 = unlimited), disagreement rows first, 16 at a time; rate-limited fetches are retried after 1 s and 2 s. |
| `vdb` | [VDB](https://vdb.ai.kr) `check-packages`: advisories with KEV/EPSS and malicious-release flags, plus the signals below. Works without a key on a quota of 100 packages per hour. |
| `none` | skip enrichment (`--no-vuln`) |

```sh
sbomcmp scan --no-vuln ./repo                        # skip entirely
sbomcmp scan --vuln-all ./repo                       # query every component
sbomcmp scan --vuln-details 0 ./repo                 # score every advisory OSV returns (no detail cap)
sbomcmp scan --osv-api https://osv.example/ ./repo   # any OSV-compatible server
sbomcmp scan --vuln-fixture fixtures.json ./repo     # offline fixture (tests, demos)
```

### VDB (optional)

[VDB](https://vdb.ai.kr) is an OSV-compatible vulnerability database that also tracks what CVE feeds do not: package names that do not exist on their registry (slopsquatting), an MCP server registry with trust tiers and declared scopes, and AI model artifacts. sbomcmp uses it as an **optional adapter**:

```sh
sbomcmp scan --vuln-source vdb ./repo    # try it: 100 packages per hour, no account
export VDB_API_KEY=vdb_…                 # free key removes the limits; auto-selects vdb
sbomcmp scan ./repo
```

With VDB active:

- Rows whose name **does not exist on the registry** get a `slopsquat` signal. That turns "found only by tool A" into "tool A copied a hallucinated dependency out of the manifest". Packages the project declares itself (its own `package.json`, `Cargo.toml`, `pyproject.toml`, `go.mod`, or a generator's `metadata.component`) are marked **first-party** and left out of registry checks, so an unpublished internal package is not reported as squatting.
- Every cell keeps the **evidence paths** the tool reported (lockfile, manifest, binary), shown when you expand a row. A row seen only inside an installed tree (`node_modules`, `.venv`, `site-packages`, …) and never in a tracked manifest or lockfile is marked **installed**: it describes this machine, not the code's declared dependencies, so it stays in the matrix (filter: *Installed only*) but is left out of Act now.
- Discovered MCP servers get a **Registry** column: trust tier, scopes, risk score, and recent scope changes. Servers VDB has never seen are marked unverified.
- Advisories carry **KEV** and **EPSS** so a critical nobody exploits ranks below a medium that is being exploited, and **malicious releases** (MAL-* reports) are flagged as something to remove, not upgrade. The viewer sorts by KEV, then EPSS, then severity when VDB data is present, and the report's "Disagreements that matter" table gains an EPSS column.

The VDB-only findings drive the first screen. Under the recommendation, an **Act now** block (viewer, Markdown report, scan summary) lists what to decide before trusting the manifest, in this order: malicious releases (remove), advisories in CISA KEV (upgrade to the fixed version), advisories with EPSS ≥ 10% (upgrade), names no registry resolves (check the name), and MCP servers that are unverified or community-tier with an `exec`, `fs:write`, `net:outbound` or `secret:read` scope, or that carry a refuse-level signal (pin and review). Each action is `refuse` or `warn`, the list is capped at 20 with the total kept, and it is stored as `actions` in the result file. Rows with a slopsquat signal also get a `hallucinated-name` reason in the "Why tools disagree" column. Without VDB the block is one line saying those signals need VDB; with VDB and nothing to act on it says so explicitly.

Coverage is always visible: the status strip under the verdict (and the `Vulnerability data:` line in the report) says which source answered, keyed or anonymous, how many of the queried rows got an answer, and what VDB added (KEV rows, rows with EPSS ≥ 10%, slopsquat signals, MCP registry hits). When the anonymous quota runs out mid-scan the strip turns amber and shows the fix; the same shortfall appears as a recommendation caveat. OSV runs log `osv: N of M advisories scored`; advisories past the detail cap or whose fetch failed after retries are counted and shown as UNKNOWN.

Without a key, sbomcmp behaves exactly as before against public OSV. `VDB_API_URL` or `--vdb-api` points at a self-hosted deployment.

### Push to VDB

A comparison answers "which SBOM should I keep?". `sbomcmp push` is the next step: it hands that SBOM to VDB so the answer stays current.

```sh
export VDB_API_KEY=vdb_…
sbomcmp push                              # the recommended tool's SBOM from ./sbomcmp.json
sbomcmp push --tool syft --watch          # a different tool; also register it as a watch
sbomcmp scan --push-watch ./repo          # scan, compare and push in one command
```

What it sends: the recommended primary tool's untouched CycloneDX from `sbomcmp.raw/<tool>.cdx.json` (override with `--tool`), uploaded as `<target>-<tool>.cdx.json` to VDB's `POST /v1/sbom/scan`. Nothing else leaves the machine: not the comparison, not the other tools' SBOMs. The output is VDB's verdict for the whole SBOM (`REFUSE` / `CONFIRM` / `PROCEED`), the counts by severity, the top findings with their fixed versions, and a link to the full result at https://vdb.ai.kr/sbom-scan.

`--watch` (or `scan --push-watch`) additionally registers the same file with `POST /v1/sbom/watches`: VDB re-checks it as new advisories, KEV entries and malicious releases land, and emails you. The command prints the watch id and name; when the account's watch quota is used up it prints the limit and exits 1. Free accounts have a small quota.

A key is required for push (`VDB_API_KEY` or `--vuln-key`; exit 2 without one). `VDB_API_URL` / `--vdb-api` point it at another deployment, like the rest of the VDB adapter.

### MCP blind spot

No SBOM generator lists MCP servers, although they are code the agent runs. sbomcmp reads `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, `.claude/settings*.json` and similar, derives the package each launcher runs (`npx -y @scope/pkg` → `pkg:npm/%40scope/pkg`, `uvx pkg` → `pkg:pypi/pkg`), and reports local heuristics: unpinned packages, broad permission flags, plain-HTTP remotes. With VDB, those packages are checked against its MCP registry.

## How the comparison works

1. **Run** every available generator in parallel, each asked for CycloneDX JSON (SPDX accepted as fallback).
2. **Normalize** each component to a purl key, collapsing known divergences: Go `v` prefixes, PEP 503 name separators, npm scope encoding (`%40babel` vs `@babel`), deb/rpm epochs, qualifiers and subpaths. Structural nodes (Trivy's per-manifest `application` entries) and version-less entries (the scanned module itself) are dropped and counted.
3. **Build the matrix**: one row per key, one cell per tool. Each row is `all` / `partial` / `single`.
4. **Explain** every disagreement with a heuristic reason, in priority order:
   - `version-mismatch` — the missing tool has the same package at another version
   - `ecosystem-coverage` — the missing tool saw no packages of this type at all
   - `scope` — a tool that found it marks it dev/optional
   - `cataloger` — same ecosystem, different depth (transitive, lockfile vs manifest, vendored)
5. **Weight** disagreement rows by vulnerability severity and non-CVE signals.
6. **Score** each tool: 60 × coverage of the union, up to 25 for unique vulnerable findings (8 per critical/high, 3 per other), up to 15 for ecosystems only it catalogued. The top tool is the primary; the runner-up is suggested as a pair if it adds anything.

The coverage matrix is derived from the run, never hard-coded, so it does not rot as the generators add catalogers.

## CI

[`examples/sbomcmp-pr-comment.yml`](examples/sbomcmp-pr-comment.yml) installs the generators, scans on every PR, uploads the raw SBOMs, and posts (or updates) a single PR comment with the report. Copy it to `.github/workflows/` in any repository; add `VDB_API_KEY` as a repository secret to switch the vulnerability source to VDB.

To turn the **Act now** list into a gate, add `--fail-on`:

```sh
sbomcmp report -i sbomcmp.json --fail-on refuse   # exit 3 on malicious releases, KEV, refuse-level names or MCP servers
sbomcmp report -i sbomcmp.json --fail-on warn     # also EPSS ≥ 10% and warn-level signals
sbomcmp scan --fail-on refuse ./repo              # same gate right after the scan (the result file is still written)
```

The default is `none`. When the gate trips, the actions are printed to stderr and the exit status is 3 (1 is a failure of sbomcmp itself, 2 a usage error), so a workflow can tell "something needs a decision" from "the tool broke". The gate only ever fires on VDB-only data: on an OSV-only run it never trips, because those signals are not there. The example workflow has the gate as a commented-out step.

## Development

```sh
make test     # gofmt, vet, unit tests (purl normalization, parser, comparison, OSV/VDB clients, MCP discovery)
make demo     # end-to-end with mock generators + offline vuln fixture, no network
```

`testdata/mock-bin/` contains shell scripts named `syft`, `cdxgen`, `trivy` that emit realistic CycloneDX with each tool's known quirks (no lockfile → Trivy finds no npm; Syft keeps `Flask_Login`; cdxgen resolves transitives and marks dev scope). `testdata/fixtures/vulns.json` stands in for OSV/VDB. Together they let the whole pipeline run without installing anything.

`testdata/golden/<tool>.keys` are normalized component-key snapshots of what each real generator currently reports for `testdata/sample-project`, written by the weekly [canary workflow](.github/workflows/canary.yml) that installs the latest syft, trivy, cdxgen and osv-scanner and asserts the adapters still work. When a release changes what a tool catalogues, the canary opens a snapshot PR with the diff instead of failing, so the change is reviewed rather than silently absorbed.

### Adding a generator

Add one `Adapter` in [`internal/gen/gen.go`](internal/gen/gen.go): binary names, a version probe, and a function that builds the argv for a directory or image target. If the tool only writes SPDX, that still works.

### Adding a vulnerability source

[`internal/osv`](internal/osv) and [`internal/vdb`](internal/vdb) are the two clients; [`internal/vuln`](internal/vuln) selects between them and maps results onto rows. A new source needs a client that fills `model.Vuln` / `model.Signal` and one more case in `vuln.Enrich`.

## Roadmap

- Drift: compare against the previous scan and comment only on what changed
- Quality score (NTIA / CRA minimum fields) by calling `sbomqs` when present

Done: push the chosen tool's SBOM to a watch service — [`sbomcmp push`](#push-to-vdb).

## License

[Apache-2.0](LICENSE)
