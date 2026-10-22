# Changelog

## 1.5.2 — 2026-10-22

- Translated the entire CLI, desktop GUI, and report output to English: command-line help, progress stages, diagnostics, HTML/JSON report labels, GUI dialogs and navigation, the 48 incident response command reference entries, and AI prompts. Cross-crate report strings, task statuses, and cancellation wording are consistent across CLI, GUI, core, and app.
- Translated README, CHANGELOG, AGENTS, `docs/PROJECTS.md`, CI release notes, and developer scripts to English; removed the redundant `README.en.md` since the main README is now the English version.
- Fixed the Tauri `beforeDevCommand` / `beforeBuildCommand` working directory for `@tauri-apps/cli` 2.x, so `npm run tauri dev` and `npm run tauri build` work from the frontend folder.
- Updated all affected fixtures and tests; full suite passes: 120 Rust tests and 85 frontend tests.

## 1.5.1 — 2026-10-15

- Fixed dropdown menus inside dialogs for source, parse status, protocol, and similar selectors being obscured and selected values not displaying; limited dialog height while keeping long lists scrollable, and fixed long project names widening the layout at the minimum window size.
- Added a project details editor covering name, client organization, timezone-aware response start/end times, location, responders, and description, persisted with manual project saves.
- Log evidence gained multi-dimensional queries and ascending/descending original or time ordering, supporting time ranges, log levels, client IPs, HTTP status codes, methods, paths, loggers, hosts, and custom fields; Windows event conditions expand separately.
- Added parsing for common Tomcat JUL, Logback/Log4j, and Spring application logs; timezone-less logs can specify an explicit source timezone, preserving original times and unknown fields without guessing times that lack a year.
- Unified pagination and page jumping across projects, evidence, findings, sources, diagnostics, IOCs, AI history, and references; filter collections, indexes, and pagination bookmarks are reused, process structures, network statistics, and references are cached on demand, and list details load on demand.
- Fixed page-turn retry after failure, stale requests overwriting fresh results, scroll positions, and remaining on an invalid page after an IOC rescan reduces the match count; combined filters prefer existing indexes with a smaller scope.
- Verified 168 paginated result sets against a real project with 2.42 million records, where the slowest backend metadata page read for source-filtered views dropped from about 2.02 s to 17 ms; 120 local Rust tests, 85 frontend tests, and repeated browser interaction checks pass. See `docs/PROJECTS.md` for measurement scope and limitations.

## 1.5.0 — 2026-10-13

- Added "Response commands" to the left workspace: 24 investigation and forensic commands each for Windows and Linux, viewable offline without opening a project; supports switching platforms, filtering by six categories, and searching by name, purpose, or command text.
- Each command notes its execution environment, permissions, applicability conditions, and parameter substitution requirements; native clipboard copies preserve the full text and line breaks, success or failure feedback is shown, and commands are never executed.
- The commands page is independent of project and evidence filters and does not write to `.eair` or change the AI scope; the page persists after background tasks finish, supports dark and light themes, and uses two columns in normal windows and one column in narrow windows.
- The sidebar navigation scrolls independently, fixing an issue where, after entries were added for narrow windows, the bottom button scrolled the whole workspace and covered the title.
- The project list gained a "Remove" action with a confirmation prompt that deletes only the local catalog entry, keeping the `.eair` file, evidence, and IOCs; entries for missing files can be cleaned up, the list recovers after reopening or saving, and stale path operations are rejected.
- Rust formatting checks, Clippy, and workspace tests now run locally before pushing; GitHub workflows keep platform builds, frontend checks, and packaging validation.

## 1.4.0 — 2026-10-09

- Standalone incident response projects are now generally available, supporting multi-day evidence appending, project details, notes, saving, and case continuation; the CLI and GUI share the same project service, and the project catalog stores only details and paths.
- In-project IOC lists and offline matching are now generally available, supporting IPs, domains, and URLs from files, pasted text, and manual entry, saving match references with pagination, navigation, and cancellation.
- Projects use the second `.eair` format, losslessly compressing evidence text, parsed data, diagnostics, and AI replies per record, removing duplicate previews, and reclaiming free pages; the old project format is not read and the report schema stays compatible.
- Fixed slow loading of large projects caused by the home page traversing all diagnostics; summary queries are skipped when there is no AI history, overview statistics are cached per project revision, and macOS APFS uses a separate copy-on-write working copy.
- Category pagination reads indexes directly and freezes the evidence scope, and keyword/regex filters reuse up to four result sets; process trees, diagnostic statistics, and AI summaries refresh as data changes, and saving notes or pagination positions no longer triggers full statistics. AI history reads by page, diagnostics load bodies only on the report page, and network sessions reuse filtered scopes.
- On a local project with 2.42 million evidence records, first-page log data reads dropped from 9.614 s to 0.044 s and next-page reads from 4.348 s to 0.001 s; the latest snapshot shrank by about 57% after compression with full data verified identical. See `docs/PROJECTS.md` for automated coverage and measurement scope.

## 1.4.0-preview.1 — 2026-10-05

- Feature branch pushes automatically run Rust/GUI tests, Clippy, and format checks on three platforms and build artifacts; preview tags publish GitHub Pre-releases with the lightweight Windows installer and the macOS DMG, validate the version and all six assets, and do not replace the stable Latest release.
- IOC matching moved to the "Evidence" group, clarifying that lists and results belong to the current project; added regression checks for database isolation across clients, the same IOC with different notes and scan policies, independent save and reopen, and the catalog not storing IOC data.
- Fixed the bottom of IOC results being clipped beyond the window; the page now scrolls independently so match results and pagination controls are fully visible.
- The project home page separates the create-project entry from the existing-projects list, with filter conditions collapsed by default and their purpose clearly labeled so they are not mistaken for a new-project form.
- Project names default to the client organization: the GUI auto-fills the name and allows manual renaming, and the CLI may omit the name when creating or saving new projects; new AI configurations plan sends automatically using the model context budget.
- Added a Windows x64 lightweight NSIS installer build entry: a Chinese/English wizard, per-user installation, Start menu and uninstall entries, and a web download of the WebView2 runtime when missing.
- The macOS DMG gained a light branded install interface, drag-and-drop guidance, and a fixed icon layout, with standard and Retina backgrounds; local and CI share the packaging process and keep the uncompressed read-only format.
- Added incident response projects: a separate UUID, client details, and timezone-aware response details; a GUI project home page with search and case continuation; CLI `project create/open/list/import/edit/note`; support for appending evidence, notes, saved filters, saving as a new file, and unsaved-change prompts.
- Added the self-contained `.eair` SQLite project file and a local catalog that stores only details and paths; a private working database, atomic snapshots via the Backup API, structure and evidence reference validation, and path and external-modification protection.
- Added IOC file, paste, and manual entry points with unified validation and deduplication; offline matching of IPs, domains, and complete HTTP/HTTPS URLs; saved match positions and evidence references; pagination, repeated scans, and retention of valid matches after cancellation.
- Project pagination, filtering, AI evidence batches, and HTML/JSON export use database cursors or on-disk batches, preserving existing core entry points and the JSON schema; the HTML report gained a project header. Added synthetic large-project performance checks with results in `docs/PROJECTS.md`.

## 1.3.1 — 2026-10-02

- The macOS ARM64 GUI now ships as an uncompressed read-only DMG; open it and drag `Easy Analyzer.app` into Applications. It includes the product icon, app metadata, license, and ad-hoc signature, and the bare GUI executable is no longer published for this platform.
- CI and local packaging share the app bundle build script; after mounting the DMG, verification checks resource integrity, version, ARM64 architecture, executable permissions, and the signature, with the DMG itself included in the checked assets. Windows/Linux CLI/GUI and macOS CLI assets are unchanged, and published releases are never overwritten.

## 1.3.0 — 2026-10-02

- The desktop icon now uses the easy-series Easy Analyzer teal-green italic E with a bar-chart mark, synchronized across the Windows ICO, macOS ICNS, Linux PNG, and GUI logo; the 16/24/32 px sizes use separately optically corrected masters, a reproducible SVG export script is provided, and the old icon is retained.
- The AI page gained a local evidence filter dialog for directly editing the full send scope; failed queries keep the valid filter, and empty collections cannot be sent. Valid findings show AI results only, while local findings remain in the overview and the full report; send controls were compacted, the results table made taller, run history moved into a separate dialog, and the budget and local triage sections collapsed by default.
- When an individual evidence batch or summary group fails, AI continues processing the remaining batches and records a successful reply noting the missing scopes; if summarization fails or is canceled, a clearly labeled local triage is provided that keeps findings, neutral leads, and evidence references and is included in HTML/JSON exports, without adding AI inference or changing the report schema.
- The AI status bar shows the current batch and total batches, and cross-batch summarization shows the round and per-round batch progress. An activity indicator remains while waiting for the last batch reply, with no fake 100% completion display.
- AI added model context budget planning: one complete send within the budget, batching only beyond it. Before sending, a local preview shows record counts, conservative token estimates, and the number of evidence batches, pins the configuration, scope, and payload for that run, and rejects stale previews.
- In context mode, validated findings and neutral related leads are summarized after batching; when the summary budget is exceeded, up to four rounds of grouped merging run with evidence references validated at each stage. If summarization fails or is canceled, accepted results and original replies are retained. Summaries do not double-count analyzed records and do not change the report schema.
- Added optional `context_tokens` with the output limit reserved plus a 20% safety margin; older configurations keep byte-based batching. Tokens are a conservative local estimate and do not represent the model's exact tokenization or automatic detection of service limits.
- Fixed nested `#attributes` fields in Windows event details not being translated, covering system attributes such as execution thread/process IDs, the event provider, record time, activity ID, and user SID; the `_attributes` path stays compatible and original field names and values are unchanged.

## 1.2.0 — 2026-10-02

- Fixed the Windows GUI close button failing to exit: the window-destroy permission required by the close event was completed, and after saving preferences the close finishes directly, avoiding duplicate close events; running tasks still offer cancellation and keep their result prompts.
- Unit tests embed synthetic log samples so that, after cross-compilation, they no longer depend on Mac build directories on Windows.
- The Windows GUI import page gained an explicit UAC elevation entry and real token permission status. The elevated window uses a separate WebView directory and temporary preferences, with local process collection preselected; the original window and evidence are kept, and canceling authorization does not clear the session.
- Windows local process collection attempts to enable SeDebugPrivilege while reading and restores the previous state afterwards; if enabling fails, readable evidence is retained and missing paths, command lines, and account information are diagnosed.
- GUI log details translate common Windows event field names, with the original field names available on hover; unknown fields, original values, and the report schema are preserved.
- Windows closing and elevated collection were verified in Parallels Windows 11 ARM64; actual UAC approval/cancellation and field deltas before and after elevation remain to be verified. See `docs/GUI_VALIDATION.md` for details.

## 1.1.1 — 2026-10-01

- Tag CI builds the CLI and Tauri GUI for Windows x64, Linux x64, and macOS ARM64 together, adding frontend build/test steps and Linux graphics library dependencies; the workspace default build members are unchanged.
- Release assets distinguish the six standalone programs with the `easy-analyzer-cli-*` / `easy-analyzer-gui-*` prefixes and generate a unified SHA256SUMS; Rust/GUI/lockfile versions are validated, missing programs and extra files such as configs or reports are rejected, and published releases are never overwritten.
- Fixed the blocking mode used by the local AI mock service after accepting a connection, avoiding occasional read failures in macOS tests; the real AI call logic is unchanged.
- Frontend sources are pinned to LF line endings to prevent format checks failing after CRLF checkouts on Windows.

## 1.1.0 — 2026-10-01

- Added a Tauri 2 + React native GUI with an eight-page workspace at 1280×720, light and dark themes, resizable detail panes, and narrow-window drawers; the CLI and shared application layer architecture are kept.
- The app added record/source/category/parse-status filters, overview and findings pagination, evidence navigation, and complete filtered collections; invalid regexes preserve valid results, process ancestor context does not expand the AI scope, and network sessions keep full statistics.
- The GUI performs import, queries, relationship building, AI, configuration, and export through background tasks and rejects stale session/revision numbers; references outside the current filter are restored on return, AI sends explicitly and pins scope/settings, and raw packets and payloads are selected explicitly every time.
- Added full path/hash details for sources, configuration key status and atomic saving, full HTML/JSON export, and Enter-key protection while confirming candidates in a Chinese input method.
- Completed macOS ARM64 GUI local packaging, synthetic-data regression, and real screenshots of all eight pages in both themes; native drag-and-drop, IME composition, and quit preferences still need manual review, and the Windows/Linux GUI has not yet been verified on real machines.
- Tag release assets keep the standalone CLI programs for the three platforms plus SHA256SUMS; GUI source ships with the tag, and installers are built locally per docs/GUI.md.

- Added analyzer-app, sharing analysis orchestration, sessions, evidence indexing, paginated queries, structured process trees, configuration saving, and report export, with the CLI migrated into an application-layer adapter.
- core gained a unified execution context, stage progress, and cooperative cancellation; the CLI supports Ctrl+C, keeping valid evidence and completed AI replies while stopping further requests.
- Added background tasks with task IDs and terminal states for a future Rust GUI; existing commands, short options, and the report schema are preserved.

## 1.0.0 — 2026-09-30

- First official Releases publication, with the repository at MoShouSecurity/easy_analyzer.
- Supports Windows/Linux login logs, Apache/Nginx, custom web formats, process snapshots, and offline PCAP/PCAPNG analysis.
- Supports local rules, keyword queries, scenario-based AI analysis, and terminal, JSON, and responsive HTML reports.
- Publishes standalone programs for Windows x64, Linux x64, and macOS ARM64 plus SHA256SUMS.

## 0.1.18 — 2026-09-30

- Raised the default AI per-batch evidence text limit to 96 KiB (98304 bytes); the setting remains batch_bytes and can be increased further.

## 0.1.17 — 2026-09-30

- The HTML report became a responsive risk overview prioritizing key findings and recommendations; findings, references, AI replies, processes, sessions, queries, and diagnostics collapse in layers, and long content has a limited display height.
- Full evidence is grouped by source in sets of 100 entries, references use short locations and expand automatically for navigation; the report remains a single offline file, and the navigation script is restricted by a CSP hash.
- Terminal sections control counts with `-n`, prioritize risks and errors, and merge identical diagnostics; JSON gained a summary overview at the top while keeping the complete data fields.

## 0.1.16 — 2026-09-30

- The HTML report gives AI analysis a dedicated section showing validated findings, batch completion scope, and each raw API reply; JSON stores batches, replies, and errors in sync.
- JSON or evidence validation failures retry up to twice with an animated retry status; on final failure, previously completed results are kept, unexecuted batches are noted, and the failure status is still returned.
- Required-field, confidence, and evidence-ID validation is preserved, and replies that fail validation are not treated as conclusions.

## 0.1.15 — 2026-09-30

- AI results tolerate and ignore extra fields such as `confidence_note`, preventing model-added fields from failing an entire batch.
- Strict checks continue for required fields, types, severity, confidence ranges, and evidence IDs; prompts explicitly define the six result fields, with explanations written into description.

## 0.1.14 — 2026-09-30

- CLI AI analysis gained a spinner animation showing evidence preparation, the current batch, and elapsed time; the animation ends on completion or failure.
- The animation appears only on the interactive terminal's standard error and stays compatible with JSON output and report export; it is disabled when stderr is redirected.

## 0.1.13 — 2026-09-30

- AI organizes parsed results into text labeled with evidence IDs, reducing repeated fields such as web requests, and still uses the Chat Completions interface.
- System prompts are generated automatically for the Windows, Linux login/SSH, web, process, network, and mixed scenarios, defining the analysis focus and evidence boundaries.
- Batches are sized by evidence-text bytes, keeping the JSON structure and evidence reference validation; PCAP raw packets and payloads remain controlled by `-P`.

## 0.1.12 — 2026-09-30

- `-o html` auto-saves to the current directory and picks a new name when a report already exists; `-O` still accepts an explicit path, and the save location is shown after export.
- Failure diagnostics print directly to the terminal for file or JSON report output, keeping existing local analysis results.
- The default AI per-batch evidence limit is now 65536 bytes, and items exceeding the per-item limit report their exact size, position, and the relevant setting.

## 0.1.11 — 2026-09-30

- Keys are persisted and read by default through the `api_key` field of `config.toml` in the current directory, with the file key taking precedence; the older `api_key_env` configuration remains compatible.
- `config show` and debug output hide keys, and configuration format errors do not echo the original config line.
- DeepSeek shows a Chinese-language hint before requests when no key is configured, and configuration help and docs were updated accordingly.

## 0.1.10 — 2026-09-30

- The default AI configuration uses the official DeepSeek API, the `deepseek-flash` model, and the `DEEPSEEK_API_KEY` environment variable.
- JSON output and `max_tokens` are used by default, the request timeout is now 300 seconds, and the output limit is 65536 tokens.
- CLI configuration hints, help, and docs were updated in sync; custom OpenAI-compatible services remain supported.

## 0.1.9 — 2026-09-30

- All platforms create and read `config.toml` in the current working directory by default; `-c` still supports specifying another configuration path.
- Configuration help and usage docs were updated in sync; an existing configuration is still never overwritten.

## 0.1.8 — 2026-09-30

- The default findings list groups by risk and shows aligned match counts and names; zero-count levels, rule IDs, confidence, duplicate notes, and evidence locations are hidden.
- Login correlation, process, traffic, and AI findings keep short context, with filenames attached to findings from multiple sources.
- `-R` shows full finding explanations, confidence, rule IDs, evidence references, and raw records; the terminal overview, titles, and action hints were unified and simplified to Chinese.

## 0.1.7 — 2026-09-30

- The default record summary condenses to a single line with risk level and key fields, hiding per-record source/location, parse status, time, and repeated rule lists.
- `-R` raw mode continues to show the full record header, time, location, and matched rules; the default summary keeps anomaly markers for unrecognized/malformed records.

## 0.1.6 — 2026-09-30

- Omitted terminal evidence now shows "N more entries" on the same line; instructions for viewing everything are shown once at the end of the output.

## 0.1.5 — 2026-09-30

- The CLI shows a key-field summary by default and hides raw logs and the full-field JSON; unrecognized records do not echo the original text either.
- Added `-R` / `--raw` to show raw records after the summary; it only controls terminal text output, while JSON/HTML keep full evidence.
- Long summary fields are limited to 120 characters, and each finding shows at most 3 source/location references by default for terminal readability.
- The full JSON report is serialized only when JSON output is requested, reducing overhead for pure terminal summaries.

## 0.1.4 — 2026-09-30

- Packaging now updates the latest programs and companion files directly in `dist/`, dropping version subdirectories; the platform workflows likewise keep the raw program files.
- Default log rules expanded to 53, covering common Windows, Linux, and web incident-response scenarios across high, medium, and low severity.
- `-s` filters all default rule matches in one step; the terminal and HTML sort by risk and show Chinese severity levels, statistics, and evidence references, with terminal records listing the matched rules.
- Evidence is grouped per rule and source, with terminal evidence references per finding limited by `-n`; JSON/HTML keep full references.
- Windows rules check provider and event IDs; login correlation additionally distinguishes target hosts within a source to avoid merging across hosts.

## 0.1.3 — 2026-09-30

- All long options gained single-letter short forms; the same parameter uses the same letter across commands, keeping the long forms and existing dependency conditions.
- Help pages show both long and short options, common examples use the short forms, and the README provides the complete comparison table.
- The macOS demo script uses `-j` / `-H` to save JSON/HTML reports.

## 0.1.2 — 2026-09-30

- Localized argument-parsing diagnostics: missing inputs, unknown commands/options, invalid values, conflicting arguments, and count errors now show Chinese messages, keeping allowed values and spelling suggestions.
- Usage headings and help hints in argument errors became Chinese, and the file placeholder was localized; help/version output channels and exit codes follow the original rules.
- The macOS local build outputs the raw program directory directly.

## 0.1.1 — 2026-09-30

- Reorganized CLI help: clearer command selection, grouped by input, queries, AI, reports, and limits, with added examples and configuration steps.
- `-h` and `--help` provide the same information.
- Split arguments per command: log format is specified only in logs/analyze; web format and automatic log loading apply to logs/analyze; including collected processes in mixed analysis uses analyze's `--live-processes`; PCAP payload sending applies to pcap/analyze.
- Missing files/collection sources, inapplicable arguments, and AI matches missing filter conditions error out during argument parsing and return exit code 2.
- The macOS release build is Apple Silicon arm64, using the existing shared analysis core.

## 0.1.0 — 2026-09-30

- First Rust CLI release: log, process, and PCAP analysis; local rules and queries; OpenAI-compatible AI; terminal/JSON/HTML reports.
- Git management, synthetic samples, and Windows/Linux/macOS build configuration.