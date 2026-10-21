# Incident Response Projects and IOCs

One incident response is one project; a separate response for the same client creates a new project. A single project can continue for multiple days while appending evidence from multiple hosts. The client organization and response start time are required; the project name defaults to the client organization, can be edited manually, and falls back to the client organization when left empty. The start time defaults to the local current time, and the end time must not be earlier than the start time. Times use RFC 3339 with offsets, and creation/update times are stored separately from response start/end times.

## Usage

Create, search for, or continue projects from the GUI home page. After opening a project, the home page's “Current project details” shows its name, client organization, response start/end times, location, responders, and description; edit via “Edit project details” or the toolbar's “Edit details”, which is also reachable by clicking the project name in the toolbar. Response times must include a timezone, and the end time must not be earlier than the start time. Click “Apply changes” to update the current working copy, then click the toolbar's “Save” to write back to `.eair` and refresh the project list; canceling keeps the original details, and a failed apply keeps what you entered for editing or retrying.

Importing appends to the current project; identical source IDs are not written twice. A source ID covers both source identity and content, so changed content becomes a new source. Evidence is never merged across hosts based solely on a matching content hash. Notes, AI history, IOCs, and filter conditions are saved with the project. New evidence expires the AI preview, keeps existing IOC matches, and prompts that an explicit scan is required.

Both save and save-as keep the UUID, while new projects generate a fresh one. Save-as updates the path in the catalog and leaves the original file untouched. Reopening a moved file updates the catalog path; missing files are clearly reported. When unsaved changes exist, switching projects or closing offers to save, go back, or discard the changes.

### Log multi-dimensional query

“Log evidence” keeps keyword/regex, source, event type/log category, parse status, and local suspicious-item filters; the “multi-dimensional query” combines time range, log level, client IP, HTTP status code, request method, request path, logger, host, and up to 16 custom-field conditions. Level, status code, and method accept comma-separated lists that match any value within the list, and all conditions must hold together. IP matches exactly; path, logger, and host match on containment. Custom fields support contains and equals, using `thread`, `duration`, `user`, `action`, or original field names shown in the details. Both field names and values are case-insensitive.

Supported inputs are Nginx/Apache access and error logs, common Tomcat JUL, Logback/Log4j, and Spring text formats, and system authentication logs. Custom access formats keep using the web format definitions from import. Tomcat/Java application logs extract time, level, thread, logger, and message; unmatched lines and exception stacks are retained verbatim line by line, marked unrecognized, with no field guessing. Already imported projects are not reparsed automatically; if Tomcat/Java logs in an older project were previously unrecognized, the missing fields are not backfilled — import the raw logs into a new project with the updated version to generate these fields. Windows event ID/level, provider, and channel live in a dedicated expandable condition section.

Query boundaries and timezone-aware time columns use the local timezone, and ranges include both endpoints. When log times themselves carry a timezone, comparison uses the actual moment; for logs without a timezone but with a full date, such as Nginx/Tomcat, “Timezone for timezone-less logs” lets you explicitly choose a fixed UTC offset for the evidence source. This option affects only queries and sorting and never rewrites the original evidence text or time fields; when unset, those times remain unknown and are excluded from time-range filters. Timestamps missing a year always remain unknown. Original timezone-less times are shown in lists marked “original”, and details keep every original time.

Sorting supports original ascending, original descending, time ascending (oldest first), and time descending (newest first). Records with unknown time sort last in both time orderings, and identical moments follow the stable original record order. Filtering and sorting apply to the complete collection before pagination, and page turns and evidence navigation keep the same conditions; complex queries cache match IDs in the working database, while original ascending/descending views keep reading on demand. Failed or canceled queries keep the last valid scope. Conditions are written to `.eair` on manual project save, and older projects missing the new query fields fall back to defaults. AI's “current filter” reuses the complete match set, and its filter dialog can edit the same general log conditions; reports still export full evidence.

```sh
easy-analyzer project create response.eair --name "Client A response" --client "Client A" \
  --response-start "2026-10-05T09:00:00+08:00" --location "On-site" --responders "Engineer A"
easy-analyzer project import response.eair host-a/auth.log host-b/auth.log
easy-analyzer project edit response.eair --response-end "2026-10-07T18:00:00+08:00"
easy-analyzer project note response.eair --record EVIDENCE_ID --text "On-site investigation note"
easy-analyzer project open response.eair -q "192.0.2.10" -H report.html
easy-analyzer project list --search "Client A" --from 2026-10-01 --until 2026-10-31

# --project appends to the working database; --save-project is also required to write back to the project file
easy-analyzer analyze host-c/auth.log --project response.eair --save-project response.eair

# Direct analysis still works as before; saving a new project requires a client, while the name and start time are optional
easy-analyzer analyze auth.log --save-project new.eair --client "Client B"
```

CLI `project import` auto-saves that explicit operation, while `project open` opens read-only without reparsing or invoking AI automatically. `--project` operations run in a private working copy, and the original file is unchanged unless `--save-project` is given. Explicit CLI query conditions are kept on save and restored when continuing a case; each GUI page saves its own filters separately.

## Pagination and large projects

Logs, processes, packets, network sessions, findings, sources, diagnostics, the project list, IOC lists/matches, AI runs/batches, and finding references all provide pagination controls. The pagination bar supports first, previous, next, last, and jumping to an entered page number; evidence, findings, and the project list can show 50, 100, or 200 entries per page. Changing filters or page size returns to the first page; duplicate requests are disabled while paging, and failures keep the previous results.

Paging reuses complete filtered collections. Ordinary records locate by page start, and sparse records keep a limited number of recent bookmarks; combined filters compare match counts per dimension and reuse the existing index with the smaller scope, avoiding a scan of all records of a type when querying a single source. Statistics, process structures, session match counts, and reference order are cached per evidence revision. New evidence, IOC scans, or finding changes invalidate the corresponding caches; caches exist only in the private working copy/memory and are never written to the project file. The first complex query or structure build may still traverse the full range, and later page turns read only the current page.

After an IOC rescan that reduces the match count, the view automatically returns to the last valid page; empty results show page 0 / 0 with paging disabled. A successful IOC page turn shows the table from the top; a failed one keeps the original page and scroll position and can be retried.

Lists transfer only the log fields, process information, and finding summaries needed for display. Clicking evidence or a finding reads the full original text, fields, explanations, recommendations, and references on demand; exports keep full evidence, unaffected by the current page or list summaries.

## IOCs

In the GUI, IOC matching lives in the “Evidence” group. Each project stores its list, notes, scan policy, and match results independently; the same IOC can carry different notes in different projects, and deduplication applies only within the current project. Switching projects restores that project's IOC data, and new projects start with an empty list. The project catalog neither stores nor aggregates IOC data.

The GUI supports TXT/CSV files, pasted text, and manual entry, all sharing the same validation and deduplication. TXT has one IOC per line; CSV can escape commas, quotes, and multi-line notes, with columns `type,value` and an optional `note`:

```csv
type,value,note
ip,192.0.2.10,Example address
ip,2001:db8::1,Example IPv6
domain,example.com,"Example note, with a comma"
url,https://example.com/a?q=1,Example URL
```

Invalid entries report their positions while the valid ones continue importing; if no entry is valid, the original list is kept. Domains include subdomains by default and match on label boundaries; IPs match the full address. URLs normalize scheme, host, and default ports, ignore fragments, and require the path and query parameters to be identical. The first release does not support hashes, CIDR, wildcards, or online lookups.

```sh
easy-analyzer project import response.eair auth.log \
  --ioc indicators.txt --ioc indicators.csv --ioc-value 192.0.2.10 \
  --ioc-value https://example.com/a?q=1 --ioc-exact-domain
easy-analyzer project open response.eair --ioc-stdin < indicators.txt
# Save the pasted/standard-input list and the scan results
easy-analyzer project open response.eair --ioc-stdin --ioc-stdin-csv \
  --save-project response.eair < indicators.csv
```

Evidence and IOCs cannot occupy standard input at the same time. Scans parse fields, log text, process commands, and network/HTTP/DNS metadata, excluding binary log text, packet hex dumps, and payloads. A match stores the IOC, note, evidence ID, actual value, and position, entering local suspicious filtering and reports as leads to investigate. Repeated scans replace results record by record; cancellation keeps new matches for completed records and earlier valid matches for records not yet reached, and the overwrite notice states whether the latest scan finished.

## Storage and architecture

Each `.eair` is a standalone SQLite file with the application identifier `0x45414952` and project schema version `2`; first-version projects are not read. SQLite is compiled into the program via `rusqlite`'s bundled feature, and core does not depend on the database. See the [SQLite application file format](https://www.sqlite.org/appfileformat.html) and the [Backup API](https://www.sqlite.org/backup.html).

- Larger raw text, parsed data, diagnostics, and AI replies are losslessly compressed into individual zlib blocks and decompressed when the current record or page is read; short text and content that does not shrink after compression stay verbatim. Identical evidence previews are restored from the full data to avoid duplicate storage; the PCAP payload-stripped preview is retained separately. Indexes and filter fields remain directly queryable. Each compressed block carries an encoding marker, original byte length, and zlib checksum, and corrupted blocks return read errors.
- Saving a snapshot reclaims free pages occupied by deleted temporary filters, and cancellation or failure keeps the original target file; compression never changes evidence IDs, times, original text, notes, IOCs, or the report schema.
- `analyzer-app`'s `ProjectService` manages the working database, details, appending, saving, and validation; `ProjectCatalog` manages details/paths/last-opened times; `IocService` manages lists and scan tasks.
- Sources, records, findings and references, network sessions and references, AI runs and batches, notes, filter conditions, and IOCs and matches are stored in separate tables. Record IDs, sources, categories, parse statuses, protocols, and relationships are indexed. Ordinary category filters read directly from indexes and freeze the scope at the current maximum record number, building a working set only when complete numbering is needed. Keyword, regex, and suspicious-item collections live in working tables with up to four cached at once, recomputed after evidence is appended or related findings change. Relationships and reports use batched cursors, keeping match semantics consistent.
- The overview is cached per evidence revision; editing project details, notes, or pagination positions still updates the project revision but does not trigger full evidence statistics. Process trees refresh as records are appended, AI history reads only run titles and summaries for the current page, and diagnostic bodies load only on the report page; report error/warning statistics merge into a single query whose result is reused. Canceling an unfinished collection build rolls it back, and closing a project frees caches and the private database.
- First import parses, runs rules, writes, and frees source by source, keeping the single-source limit. Rules expose a source-cursor interface, AI planning reads batch by batch and freezes results into private on-disk batches, and HTML/JSON encoding is emitted through core's `ReportCursor`; common project-open, page, filter, IOC, and export paths do not invoke the full report-compatible materialization entry point. The process tree still needs the process-node collection, and the older `with_report`/core public entry points keep their original behavior.
- The working copy lives in a private temporary directory. Manual saving uses the Backup API to create a temporary snapshot inside the target directory, clears runtime collections, closes sidecar files, syncs, and replaces atomically; cancellation or a failed replacement keeps the original target. Opening validates the identifier, version, complete structure/indexes, database and foreign keys, and AI evidence references, without reparsing.
- Output path protection covers original evidence, configuration, IOCs, and projects, and saving detects UUID/revision changes to the original file. Projects have no AI configuration key field. The catalog stores only basic details, paths, and last-opened times, with no evidence tables; it defaults to the application data directory, and `EASY_ANALYZER_DATA_DIR` selects an isolated directory.
- GUI background tasks bind to sessions and revisions, and switching clears old selections/previews; results from stale tasks are refused when writing to a new project. The HTML report shows the project name, client, and response times, JSON follows the existing report schema, and full project details and notes stay in the database.

## Verification record (2026-10-15, v1.5.1)

On macOS ARM64, 120 local Rust workspace tests and 85 GUI frontend tests pass, along with format checks, Clippy, and the frontend production build. Using a real compressed project with 2,422,767 records, 168 paginated result sets were verified row by row against SQL in a separate working copy, covering original ascending/descending order, source/category/parse status, 50/100/200 rows per page, first/middle/last pages, backwards jumps, and out-of-range requests; the original project was never modified.

In the same project, a source filter for 41,417 logs brought the slowest debug-backend metadata page read down from 2.018 s to 0.017 s, with results covering ascending/descending order and different page sizes. Building that source filter initially dropped from 2.264 s to 0.202 s. These are local measurements including page location and decoding but excluding frontend IPC, rendering, or external AI; disk cache, data distribution, and hardware affect the timings.

Additional checks covered 8,000 sparse out-of-order lookups compared against SQL, cache refreshes after an IOC rescan shrinks or restores matches, SQLite VM work for small-source queries, and regression checks for retry after failure and stale responses.

Browser checks with the latest frontend and synthetic data covered project, log, diagnostic, and IOC pagination, the log multi-dimensional query, on-demand details, project details editing, and dropdown overlays at 1280×800 / 960×600 windows in dark and light themes. Confirmed that reduced IOC match counts return automatically to the last valid page and that zero results disable paging; fixed long project details widening the top-level layout at the minimum window size. These browser checks used synthetic interfaces and do not constitute acceptance on real Windows/Linux desktops, packaged-application IPC, or external AI services.

## Verification record (2026-10-09)

All automated checks were rerun locally on macOS ARM64: 103 Rust workspace tests (including doc tests), 46 GUI frontend tests, and 21 packaging-rule tests pass, along with Clippy, format checks, and the frontend production build. Coverage includes importing and each parser, process trees, network sessions, filtering/navigation, IOCs, AI scope/replies/cancellation, project details/save/restore/isolation, the CLI, reports, and settings. New checks confirmed that ordinary pagination does not copy the complete evidence ID list, old selections stay frozen after appending, at most four collections are cached, closing a project frees the database, note/pagination preferences do not invalidate statistics, and AI history pagination and diagnostic cache refresh work.

In the same compressed project of 2,422,767 records and 1,468,833 diagnostics, views were generated with the release backend at 100 rows per page; pagination preferences were saved before paging to cover the real UI flow. The original file was opened read-only, and running collections and preferences were written to a private copy. Single-run measurements:

| Operation | Before | After |
|---|---:|---:|
| Log first page | 9.614 s | 0.044 s |
| Log next page | 4.348 s | 0.001 s |
| Last 50 diagnostics | 0.117 s | 0.046 s |

Stand-alone open plus home view generation totaled 2.004 s (open 1.875 s, home view 0.129 s). Modules that hold data were additionally confirmed using 10,000 synthetic processes and 10,000 packets: process tree first page 0.031 s and next page 0.008 s, network view first page 0.005 s. The 100,000 synthetic logs also ran keyword/regex queries, a full IOC scan, snapshot save/reopen, and full JSON/HTML exports, with match and record counts correct.

The timings above measure backend view generation only, excluding UI drawing or remote AI responses; disk cache and machine load affect results. The AI protocol was tested with a local mock service, and this round did not run real Windows/Linux desktops or call external AI services.

```sh
cargo test --offline --locked --release --workspace
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
# GUI frontend directory: npm test && npm run build && npm run format:check
python3 scripts/test_release_assets.py
EASY_ANALYZER_BENCH_PROJECT=/path/to/new-format.eair cargo test --offline --locked --release -p analyzer-gui benchmark_ -- --ignored --nocapture --test-threads=1
cargo run --offline --locked --release -p analyzer-app --example project_benchmark -- 100000 256
```

## Verification record (2026-10-05)

91 Rust workspace tests (including doc tests) and 46 GUI frontend tests pass; coverage includes cross-client session isolation, per-client UUIDs, multi-day appending, repeated sources/content changes, recovery after removing original inputs, catalog relocation, save cancellation and external modification, path protection, metadata/filter/note handling, expired AI previews, and the IOCs' three entry points, escaping, invalid rows, boundaries, duplicates, and cancellation coverage. The dedicated IOC database verification used two client projects: the same IOC was saved with different notes and scan policies, editing one project did not affect the other, alternating reopen after independent saves kept list, match, and scan states consistent, new projects started empty, and the catalog held only project details. The frontend covered continuing after a successful save, staying on the original project after a failed save, and unsaved-close prompts.

The native macOS ARM64 GUI ran a synthetic client through creating a project, importing `auth.log`, pasting IOCs that included invalid rows, completing a scan, and saving the project; the CLI reopened it to restore evidence/IOCs and write a note. After the file was moved, the GUI flagged it missing, relocated it, and displayed the CLI note. Windows/Linux desktop interaction is not yet verified on real machines. SQLite compile checks are complete for macOS ARM64, Linux x64 GNU, and Windows x64 GNU; a real Windows MSVC build still requires the Windows SDK/Visual Studio toolchain, which this macOS environment lacks, so GNU checks cannot substitute for MSVC verification. The three native runners of the existing release CI will build bundled SQLite; no release Actions were run this time.

### Synthetic large-project measurements

macOS ARM64, local SSD, Rust release build; each log entry is about 1 KiB, 25,000 entries per source, and one IOC per 10,000 entries. Initial parse/save and reopen-resume were measured in separate processes, with `/usr/bin/time -l` recording peak RSS. No real client data and no AI network calls.

| Metric | 100k entries | 1M entries |
|---|---:|---:|
| `.eair` file size | 248,496,128 B | 2,488,332,288 B |
| Initial parse and import | 3.790 s | 38.167 s |
| Save snapshot | 0.261 s | 2.198 s |
| Peak RSS during initial processing | 184.1 MiB | 944.6 MiB |
| Open (last round) | 1.561 s | 13.447 s |
| Last page, 100 entries | 0.002 s | 0.021 s |
| Text filter | 0.061 s | 0.595 s |
| Regex filter | 0.060 s | 0.601 s |
| Full-project IOC scan | 0.764 s | 7.474 s |
| JSON streaming export | 0.322 s | 2.884 s |
| HTML streaming export | 0.490 s | 4.519 s |
| Peak RSS when resuming | 26.1 MiB | 26.0 MiB |

Open includes full-file validation and private-copy duplication and is strongly affected by disk cache/system I/O; earlier rounds measured 0.369 s and 3.169–3.679 s, the table keeps the last round's results, and no fixed latency is promised. Peak RSS during initial processing grows with total volume, so the resume results do not establish that initial imports also need only 26 MiB; the current source-by-source freeing still retains records within a source, and a constant initial RSS is not yet proven. Synthetic text results also do not substitute for large-scale measurements with EVTX/PCAP, dense IOC matches, or long AI history.

Reproducible commands (output covers only self-built synthetic projects; external paths must never overwrite existing projects):

```sh
cargo build --release --locked -p analyzer-app --example project_benchmark
/usr/bin/time -l target/release/examples/project_benchmark 100000 1024 import /tmp/synthetic-100k.eair
/usr/bin/time -l target/release/examples/project_benchmark 100000 1024 resume /tmp/synthetic-100k.eair
/usr/bin/time -l target/release/examples/project_benchmark 1000000 1024 import /tmp/synthetic-1m.eair
/usr/bin/time -l target/release/examples/project_benchmark 1000000 1024 resume /tmp/synthetic-1m.eair
```

Local files and manual saving are first-release boundaries; client contacts, contracts/billing, multi-user collaboration, cloud sync, autosave, and review statuses are not included.