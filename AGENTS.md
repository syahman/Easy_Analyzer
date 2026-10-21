# Project Conventions

## Architecture

- Dependencies flow `analyzer-cli / future analyzer-gui → analyzer-app → analyzer-core`. The CLI does not depend on core directly; shared models are accessed through the app's exported interfaces.
- Analysis orchestration, scope selection, sessions, configuration saving, and export validation live in the app; parsers, rules, the AI protocol, and report encoding live in core. Frontends handle parameters/controls, standard input/output, and progress display.
- app/core do not depend on CLI or GUI frameworks and never print to the terminal; newly added long-running loops must hook into the execution context. Task cancellation keeps valid evidence, valid AI results, and unfinished diagnostics.
- Keep the report schema and the existing core public entry points compatible; the GUI uses session pagination and background tasks and does not duplicate the full CLI flow.

## Git and releases

- Daily changes commit source code only; push branches when the user asks to sync GitHub. Pushes to `codex/incident-projects-ioc` automatically run CI and upload build artifacts, do not create a Release, and do not manually start release Actions.
- Only when the user explicitly asks to package a version tag or publish a preview installer should `vX.Y.Z` or `vX.Y.Z-preview.N` tags be created and pushed. Confirm the version first when it is unclear; a tag must point to committed release source, match the project version in `Cargo.toml` and `Cargo.lock`, and `CHANGELOG.md` must be updated.
- After a tag is pushed, `.github/workflows/ci.yml` builds and publishes automatically: stable tags publish stable Releases, preview tags publish Pre-releases without marking Latest; report success or failure after waiting for the Actions result. Do not publish a Release during ordinary updates.
- Release assets contain only the CLI and GUI for Windows x64, Linux x64, and macOS ARM64 — six attachments plus `SHA256SUMS`; the macOS GUI is an uncompressed DMG containing `Easy Analyzer.app` (`easy-analyzer-gui-macos-arm64.dmg`), and the rest are standalone programs; filenames explicitly include `-cli-` / `-gui-`. Do not publish a macOS Intel build, and do not upload documentation, samples, configuration, or other archives.
- Previews keep the six attachments and `SHA256SUMS`, with the Windows GUI replaced by the lightweight NSIS installer `easy-analyzer-gui-windows-x64-setup.exe`, which downloads WebView2 online when missing; stable-release asset rules are unchanged.
- Do not overwrite published versions; after changes, publish with a new version tag.

## Local files

- `dist/` keeps the latest programs only, without per-version directories; when updating programs, keep the user's `config.toml`, reports, and case files.
- Secrets, local configuration, real logs, case data, and build artifacts must not be committed to Git.