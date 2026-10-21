use analyzer_app::InputFormat;
use clap::{
    Arg, ArgAction, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum,
    builder::{PossibleValuesParser, TypedValueParser},
};
use std::path::PathBuf;

// Keep each spelling consistent across commands, including global arguments.
const SHORT_OPTIONS: &[(&str, char)] = &[
    ("config", 'c'),
    ("format", 'f'),
    ("web_format", 'w'),
    ("web_format_file", 'W'),
    ("auto_load", 'l'),
    ("live_processes", 'p'),
    ("evidence_dir", 'e'),
    ("query", 'q'),
    ("regex", 'r'),
    ("suspicious", 's'),
    ("tree", 't'),
    ("ai", 'a'),
    ("ai_scope", 'S'),
    ("include_payload", 'P'),
    ("output", 'o'),
    ("out", 'O'),
    ("json_out", 'j'),
    ("html_out", 'H'),
    ("limit", 'n'),
    ("raw", 'R'),
    ("max_file_mb", 'm'),
    ("max_records", 'M'),
];

const HELP_TEMPLATE: &str = "{about-with-newline}\nUsage: {usage}\n\n{all-args}{after-help}";
const COMMAND_HELP_TEMPLATE: &str = "{about-with-newline}\nUsage: {usage}\n\nCommands:\n{subcommands}\n\nOptions:\n{options}{after-help}";
const ROOT_EXAMPLES: &str = "How to pick a command:
  Known log file → logs; process capture/snapshot → processes; network capture file → pcap
  Unsure of the file type, or need mixed analysis → analyze; AI service configuration → config

Common examples:
  easy-analyzer logs cases/Security.evtx -s
  easy-analyzer logs cases/Security.evtx -s -R
  easy-analyzer logs cases/access.log -q '.env'
  easy-analyzer processes -t
  easy-analyzer pcap cases/capture.pcapng
  easy-analyzer analyze cases/wtmp cases/processes.json cases/capture.pcap
  easy-analyzer config init

See arguments and examples for a command: easy-analyzer logs -h
Local parsing and rules run by default; evidence is only sent to the configured service when --ai is given.";

#[derive(Parser)]
#[command(version, about = "Easy Analyzer · Log, process, and offline network evidence analysis", after_help = ROOT_EXAMPLES)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help_heading = "AI analysis",
        help = "AI configuration file path; when omitted, the config.toml in the current working directory is used"
    )]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Incident response projects: create, reopen, append evidence and notes
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Mixed analysis: automatically identify log, process snapshot, and PCAP files
    #[command(after_help = "Examples:
  easy-analyzer analyze cases/Security.evtx cases/wtmp cases/processes.json cases/capture.pcap
  easy-analyzer analyze cases/access.log -j reports/case.json -H reports/case.html
  easy-analyzer analyze -p -t

Input: provide files, or use --auto-load / --live-processes; file name - means standard input.
--format forces the format for all inputs; mixed files usually keep auto.
--auto-load loads logs on the local Windows/Linux machine; on macOS provide offline files.
Filtering only controls terminal records and the AI matches scope; JSON/HTML keep full records plus query_matches.")]
    Analyze(AnalyzeArgs),
    /// Log analysis: EVTX, Linux login logs, SSH, and web logs
    #[command(after_help = "Examples:
  easy-analyzer logs cases/Security.evtx -s
  easy-analyzer logs cases/wtmp cases/btmp
  easy-analyzer logs cases/access.log -q 'union.*select|\\.env' -r
  easy-analyzer logs cases/access.log -W nginx-format.conf
  cat cases/auth.log | easy-analyzer logs - -f text
  easy-analyzer logs cases/Security.evtx -a -S suspicious

Input: provide log files or --auto-load; file name - means standard input.
--auto-load only loads logs of the current Windows/Linux host; on macOS provide offline files.
Local rules run automatically; --suspicious selects records referenced by rules, intersecting with --query when both are used.
JSON/HTML keep full records; filtered result IDs appear in query_matches.")]
    Logs(LogArgs),
    /// Process analysis: collects the local machine without files; imports JSON snapshots when files are given
    #[command(after_help = "Examples:
  easy-analyzer processes -t
  easy-analyzer processes cases/processes.json -q powershell
  easy-analyzer processes cases/processes.json -a -S suspicious
  easy-analyzer processes -j reports/processes.json

Input: collects the current host when no files are given; file input must be a process JSON array or a report from this tool.
Multiple snapshots can be provided; file name - means reading JSON from standard input.
The terminal shows the process tree by default; --tree explicitly requests the tree view.
Query/filter only control terminal records and the AI matches scope; JSON/HTML keep full records.")]
    Processes(ProcessArgs),
    /// Network analysis: import PCAP/PCAPNG and parse packets and network sessions
    #[command(after_help = "Examples:
  easy-analyzer pcap cases/capture.pcapng
  easy-analyzer pcap cases/capture.pcap -q '/.env'
  easy-analyzer pcap cases/capture.pcap -a
  easy-analyzer pcap cases/capture.pcap -a -P

Input: one or more PCAP/PCAPNG files; file name - means standard input.
This command analyzes existing capture files offline and does not start live capture.
By default AI only receives packet summaries; --include-payload additionally sends raw packets and payloads.
Query/filter only control terminal records and the AI matches scope; JSON/HTML keep full records.")]
    Pcap(PcapArgs),
    /// AI configuration: create the template, view settings, check the service
    #[command(after_help = "Configuration steps:
  1. easy-analyzer config init
  2. DeepSeek deepseek-flash is the default; fill in api_key in config.toml
  3. easy-analyzer config check
  4. easy-analyzer logs cases/Security.evtx -a

Custom config path: easy-analyzer -c settings.toml config init
Default on all platforms: the config.toml in the current working directory (the directory where the command runs)
Other AI services can change base_url, model, and api_key.
config check sends a small request without project evidence and may incur service charges.")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Args)]
pub struct ProjectMetadata {
    #[arg(long, help = "Project name; defaults to the client organization when creating")]
    pub name: Option<String>,
    #[arg(long)]
    pub client: Option<String>,
    #[arg(long)]
    pub response_start: Option<String>,
    #[arg(long)]
    pub response_end: Option<String>,
    #[arg(long)]
    pub location: Option<String>,
    #[arg(long)]
    pub responders: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
}
#[derive(Subcommand)]
pub enum ProjectCommand {
    /// Create and save an empty project; the client organization is required, and the name defaults to it
    Create {
        path: PathBuf,
        #[command(flatten)]
        info: ProjectMetadata,
    },
    /// Open an existing project without re-parsing or sending AI automatically
    Open {
        path: PathBuf,
        #[command(flatten)]
        common: CommonArgs,
    },
    /// Search recently opened projects on this machine
    List {
        #[arg(long, default_value = "")]
        search: String,
        #[arg(long, default_value = "")]
        client: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        until: Option<String>,
    },
    /// Append evidence to the project and save it back to the project file
    Import {
        path: PathBuf,
        #[command(flatten)]
        args: AnalyzeArgs,
    },
    /// Edit basic information and save it back to the project file
    Edit {
        path: PathBuf,
        #[command(flatten)]
        info: ProjectMetadata,
    },
    /// Write or read evidence notes; an empty string deletes the note
    Note {
        path: PathBuf,
        #[arg(long)]
        record: String,
        #[arg(long)]
        text: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Create the configuration template; fill in the api_key field; returns an error if it already exists
    Init,
    /// Show the configuration path and current settings (key hidden)
    Show,
    /// Request the AI service to check connectivity and structured JSON responses
    Check,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Output {
    Text,
    Json,
    Html,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AiScope {
    All,
    Matches,
    Suspicious,
}

#[derive(Args)]
#[command(group(ArgGroup::new("selection").args(["query", "suspicious"]).multiple(true)))]
pub struct CommonArgs {
    #[arg(long, value_name = "PATH", help = "Open an incident response project and append this evidence")]
    pub project: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "Manually save a project as a .eair file")]
    pub save_project: Option<PathBuf>,
    #[arg(long, help = "New project name; defaults to the client organization")]
    pub project_name: Option<String>,
    #[arg(long, help = "Client organization; required when saving a new project")]
    pub client: Option<String>,
    #[arg(long, help = "Response start time in RFC3339 format, including the time zone")]
    pub response_start: Option<String>,
    #[arg(long, action=ArgAction::Append, value_name="FILE", help="Append TXT/CSV IOC files; repeatable")]
    pub ioc: Vec<PathBuf>,
    #[arg(long, action=ArgAction::Append, value_name="VALUE", help="Add IOCs manually; repeatable")]
    pub ioc_value: Vec<String>,
    #[arg(long, help = "Read the IOC list from standard input; mutually exclusive with evidence stdin")]
    pub ioc_stdin: bool,
    #[arg(
        long,
        requires = "ioc_stdin",
        help = "Stdin IOCs use type,value,note CSV"
    )]
    pub ioc_stdin_csv: bool,
    #[arg(long, help = "Domains match only themselves, without subdomains")]
    pub ioc_exact_domain: bool,

    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "Query and filter",
        help = "Search raw content and parsed fields; case-insensitive"
    )]
    query: Option<String>,
    #[arg(
        long,
        requires = "query",
        help_heading = "Query and filter",
        help = "Match --query as a regular expression"
    )]
    regex: bool,
    #[arg(
        long,
        help_heading = "Query and filter",
        help = "Query with one switch the high, medium, and low severity evidence hit by default rules; intersects when combined with --query"
    )]
    suspicious: bool,
    #[arg(
        long,
        help_heading = "AI analysis",
        help = "Actively send evidence to the configured AI service for analysis"
    )]
    ai: bool,
    #[arg(
        long,
        value_enum,
        default_value = "all",
        requires = "ai",
        requires_if("matches", "selection"),
        value_name = "SCOPE",
        help_heading = "AI analysis",
        help = "Send scope: all=everything, matches=filtered, suspicious=rule evidence"
    )]
    ai_scope: AiScope,
    #[arg(
        long,
        value_enum,
        default_value = "text",
        value_name = "TYPE",
        help_heading = "Report output",
        help = "Primary output format: text=terminal summary, json=full JSON, html=saves a full HTML file"
    )]
    output: Output,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "Report output",
        help = "Primary output file path; when omitted text/json go to the terminal and html auto-saves as report.html (with an alternate name if the file exists)"
    )]
    out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "Report output",
        help = "Additionally save a full JSON report"
    )]
    json_out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "Report output",
        help = "Additionally save a standalone HTML report"
    )]
    html_out: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = 50,
        value_name = "N",
        help_heading = "Report output",
        help = "Terminal caps per section for sources, findings, records, the process tree, diagnostics, and detail references; 0 shows all and does not trim JSON/HTML"
    )]
    limit: usize,
    #[arg(
        long,
        help_heading = "Report output",
        help = "Show finding explanations, rule IDs, confidence, evidence references, and raw records; defaults to the compact view"
    )]
    raw: bool,
    #[arg(
        long,
        default_value_t = 512,
        value_name = "MB",
        help_heading = "Input limits",
        help = "Per-input file size cap (MiB); exceeding it is an error"
    )]
    max_file_mb: u64,
    #[arg(
        long,
        default_value_t = 1_000_000,
        value_name = "N",
        help_heading = "Input limits",
        help = "Record count cap per input; exceeding it is an error instead of silently truncating"
    )]
    max_records: usize,
}

#[derive(Args)]
pub struct LogLoadingArgs {
    #[arg(
        long,
        conflicts_with = "web_format_file",
        value_name = "FORMAT",
        help_heading = "Web log format",
        help = "Apache LogFormat / Nginx log_format definition or format string"
    )]
    web_format: Option<String>,
    #[arg(
        long,
        value_name = "PATH",
        help_heading = "Web log format",
        help = "Read an Apache/Nginx format definition from a file"
    )]
    web_format_file: Option<PathBuf>,
    #[arg(
        long,
        help_heading = "Local collection",
        help = "Load common logs of the current Windows/Linux host; not supported on macOS"
    )]
    auto_load: bool,
    #[arg(
        long,
        default_value = "cases/captured",
        requires = "auto_load",
        value_name = "DIR",
        help_heading = "Local collection",
        help = "When auto-loading on Windows, saves the EVTX exported by wevtutil"
    )]
    evidence_dir: PathBuf,
}

#[derive(Args)]
#[command(group(ArgGroup::new("source").args(["files", "auto_load", "live_processes", "project"]).required(true).multiple(true)))]
pub struct AnalyzeArgs {
    #[arg(
        value_name = "FILES",
        help_heading = "Input files",
        help = "Logs, process snapshots, and PCAP files; multiple files can be mixed, - means standard input"
    )]
    files: Vec<PathBuf>,
    #[arg(long, default_value = "auto", value_name = "TYPE", help_heading = "Input files", value_parser = all_formats(), help = "Input format; auto detects it, and another value applies to all files")]
    format: InputFormat,
    #[command(flatten)]
    loading: LogLoadingArgs,
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long, help_heading = "Local collection", help = "Include the current host's processes in the analysis")]
    live_processes: bool,
    #[arg(long, help_heading = "Report output", help = "Show the process tree in the terminal report")]
    tree: bool,
    #[arg(
        long,
        requires = "ai",
        help_heading = "AI analysis",
        help = "Send raw PCAP packets and payloads; must be combined with --ai"
    )]
    include_payload: bool,
}

#[derive(Args)]
#[command(group(ArgGroup::new("source").args(["files", "auto_load", "project"]).required(true).multiple(true)))]
pub struct LogArgs {
    #[arg(
        value_name = "FILES",
        help_heading = "Input files",
        help = "One or more log files; - means standard input"
    )]
    files: Vec<PathBuf>,
    #[arg(long, default_value = "auto", value_name = "TYPE", help_heading = "Input files", value_parser = log_formats(), help = "Log format; auto detects it, binary login logs with unknown names must specify it")]
    format: InputFormat,
    #[command(flatten)]
    loading: LogLoadingArgs,
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
pub struct ProcessArgs {
    #[arg(
        value_name = "FILES",
        help_heading = "Input files",
        help = "Process JSON snapshots or reports from this tool; collects the local machine when omitted, - means standard input"
    )]
    files: Vec<PathBuf>,
    #[command(flatten)]
    common: CommonArgs,
    #[arg(
        long,
        help_heading = "Report output",
        help = "Show the process tree (enabled by default for this command's terminal output)"
    )]
    tree: bool,
}

#[derive(Args)]
pub struct PcapArgs {
    #[arg(
        required = true,
        value_name = "FILES",
        help_heading = "Input files",
        help = "One or more PCAP/PCAPNG files; - means standard input"
    )]
    files: Vec<PathBuf>,
    #[command(flatten)]
    common: CommonArgs,
    #[arg(
        long,
        requires = "ai",
        help_heading = "AI analysis",
        help = "Also send raw packets and payloads; must be combined with --ai"
    )]
    include_payload: bool,
}

fn all_formats() -> impl TypedValueParser<Value = InputFormat> {
    PossibleValuesParser::new([
        "auto",
        "evtx",
        "utmp",
        "wtmp",
        "btmp",
        "web",
        "text",
        "processes",
        "pcap",
        "pcapng",
    ])
    .map(|value| value.parse().expect("supported format"))
}
fn log_formats() -> impl TypedValueParser<Value = InputFormat> {
    PossibleValuesParser::new(["auto", "evtx", "utmp", "wtmp", "btmp", "web", "text"])
        .map(|value| value.parse().expect("supported log format"))
}

/// Use the same readable layout and English help on every command level.
pub fn command() -> clap::Command {
    fn configure(command: clap::Command) -> clap::Command {
        let has_subcommands = command.get_subcommands().next().is_some();
        command
            .help_template(if has_subcommands {
                COMMAND_HELP_TEMPLATE
            } else {
                HELP_TEMPLATE
            })
            .arg_required_else_help(has_subcommands)
            .disable_help_subcommand(true)
            .disable_help_flag(true)
            .arg(
                Arg::new("help")
                    .short('h')
                    .long("help")
                    .action(ArgAction::Help)
                    .help("Show help and examples for the current command")
                    .help_heading("General options"),
            )
            .mut_args(|arg| {
                let arg = if let Some((_, short)) = SHORT_OPTIONS
                    .iter()
                    .find(|(id, _)| *id == arg.get_id().as_str())
                {
                    arg.short(*short)
                } else {
                    arg
                };
                let order = match arg.get_id().as_str() {
                    "files" => 10,
                    "format" => 11,
                    "web_format" => 20,
                    "web_format_file" => 21,
                    "auto_load" => 30,
                    "evidence_dir" => 31,
                    "live_processes" => 32,
                    "query" => 40,
                    "regex" => 41,
                    "suspicious" => 42,
                    "config" => 50,
                    "ai" => 51,
                    "ai_scope" => 52,
                    "include_payload" => 53,
                    "tree" => 60,
                    "output" => 61,
                    "out" => 62,
                    "json_out" => 63,
                    "html_out" => 64,
                    "limit" => 65,
                    "raw" => 66,
                    "max_file_mb" => 70,
                    "max_records" => 71,
                    _ => 90,
                };
                let arg = if arg.get_id() == "files" {
                    arg.value_name("FILES")
                } else {
                    arg
                };
                arg.display_order(order)
            })
            .mut_subcommands(configure)
    }
    configure(Cli::command()).disable_version_flag(true).arg(
        Arg::new("version")
            .short('V')
            .long("version")
            .action(ArgAction::Version)
            .display_order(91)
            .help("Show version")
            .help_heading("General options"),
    )
}

/// Shared execution options; presentation stays specific to each subcommand.
pub struct AnalysisArgs {
    pub project: Option<PathBuf>,
    pub save_project: Option<PathBuf>,
    pub project_name: Option<String>,
    pub client: Option<String>,
    pub response_start: Option<String>,
    pub ioc: Vec<PathBuf>,
    pub ioc_value: Vec<String>,
    pub ioc_stdin: bool,
    pub ioc_stdin_csv: bool,
    pub ioc_exact_domain: bool,

    pub files: Vec<PathBuf>,
    pub format: InputFormat,
    pub web_format: Option<String>,
    pub web_format_file: Option<PathBuf>,
    pub auto_load: bool,
    pub live_processes: bool,
    pub evidence_dir: PathBuf,
    pub query: Option<String>,
    pub regex: bool,
    pub suspicious: bool,
    pub tree: bool,
    pub ai: bool,
    pub ai_scope: AiScope,
    pub include_payload: bool,
    pub output: Output,
    pub out: Option<PathBuf>,
    pub json_out: Option<PathBuf>,
    pub html_out: Option<PathBuf>,
    pub limit: usize,
    pub raw: bool,
    pub max_file_mb: u64,
    pub max_records: usize,
}
impl AnalysisArgs {
    pub fn new(files: Vec<PathBuf>, a: CommonArgs) -> Self {
        Self {
            project: a.project,
            save_project: a.save_project,
            project_name: a.project_name,
            client: a.client,
            response_start: a.response_start,
            ioc: a.ioc,
            ioc_value: a.ioc_value,
            ioc_stdin: a.ioc_stdin,
            ioc_stdin_csv: a.ioc_stdin_csv,
            ioc_exact_domain: a.ioc_exact_domain,
            files,
            format: InputFormat::Auto,
            web_format: None,
            web_format_file: None,
            auto_load: false,
            live_processes: false,
            evidence_dir: "cases/captured".into(),
            query: a.query,
            regex: a.regex,
            suspicious: a.suspicious,
            tree: false,
            ai: a.ai,
            ai_scope: a.ai_scope,
            include_payload: false,
            output: a.output,
            out: a.out,
            json_out: a.json_out,
            html_out: a.html_out,
            limit: a.limit,
            raw: a.raw,
            max_file_mb: a.max_file_mb,
            max_records: a.max_records,
        }
    }
    fn loading(&mut self, a: LogLoadingArgs) {
        self.web_format = a.web_format;
        self.web_format_file = a.web_format_file;
        self.auto_load = a.auto_load;
        self.evidence_dir = a.evidence_dir;
    }
}
impl From<AnalyzeArgs> for AnalysisArgs {
    fn from(a: AnalyzeArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.format = a.format;
        result.loading(a.loading);
        result.live_processes = a.live_processes;
        result.tree = a.tree;
        result.include_payload = a.include_payload;
        result
    }
}
impl From<LogArgs> for AnalysisArgs {
    fn from(a: LogArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.format = a.format;
        result.loading(a.loading);
        result
    }
}
impl From<ProcessArgs> for AnalysisArgs {
    fn from(a: ProcessArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.tree = a.tree;
        result
    }
}
impl From<PcapArgs> for AnalysisArgs {
    fn from(a: PcapArgs) -> Self {
        let mut result = Self::new(a.files, a.common);
        result.include_payload = a.include_payload;
        result
    }
}
