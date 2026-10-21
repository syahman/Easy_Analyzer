export type SessionScreen =
  | "projects"
  | "ioc"
  | "import"
  | "overview"
  | "logs"
  | "processes"
  | "network"
  | "ai"
  | "reports"
  | "settings";
export type Screen = SessionScreen | "commands";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ParseStatus = "parsed" | "unrecognized" | "malformed";
export interface Preferences {
  dark: boolean;
  inspector: boolean;
  inspector_width: number;
  config_path: string;
  window_width: number;
  window_height: number;
}
export interface PublicConfig {
  base_url: string;
  model: string;
  api_key_configured: boolean;
  api_key_env: string;
  timeout_seconds: number;
  batch_bytes: number;
  context_tokens: number | null;
  max_output_tokens: number;
  response_format: string;
  token_parameter: string;
}
export type ConfigInput = Omit<PublicConfig, "api_key_configured"> & {
  key_action: "keep" | "replace" | "clear";
  key_value: string;
};
export interface SelectionInfo {
  id: number;
  count: number;
  label: string;
}
export interface TaskMessage {
  task_id: number;
  session_id: number | null;
  epoch: number;
  revision: number;
  kind: string;
  status: string;
  label: string;
  stage: string | null;
  completed: number | null;
  total: number | null;
  error: string | null;
  saved_paths: string[];
}
export interface Bootstrap {
  project?: ProjectStatus | null;
  filters?: Record<SessionScreen, Filters> | null;
  preferences: Preferences;
  config: PublicConfig;
  config_loaded: boolean;
  config_error: string | null;
  session_id: number | null;
  selection: SelectionInfo;
  busy: TaskMessage | null;
  platform: string;
  elevated: boolean | null;
  elevation_error: string | null;
  live_processes: boolean;
  capture_dir: string;
  inputs: string[];
  qa: boolean;
  qa_ai: boolean;
}
export interface Filters {
  text: string;
  regex: boolean;
  suspicious: boolean;
  source: string | null;
  category: string | null;
  status: ParseStatus | null;
  protocol: string | null;
  log_query: LogQuery;
  order: RecordOrder;
  offset: number;
  limit: number;
  tree: boolean;
  packets: boolean;
  flow: number | null;
  collapsed: string[];
  severity: Severity | null;
  origin: string;
}
export type RecordOrder =
  "original_asc" | "original_desc" | "time_asc" | "time_desc";
export interface LogFieldQuery {
  field: string;
  value: string;
  mode: "contains" | "equals";
}
export interface LogQuery {
  time_offset: number | null;
  log_level: string;
  client_ip: string;
  http_status: string;
  method: string;
  uri: string;
  logger: string;
  time_from: string | null;
  time_until: string | null;
  event_ids: string;
  level: string | null;
  provider: string;
  channel: string;
  host: string;
  fields: LogFieldQuery[];
}
export function defaultLogQuery(): LogQuery {
  return {
    time_offset: null,
    log_level: "",
    client_ip: "",
    http_status: "",
    method: "",
    uri: "",
    logger: "",
    time_from: null,
    time_until: null,
    event_ids: "",
    level: null,
    provider: "",
    channel: "",
    host: "",
    fields: [],
  };
}
export function defaultFilters(): Filters {
  return {
    text: "",
    regex: false,
    suspicious: false,
    source: null,
    category: null,
    status: null,
    protocol: null,
    log_query: defaultLogQuery(),
    order: "original_asc",
    offset: 0,
    limit: 100,
    tree: true,
    packets: false,
    flow: null,
    collapsed: [],
    severity: null,
    origin: "all",
  };
}
export interface Page<T> {
  offset: number;
  total: number;
  items: T[];
}
export interface Source {
  id: string;
  path: string;
  format: string;
  sha256: string;
  bytes: number;
}
export interface LogData {
  category: string;
  fields: Record<string, string>;
}
export interface ProcessData {
  pid: number;
  parent_pid: number | null;
  name: string;
  path: string | null;
  command: string[];
  user: string | null;
  status: string | null;
}
export interface PacketData {
  link_type: number;
  captured_bytes: number;
  original_bytes: number;
  source: string | null;
  destination: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  tcp_flags: number | null;
  application: Record<string, string>;
  payload_hex: string;
}
export type RecordData =
  | { kind: "log"; fields: LogData }
  | { kind: "process"; fields: ProcessData }
  | { kind: "packet"; fields: PacketData };
export interface RecordSummary {
  id: string;
  source_id: string;
  position: string;
  timestamp: string | null;
  status: ParseStatus;
  data: RecordData;
  summary: string;
}
export type EvidenceRecord = RecordSummary & { raw: string };
export interface Finding {
  evidence_count?: number;
  table_preview?: boolean;
  id: string;
  origin: string;
  severity: Severity;
  title: string;
  description: string;
  evidence_ids: string[];
  confidence: number;
  recommendations: string[];
}
export interface Overview {
  sources: number;
  records: number;
  logs: number;
  processes: number;
  packets: number;
  flows: number;
  local_findings: number;
  ai_findings: number;
  suspicious: number;
  risks: number[];
  categories: string[];
  protocols: string[];
  parse_counts: number[];
}
export interface Flow {
  key: number;
  source_id: string;
  endpoint_a: string;
  endpoint_b: string;
  protocol: string;
  packets: number;
  matched_packets: number;
  bytes: number;
  first_seen: string | null;
  last_seen: string | null;
}
export interface ProcessRow {
  record_id: string;
  depth: number;
  context: boolean;
  orphan: boolean;
  cyclic: boolean;
  has_children: boolean;
}
export interface Diagnostic {
  level: "error" | "warning";
  source: string;
  position: string | null;
  message: string;
}
export interface RunSummary {
  index: number;
  model: string;
  endpoint: string;
  batches: number;
  completed: number;
  analyzed: number;
  selected: number;
  include_payload: boolean;
  local_summary: string | null;
}
export interface AiBatch {
  index: number;
  evidence_ids: string[];
  attempts: { response: string | null; error: string | null }[];
  error: string | null;
}
export interface ViewResponse {
  project?: ProjectStatus | null;
  session_id: number;
  revision: number;
  overview: Overview;
  records: Page<RecordSummary> | null;
  findings: Page<Finding> | null;
  flows: Page<Flow> | null;
  process_rows: ProcessRow[];
  sources: Page<Source>;
  record_sources: Record<string, string>;
  diagnostics: Page<Diagnostic>;
  runs: Page<RunSummary>;
  outside: boolean;
  offset: number;
  selection: SelectionInfo;
}
export interface DetailResponse {
  note?: string | null;
  session_id: number;
  record: EvidenceRecord;
  source: Source | null;
  related: Finding[];
}
export interface ViewRequest {
  session_id: number;
  revision: number;
  screen: SessionScreen;
  filters: Filters;
  focus_id: string | null;
  commit_selection: boolean;
  source_offset: number;
  diagnostic_offset: number;
  run_offset: number;
}
export interface ImportRequest {
  paths: string[];
  live: boolean;
  auto_logs: boolean;
  capture_dir: string;
  format: string;
  max_file_bytes: number;
  max_records: number;
  web_format: string | null;
}
export const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};
export const statusLabel: Record<ParseStatus, string> = {
  parsed: "Parsed",
  unrecognized: "Unrecognized",
  malformed: "Malformed",
};
export const sessionScreens: SessionScreen[] = [
  "projects",
  "import",
  "overview",
  "logs",
  "ioc",
  "processes",
  "network",
  "ai",
  "reports",
  "settings",
];
export const screens: Screen[] = [
  "projects",
  "commands",
  ...sessionScreens.filter((s) => s !== "projects"),
];
export const titles: Record<Screen, string> = {
  projects: "Incident response projects",
  commands: "Incident response commands",
  ioc: "IOC matching",
  import: "Import analysis",
  overview: "Analysis overview",
  logs: "Log evidence",
  processes: "Process analysis",
  network: "Network analysis",
  ai: "AI analysis",
  reports: "Reports and sources",
  settings: "Settings",
};
export const evidenceScreen = (
  s: Screen,
): s is "logs" | "processes" | "network" =>
  ["logs", "processes", "network"].includes(s);

export interface AiPreview {
  id: number;
  session_id: number;
  plan: {
    selected_records: number;
    evidence_tokens: number;
    prompt_tokens: number;
    input_budget_tokens: number | null;
    context_tokens: number | null;
    evidence_batches: number;
    summary_planned: boolean;
  };
}

export interface ProjectInfo {
  id: string;
  name: string;
  client: string;
  response_start: string;
  response_end: string | null;
  location: string;
  responders: string;
  description: string;
  created_at: string;
  updated_at: string;
}
export interface ProjectStatus {
  info: ProjectInfo;
  path: string | null;
  dirty: boolean;
  revision: number;
}
export interface ProjectEntry {
  info: ProjectInfo;
  path: string;
  last_opened: string;
  missing: boolean;
}
export interface Indicator {
  id: string;
  kind: "ip" | "domain" | "url";
  value: string;
  note: string;
}
export interface IocInput {
  paths?: string[];
  text?: string;
  csv?: boolean;
  value?: string;
  kind?: Indicator["kind"];
  note?: string;
}
export interface IocImport {
  indicators: Indicator[];
  issues: { line: number; message: string }[];
}
export interface IocHit {
  value: string;
  note: string;
  indicator_id: string;
  record_id: string;
  source_id: string;
  position: string;
  timestamp: string | null;
  field: string;
  matched_value: string;
  byte_offset: number | null;
}
export interface IocView {
  status: {
    indicators: number;
    records: number;
    needs_rescan: boolean;
    run: {
      total_records: number;
      scanned_records: number;
      complete: boolean;
      include_subdomains: boolean;
    } | null;
  };
  indicators: Page<Indicator>;
  hits: Page<IocHit>;
}
