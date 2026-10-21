import type { LogQuery, RecordSummary } from "../types";

export function logTypeLabel(category: string): string {
  return (
    (
      {
        windows_event: "Windows events",
        auth_text: "System / auth text",
        web_access: "Web access",
        web_error: "Web errors",
        application_log: "Application / middleware logs",
        utmp: "Current sessions",
        wtmp: "Login history",
        btmp: "Failed logins",
      } as Record<string, string>
    )[category] || category
  );
}
export function logEventId(record: RecordSummary): string {
  if (record.data.kind !== "log") return "—";
  const fields = record.data.fields.fields;
  return (
    fields.event_id ||
    Object.entries(fields).find(([key]) =>
      /(?:^|\.)EventID(?:\.#text)?$/i.test(key),
    )?.[1] ||
    "—"
  );
}

export function logDetail(record: RecordSummary): string {
  if (record.data.kind !== "log") return "—";
  const fields = record.data.fields.fields;
  return (
    fields.level ||
    (fields.status ? `HTTP ${fields.status}` : logEventId(record))
  );
}
export function localTimeInput(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
export function queryTime(value: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}
export function displayLogTime(value: string | null): string {
  if (!value) return "Unknown";
  const normalized = value.replace(/ UTC$/, "Z").replace(" ", "T");
  if (!/(?:Z|[+-]\d{2}:\d{2})$/i.test(normalized)) return "Unknown";
  const local = localTimeInput(normalized);
  return local ? local.replace("T", " ") : "Unknown";
}
export function displayRecordLogTime(record: RecordSummary): string {
  const time = displayLogTime(record.timestamp);
  if (time !== "Unknown" || record.data.kind !== "log") return time;
  const raw =
    record.timestamp ||
    record.data.fields.fields.time ||
    record.data.fields.fields.timestamp;
  return raw ? `${raw} (raw)` : time;
}
export function logQueryCount(query: LogQuery): number {
  return (
    [
      query.time_offset === null ? null : String(query.time_offset),
      query.log_level,
      query.client_ip,
      query.http_status,
      query.method,
      query.uri,
      query.logger,
      query.time_from,
      query.time_until,
      query.event_ids,
      query.level,
      query.provider,
      query.channel,
      query.host,
    ].filter((v) => v?.trim()).length + query.fields.length
  );
}
export function validateLogQuery(query: LogQuery): void {
  if (
    [query.log_level, query.method, query.http_status].some(
      (v) => v.trim() && !v.split(/[,;\s]+/).filter(Boolean).length,
    )
  )
    throw new Error("List conditions must include at least one valid value");
  if (
    query.http_status.trim() &&
    query.http_status
      .split(/[,;\s]+/)
      .filter(Boolean)
      .some((v) => !/^\d{3}$/.test(v) || Number(v) < 100 || Number(v) > 599)
  )
    throw new Error(
      "HTTP status must be integers from 100 to 599, separated by commas",
    );
  if (
    query.event_ids.trim() &&
    query.event_ids.split(/[,;\s]+/).filter(Boolean).length === 0
  )
    throw new Error("Enter at least one valid event ID");
  if (
    query.time_from &&
    query.time_until &&
    new Date(query.time_until) < new Date(query.time_from)
  )
    throw new Error("End time must not be earlier than start time");
  if (
    query.event_ids.trim() &&
    query.event_ids
      .split(/[,;\s]+/)
      .filter(Boolean)
      .some((v) => !/^\d+$/.test(v) || Number(v) > 65535)
  )
    throw new Error(
      "Event IDs must be integers from 0 to 65535, separated by commas",
    );
  if (query.fields.some((f) => !f.field.trim() || !f.value.trim()))
    throw new Error("Custom conditions need both a field name and a value");
}
