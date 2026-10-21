//! Shared log dimensions and chronological ordering, without changing raw evidence.
use crate::core::{LogData, Record, RecordData};
use anyhow::{Result, bail};
use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use rusqlite::{Connection, functions::FunctionFlags};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordOrder {
    #[default]
    OriginalAsc,
    OriginalDesc,
    TimeAsc,
    TimeDesc,
}
impl RecordOrder {
    pub(crate) fn sql(self) -> &'static str {
        match self {
            Self::OriginalAsc => "r.ordinal ASC",
            Self::OriginalDesc => "r.ordinal DESC",
            Self::TimeAsc => {
                "eair_time(r.timestamp) IS NULL,eair_time(r.timestamp) ASC,r.ordinal ASC"
            }
            Self::TimeDesc => {
                "eair_time(r.timestamp) IS NULL,eair_time(r.timestamp) DESC,r.ordinal DESC"
            }
        }
    }
    pub(crate) fn query_sql(self, offset: Option<i32>) -> String {
        let time = time_sql(offset);
        match self {
            Self::TimeAsc => format!("{time} IS NULL,{time} ASC,r.ordinal ASC"),
            Self::TimeDesc => format!("{time} IS NULL,{time} DESC,r.ordinal DESC"),
            _ => self.sql().into(),
        }
    }
    pub(crate) fn original(self) -> bool {
        matches!(self, Self::OriginalAsc | Self::OriginalDesc)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldMatch {
    #[default]
    Contains,
    Equals,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogFieldQuery {
    pub field: String,
    pub value: String,
    pub mode: FieldMatch,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogQuery {
    pub time_from: Option<String>,
    pub time_until: Option<String>,
    /// Explicit offset in minutes for full-year timestamps without a zone.
    pub time_offset: Option<i32>,
    pub log_level: String,
    pub client_ip: String,
    pub http_status: String,
    pub method: String,
    pub uri: String,
    pub logger: String,
    pub event_ids: String,
    pub level: Option<String>,
    pub provider: String,
    pub channel: String,
    pub host: String,
    pub fields: Vec<LogFieldQuery>,
}

/// Only explicit timezone-bearing evidence times are comparable. EVTX's UTC
/// display form is accepted, while yearless/zone-less text stays unknown.
pub(crate) fn record_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            value.strip_suffix(" UTC").and_then(|v| {
                NaiveDateTime::parse_from_str(v, "%Y-%m-%d %H:%M:%S%.f")
                    .ok()
                    .map(|v| v.and_utc())
            })
        })
}
pub(crate) fn canonical_time(value: &str) -> Option<String> {
    record_time(value).map(|v| v.to_rfc3339_opts(SecondsFormat::Nanos, true))
}
pub(crate) fn time_sql(offset: Option<i32>) -> String {
    offset.map_or_else(
        || "eair_time(r.timestamp)".into(),
        |minutes| {
            // The offset is an integer validated before constructing this expression.
            format!("eair_log_time(r.timestamp,r.data,{minutes})")
        },
    )
}
fn naive_time(value: &str, minutes: i32) -> Option<DateTime<Utc>> {
    let offset = FixedOffset::east_opt(minutes.checked_mul(60)?)?;
    let value = value.replace(',', ".");
    [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S%.f",
        "%d-%b-%Y %H:%M:%S%.f",
        "%a %b %d %H:%M:%S%.f %Y",
    ]
    .iter()
    .find_map(|format| NaiveDateTime::parse_from_str(&value, format).ok())
    .and_then(|time| offset.from_local_datetime(&time).single())
    .map(|time| time.with_timezone(&Utc))
}
fn evidence_time(
    timestamp: Option<&str>,
    data: &RecordData,
    offset: Option<i32>,
) -> Option<DateTime<Utc>> {
    if let Some(time) = timestamp.and_then(record_time) {
        return Some(time);
    }
    let offset = offset?;
    let RecordData::Log(log) = data else {
        return None;
    };
    timestamp
        .into_iter()
        .chain(
            ["time", "timestamp", "@timestamp"]
                .into_iter()
                .filter_map(|key| log.fields.get(key).map(String::as_str)),
        )
        .find_map(|time| record_time(time).or_else(|| naive_time(time, offset)))
}
impl LogQuery {
    pub(crate) fn bounds(&self) -> Result<(Option<String>, Option<String>)> {
        let parse = |value: &Option<String>, label: &str| -> Result<Option<String>> {
            value
                .as_ref()
                .map(|v| {
                    let time = DateTime::parse_from_rfc3339(v)
                        .map_err(|_| anyhow::anyhow!("{label} must include a date, time, and time zone"))?;
                    Ok(time
                        .with_timezone(&Utc)
                        .to_rfc3339_opts(SecondsFormat::Nanos, true))
                })
                .transpose()
        };
        let from = parse(&self.time_from, "Query start time")?;
        let until = parse(&self.time_until, "Query end time")?;
        if let (Some(a), Some(b)) = (&from, &until)
            && a > b
        {
            bail!("The query end time cannot be earlier than the start time");
        }
        Ok((from, until))
    }
    pub(crate) fn prepare(&self) -> Result<PreparedLogQuery> {
        let (from, until) = self.bounds()?;
        if self.time_offset.is_some_and(|v| !(-840..=840).contains(&v)) {
            bail!("The time zone offset for zone-less logs must be between UTC-14:00 and UTC+14:00");
        }
        let mut conditions = Vec::new();
        let ids = self
            .event_ids
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .filter(|v| !v.is_empty())
            .map(|v| {
                let id = v.parse::<u16>().map_err(|_| {
                    anyhow::anyhow!("Event IDs must be integers from 0 to 65535; separate multiple IDs with commas")
                })?;
                Ok(id.to_string())
            })
            .collect::<Result<Vec<_>>>()?;
        if !self.event_ids.trim().is_empty() && ids.is_empty() {
            bail!("Enter at least one valid event ID");
        }
        if !ids.is_empty() {
            conditions.push(("event_id".into(), ids, FieldMatch::Equals));
        }
        if let Some(level) = &self.level {
            if !["0", "1", "2", "3", "4", "5"].contains(&level.as_str()) {
                bail!("Windows event levels must be from 0 to 5");
            }
            conditions.push(("level".into(), vec![level.clone()], FieldMatch::Equals));
        }
        for (field, value) in [
            ("provider", &self.provider),
            ("channel", &self.channel),
            ("host", &self.host),
        ] {
            if !value.trim().is_empty() {
                conditions.push((
                    field.into(),
                    vec![value.trim().to_lowercase()],
                    FieldMatch::Contains,
                ));
            }
        }
        for (field, value) in [
            ("level", &self.log_level),
            ("status", &self.http_status),
            ("method", &self.method),
        ] {
            let values = value
                .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
                .filter(|v| !v.is_empty())
                .map(str::to_lowercase)
                .collect::<Vec<_>>();
            if !value.trim().is_empty() && values.is_empty() {
                bail!("List conditions must contain at least one valid value");
            }
            if field == "status"
                && values
                    .iter()
                    .any(|v| v.parse::<u16>().map_or(true, |n| !(100..=599).contains(&n)))
            {
                bail!("HTTP status codes must be integers from 100 to 599; separate multiple values with commas");
            }
            if !values.is_empty() {
                conditions.push((field.into(), values, FieldMatch::Equals));
            }
        }
        for (field, value, mode) in [
            ("client_ip", &self.client_ip, FieldMatch::Equals),
            ("uri", &self.uri, FieldMatch::Contains),
            ("logger", &self.logger, FieldMatch::Contains),
        ] {
            if !value.trim().is_empty() {
                conditions.push((field.into(), vec![value.trim().to_lowercase()], mode));
            }
        }
        if self.fields.len() > 16 {
            bail!("Custom field conditions are limited to 16");
        }
        for field in &self.fields {
            if field.field.trim().is_empty() || field.value.trim().is_empty() {
                bail!("Custom conditions must specify both a field name and a field value");
            }
            conditions.push((
                field.field.trim().to_lowercase(),
                vec![field.value.trim().to_lowercase()],
                field.mode,
            ));
        }
        Ok(PreparedLogQuery {
            from,
            until,
            offset: self.time_offset,
            conditions,
        })
    }
    pub(crate) fn has_fields(&self) -> bool {
        [
            &self.log_level,
            &self.client_ip,
            &self.http_status,
            &self.method,
            &self.uri,
            &self.logger,
        ]
        .iter()
        .any(|v| !v.trim().is_empty())
            || !self.event_ids.trim().is_empty()
            || self.level.is_some()
            || !self.provider.trim().is_empty()
            || !self.channel.trim().is_empty()
            || !self.host.trim().is_empty()
            || !self.fields.is_empty()
    }
}
pub(crate) struct PreparedLogQuery {
    pub from: Option<String>,
    pub until: Option<String>,
    offset: Option<i32>,
    conditions: Vec<(String, Vec<String>, FieldMatch)>,
}
fn field_key(key: &str, wanted: &str) -> bool {
    let key = key.to_lowercase();
    let plain = key.strip_suffix(".#text").unwrap_or(&key);
    let suffix = |name: &str| plain == name || plain.ends_with(&format!(".{name}"));
    match wanted {
        "event_id" => suffix("event_id") || suffix("eventid"),
        "level" => suffix("level"),
        "provider" => [
            "provider",
            "provider.name",
            "provider.#attributes.name",
            "provider._attributes.name",
        ]
        .iter()
        .any(|v| suffix(v)),
        "channel" => suffix("channel"),
        "host" => suffix("host") || suffix("computer") || suffix("hostname") || suffix("server"),
        "status" => ["status", "status_code", "http_status"]
            .iter()
            .any(|v| suffix(v)),
        "uri" => ["uri", "path", "request_uri", "url"]
            .iter()
            .any(|v| suffix(v)),
        "logger" => suffix("logger") || suffix("class"),
        "user" => ["user", "username", "targetusername", "subjectusername"]
            .iter()
            .any(|v| suffix(v)),
        "client_ip" => ["client_ip", "ipaddress", "remote_host"]
            .iter()
            .any(|v| suffix(v)),
        _ => key == wanted || plain == wanted,
    }
}
impl PreparedLogQuery {
    pub(crate) fn matches_log(&self, log: &LogData) -> bool {
        self.conditions.iter().all(|(field, values, mode)| {
            log.fields.iter().any(|(key, value)| {
                if !field_key(key, field) {
                    return false;
                }
                let value = if field == "level" {
                    value.rsplit(':').next().unwrap_or(value).to_lowercase()
                } else {
                    value.to_lowercase()
                };
                values.iter().any(|wanted| match mode {
                    FieldMatch::Equals => value == *wanted,
                    FieldMatch::Contains => value.contains(wanted),
                })
            })
        })
    }
    pub(crate) fn time(&self, record: &Record) -> Option<DateTime<Utc>> {
        evidence_time(record.timestamp.as_deref(), &record.data, self.offset)
    }
    pub(crate) fn matches(&self, record: &Record) -> bool {
        if self.from.is_some() || self.until.is_some() {
            let Some(time) = self
                .time(record)
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Nanos, true))
            else {
                return false;
            };
            if self.from.as_ref().is_some_and(|v| &time < v)
                || self.until.as_ref().is_some_and(|v| &time > v)
            {
                return false;
            }
        }
        self.conditions.is_empty()
            || matches!(&record.data, RecordData::Log(log) if self.matches_log(log))
    }
}
pub(crate) fn register(connection: &Connection) -> Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8
        | FunctionFlags::SQLITE_DETERMINISTIC
        | FunctionFlags::SQLITE_INNOCUOUS;
    connection.create_scalar_function("eair_time", 1, flags, |ctx| {
        Ok(ctx
            .get::<Option<String>>(0)?
            .as_deref()
            .and_then(canonical_time))
    })?;
    connection.create_scalar_function("eair_log_time", 3, flags, |ctx| {
        let timestamp = ctx.get::<Option<String>>(0)?;
        if let Some(time) = timestamp.as_deref().and_then(canonical_time) {
            return Ok(Some(time));
        }
        let data = crate::compression::text(ctx.get_raw(1))
            .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
        let data: RecordData = serde_json::from_str(&data)
            .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
        Ok(
            evidence_time(timestamp.as_deref(), &data, ctx.get::<Option<i32>>(2)?)
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Nanos, true)),
        )
    })?;
    connection.create_scalar_function("eair_log_match", 2, flags, |ctx| {
        let query = ctx.get_or_create_aux(
            1,
            |value| -> std::result::Result<_, Box<dyn std::error::Error + Send + Sync>> {
                let query: LogQuery = serde_json::from_str(value.as_str()?)?;
                query.prepare().map_err(|e| e.into())
            },
        )?;
        let data = crate::compression::text(ctx.get_raw(0))
            .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
        let data: RecordData = serde_json::from_str(&data)
            .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
        Ok(matches!(data, RecordData::Log(log) if query.matches_log(&log)))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::*, *};
    fn report() -> AnalysisReport {
        let mut report = AnalysisReport::default();
        report.sources.push(Source {
            id: "source".into(),
            path: "synthetic.evtx".into(),
            format: "evtx".into(),
            sha256: "synthetic".into(),
            bytes: 0,
            collected_at: "2026-10-14T00:00:00Z".into(),
        });
        let times = [
            Some("2026-10-14T08:02:00+08:00"),
            None,
            Some("2026-10-14 00:00:00.000000200 UTC"),
            Some("2026-10-14T00:00:00.000000100Z"),
            Some("2026-10-14T00:02:00Z"),
        ];
        for (i, time) in times.into_iter().enumerate() {
            let fields = [
                (
                    if i == 2 {
                        "Event.System.EventID.#text"
                    } else {
                        "event_id"
                    },
                    if i == 4 { "4688" } else { "4624" },
                ),
                ("Event.System.Level", "0"),
                (
                    "Event.System.Provider.#attributes.Name",
                    "Microsoft-Windows-Security-Auditing",
                ),
                ("Event.System.Channel", "Security"),
                ("Event.System.Computer", "Server-A"),
                ("Event.EventData.TargetUserName", "user A"),
                ("long_field", &"compressible field".repeat(100)),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
            report.records.push(Record {
                id: format!("r{i}"),
                source_id: "source".into(),
                position: format!("event:{i}"),
                timestamp: time.map(String::from),
                raw: format!("synthetic event {i} user A"),
                status: ParseStatus::Parsed,
                data: RecordData::Log(LogData {
                    category: "windows_event".into(),
                    fields,
                }),
            });
        }
        report
    }
    fn session(stored: bool) -> AnalysisSession {
        if stored {
            let session = ProjectService::create(ProjectInfo::new("Log query test", "synthetic client")).unwrap();
            session
                .0
                .store
                .as_ref()
                .unwrap()
                .ingest(&report(), &ExecutionContext::default())
                .unwrap();
            session
        } else {
            AnalysisSession::new(report(), vec![])
        }
    }
    #[test]
    fn chronological_order_is_global_precise_stable_and_keeps_unknowns_last() {
        for stored in [false, true] {
            let session = session(stored);
            for (order, expected) in [
                (RecordOrder::OriginalAsc, vec!["r0", "r1", "r2", "r3", "r4"]),
                (
                    RecordOrder::OriginalDesc,
                    vec!["r4", "r3", "r2", "r1", "r0"],
                ),
                (RecordOrder::TimeAsc, vec!["r3", "r2", "r0", "r4", "r1"]),
                (RecordOrder::TimeDesc, vec!["r4", "r0", "r2", "r3", "r1"]),
            ] {
                let selected = session
                    .select_records(
                        &RecordFilter {
                            kind: RecordKind::Log,
                            order,
                            ..Default::default()
                        },
                        &ExecutionContext::default(),
                    )
                    .unwrap();
                let first = session.page_metadata(Some(&selected), 0, 2).unwrap();
                let next = session.page_metadata(Some(&selected), 2, 3).unwrap();
                assert_eq!(first.total, 5);
                let ids = first
                    .items
                    .iter()
                    .chain(&next.items)
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(ids, expected, "{stored:?} {order:?}");
                for (index, id) in expected.iter().enumerate() {
                    assert_eq!(
                        session.locate_record(Some(&selected), id).unwrap(),
                        Some(index)
                    );
                }
                assert_eq!(selected.try_ids().unwrap(), &expected);
            }
        }
    }
    #[test]
    fn combined_log_dimensions_match_compressed_and_memory_evidence_equally() {
        for stored in [false, true] {
            let session = session(stored);
            let filter = RecordFilter {
                kind: RecordKind::Log,
                order: RecordOrder::TimeAsc,
                log_query: LogQuery {
                    time_from: Some("2026-10-14T08:00:00+08:00".into()),
                    time_until: Some("2026-10-14T00:02:00Z".into()),
                    event_ids: "4624,4625".into(),
                    level: Some("0".into()),
                    provider: "security-auditing".into(),
                    channel: "security".into(),
                    host: "SERVER".into(),
                    fields: vec![LogFieldQuery {
                        field: "USER".into(),
                        value: "user A".into(),
                        mode: FieldMatch::Equals,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            };
            let selected = session
                .select_records(&filter, &ExecutionContext::default())
                .unwrap();
            assert_eq!(selected.try_ids().unwrap(), ["r3", "r2", "r0"]);
            assert_eq!(
                session.record("r0").unwrap().unwrap().timestamp.as_deref(),
                Some("2026-10-14T08:02:00+08:00")
            );
            let mut exact = filter.clone();
            exact.log_query.time_from = Some("2026-10-14T00:00:00.000000200Z".into());
            exact.log_query.time_until = exact.log_query.time_from.clone();
            assert_eq!(
                session
                    .select_records(&exact, &ExecutionContext::default())
                    .unwrap()
                    .try_ids()
                    .unwrap(),
                ["r2"]
            );
            exact.log_query.fields[0].value = "missing user".into();
            assert!(
                session
                    .select_records(&exact, &ExecutionContext::default())
                    .unwrap()
                    .is_empty()
            );
            exact.log_query.time_until = Some("2026-10-13T00:00:00Z".into());
            assert!(
                session
                    .select_records(&exact, &ExecutionContext::default())
                    .is_err()
            );
        }
    }
    #[test]
    fn middleware_dimensions_time_assumptions_and_order_match_both_stores() {
        let dir = tempfile::tempdir().unwrap();
        let samples = [
            (
                "nginx-access.log",
                r#"192.0.2.10 - - [14/Oct/2026:09:00:00 +0800] "POST /api/login HTTP/1.1" 500 20"#,
            ),
            (
                "nginx-error.log",
                r#"2026/10/14 09:00:01 [error] 123#0: failure, client: 192.0.2.10, request: "POST /api/login HTTP/1.1""#,
            ),
            (
                "catalina.log",
                "14-Oct-2026 09:00:02.123 SEVERE [main] org.apache.catalina.startup.Catalina.start Startup failure\n\tat org.example.App.main(App.java:12)",
            ),
            (
                "spring.log",
                "2026-10-14T09:00:03.456+08:00 ERROR 123 --- [main] org.example.App : Failed",
            ),
            (
                "apache-error.log",
                "[Wed Oct 14 09:00:04.123456 2026] [core:error] [pid 123] failure",
            ),
        ];
        let mut report = AnalysisReport::default();
        for (name, text) in samples {
            let path = dir.path().join(name);
            std::fs::write(&path, text).unwrap();
            let parsed = crate::core::ingest_file(&path, &IngestOptions::default()).unwrap();
            report.sources.extend(parsed.sources);
            report.records.extend(parsed.records);
        }
        let ids = report
            .records
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(report.records[2].timestamp, None);
        assert_eq!(
            report.records[3].raw,
            "\tat org.example.App.main(App.java:12)"
        );
        assert_eq!(report.records[3].status, ParseStatus::Unrecognized);
        for stored in [false, true] {
            let session = if stored {
                let session =
                    ProjectService::create(ProjectInfo::new("Middleware query", "synthetic client")).unwrap();
                session
                    .0
                    .store
                    .as_ref()
                    .unwrap()
                    .ingest(&report, &ExecutionContext::default())
                    .unwrap();
                session
            } else {
                AnalysisSession::new(report.clone(), vec![])
            };
            let mut filter = RecordFilter {
                kind: RecordKind::Log,
                order: RecordOrder::TimeAsc,
                log_query: LogQuery {
                    time_from: Some("2026-10-14T01:00:00Z".into()),
                    time_until: Some("2026-10-14T01:00:04.123456Z".into()),
                    ..Default::default()
                },
                ..Default::default()
            };
            let select = |filter: &RecordFilter| {
                session
                    .select_records(filter, &ExecutionContext::default())
                    .unwrap()
                    .try_ids()
                    .unwrap()
                    .to_vec()
            };
            assert_eq!(select(&filter), [ids[0].clone(), ids[4].clone()]);
            filter.log_query.time_offset = Some(480);
            assert_eq!(
                select(&filter),
                [
                    ids[0].clone(),
                    ids[1].clone(),
                    ids[2].clone(),
                    ids[4].clone(),
                    ids[5].clone()
                ]
            );
            filter.order = RecordOrder::TimeDesc;
            assert_eq!(
                select(&filter),
                [
                    ids[5].clone(),
                    ids[4].clone(),
                    ids[2].clone(),
                    ids[1].clone(),
                    ids[0].clone()
                ]
            );
            filter.log_query.log_level = "ERROR, SEVERE".into();
            assert_eq!(
                select(&filter),
                [
                    ids[5].clone(),
                    ids[4].clone(),
                    ids[2].clone(),
                    ids[1].clone()
                ]
            );
            filter.log_query.logger = "APACHE.CATALINA".into();
            assert_eq!(select(&filter), [ids[2].clone()]);
            filter.log_query.logger.clear();
            filter.log_query.log_level.clear();
            filter.log_query.client_ip = "192.0.2.10".into();
            filter.log_query.method = "post".into();
            filter.log_query.uri = "/api/".into();
            assert_eq!(select(&filter), [ids[1].clone(), ids[0].clone()]);
            filter.log_query.http_status = "403,500".into();
            assert_eq!(select(&filter), [ids[0].clone()]);
            filter.log_query.http_status = "999".into();
            assert!(
                session
                    .select_records(&filter, &ExecutionContext::default())
                    .is_err()
            );
            filter.log_query.http_status.clear();
            filter.log_query.time_offset = Some(841);
            assert!(
                session
                    .select_records(&filter, &ExecutionContext::default())
                    .is_err()
            );
        }
        assert!(naive_time("Oct 14 09:00:00", 480).is_none());
    }
    #[test]
    fn reverse_lazy_selection_stays_frozen_and_query_settings_survive_reopening() {
        let session = session(true);
        let filter = RecordFilter {
            kind: RecordKind::Log,
            order: RecordOrder::OriginalDesc,
            ..Default::default()
        };
        let selected = session
            .select_records(&filter, &ExecutionContext::default())
            .unwrap();
        assert!(selected.stored.as_ref().unwrap().lazy.is_some());
        let mut appended = report();
        appended.records = vec![Record {
            id: "new".into(),
            ..appended.records[0].clone()
        }];
        session
            .0
            .store
            .as_ref()
            .unwrap()
            .ingest(&appended, &ExecutionContext::default())
            .unwrap();
        assert_eq!(
            session.page(Some(&selected), 0, 1).unwrap().items[0].id,
            "r4"
        );
        assert_eq!(selected.len(), 5);
        let query = LogQuery {
            event_ids: "4624".into(),
            ..Default::default()
        };
        let saved = serde_json::json!({"logs":{"order":"time_desc","log_query":query}});
        ProjectService::save_view_state(&session, &saved).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("query.eair");
        ProjectService::save(
            &session,
            &path,
            std::path::Path::new("config"),
            false,
            &ExecutionContext::default(),
        )
        .unwrap();
        let reopened = ProjectService::open(&path, &ExecutionContext::default()).unwrap();
        assert_eq!(ProjectService::view_state(&reopened).unwrap(), Some(saved));
    }
}
