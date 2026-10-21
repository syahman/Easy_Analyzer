use crate::{collect::process_tree, model::*};
use std::fmt::Write;

fn ordered_findings(report: &AnalysisReport, apply_query: bool) -> Vec<&Finding> {
    let matches = report.query_matches.as_ref().map(|ids| {
        ids.iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });
    let mut findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            !apply_query
                || matches
                    .as_ref()
                    .is_none_or(|ids| f.evidence_ids.iter().any(|id| ids.contains(id.as_str())))
        })
        .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    findings
}
fn risk_summary(findings: &[&Finding]) -> String {
    let mut counts = [0; 5];
    for f in findings {
        counts[f.severity.rank() as usize] += 1;
    }
    format!(
        "Critical {} | High {} | Medium {} | Low {} | Info {}",
        counts[4], counts[3], counts[2], counts[1], counts[0]
    )
}
fn compact_risk_summary(findings: &[&Finding]) -> String {
    let mut counts = [0; 5];
    for finding in findings {
        counts[finding.severity.rank() as usize] += 1;
    }
    [
        (4, "Critical"),
        (3, "High"),
        (2, "Medium"),
        (1, "Low"),
        (0, "Info"),
    ]
    .into_iter()
    .filter(|(rank, _)| counts[*rank] != 0)
    .map(|(rank, label)| format!("{label} {}", counts[rank]))
    .collect::<Vec<_>>()
    .join("  ·  ")
}

pub fn terminal(report: &AnalysisReport, limit: usize, tree: bool) -> String {
    terminal_with_raw(report, limit, tree, false)
}

/// Add a compact overview while retaining the existing complete evidence schema.
pub fn json(report: &AnalysisReport) -> anyhow::Result<String> {
    let findings = ordered_findings(report, false);
    let mut counts = [0; 5];
    let mut evidence_ids = std::collections::HashSet::new();
    let mut ai_count = 0;
    for finding in &findings {
        counts[finding.severity.rank() as usize] += 1;
        evidence_ids.extend(finding.evidence_ids.iter());
        ai_count += usize::from(finding.origin.starts_with("ai:"));
    }
    let errors = report
        .diagnostics
        .iter()
        .filter(|d| d.level == DiagnosticLevel::Error)
        .count();
    let summary = serde_json::json!({
        "sources": report.sources.len(), "records": report.records.len(),
        "findings": findings.len(), "local_findings": findings.len() - ai_count, "ai_findings": ai_count,
        "findings_by_severity": {"critical":counts[4],"high":counts[3],"medium":counts[2],"low":counts[1],"info":counts[0]},
        "risk_summary": risk_summary(&findings),
        "unique_referenced_records": evidence_ids.len(), "flows": report.flows.len(),
        "diagnostics": {"errors":errors,"warnings":report.diagnostics.len()-errors},
        "query_matches":report.query_matches.as_ref().map(Vec::len),
        "priority_findings":findings.iter().take(5).map(|f| serde_json::json!({"id":f.id,"severity":f.severity,"title":f.title,"origin":f.origin,"evidence_count":f.evidence_ids.len(),"confidence":f.confidence})).collect::<Vec<_>>(),
        "ai_coverage":report.ai_runs.iter().map(|r|serde_json::json!({"model":r.model,"complete":r.is_complete(),"completed_batches":r.completed(),"total_batches":r.batches,"analyzed_records":r.analyzed_records,"selected_records":r.selected()})).collect::<Vec<_>>()
    });
    #[derive(serde::Serialize)]
    struct JsonReport<'a> {
        summary: serde_json::Value,
        #[serde(flatten)]
        report: &'a AnalysisReport,
    }
    Ok(serde_json::to_string_pretty(&JsonReport {
        summary,
        report,
    })?)
}

fn brief(text: &str) -> String {
    let mut result = String::new();
    let mut count = 0;
    let mut gap = false;
    for c in text.chars() {
        if c.is_whitespace() {
            gap = !result.is_empty();
            continue;
        }
        if count == 120 {
            result.push('…');
            break;
        }
        if gap {
            result.push(' ');
            count += 1;
            gap = false;
            if count == 120 {
                result.push('…');
                break;
            }
        }
        result.push(c);
        count += 1;
    }
    result
}
fn log_field<'a>(log: &'a LogData, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        log.fields
            .get(*name)
            .map(String::as_str)
            .or_else(|| {
                let suffix = format!(".{name}");
                let text_suffix = format!(".{name}.#text");
                log.fields.iter().find_map(|(key, value)| {
                    (key.ends_with(&suffix) || key.ends_with(&text_suffix))
                        .then_some(value.as_str())
                })
            })
            .filter(|value| !value.is_empty() && *value != "-")
    })
}
pub fn record_summary(record: &Record) -> String {
    match &record.data {
        RecordData::Log(log) => {
            let fields: &[(&str, &[&str])] = if log.category == "windows_event" {
                &[
                    ("Event", &["event_id", "EventID"]),
                    ("Host", &["host", "Computer"]),
                    ("Account", &["user", "TargetUserName"]),
                    ("Domain", &["TargetDomainName"]),
                    ("Source IP", &["client_ip", "IpAddress", "ClientAddress"]),
                    ("Logon type", &["LogonType"]),
                    ("Actor", &["SubjectUserName"]),
                    (
                        "Process",
                        &["ProcessName", "NewProcessName", "CallerProcessName"],
                    ),
                    ("Service", &["ServiceName"]),
                    ("Service path", &["ServiceFileName", "ImagePath"]),
                    ("Task", &["TaskName"]),
                    ("Share", &["ShareName"]),
                    ("Target file", &["RelativeTargetName"]),
                    ("Target group/SID", &["TargetSid"]),
                    ("Status", &["Status", "FailureReason"]),
                    ("Substatus", &["SubStatus"]),
                    ("Command summary", &["CommandLine", "ScriptBlockText"]),
                ]
            } else if log.category == "web_access" || log.category == "web_error" {
                &[
                    ("Source IP", &["client_ip"]),
                    ("Method", &["method"]),
                    ("Path", &["uri"]),
                    ("Response", &["status"]),
                    ("Account", &["user"]),
                    ("Bytes", &["bytes"]),
                    ("Client", &["user_agent"]),
                    ("Level", &["level"]),
                    ("Error summary", &["message"]),
                ]
            } else {
                &[
                    ("Action", &["action"]),
                    ("Account", &["user"]),
                    ("Source", &["client_ip", "host"]),
                    ("Terminal", &["terminal"]),
                    ("PID", &["pid"]),
                ]
            };
            let values: Vec<_> = fields
                .iter()
                .filter_map(|(label, names)| {
                    log_field(log, names).map(|value| format!("{label}={}", brief(value)))
                })
                .collect();
            if values.is_empty() {
                "No key fields extracted; use -R to view the raw content.".into()
            } else {
                values.join(" · ")
            }
        }
        RecordData::Process(p) => {
            let mut summary = format!(
                "PID={} · Name={} · Parent PID={}",
                p.pid,
                brief(&p.name),
                p.parent_pid
                    .map_or_else(|| "Unknown".into(), |v| v.to_string())
            );
            if let Some(path) = &p.path {
                let _ = write!(summary, " · Path={}", brief(path));
            }
            if let Some(user) = &p.user {
                let _ = write!(summary, " · User={}", brief(user));
            }
            if !p.command.is_empty() {
                let _ = write!(summary, " · Command={}", brief(&p.command.join(" ")));
            }
            summary
        }
        RecordData::Packet(p) => {
            let mut summary = format!(
                "{} · {}:{} → {}:{} · {} bytes",
                brief(&p.protocol),
                p.source.as_deref().unwrap_or("Unknown"),
                p.source_port.map_or_else(|| "-".into(), |v| v.to_string()),
                p.destination.as_deref().unwrap_or("Unknown"),
                p.destination_port
                    .map_or_else(|| "-".into(), |v| v.to_string()),
                p.original_bytes
            );
            for name in ["method", "uri", "host", "query", "protocol"] {
                if let Some(value) = p.application.get(name) {
                    let _ = write!(summary, " · {name}={}", brief(value));
                }
            }
            summary
        }
    }
}

pub fn terminal_with_raw(report: &AnalysisReport, limit: usize, tree: bool, raw: bool) -> String {
    let mut out = String::from("Easy Analyzer · Incident Analysis\n");
    if raw {
        let _ = writeln!(out, "Generated at: {}", report.generated_at);
    }
    let _ = write!(
        out,
        "Sources {}  ·  Records {}",
        report.sources.len(),
        report.records.len()
    );
    if let Some(ids) = &report.query_matches {
        let _ = write!(out, "  ·  Query matches {}", ids.len());
    }
    if !report.flows.is_empty() {
        let _ = write!(out, "  ·  Network sessions {}", report.flows.len());
    }
    if !report.diagnostics.is_empty() {
        let _ = write!(out, "  ·  Diagnostics {}", report.diagnostics.len());
    }
    out.push('\n');
    for run in &report.ai_runs {
        let _ = writeln!(
            out,
            "AI {} · {} · Completed {}/{} batches · Verified {}/{} records",
            if run.is_complete() {
                "Analysis complete"
            } else {
                "Analysis incomplete"
            },
            run.model,
            run.completed(),
            run.batches,
            run.analyzed_records,
            run.selected()
        );
    }
    for (index, s) in
        report
            .sources
            .iter()
            .enumerate()
            .take(if limit == 0 { usize::MAX } else { limit })
    {
        let _ = write!(
            out,
            "  Source {} [{}] {} ({} bytes",
            index + 1,
            s.format,
            s.path,
            s.bytes
        );
        if raw {
            let _ = write!(out, ", SHA256 {}", s.sha256);
        }
        out.push_str(")\n");
    }
    if limit != 0 && report.sources.len() > limit {
        let _ = writeln!(
            out,
            "  Remaining {} sources in HTML/JSON or -n 0.",
            report.sources.len() - limit
        );
    }
    let source_numbers: std::collections::HashMap<_, _> = report
        .sources
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i + 1))
        .collect();
    let records_by_id: std::collections::HashMap<_, _> =
        report.records.iter().map(|r| (r.id.as_str(), r)).collect();
    let location = |record: &Record| {
        format!(
            "Source {}/{}",
            source_numbers
                .get(record.source_id.as_str())
                .map_or_else(|| "?".into(), |i| i.to_string()),
            record.position
        )
    };
    let matches = report.query_matches.as_ref().map(|ids| {
        ids.iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });
    let findings = ordered_findings(report, true);
    let _ = writeln!(out, "\nFindings · {}", findings.len());
    if !findings.is_empty() {
        let _ = writeln!(out, "{}", compact_risk_summary(&findings));
    }
    if findings.is_empty() {
        out.push_str("  No rules matched the current scope.\n");
    }
    let mut record_findings: std::collections::HashMap<&str, Vec<&Finding>> =
        std::collections::HashMap::new();
    let mut omitted_evidence = false;
    let mut previous_severity = None;
    let count_width = findings
        .iter()
        .map(|f| f.evidence_ids.len().to_string().len())
        .max()
        .unwrap_or(1);
    for f in &findings {
        for id in &f.evidence_ids {
            record_findings.entry(id).or_default().push(f);
        }
    }
    let shown_findings = if limit == 0 {
        findings.len()
    } else {
        limit.min(findings.len())
    };
    for f in findings.iter().take(shown_findings) {
        let ids: Vec<_> = f
            .evidence_ids
            .iter()
            .filter(|id| matches.as_ref().is_none_or(|m| m.contains(id.as_str())))
            .collect();
        if !raw {
            if previous_severity != Some(f.severity.rank()) {
                let _ = writeln!(out, "\n{}", f.severity.label());
                previous_severity = Some(f.severity.rank());
            }
            let _ = write!(
                out,
                "  {:>width$} records  {}",
                ids.len(),
                brief(&f.title),
                width = count_width
            );
            if report.sources.len() > 1
                && let Some(record) = ids.first().and_then(|id| records_by_id.get(id.as_str()))
                && let Some(source) = report.sources.iter().find(|s| s.id == record.source_id)
            {
                let _ = write!(
                    out,
                    "  ·  {}",
                    brief(
                        source
                            .path
                            .rsplit(['/', '\\'])
                            .next()
                            .unwrap_or(&source.path)
                    )
                );
            }
            out.push('\n');
            // These findings need their actor/command context to remain actionable.
            if matches!(
                f.origin.as_str(),
                "local:login-failures"
                    | "local:success-after-failures"
                    | "local:process-command"
                    | "local:process-temp-path"
                    | "local:office-shell"
                    | "local:network-web-probe"
            ) || !f.origin.starts_with("local:")
            {
                let _ = writeln!(out, "        {}", brief(&f.description));
                if let Some(recommendation) = f.recommendations.first() {
                    let _ = writeln!(out, "        Recommendation: {}", brief(recommendation));
                }
            }
            continue;
        }
        let shown = if limit == 0 {
            ids.len()
        } else {
            limit.min(ids.len())
        };
        let _ = write!(
            out,
            "  [{}] {} ({}, confidence {:.2})\n    {}\n    Evidence ({} in this scope): {}",
            f.severity.label(),
            f.title,
            f.origin,
            f.confidence,
            f.description,
            ids.len(),
            ids.iter()
                .take(shown)
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if shown < ids.len() {
            omitted_evidence = true;
            let _ = write!(out, " (+{} more)", ids.len() - shown);
        }
        out.push('\n');
        for recommendation in
            f.recommendations
                .iter()
                .take(if limit == 0 { usize::MAX } else { limit })
        {
            let _ = writeln!(out, "    Recommendation: {recommendation}");
        }
    }
    if shown_findings < findings.len() {
        let _ = writeln!(
            out,
            "\n  Showing {shown_findings}/{} findings (risk-first); full content in HTML/JSON or -n 0.",
            findings.len()
        );
    }
    if tree {
        out.push_str("\nProcess tree\n");
        let process_tree = process_tree(&report.records);
        let lines = process_tree.lines().count();
        for line in process_tree
            .lines()
            .take(if limit == 0 { usize::MAX } else { limit })
        {
            let _ = writeln!(out, "{line}");
        }
        if limit != 0 && lines > limit {
            let _ = writeln!(
                out,
                "  Remaining {} process tree lines in HTML/JSON or -n 0.",
                lines - limit
            );
        }
    }
    out.push_str(if raw {
        "\nRecord details\n"
    } else {
        "\nRecord summaries\n"
    });
    let mut selected: Vec<_> = report
        .records
        .iter()
        .filter(|r| {
            matches
                .as_ref()
                .is_none_or(|ids| ids.contains(r.id.as_str()))
        })
        .collect();
    if !record_findings.is_empty() {
        selected.sort_by_key(|r| {
            std::cmp::Reverse(
                record_findings
                    .get(r.id.as_str())
                    .map_or(0, |f| f[0].severity.rank()),
            )
        });
    }
    let n = if limit == 0 {
        selected.len()
    } else {
        limit.min(selected.len())
    };
    for r in selected.iter().take(n) {
        if raw {
            if let Some(found) = record_findings.get(r.id.as_str()) {
                let _ = writeln!(
                    out,
                    "  Risk: {} · Rules: {}",
                    found[0].severity.label(),
                    found
                        .iter()
                        .map(|f| f.origin.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let _ = writeln!(
                out,
                "  {} [{}] {}\n    {}",
                location(r),
                match r.status {
                    ParseStatus::Parsed => "Parsed",
                    ParseStatus::Unrecognized => "Unrecognized",
                    ParseStatus::Malformed => "Malformed",
                },
                r.timestamp.as_deref().unwrap_or("Time unknown"),
                record_summary(r)
            );
            let _ = writeln!(out, "    Evidence ID: {}\n    Raw content:\n{}", r.id, r.raw);
        } else {
            out.push_str("  ");
            if let Some(found) = record_findings.get(r.id.as_str()) {
                let _ = write!(out, "[{}] ", found[0].severity.label());
            }
            match r.status {
                ParseStatus::Parsed => {}
                ParseStatus::Unrecognized => out.push_str("[Unrecognized] "),
                ParseStatus::Malformed => out.push_str("[Malformed] "),
            }
            let _ = writeln!(out, "{}", record_summary(r));
        }
    }
    if selected.len() > n {
        let _ = writeln!(out, "  Showing {n}/{} records.", selected.len());
    }
    let mut diagnostics: std::collections::BTreeMap<(u8, &str, &str), (usize, &Diagnostic)> =
        std::collections::BTreeMap::new();
    for diagnostic in &report.diagnostics {
        let key = (
            u8::from(diagnostic.level != DiagnosticLevel::Error),
            diagnostic.source.as_str(),
            diagnostic.message.as_str(),
        );
        let group = diagnostics.entry(key).or_insert((0, diagnostic));
        group.0 += 1;
    }
    if !diagnostics.is_empty() {
        out.push_str("\nDiagnostics (duplicate messages merged, errors first)\n");
    }
    for (count, d) in diagnostics
        .values()
        .take(if limit == 0 { usize::MAX } else { limit })
    {
        let _ = writeln!(
            out,
            "  [{}] {} {}: {} ({} occurrences)",
            if d.level == DiagnosticLevel::Error {
                "Error"
            } else {
                "Warning"
            },
            d.source,
            d.position.as_deref().unwrap_or(""),
            if raw {
                d.message.clone()
            } else {
                brief(&d.message)
            },
            count
        );
    }
    if limit != 0 && diagnostics.len() > limit {
        let _ = writeln!(
            out,
            "Remaining {} diagnostic groups omitted; full content in HTML/JSON.",
            diagnostics.len() - limit
        );
    }
    if !raw && (!findings.is_empty() || !selected.is_empty()) {
        out.push_str("\nDetails with -R  ·  All summaries with -n 0  ·  Export report with -j path / -H path\n");
    } else if omitted_evidence
        || selected.len() > n
        || (limit != 0 && report.diagnostics.len() > limit)
    {
        out.push_str("\nAll records and references with -n 0  ·  Export report with -j path / -H path\n");
    }
    out.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn pre(s: &str) -> String {
    format!("<pre>{}</pre>", escape(s))
}
mod html;
pub use html::render as html;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_and_ai_text_cannot_inject_html() {
        let mut r = AnalysisReport::default();
        r.warn("<script>bad</script>", None, "<img src=x>");
        let page = html(&r);
        assert!(!page.contains("<script>bad"));
        assert!(page.contains("&lt;script&gt;bad"));
        assert!(page.contains("Content-Security-Policy"));
    }
}

pub mod stream;
