use super::{brief, escape, ordered_findings, pre, record_summary};
use crate::{collect::process_tree, model::*};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt::Write};

const STYLE: &str = include_str!("style.css");
const SCRIPT: &str = include_str!("navigation.js");

struct Context<'a> {
    records: HashMap<&'a str, (usize, &'a Record)>,
    sources: HashMap<&'a str, (usize, &'a Source)>,
}

fn severity_class(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}
fn badge(severity: &Severity) -> String {
    format!(
        "<span class=\"badge {}\">{}</span>",
        severity_class(severity),
        severity.label()
    )
}
fn filename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}
fn evidence_link(out: &mut String, id: &str, context: &Context<'_>) {
    if let Some((index, record)) = context.records.get(id) {
        let source = context
            .sources
            .get(record.source_id.as_str())
            .map_or_else(|| "Unknown source".into(), |(n, _)| format!("S{}", n + 1));
        let _ = write!(
            out,
            "<a href=\"#evidence-{index}\">{} · {}</a>",
            source,
            escape(&record.position)
        );
    } else {
        let _ = write!(
            out,
            "<span class=\"muted\">Record not found: {}</span>",
            escape(id)
        );
    }
}
fn links(out: &mut String, ids: &[String], context: &Context<'_>) {
    out.push_str("<div class=\"evidence-links\">");
    for id in ids.iter().take(3) {
        evidence_link(out, id, context);
    }
    out.push_str("</div>");
    if ids.len() > 3 {
        let _ = write!(
            out,
            "<details class=\"subfold\"><summary>Expand all {} evidence references</summary><div class=\"scroll refs evidence-links\">",
            ids.len()
        );
        for id in ids {
            evidence_link(out, id, context);
        }
        out.push_str("</div></details>");
    }
}
fn findings(out: &mut String, items: &[(usize, &Finding)], context: &Context<'_>) {
    if items.is_empty() {
        out.push_str("<div class=\"panel empty\">No findings were produced for the current scope.</div>");
        return;
    }
    for level in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let group: Vec<_> = items.iter().filter(|(_, f)| f.severity == level).collect();
        if group.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "<details class=\"severity-group\"{}><summary>{}<span>{} findings</span><span class=\"muted\">Expand to view</span></summary><div class=\"group-body\">",
            if level.rank() >= 3 { " open" } else { "" },
            badge(&level),
            group.len()
        );
        for (index, finding) in group {
            let _ = write!(
                out,
                "<details class=\"finding\" id=\"finding-{index}\"><summary><span class=\"finding-title\">{}<small>{} · Confidence {:.0}%</small></span><span class=\"count\">{} evidence records</span></summary><div class=\"finding-body\"><div class=\"reader\"><p>{}</p></div>",
                escape(&finding.title),
                if finding.origin.starts_with("ai:") {
                    "AI finding"
                } else {
                    "Local rule"
                },
                finding.confidence * 100.0,
                finding.evidence_ids.len(),
                escape(&finding.description)
            );
            if !finding.recommendations.is_empty() {
                out.push_str("<h4>Recommended actions</h4><ul class=\"actions reader\">");
                for recommendation in &finding.recommendations {
                    let _ = write!(out, "<li>{}</li>", escape(recommendation));
                }
                out.push_str("</ul>");
            }
            out.push_str("<h4>Linked evidence</h4>");
            links(out, &finding.evidence_ids, context);
            let _ = write!(
                out,
                "<small>Rule / model: <code>{}</code> · Finding ID: <code>{}</code></small></div></details>",
                escape(&finding.origin),
                escape(&finding.id)
            );
        }
        out.push_str("</div></details>");
    }
}
fn section(out: &mut String, id: &str, title: &str, subtitle: &str, count: usize) {
    let _ = write!(
        out,
        "<div class=\"section-head\" id=\"{id}\"><div><h2>{title}</h2><p>{subtitle}</p></div><span>{count} items</span></div>"
    );
}
pub(super) fn script_hash() -> String {
    let digest = Sha256::digest(SCRIPT.as_bytes());
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in digest.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        result.push(alphabet[(n >> 18) as usize] as char);
        result.push(alphabet[((n >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 {
            alphabet[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            alphabet[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}

pub fn render(report: &AnalysisReport) -> String {
    let context = Context {
        records: report
            .records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.as_str(), (i, r)))
            .collect(),
        sources: report
            .sources
            .iter()
            .enumerate()
            .map(|(i, s)| (s.id.as_str(), (i, s)))
            .collect(),
    };
    let ordered = ordered_findings(report, false);
    let indexed: Vec<_> = ordered.iter().enumerate().map(|(i, f)| (i, *f)).collect();
    let (ai, local): (Vec<_>, Vec<_>) = indexed
        .iter()
        .copied()
        .partition(|(_, f)| f.origin.starts_with("ai:"));
    let has_ai = !report.ai_runs.is_empty()
        || !ai.is_empty()
        || report.diagnostics.iter().any(|d| d.source == "AI");
    let mut counts = [0; 5];
    for finding in &ordered {
        counts[finding.severity.rank() as usize] += 1;
    }
    let errors = report
        .diagnostics
        .iter()
        .filter(|d| d.level == DiagnosticLevel::Error)
        .count();
    let incomplete = report.ai_runs.iter().any(|run| !run.is_complete());
    let mut out = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{}'; img-src 'none'; base-uri 'none'; form-action 'none'\"><title>Easy Analyzer · Incident Response Report</title><style>{STYLE}</style></head><body><main>",
        script_hash()
    );
    let _ = write!(
        out,
        "<header class=\"hero\"><div><div class=\"eyebrow\">EASY ANALYZER / INCIDENT REVIEW</div><h1>Incident Response Analysis Report</h1><p>Risk-first with traceable evidence. Expand items to see explanations and forensic details.</p></div><div class=\"meta\"><strong>{}</strong>{}<br>Offline report · Local rules {} / AI {}</div></header>",
        if errors > 0 || incomplete {
            "Analysis partially complete"
        } else {
            "Analysis complete"
        },
        escape(&report.generated_at),
        local.len(),
        ai.len()
    );
    out.push_str("<nav class=\"nav\" aria-label=\"Report navigation\"><a href=\"#overview\">Overview</a><a href=\"#local\">Local findings</a>");
    if has_ai {
        out.push_str("<a href=\"#ai\">AI Analysis</a>");
    }
    out.push_str("<a href=\"#sources\">Sources</a><a href=\"#evidence\">Evidence</a><a href=\"#diagnostics\">Diagnostics</a></nav><div id=\"overview\" class=\"stats\">");
    for (value, label, class) in [
        (report.records.len(), "Evidence records", ""),
        (ordered.len(), "Findings", ""),
        (counts[4] + counts[3], "Critical / High findings", "hot"),
        (report.sources.len(), "Evidence sources", ""),
    ] {
        let _ = write!(
            out,
            "<div class=\"stat {class}\"><strong>{value}</strong><span>{label}</span></div>"
        );
    }
    out.push_str("</div>");
    if errors > 0 || incomplete {
        let _ = write!(
            out,
            "<aside class=\"alert\"><strong>Analysis partially incomplete</strong> · {} errors. Completed results are kept in this report; an unfinished scope must not be treated as risk that has been ruled out. <a href=\"#diagnostics\">View specific causes →</a></aside>",
            errors
        );
    }
    out.push_str(
        "<div class=\"split\"><section class=\"panel\"><h3>Priority focus</h3><div class=\"risk-strip\">",
    );
    for level in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let _ = write!(
            out,
            "<span class=\"badge {}\">{} {}</span>",
            severity_class(&level),
            level.label(),
            counts[level.rank() as usize]
        );
    }
    out.push_str("</div>");
    for (index, finding) in indexed.iter().take(5) {
        let _ = write!(
            out,
            "<div class=\"focus-item\">{}<a href=\"#finding-{index}\">{}</a><small>{} evidence records · {}</small></div>",
            badge(&finding.severity),
            escape(&finding.title),
            finding.evidence_ids.len(),
            if finding.origin.starts_with("ai:") {
                "AI"
            } else {
                "Local"
            }
        );
    }
    if indexed.is_empty() {
        out.push_str("<p class=\"empty\">No findings are available for the current scope.</p>");
    }
    if indexed.len() > 5 {
        let _ = write!(
            out,
            "<p class=\"note\">Showing the top 5 / {} by risk; the groups below keep every finding.</p>",
            indexed.len()
        );
    }
    out.push_str("</section><aside class=\"panel\"><h3>Analysis scope</h3><dl class=\"facts\">");
    let _ = write!(
        out,
        "<dt>Input sources</dt><dd>{}</dd><dt>Offline sessions</dt><dd>{}</dd><dt>Query scope</dt><dd>{}</dd><dt>Diagnostics</dt><dd>{} errors / {} warnings</dd><dt>AI status</dt><dd>{}</dd>",
        report.sources.len(),
        report.flows.len(),
        report.query_matches.as_ref().map_or_else(
            || "No query applied".into(),
            |ids| format!("{} matches", ids.len())
        ),
        errors,
        report.diagnostics.len() - errors,
        if incomplete {
            "Partial"
        } else if report.ai_runs.is_empty() {
            if has_ai {
                "No valid run produced"
            } else {
                "Not enabled"
            }
        } else {
            "Complete"
        }
    );
    out.push_str("</dl><p class=\"note\">Finding counts differ from matched record counts; one record may be linked to multiple findings. Rule and AI results are review leads, not confirmed intrusions.</p></aside></div>");
    let mut actions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for finding in &ordered {
        for recommendation in &finding.recommendations {
            if !recommendation.trim().is_empty() && seen.insert(recommendation.as_str()) {
                actions.push((recommendation, finding));
            }
            if actions.len() == 5 {
                break;
            }
        }
        if actions.len() == 5 {
            break;
        }
    }
    if !actions.is_empty() {
        out.push_str("<section class=\"panel\"><h3>Recommended first actions</h3><ol class=\"actions\">");
        for (recommendation, finding) in actions {
            let _ = write!(
                out,
                "<li>{}<small>Basis: {}</small></li>",
                escape(&brief(recommendation)),
                escape(&finding.title)
            );
        }
        out.push_str("</ol><small>Full recommendations can be expanded in each finding.</small></section>");
    }
    section(
        &mut out,
        "local",
        "Local rule analysis",
        "Grouped by risk · Expand an item for details, recommendations, and full references",
        local.len(),
    );
    findings(&mut out, &local, &context);
    if has_ai {
        section(
            &mut out,
            "ai",
            "AI analysis",
            "Findings passing structural and evidence validation · Unverified replies are saved separately",
            ai.len(),
        );
        out.push_str("<section class=\"panel\">");
        for run in &report.ai_runs {
            let _ = write!(
                out,
                "<div class=\"run\"><strong>{}</strong> · <span class=\"muted\">{}</span><p>Completed {}/{} batches · Verified {}/{} records · Raw packets and payloads: {}</p><progress max=\"{}\" value=\"{}\" aria-label=\"AI batch completion progress\"></progress><details class=\"subfold\"><summary>Service info</summary><p>{}</p></details></div>",
                if run.is_complete() {
                    "Analysis complete"
                } else {
                    "Analysis incomplete, partial results retained"
                },
                escape(&run.model),
                run.completed(),
                run.batches,
                run.analyzed_records,
                run.selected(),
                if run.include_payload {
                    "Included"
                } else {
                    "Not included"
                },
                run.batches.max(1),
                run.completed(),
                escape(&run.endpoint)
            );
        }
        if ai.is_empty() {
            out.push_str("<p class=\"empty\">No AI findings are available. Judge this against the completion scope and diagnostics; it does not confirm that all evidence is risk-free.</p>");
        }
        out.push_str("</section>");
        findings(&mut out, &ai, &context);
        for run in &report.ai_runs {
            if run.batch_results.is_empty() {
                continue;
            }
            out.push_str("<section class=\"panel\"><details><summary>Raw replies and diagnostics per AI batch</summary><p class=\"note\">Replies that failed validation are for troubleshooting only and are not conclusions.</p><div class=\"scroll\">");
            for batch in &run.batch_results {
                let _ = write!(
                    out,
                    "<details class=\"subfold\"><summary>Batch {}/{} · {} · {} records · {} requests</summary>",
                    batch.index,
                    run.batches,
                    if batch.error.is_some() {
                        "Failed"
                    } else {
                        "Verified"
                    },
                    batch.evidence_ids.len(),
                    batch.attempts.len()
                );
                for (index, attempt) in batch.attempts.iter().enumerate() {
                    let _ = write!(
                        out,
                        "<details class=\"subfold\"><summary>Reply {} · {}</summary>",
                        index + 1,
                        if attempt.error.is_some() {
                            "Failed validation or request"
                        } else {
                            "Verified"
                        }
                    );
                    if let Some(error) = &attempt.error {
                        let _ = write!(out, "<p class=\"note\">{}</p>", escape(error));
                    }
                    if let Some(response) = &attempt.response {
                        out.push_str(&pre(response));
                    }
                    out.push_str("</details>");
                }
                out.push_str("</details>");
            }
            out.push_str("</div></details></section>");
        }
    }
    section(
        &mut out,
        "sources",
        "Evidence sources",
        "File info, collection time, and full SHA256",
        report.sources.len(),
    );
    out.push_str("<section class=\"panel\"><div class=\"table-wrap\"><table class=\"source-table\"><thead><tr><th>Source</th><th>Format / size</th><th>Forensic metadata</th></tr></thead><tbody>");
    for (i, source) in report.sources.iter().enumerate() {
        let _ = write!(
            out,
            "<tr><td><strong>S{} · {}</strong><small>{}</small></td><td>{}<small>{} bytes</small></td><td><details><summary>Time and hash</summary><small>{}</small><code>{}</code></details></td></tr>",
            i + 1,
            escape(filename(&source.path)),
            escape(&source.path),
            escape(&source.format),
            source.bytes,
            escape(&source.collected_at),
            escape(&source.sha256)
        );
    }
    out.push_str("</tbody></table></div></section>");
    auxiliary(&mut out, report, &context);
    section(
        &mut out,
        "evidence",
        "All evidence",
        "Grouped by source in pages of 100 · Click a reference to locate and expand it",
        report.records.len(),
    );
    evidence(&mut out, report, &context);
    diagnostics(&mut out, report);
    let _ = write!(
        out,
        "<footer class=\"footer\"><span>Easy Analyzer · Schema {} · Full evidence is retained in this file</span><span>Generated at {}</span></footer></main><script>{SCRIPT}</script></body></html>",
        report.schema_version,
        escape(&report.generated_at)
    );
    out
}

fn auxiliary(out: &mut String, report: &AnalysisReport, context: &Context<'_>) {
    if report
        .records
        .iter()
        .any(|r| matches!(r.data, RecordData::Process(_)))
    {
        out.push_str("<section class=\"panel\"><details><summary>Process parent-child relationships</summary>");
        out.push_str(&pre(&process_tree(&report.records)));
        out.push_str("</details></section>");
    }
    if !report.flows.is_empty() {
        let _ = write!(
            out,
            "<section class=\"panel\"><details><summary>Offline network sessions · {}</summary><div class=\"table-wrap\"><table><thead><tr><th>Endpoints</th><th>Protocol</th><th>Packets / bytes</th><th>Time</th></tr></thead><tbody>",
            report.flows.len()
        );
        for flow in &report.flows {
            let _ = write!(
                out,
                "<tr><td>{}<br>{}</td><td>{}</td><td>{} / {}</td><td>{}<br>{}</td></tr>",
                escape(&flow.endpoint_a),
                escape(&flow.endpoint_b),
                escape(&flow.protocol),
                flow.packets,
                flow.bytes,
                escape(flow.first_seen.as_deref().unwrap_or("Unknown")),
                escape(flow.last_seen.as_deref().unwrap_or("Unknown"))
            );
        }
        out.push_str("</tbody></table></div></details></section>");
    }
    if let Some(ids) = &report.query_matches {
        let _ = write!(
            out,
            "<section class=\"panel\"><details><summary>Query matches · {}</summary><div class=\"scroll evidence-links\">",
            ids.len()
        );
        for id in ids {
            evidence_link(out, id, context);
        }
        out.push_str("</div></details></section>");
    }
}
fn evidence(out: &mut String, report: &AnalysisReport, context: &Context<'_>) {
    let mut groups: std::collections::BTreeMap<&str, Vec<(usize, &Record)>> =
        std::collections::BTreeMap::new();
    for (i, record) in report.records.iter().enumerate() {
        groups
            .entry(&record.source_id)
            .or_default()
            .push((i, record));
    }
    let mut ordered_groups = Vec::new();
    for source in &report.sources {
        if let Some(records) = groups.remove(source.id.as_str()) {
            ordered_groups.push((source.id.as_str(), records));
        }
    }
    ordered_groups.extend(groups);
    out.push_str("<section class=\"panel\">");
    if report.records.is_empty() {
        out.push_str("<p class=\"empty\">No evidence records.</p>");
    }
    for (source_id, records) in ordered_groups {
        let label = context.sources.get(source_id).map_or_else(
            || "Unknown source".into(),
            |(i, source)| format!("S{} · {}", i + 1, filename(&source.path)),
        );
        let _ = write!(
            out,
            "<details class=\"subfold\"><summary>{} · {} records</summary><div class=\"scroll\">",
            escape(&label),
            records.len()
        );
        for (page, chunk) in records.chunks(100).enumerate() {
            let _ = write!(
                out,
                "<details class=\"subfold\"><summary>Records {}–{}</summary>",
                page * 100 + 1,
                page * 100 + chunk.len()
            );
            for (index, record) in chunk {
                let status = match record.status {
                    ParseStatus::Parsed => "Parsed",
                    ParseStatus::Unrecognized => "Unrecognized",
                    ParseStatus::Malformed => "Malformed",
                };
                let _ = write!(
                    out,
                    "<details class=\"record\" id=\"evidence-{index}\"><summary><span class=\"record-title\">{}<small class=\"muted\"> · {} · {}</small><br>{}</span></summary><div class=\"record-body\"><p><code>{}</code></p><h4>Parsed fields</h4>",
                    escape(&record.position),
                    escape(record.timestamp.as_deref().unwrap_or("Time unknown")),
                    status,
                    escape(&brief(&record_summary(record))),
                    escape(&record.id)
                );
                out.push_str(&pre(
                    &serde_json::to_string_pretty(&record.data).unwrap_or_default()
                ));
                out.push_str("<details class=\"subfold\"><summary>Raw record (text / JSON / hex)</summary>");
                out.push_str(&pre(&record.raw));
                out.push_str("</details></div></details>");
            }
            out.push_str("</details>");
        }
        out.push_str("</div></details>");
    }
    out.push_str("</section>");
}
fn diagnostics(out: &mut String, report: &AnalysisReport) {
    section(
        out,
        "diagnostics",
        "Analysis diagnostics",
        "Errors first · Duplicate messages merged and counted by source and content",
        report.diagnostics.len(),
    );
    out.push_str("<section class=\"panel\">");
    if report.diagnostics.is_empty() {
        out.push_str("<p class=\"empty\">No parsing, collection, or AI errors.</p>");
    }
    for level in [DiagnosticLevel::Error, DiagnosticLevel::Warning] {
        let mut groups: std::collections::BTreeMap<(&str, &str), Vec<&Diagnostic>> =
            std::collections::BTreeMap::new();
        for diagnostic in report.diagnostics.iter().filter(|d| d.level == level) {
            groups
                .entry((&diagnostic.source, &diagnostic.message))
                .or_default()
                .push(diagnostic);
        }
        if groups.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "<details{}><summary>{} · {} groups</summary><div class=\"scroll\">",
            if level == DiagnosticLevel::Error {
                " open"
            } else {
                ""
            },
            if level == DiagnosticLevel::Error {
                "Errors"
            } else {
                "Warnings"
            },
            groups.len()
        );
        for ((source, message), items) in groups {
            let _ = write!(
                out,
                "<details class=\"subfold {}\"><summary><span class=\"finding-title\">{}<small>{} · {} occurrences</small></span></summary><div class=\"reader\"><p>{}</p></div><details class=\"subfold\"><summary>All locations</summary><ul class=\"row-list scroll refs\">",
                if level == DiagnosticLevel::Error {
                    "diagnostic-error"
                } else {
                    "diagnostic-warning"
                },
                escape(&brief(message)),
                escape(source),
                items.len(),
                escape(message)
            );
            for item in items {
                let _ = write!(
                    out,
                    "<li>{}</li>",
                    escape(item.position.as_deref().unwrap_or("No position specified"))
                );
            }
            out.push_str("</ul></details></details>");
        }
        out.push_str("</div></details>");
    }
    out.push_str("</section>");
}
