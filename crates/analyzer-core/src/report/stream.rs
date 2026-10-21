//! Cursor-based report encoding. Implementations own storage, this module owns wire/HTML output.
use crate::{execution::ExecutionContext, model::*};
use anyhow::Result;
use serde::Serialize;
use std::io::Write;

#[derive(Clone, Copy)]
pub enum Section {
    Sources,
    Records,
    Findings,
    Flows,
    Diagnostics,
    AiRuns,
    QueryMatches,
    SelectedRecords,
    SelectedFindings,
}
#[derive(Serialize)]
#[serde(untagged)]
pub enum Item {
    Source(Source),
    Record(Record),
    Finding(Finding),
    Flow(NetworkFlow, i64),
    Diagnostic(Diagnostic),
    AiRun(AiRun, i64),
    QueryId(String),
}
#[derive(Default)]
pub struct Statistics {
    pub sources: usize,
    pub records: usize,
    pub findings: usize,
    pub local_findings: usize,
    pub ai_findings: usize,
    pub flows: usize,
    pub risks: [usize; 5],
    pub errors: usize,
    pub warnings: usize,
    pub referenced: usize,
    pub query_matches: Option<usize>,
    pub priorities: Vec<serde_json::Value>,
    pub ai_runs: Vec<AiRun>,
}
#[derive(Default)]
pub struct Heading {
    pub name: String,
    pub client: String,
    pub response_start: String,
    pub response_end: Option<String>,
}
pub struct Metadata {
    pub schema_version: u32,
    pub generated_at: String,
    pub stats: Statistics,
    pub heading: Option<Heading>,
}
pub enum References<'a> {
    Finding(&'a str),
    Flow(i64),
}
pub trait ReportCursor {
    fn references(
        &self,
        key: References<'_>,
        ctx: &ExecutionContext,
        visitor: &mut dyn FnMut(String) -> Result<bool>,
    ) -> Result<()>;
    fn ai_batches(
        &self,
        run: i64,
        ctx: &ExecutionContext,
        visitor: &mut dyn FnMut(AiBatch) -> Result<bool>,
    ) -> Result<()>;
    fn metadata(&self) -> Result<Metadata>;
    /// Stop without loading later rows when the visitor returns false.
    fn visit(
        &self,
        section: Section,
        ctx: &ExecutionContext,
        visitor: &mut dyn FnMut(Item) -> Result<bool>,
    ) -> Result<()>;
}
fn summary(s: &Statistics) -> serde_json::Value {
    serde_json::json!({"sources":s.sources,"records":s.records,"findings":s.findings,"local_findings":s.local_findings,"ai_findings":s.ai_findings,"findings_by_severity":{"critical":s.risks[4],"high":s.risks[3],"medium":s.risks[2],"low":s.risks[1],"info":s.risks[0]},"risk_summary":format!("Critical {} | High {} | Medium {} | Low {} | Info {}",s.risks[4],s.risks[3],s.risks[2],s.risks[1],s.risks[0]),"unique_referenced_records":s.referenced,"flows":s.flows,"diagnostics":{"errors":s.errors,"warnings":s.warnings},"query_matches":s.query_matches,"priority_findings":s.priorities,"ai_coverage":s.ai_runs.iter().map(|r|serde_json::json!({"model":r.model,"complete":r.is_complete(),"completed_batches":r.completed(),"total_batches":r.batches,"analyzed_records":r.analyzed_records,"selected_records":r.selected()})).collect::<Vec<_>>()})
}
pub fn json(reader: &dyn ReportCursor, out: &mut dyn Write, ctx: &ExecutionContext) -> Result<()> {
    let m = reader.metadata()?;
    write!(out, "{{\"summary\":")?;
    serde_json::to_writer(&mut *out, &summary(&m.stats))?;
    write!(
        out,
        ",\"schema_version\":{},\"generated_at\":",
        m.schema_version
    )?;
    serde_json::to_writer(&mut *out, &m.generated_at)?;
    for (key, section) in [
        ("sources", Section::Sources),
        ("records", Section::Records),
        ("findings", Section::Findings),
        ("flows", Section::Flows),
        ("diagnostics", Section::Diagnostics),
        ("query_matches", Section::QueryMatches),
        ("ai_runs", Section::AiRuns),
    ] {
        write!(out, ",\"{key}\":")?;
        if key == "query_matches" && m.stats.query_matches.is_none() {
            write!(out, "null")?;
            continue;
        }
        write!(out, "[")?;
        let mut first = true;
        reader.visit(section, ctx, &mut |item| {
            ctx.check()?;
            if !first {
                write!(out, ",")?;
            }
            first = false;
            encode_item(reader, item, out, ctx)?;
            Ok(true)
        })?;
        write!(out, "]")?;
    }
    write!(out, "}}")?;
    Ok(())
}
fn object_array<T: Serialize>(
    header: &T,
    field: &str,
    out: &mut dyn Write,
    visit: &mut dyn FnMut(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let mut header = serde_json::to_value(header)?;
    header.as_object_mut().expect("report object").remove(field);
    let encoded = serde_json::to_string(&header)?;
    out.write_all(&encoded.as_bytes()[..encoded.len() - 1])?;
    write!(out, ",\"{field}\":[")?;
    visit(out)?;
    write!(out, "]}}")?;
    Ok(())
}
fn encode_item(
    reader: &dyn ReportCursor,
    item: Item,
    out: &mut dyn Write,
    ctx: &ExecutionContext,
) -> Result<()> {
    match item {
        Item::Finding(f) => object_array(&f, "evidence_ids", out, &mut |out| {
            let mut first = true;
            reader.references(References::Finding(&f.id), ctx, &mut |id| {
                if !first {
                    write!(out, ",")?;
                }
                first = false;
                serde_json::to_writer(&mut *out, &id)?;
                Ok(true)
            })
        }),
        Item::Flow(f, id) => object_array(&f, "evidence_ids", out, &mut |out| {
            let mut first = true;
            reader.references(References::Flow(id), ctx, &mut |id| {
                if !first {
                    write!(out, ",")?;
                }
                first = false;
                serde_json::to_writer(&mut *out, &id)?;
                Ok(true)
            })
        }),
        Item::AiRun(r, id) => object_array(&r, "batch_results", out, &mut |out| {
            let mut first = true;
            reader.ai_batches(id, ctx, &mut |batch| {
                if !first {
                    write!(out, ",")?;
                }
                first = false;
                serde_json::to_writer(&mut *out, &batch)?;
                Ok(true)
            })
        }),
        item => {
            serde_json::to_writer(out, &item)?;
            Ok(())
        }
    }
}
fn reference_links(
    reader: &dyn ReportCursor,
    key: References<'_>,
    out: &mut dyn Write,
    ctx: &ExecutionContext,
) -> Result<()> {
    write!(out, "<div class=\"evidence-links\">")?;
    reader.references(key, ctx, &mut |id| {
        write!(
            out,
            "<a href=\"#evidence-{}\">{}</a>",
            super::escape(&id),
            super::escape(&id)
        )?;
        Ok(true)
    })?;
    write!(out, "</div>")?;
    Ok(())
}

fn links(out: &mut dyn Write, ids: &[String]) -> Result<()> {
    write!(out, "<div class=\"evidence-links\">")?;
    for id in ids {
        write!(
            out,
            "<a href=\"#evidence-{}\">{}</a>",
            super::escape(id),
            super::escape(id)
        )?;
    }
    write!(out, "</div>")?;
    Ok(())
}
pub fn html(reader: &dyn ReportCursor, out: &mut dyn Write, ctx: &ExecutionContext) -> Result<()> {
    let m = reader.metadata()?;
    let script = include_str!("navigation.js");
    let style = include_str!("style.css");
    let script_hash = super::html::script_hash();
    write!(
        out,
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; base-uri 'none'; form-action 'none'\"><title>Easy Analyzer Analysis Report</title><style>{style}</style></head><body><main><header class=\"hero\"><h1>Easy Analyzer · Incident Response Analysis Report</h1>"
    )?;
    if let Some(h) = m.heading {
        write!(
            out,
            "<h2>{}</h2><p>Client: {} · Response start: {} · Response end: {}</p>",
            super::escape(&h.name),
            super::escape(&h.client),
            super::escape(&h.response_start),
            super::escape(h.response_end.as_deref().unwrap_or("Not provided"))
        )?;
    }
    write!(
        out,
        "<p>Sources {} · Records {} · Findings {} · Network sessions {}</p><p>{}</p></header><nav><a href=\"#findings\">Findings</a> · <a href=\"#ai\">AI Analysis</a> · <a href=\"#sources\">Sources</a> · <a href=\"#flows\">Network sessions</a> · <a href=\"#evidence\">All evidence</a> · <a href=\"#diagnostics\">Diagnostics</a></nav><section id=\"findings\"><h2>Findings</h2>",
        m.stats.sources,
        m.stats.records,
        m.stats.findings,
        m.stats.flows,
        super::escape(
            summary(&m.stats)["risk_summary"]
                .as_str()
                .unwrap_or_default()
        )
    )?;
    reader.visit(Section::Findings, ctx, &mut |item| {
        if let Item::Finding(f) = item {
            write!(
                out,
                "<details class=\"panel\"><summary>{} · {} · {}</summary><p>{}</p><p>Confidence {}</p>",
                super::escape(f.severity.label()),
                super::escape(&f.title),
                if f.origin.starts_with("ai:") {
                    "AI"
                } else {
                    "Local analysis"
                },
                super::escape(&f.description),
                f.confidence
            )?;
            reference_links(reader, References::Finding(&f.id), out, ctx)?;
            for r in f.recommendations {
                write!(out, "<p>{}</p>", super::escape(&r))?;
            }
            write!(out, "</details>")?;
        }
        Ok(true)
    })?;
    write!(
        out,
        "</section><section id=\"ai\"><h2>AI Analysis · Batch completion scope and raw replies</h2>"
    )?;
    reader.visit(Section::AiRuns,ctx,&mut|item|{if let Item::AiRun(r,id)=item{write!(out,"<details class=\"panel\"><summary>{} · Completed {} / {} batches · Analyzed {} / {} records</summary><p>{}</p><pre>{}</pre></details>",super::escape(&r.model),r.completed(),r.batches,r.analyzed_records,r.selected(),super::escape(&r.endpoint),super::escape(&serde_json::to_string_pretty(&r)?))?;reader.ai_batches(id,ctx,&mut|batch|{write!(out,"<details class=\"panel\"><summary>Batch {}</summary><pre>{}</pre></details>",batch.index,super::escape(&serde_json::to_string_pretty(&batch)?))?;Ok(true)})?;}Ok(true)})?;
    write!(out, "</section><section id=\"sources\"><h2>Evidence sources</h2>")?;
    reader.visit(Section::Sources,ctx,&mut|item|{if let Item::Source(s)=item{write!(out,"<details class=\"panel\"><summary>{}</summary><p>{} · {} bytes · {}</p><p>Collected at: {}</p><p>SHA256: {}</p></details>",super::escape(&s.path),super::escape(&s.id),s.bytes,super::escape(&s.format),super::escape(&s.collected_at),super::escape(&s.sha256))?;}Ok(true)})?;
    write!(out, "</section><section id=\"flows\"><h2>Offline network sessions</h2>")?;
    reader.visit(Section::Flows,ctx,&mut|item|{if let Item::Flow(f,id)=item{write!(out,"<details class=\"panel\"><summary>{} ↔ {} · {} · {} packets / {} bytes</summary><p>{} — {}</p>",super::escape(&f.endpoint_a),super::escape(&f.endpoint_b),super::escape(&f.protocol),f.packets,f.bytes,super::escape(f.first_seen.as_deref().unwrap_or("Unknown")),super::escape(f.last_seen.as_deref().unwrap_or("Unknown")))?;reference_links(reader,References::Flow(id),out,ctx)?;write!(out,"</details>")?;}Ok(true)})?;
    write!(out, "</section><section id=\"evidence\"><h2>All evidence</h2>")?;
    let mut n = 0;
    reader.visit(Section::Records,ctx,&mut|item|{if let Item::Record(r)=item{if n%100==0{if n>0{write!(out,"</details>")?;}write!(out,"<details class=\"panel\"><summary>Records {}–{}</summary>",n+1,(n+100).min(m.stats.records))?;}write!(out,"<details class=\"record\" id=\"evidence-{}\"><summary>{} · {} · {}</summary><p>ID: {} · Source: {} · Status: {:?}</p><h4>Parsed fields</h4><pre>{}</pre><details><summary>Raw record</summary><pre>{}</pre></details></details>",super::escape(&r.id),super::escape(&r.position),super::escape(r.timestamp.as_deref().unwrap_or("Time unknown")),super::escape(&super::record_summary(&r)),super::escape(&r.id),super::escape(&r.source_id),r.status,super::escape(&serde_json::to_string_pretty(&r.data)?),super::escape(&r.raw))?;n+=1;}Ok(true)})?;
    if n > 0 {
        write!(out, "</details>")?;
    }
    write!(out, "</section><section id=\"query\"><h2>Query matches</h2>")?;
    reader.visit(Section::QueryMatches, ctx, &mut |item| {
        if let Item::QueryId(id) = item {
            links(out, &[id])?;
        }
        Ok(true)
    })?;
    write!(
        out,
        "</section><section id=\"diagnostics\"><h2>Diagnostics and incomplete scope</h2>"
    )?;
    reader.visit(Section::Diagnostics, ctx, &mut |item| {
        if let Item::Diagnostic(d) = item {
            write!(
                out,
                "<details class=\"panel\"><summary>{:?} · {}</summary><p>{} · {}</p></details>",
                d.level,
                super::escape(&d.source),
                super::escape(d.position.as_deref().unwrap_or("")),
                super::escape(&d.message)
            )?;
        }
        Ok(true)
    })?;
    write!(
        out,
        "</section><footer>Easy Analyzer · Schema {} · Generated at {}</footer></main><script>{script}</script></body></html>",
        m.schema_version,
        super::escape(&m.generated_at)
    )?;
    Ok(())
}
pub fn text(
    reader: &dyn ReportCursor,
    out: &mut dyn Write,
    limit: usize,
    raw: bool,
    tree: bool,
    ctx: &ExecutionContext,
) -> Result<()> {
    let m = reader.metadata()?;
    writeln!(
        out,
        "Easy Analyzer · Sources {} · Records {} · Findings {} · Sessions {}",
        m.stats.sources, m.stats.records, m.stats.findings, m.stats.flows
    )?;
    if let Some(h) = m.heading {
        writeln!(
            out,
            "Project: {} · Client: {} · Response start: {}",
            h.name, h.client, h.response_start
        )?;
    }
    if tree {
        let mut processes = Vec::new();
        reader.visit(Section::Records, ctx, &mut |item| {
            if let Item::Record(mut r) = item
                && let RecordData::Process(p) = &mut r.data
            {
                r.raw.clear();
                p.command.clear();
                p.path = None;
                processes.push(r);
            }
            Ok(true)
        })?;
        ctx.check()?;
        writeln!(out, "\nProcess tree")?;
        for line in crate::collect::process_tree(&processes)
            .lines()
            .take(if limit == 0 { usize::MAX } else { limit })
        {
            ctx.check()?;
            writeln!(out, "{line}")?;
        }
    }
    for section in [
        Section::SelectedFindings,
        Section::SelectedRecords,
        Section::Diagnostics,
    ] {
        let mut n = 0;
        reader.visit(section, ctx, &mut |item| {
            if limit > 0 && n >= limit {
                return Ok(false);
            }
            n += 1;
            match item {
                Item::Finding(f) => {
                    writeln!(out, "[{}] {}", f.severity.label(), f.title)?;
                    if raw {
                        writeln!(out, "{}", f.description)?;
                        reader.references(References::Finding(&f.id), ctx, &mut |id| {
                            writeln!(out, "  Evidence: {id}")?;
                            Ok(true)
                        })?;
                    }
                }
                Item::Record(r) => {
                    writeln!(out, "{} · {}", r.position, super::record_summary(&r))?;
                    if raw {
                        writeln!(out, "{}", r.raw)?;
                    }
                }
                Item::Diagnostic(d) => {
                    writeln!(out, "[{:?}] {}: {}", d.level, d.source, d.message)?
                }
                _ => {}
            }
            Ok(true)
        })?;
    }
    Ok(())
}
