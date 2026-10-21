use crate::compression::{encode, row_text};
use crate::{core::*, *};
use anyhow::{Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

pub(crate) const APP_ID: i32 = 0x45414952;
pub(crate) const VERSION: i32 = 2;
#[derive(Debug)]
pub(crate) struct Database {
    pub connection: Mutex<Connection>,
    pub _directory: tempfile::TempDir,
    pub overview_cache: Mutex<Option<(u64, SessionOverview)>>,
    pub ai_summary_cache: Mutex<Option<(u64, std::collections::BTreeMap<String, String>)>>,
    pub diagnostic_count_cache: Mutex<Option<(i64, usize)>>,
    pub diagnostic_level_cache: Mutex<Option<(i64, (usize, usize))>>,
    pub read_cache: Mutex<crate::pagination::ReadCache>,
    pub process_cache: Mutex<Option<(i64, Arc<core::process::ProcessForest>)>>,
}
pub(crate) fn json<T: Serialize>(v: &T) -> Result<String> {
    Ok(serde_json::to_string(v)?)
}
pub(crate) fn packed_json<T: Serialize>(v: &T) -> Result<rusqlite::types::Value> {
    encode(json(v)?)
}
pub(crate) fn decode<T: DeserializeOwned>(v: String) -> Result<T> {
    Ok(serde_json::from_str(&v)?)
}
pub(crate) fn page_limit(limit: usize) -> Result<()> {
    if !(1..=1000).contains(&limit) {
        bail!("Page size must be between 1 and 1000");
    }
    Ok(())
}
pub(crate) fn scalar(c: &Connection, sql: &str) -> Result<usize> {
    Ok(c.query_row(sql, [], |r| r.get::<_, i64>(0))? as usize)
}
pub(crate) fn with_progress<T>(
    c: &Connection,
    ctx: &ExecutionContext,
    run: impl FnOnce() -> Result<T>,
) -> Result<T> {
    ctx.check()?;
    let token = ctx.cancellation.clone();
    c.progress_handler(2048, Some(move || token.is_cancelled()))?;
    let result = run();
    c.progress_handler(0, None::<fn() -> bool>)?;
    ctx.check()?;
    result
}
pub(crate) fn values<T: DeserializeOwned>(
    c: &Connection,
    sql: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<T>> {
    let mut stmt = c.prepare(sql)?;
    let mut rows = stmt.query(p)?;
    let mut out = vec![];
    while let Some(r) = rows.next()? {
        out.push(decode(row_text(r, 0)?)?);
    }
    Ok(out)
}
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE sources(id TEXT PRIMARY KEY,path TEXT NOT NULL,json TEXT NOT NULL);
CREATE TABLE records(ordinal INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,source_id TEXT NOT NULL REFERENCES sources(id),timestamp TEXT,status TEXT NOT NULL,kind TEXT NOT NULL,category TEXT NOT NULL,protocol TEXT NOT NULL,raw TEXT NOT NULL,data TEXT NOT NULL,preview TEXT NOT NULL,summary TEXT NOT NULL);
CREATE INDEX record_source ON records(source_id,ordinal);
CREATE INDEX record_kind ON records(kind,ordinal);
CREATE INDEX record_status ON records(status,ordinal);
CREATE INDEX record_category ON records(category,ordinal);
CREATE INDEX record_protocol ON records(protocol,ordinal);
CREATE TABLE findings(ordinal INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,origin TEXT NOT NULL,severity INTEGER NOT NULL,json TEXT NOT NULL);
CREATE INDEX finding_order ON findings(severity DESC,ordinal);
CREATE TABLE finding_refs(finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,record_id TEXT NOT NULL REFERENCES records(id),ordinal INTEGER NOT NULL,PRIMARY KEY(finding_id,record_id));
CREATE INDEX finding_record ON finding_refs(record_id,finding_id);
CREATE TABLE flows(ordinal INTEGER PRIMARY KEY,source_id TEXT NOT NULL REFERENCES sources(id),json TEXT NOT NULL);
CREATE TABLE flow_refs(flow_id INTEGER NOT NULL REFERENCES flows(ordinal) ON DELETE CASCADE,record_id TEXT NOT NULL REFERENCES records(id),ordinal INTEGER NOT NULL,PRIMARY KEY(flow_id,record_id));
CREATE INDEX flow_record ON flow_refs(record_id,flow_id);
CREATE TABLE diagnostics(ordinal INTEGER PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ai_runs(ordinal INTEGER PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ai_batches(run_id INTEGER NOT NULL REFERENCES ai_runs(ordinal),ordinal INTEGER NOT NULL,json TEXT NOT NULL,PRIMARY KEY(run_id,ordinal));
CREATE TABLE notes(record_id TEXT PRIMARY KEY REFERENCES records(id),text TEXT NOT NULL);
CREATE TABLE view_state(key TEXT PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE protected(path TEXT PRIMARY KEY);
CREATE TABLE iocs(id TEXT PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ioc_origins(ioc_id TEXT NOT NULL REFERENCES iocs(id),origin TEXT NOT NULL,PRIMARY KEY(ioc_id,origin));
CREATE TABLE ioc_runs(id INTEGER PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE ioc_matches(ordinal INTEGER PRIMARY KEY,run_id INTEGER NOT NULL REFERENCES ioc_runs(id),ioc_id TEXT NOT NULL REFERENCES iocs(id),record_id TEXT NOT NULL REFERENCES records(id),json TEXT NOT NULL);
CREATE INDEX ioc_match_record ON ioc_matches(record_id);
CREATE TABLE selections(id INTEGER PRIMARY KEY,count INTEGER NOT NULL);
CREATE TABLE selection_refs(selection_id INTEGER NOT NULL REFERENCES selections(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,record_id TEXT NOT NULL REFERENCES records(id),PRIMARY KEY(selection_id,ordinal),UNIQUE(selection_id,record_id));
CREATE INDEX selection_record ON selection_refs(selection_id,record_id);
"#;
impl Database {
    pub fn new() -> Result<Arc<Self>> {
        let directory = tempfile::tempdir()?;
        let c = Connection::open(directory.path().join("working.sqlite"))?;
        Self::configure(&c)?;
        c.pragma_update(None, "application_id", APP_ID)?;
        c.pragma_update(None, "user_version", VERSION)?;
        c.execute_batch(SCHEMA)?;
        c.execute(
            "INSERT INTO metadata VALUES('report',?1)",
            [json(&AnalysisReport::default())?],
        )?;
        Ok(Self::from_connection(c, directory))
    }
    pub fn from_connection(c: Connection, directory: tempfile::TempDir) -> Arc<Self> {
        Arc::new(Self {
            connection: Mutex::new(c),
            _directory: directory,
            overview_cache: Mutex::default(),
            ai_summary_cache: Mutex::default(),
            diagnostic_count_cache: Mutex::default(),
            diagnostic_level_cache: Mutex::default(),
            process_cache: Mutex::default(),
            read_cache: Mutex::default(),
        })
    }
    pub fn configure(c: &Connection) -> Result<()> {
        crate::compression::register(c)?;
        crate::log_query::register(c)?;
        c.execute_batch("PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;PRAGMA temp_store=FILE;PRAGMA cache_size=-8192;PRAGMA journal_mode=DELETE;")?;
        c.busy_timeout(std::time::Duration::from_secs(2))?;
        Ok(())
    }
    pub fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!("The project database is unavailable"))
    }
    pub fn cached_count(
        &self,
        c: &Connection,
        sql: &str,
        args: &[rusqlite::types::Value],
    ) -> Result<usize> {
        let revision = crate::project::content_revision(c)?;
        let key = format!("{sql}:{args:?}");
        let mut cache = self
            .read_cache
            .lock()
            .map_err(|_| anyhow!("The pagination cache is unavailable"))?;
        cache.update(revision);
        if let Some(count) = cache.counts.get(&key) {
            return Ok(*count);
        }
        let count = c.query_row(sql, rusqlite::params_from_iter(args), |r| {
            r.get::<_, i64>(0)
        })? as usize;
        if cache.counts.len() >= 512 {
            cache.counts.clear();
        }
        cache.counts.insert(key, count);
        Ok(count)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn page_boundary(
        &self,
        c: &Connection,
        table: &str,
        condition: &str,
        args: &[rusqlite::types::Value],
        key: &str,
        descending: bool,
        total: usize,
        offset: usize,
    ) -> Result<Option<i64>> {
        let revision = crate::project::content_revision(c)?;
        let cache_key = format!("{table}:{condition}:{args:?}:{key}:{descending}:{total}");
        let mut cache = self
            .read_cache
            .lock()
            .map_err(|_| anyhow!("The pagination cache is unavailable"))?;
        cache.update(revision);
        if cache.pagers.len() >= 32 && !cache.pagers.contains_key(&cache_key) {
            cache.pagers.clear();
        }
        cache
            .pagers
            .entry(cache_key)
            .or_default()
            .boundary(c, table, condition, args, key, descending, total, offset)
    }
    pub fn set<T: Serialize>(c: &Connection, key: &str, value: &T) -> Result<()> {
        c.execute("INSERT INTO metadata VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,json(value)?])?;
        Ok(())
    }
    pub fn get<T: DeserializeOwned>(c: &Connection, key: &str) -> Result<T> {
        decode(
            c.query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                r.get(0)
            })?,
        )
    }
    pub fn protect(&self, paths: &[PathBuf]) -> Result<()> {
        let c = self.lock()?;
        for p in paths {
            c.execute(
                "INSERT OR IGNORE INTO protected VALUES(?1)",
                [p.to_string_lossy().as_ref()],
            )?;
        }
        Ok(())
    }
    pub fn protected(&self) -> Result<Vec<PathBuf>> {
        let c = self.lock()?;
        let mut s = c.prepare("SELECT path FROM protected UNION SELECT path FROM sources WHERE path NOT LIKE '%://%' AND path<>'stdin'")?;
        Ok(s.query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(PathBuf::from)
            .collect())
    }
    pub fn record(c: &Connection, id: &str) -> Result<Option<Record>> {
        let row = c.query_row("SELECT id,source_id,timestamp,status,raw,data,ordinal,json_extract(summary,'$.position') FROM records WHERE id=?1", [id], Self::record_row).optional()?;
        Ok(row.map(|r| r.1))
    }
    pub fn record_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, Record)> {
        let status: String = r.get(3)?;
        let data = row_text(r, 5)?;
        let parse = |e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        };
        Ok((
            r.get(6)?,
            Record {
                id: r.get(0)?,
                source_id: r.get(1)?,
                timestamp: r.get(2)?,
                status: serde_json::from_str(&status).map_err(parse)?,
                raw: row_text(r, 4)?,
                data: serde_json::from_str(&data).map_err(parse)?,
                position: r.get(7)?,
            },
        ))
    }
    pub fn records_after(&self, after: i64, limit: usize) -> Result<Vec<(i64, Record)>> {
        let c = self.lock()?;
        let mut stmt = c.prepare("SELECT id,source_id,timestamp,status,raw,data,ordinal,json_extract(summary,'$.position') FROM records WHERE ordinal>?1 ORDER BY ordinal LIMIT ?2")?;
        Ok(stmt
            .query_map(params![after, limit as i64], Self::record_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn insert_finding(c: &Connection, finding: &Finding) -> Result<usize> {
        let mut header = finding.clone();
        header.evidence_ids.clear();
        let mut changed=c.execute("INSERT INTO findings(id,origin,severity,json) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET origin=excluded.origin,severity=excluded.severity,json=excluded.json WHERE findings.json<>excluded.json", params![finding.id,finding.origin,finding.severity.rank(),json(&header)?])?;
        for (i, id) in finding.evidence_ids.iter().enumerate() {
            changed += c.execute(
                "INSERT OR IGNORE INTO finding_refs VALUES(?1,?2,?3)",
                params![finding.id, id, i as i64],
            )?;
        }
        Ok(changed)
    }
    pub fn finding(c: &Connection, data: String) -> Result<Finding> {
        let mut f: Finding = decode(data)?;
        let mut s =
            c.prepare("SELECT record_id FROM finding_refs WHERE finding_id=?1 ORDER BY ordinal")?;
        f.evidence_ids = s
            .query_map([&f.id], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(f)
    }
    pub fn ai(c: &Connection) -> Result<Vec<AiRun>> {
        let mut runs: Vec<AiRun> = values(c, "SELECT json FROM ai_runs ORDER BY ordinal", [])?;
        for (i, run) in runs.iter_mut().enumerate() {
            run.batch_results = values(
                c,
                "SELECT json FROM ai_batches WHERE run_id=?1 ORDER BY ordinal",
                [i as i64 + 1],
            )?;
        }
        Ok(runs)
    }
    pub fn insert_ai(c: &Connection, run: &AiRun) -> Result<()> {
        let mut header = run.clone();
        header.batch_results.clear();
        c.execute("INSERT INTO ai_runs(json) VALUES(?1)", [json(&header)?])?;
        let id = c.last_insert_rowid();
        for (i, b) in run.batch_results.iter().enumerate() {
            c.execute(
                "INSERT INTO ai_batches VALUES(?1,?2,?3)",
                params![id, i as i64, encode(json(b)?)?],
            )?;
        }
        Ok(())
    }
    pub fn ingest(&self, report: &AnalysisReport, ctx: &ExecutionContext) -> Result<usize> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut added = 0;
        let mut new_sources = 0;
        let mut changed_findings = 0;
        let mut changed_sources = std::collections::HashSet::new();
        for source in &report.sources {
            new_sources += tx.execute(
                "INSERT OR IGNORE INTO sources VALUES(?1,?2,?3)",
                params![source.id, source.path, json(source)?],
            )?;
        }
        let mut insert=tx.prepare("INSERT OR IGNORE INTO records(id,source_id,timestamp,status,kind,category,protocol,raw,data,preview,summary) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")?;
        for (i, r) in report.records.iter().enumerate() {
            // A cancelled import may already contain validated, useful evidence. Persist it.
            if !ctx.cancellation.is_cancelled() {
                ctx.tick(
                    core::execution::Stage::Finalizing,
                    None,
                    i,
                    Some(report.records.len()),
                )?;
            }
            let (kind, cat, proto) = match &r.data {
                RecordData::Log(l) => ("log", l.category.as_str(), ""),
                RecordData::Process(_) => ("process", "", ""),
                RecordData::Packet(p) => ("packet", "", p.protocol.as_str()),
            };
            let mut preview = r.data.clone();
            if let RecordData::Packet(p) = &mut preview {
                p.payload_hex.clear();
            }
            let data = json(&r.data)?;
            let preview = json(&preview)?;
            let preview = if preview == data {
                rusqlite::types::Value::Text(String::new())
            } else {
                encode(preview)?
            };
            let n=insert.execute(params![r.id,r.source_id,r.timestamp,json(&r.status)?,kind,cat,proto,encode(r.raw.clone())?,encode(data)?,preview,json(&serde_json::json!({"position":r.position,"text":core::report::record_summary(r)}))?])?;
            added += n;
            if n > 0 {
                changed_sources.insert(&r.source_id);
            }
        }
        drop(insert);
        // A source may have been interrupted before. Replace its partial flow groups
        // with the groups from this parse, rather than duplicating the same sessions.
        for source in &changed_sources {
            tx.execute("DELETE FROM flows WHERE source_id=?1", [source])?;
        }
        for f in &report.findings {
            changed_findings += Self::insert_finding(&tx, f)?;
        }
        let record_sources: std::collections::HashMap<_, _> = report
            .records
            .iter()
            .map(|r| (&r.id, &r.source_id))
            .collect();
        for flow in &report.flows {
            let source = flow
                .evidence_ids
                .first()
                .and_then(|id| record_sources.get(id))
                .copied();
            let Some(source) = source else {
                continue;
            };
            if !changed_sources.contains(source) {
                continue;
            }
            let mut head = flow.clone();
            head.evidence_ids.clear();
            tx.execute(
                "INSERT INTO flows(source_id,json) VALUES(?1,?2)",
                params![source, json(&head)?],
            )?;
            let id = tx.last_insert_rowid();
            for (i, r) in flow.evidence_ids.iter().enumerate() {
                tx.execute(
                    "INSERT OR IGNORE INTO flow_refs VALUES(?1,?2,?3)",
                    params![id, r, i as i64],
                )?;
            }
        }
        let new_diagnostics = new_sources > 0 || added > 0 || report.sources.is_empty();
        if new_diagnostics {
            for d in &report.diagnostics {
                tx.execute(
                    "INSERT INTO diagnostics(json) VALUES(?1)",
                    [encode(json(d)?)?],
                )?;
            }
        }
        for run in &report.ai_runs {
            Self::insert_ai(&tx, run)?;
        }
        if new_sources > 0
            || added > 0
            || changed_findings > 0
            || (new_diagnostics && !report.diagnostics.is_empty())
            || !report.ai_runs.is_empty()
        {
            crate::project::touch(&tx)?;
        }
        tx.commit()?;
        Ok(added)
    }
    /// Explicit compatibility materialization; GUI pages and IOC never call this.
    pub fn report(&self) -> Result<AnalysisReport> {
        let mut report: AnalysisReport = {
            let c = self.lock()?;
            Self::get(&c, "report")?
        };
        let mut after = 0;
        loop {
            let batch = self.records_after(after, 256)?;
            if batch.is_empty() {
                break;
            }
            for (n, r) in batch {
                after = n;
                report.records.push(r);
            }
        }
        let c = self.lock()?;
        report.sources = values(&c, "SELECT json FROM sources ORDER BY rowid", [])?;
        let mut s = c.prepare("SELECT json FROM findings ORDER BY severity DESC,ordinal")?;
        let rows = s.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            report.findings.push(Self::finding(&c, row?)?);
        }
        report.flows = values(&c, "SELECT json FROM flows ORDER BY ordinal", [])?;
        for (i, f) in report.flows.iter_mut().enumerate() {
            let mut s =
                c.prepare("SELECT record_id FROM flow_refs WHERE flow_id=?1 ORDER BY ordinal")?;
            f.evidence_ids = s
                .query_map([i as i64 + 1], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
        }
        report.diagnostics = values(&c, "SELECT json FROM diagnostics ORDER BY ordinal", [])?;
        report.ai_runs = Self::ai(&c)?;
        if let Some(selection) = c
            .query_row(
                "SELECT value FROM metadata WHERE key='query_selection'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            && let Some(id) = serde_json::from_str::<Option<i64>>(&selection)?
        {
            let mut s = c.prepare(
                "SELECT record_id FROM selection_refs WHERE selection_id=?1 ORDER BY ordinal",
            )?;
            report.query_matches = Some(
                s.query_map([id], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?,
            );
        }
        Ok(report)
    }
    pub fn read_page(
        &self,
        selection: Option<i64>,
        offset: usize,
        limit: usize,
        payload: bool,
    ) -> Result<Page<RecordSummary>> {
        page_limit(limit)?;
        let c = self.lock()?;
        let total = if let Some(id) = selection {
            c.query_row("SELECT count FROM selections WHERE id=?1", [id], |r| {
                r.get::<_, i64>(0).map(|n| n as usize)
            })?
        } else {
            scalar(&c, "SELECT COUNT(*) FROM records")?
        };
        let data = if payload {
            "r.data"
        } else {
            "COALESCE(NULLIF(r.preview,''),r.data)"
        };
        let sql = if selection.is_some() {
            format!(
                "SELECT r.id,r.source_id,r.timestamp,r.status,{data},r.summary FROM selection_refs s JOIN records r ON r.id=s.record_id WHERE s.selection_id=?1 AND s.ordinal>=?3 ORDER BY s.ordinal LIMIT ?2"
            )
        } else {
            format!(
                "SELECT r.id,r.source_id,r.timestamp,r.status,{data},r.summary FROM records r WHERE ordinal>?3 ORDER BY ordinal LIMIT ?2"
            )
        };
        let mut s = c.prepare(&sql)?;
        let mut rows = s.query(params![
            selection.unwrap_or(0),
            limit as i64,
            offset.min(total) as i64
        ])?;
        let mut items = vec![];
        while let Some(r) = rows.next()? {
            items.push(Self::summary_row(r)?);
        }
        Ok(Page {
            offset,
            total,
            items,
        })
    }
    fn summary_row(r: &rusqlite::Row<'_>) -> Result<RecordSummary> {
        let summary: serde_json::Value = decode(r.get(5)?)?;
        Ok(RecordSummary {
            id: r.get(0)?,
            source_id: r.get(1)?,
            timestamp: r.get(2)?,
            status: decode(r.get(3)?)?,
            data: decode(row_text(r, 4)?)?,
            position: summary["position"].as_str().unwrap_or_default().into(),
            summary: summary["text"].as_str().unwrap_or_default().into(),
        })
    }
    pub fn read_lazy_page(
        &self,
        selection: &StoredSelection,
        offset: usize,
        limit: usize,
        payload: bool,
    ) -> Result<Page<RecordSummary>> {
        page_limit(limit)?;
        let c = self.lock()?;
        let mut membership = selection.membership();
        let table = membership.table();
        let descending = selection.order == RecordOrder::OriginalDesc;
        let mut pager = selection
            .pager
            .lock()
            .map_err(|_| anyhow!("The pagination cache is unavailable"))?;
        let boundary = pager.boundary(
            &c,
            &table,
            &membership.predicate,
            &membership.arguments,
            "r.ordinal",
            descending,
            selection.count,
            offset,
        )?;
        let mut items = Vec::new();
        if let Some(boundary) = boundary {
            membership.arguments.push(boundary.into());
            membership.arguments.push((limit as i64).into());
            let data = if payload {
                "r.data"
            } else {
                "COALESCE(NULLIF(r.preview,''),r.data)"
            };
            let comparison = if descending { "<=" } else { ">=" };
            let mut stmt = c.prepare(&format!("SELECT r.id,r.source_id,r.timestamp,r.status,{data},r.summary,r.ordinal FROM {table} WHERE {} AND r.ordinal{comparison}? ORDER BY {} LIMIT ?", membership.predicate, selection.order.sql()))?;
            let mut rows = stmt.query(rusqlite::params_from_iter(&membership.arguments))?;
            while let Some(r) = rows.next()? {
                pager.remember(offset + items.len(), r.get(6)?);
                items.push(Self::summary_row(r)?);
            }
        }
        Ok(Page {
            offset,
            total: selection.count,
            items,
        })
    }
    pub fn locate_lazy_record(
        &self,
        selection: &StoredSelection,
        id: &str,
    ) -> Result<Option<usize>> {
        let c = self.lock()?;
        let membership = selection.membership();
        let table = membership.table();
        let mut args = vec![rusqlite::types::Value::Text(id.into())];
        args.extend(membership.arguments.clone());
        let ordinal = c
            .query_row(
                &format!(
                    "SELECT r.ordinal FROM records r WHERE r.id=? AND {}",
                    membership.predicate
                ),
                rusqlite::params_from_iter(args),
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        ordinal
            .map(|ordinal| {
                let mut args = membership.arguments;
                args.push(ordinal.into());
                Ok(c.query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {table} WHERE {} AND r.ordinal{}?",
                        membership.predicate,
                        if selection.order == RecordOrder::OriginalDesc {
                            ">"
                        } else {
                            "<"
                        }
                    ),
                    rusqlite::params_from_iter(args),
                    |r| r.get::<_, i64>(0),
                )? as usize)
            })
            .transpose()
    }
}

#[derive(Debug)]
pub(crate) struct StoredSelection {
    pub db: Arc<Database>,
    pub id: i64,
    pub count: usize,
    pub ids: std::sync::OnceLock<Vec<String>>,
    pub lazy: Option<SqlSelection>,
    pub order: RecordOrder,
    pub pager: Mutex<crate::pagination::OrdinalPager>,
    pub process_rows: Mutex<Option<(u64, Arc<Vec<ProcessRow>>)>>,
    pub flow_index: Mutex<Option<(u64, i64)>>,
    pub materialized: std::sync::OnceLock<()>,
}
#[derive(Debug)]
pub(crate) struct SqlSelection {
    pub predicate: String,
    pub arguments: Vec<rusqlite::types::Value>,
    pub index: Option<&'static str>,
}
fn record_table(index: Option<&str>) -> String {
    index.map_or_else(
        || "records r".into(),
        |name| format!("records r INDEXED BY {name}"),
    )
}
impl SqlSelection {
    fn table(&self) -> String {
        record_table(self.index)
    }
}
impl StoredSelection {
    pub fn membership(&self) -> SqlSelection {
        if let Some(lazy) = &self.lazy {
            SqlSelection {
                predicate: lazy.predicate.clone(),
                arguments: lazy.arguments.clone(),
                index: lazy.index,
            }
        } else {
            SqlSelection { predicate: "EXISTS(SELECT 1 FROM selection_refs s WHERE s.selection_id=? AND s.record_id=r.id)".into(), arguments: vec![self.id.into()], index: None }
        }
    }
    pub fn materialize(&self, ctx: &ExecutionContext) -> Result<i64> {
        ctx.check()?;
        if let Some(lazy) = &self.lazy
            && self.materialized.get().is_none()
        {
            let mut c = self.db.lock()?;
            if self.materialized.get().is_none() {
                let tx = c.transaction()?;
                let table = lazy.table();
                let sql = format!(
                    "INSERT INTO selection_refs SELECT {},ROW_NUMBER() OVER(ORDER BY {})-1,r.id FROM {table} WHERE {}",
                    self.id,
                    self.order.sql(),
                    lazy.predicate
                );
                with_progress(&tx, ctx, || {
                    Ok(tx.execute(&sql, rusqlite::params_from_iter(&lazy.arguments))?)
                })?;
                ctx.check()?;
                tx.commit()?;
                let _ = self.materialized.set(());
            }
        }
        Ok(self.id)
    }
    pub fn load_ids(&self) -> Result<&[String]> {
        if self.ids.get().is_none() {
            self.materialize(&ExecutionContext::default())?;
            let c = self.db.lock()?;
            let mut s = c.prepare(
                "SELECT record_id FROM selection_refs WHERE selection_id=?1 ORDER BY ordinal",
            )?;
            let ids = s
                .query_map([self.id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            let _ = self.ids.set(ids);
        }
        Ok(self.ids.get().ok_or_else(|| anyhow!("Failed to read selection IDs"))?)
    }
}
impl Database {
    pub fn select(
        self: &Arc<Self>,
        session_id: u64,
        filter: &RecordFilter,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        use rusqlite::types::Value;
        let search =
            core::rules::compile_query(filter.query.expression.as_deref(), filter.query.regex)?;
        let (from, until) = filter.log_query.bounds()?;
        let log_filtered = from.is_some() || until.is_some() || filter.log_query.has_fields();
        let time_sql = crate::log_query::time_sql(filter.log_query.time_offset);
        let order_sql = filter.order.query_sql(filter.log_query.time_offset);
        let mut clauses = vec!["1=1".to_string()];
        let mut args: Vec<Value> = vec![];
        let mut indexes = vec![];
        for (column, value) in [
            (
                "kind",
                match filter.kind {
                    RecordKind::All => None,
                    RecordKind::Log => Some("log".to_string()),
                    RecordKind::Process => Some("process".to_string()),
                    RecordKind::Packet => Some("packet".to_string()),
                },
            ),
            ("source_id", filter.source.clone()),
            ("category", filter.category.clone()),
            ("protocol", filter.protocol.clone()),
            ("status", filter.status.as_ref().map(json).transpose()?),
        ] {
            if let Some(v) = value {
                let index = match column {
                    "kind" => "record_kind",
                    "source_id" => "record_source",
                    "category" => "record_category",
                    "protocol" => "record_protocol",
                    "status" => "record_status",
                    _ => unreachable!(),
                };
                indexes.push((index, column, Value::Text(v.clone())));
                args.push(v.into());
                clauses.push(format!("r.{column}=?"));
            }
        }
        if filter.query.suspicious {
            clauses.push("EXISTS(SELECT 1 FROM finding_refs e JOIN findings f ON f.id=e.finding_id WHERE e.record_id=r.id AND f.origin LIKE 'local:%')".into());
        }
        for (comparison, value) in [(">=", from), ("<=", until)] {
            if let Some(value) = value {
                args.push(value.into());
                clauses.push(format!("{time_sql}{comparison}?"));
            }
        }
        if filter.log_query.has_fields() {
            args.push(json(&filter.log_query)?.into());
            clauses.push("eair_log_match(r.data,?)".into());
        }
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        // Without ANALYZE, SQLite can choose the broad kind index for a tiny
        // source or category. Compare cached covering-index counts once, then
        // keep the chosen index for the frozen selection and all its pages.
        let index = with_progress(&tx, ctx, || {
            let mut best = None;
            for (index, column, value) in &indexes {
                let count = if indexes.len() == 1 {
                    0
                } else {
                    self.cached_count(
                        &tx,
                        &format!("SELECT COUNT(*) FROM records WHERE {column}=?"),
                        std::slice::from_ref(value),
                    )?
                };
                if best.is_none_or(|(_, old)| count < old) {
                    best = Some((*index, count));
                }
            }
            Ok(best.map(|(index, _)| index))
        })?;
        let table = record_table(index);
        // Records are append-only. The upper ordinal freezes a typed selection
        // without copying every ID; text and finding-dependent selections stay materialized.
        let lazy = search.is_none()
            && !filter.query.suspicious
            && filter.order.original()
            && !log_filtered;
        if lazy {
            args.push(
                tx.query_row("SELECT COALESCE(MAX(ordinal),0) FROM records", [], |r| {
                    r.get::<_, i64>(0)
                })?
                .into(),
            );
            clauses.push("r.ordinal<=?".into());
        }
        let where_sql = clauses.join(" AND ");
        tx.execute("INSERT INTO selections(count) VALUES(0)", [])?;
        let id = tx.last_insert_rowid();
        let count = if let Some(search) = search {
            with_progress(&tx, ctx, || {
                let mut count = 0;
                let mut s = tx.prepare(&format!(
                    "SELECT id,raw,data FROM {table} WHERE {where_sql} ORDER BY {}",
                    order_sql
                ))?;
                let mut rows = s.query(rusqlite::params_from_iter(args.iter()))?;
                let mut n = 0;
                while let Some(r) = rows.next()? {
                    ctx.tick(core::execution::Stage::Query, None, n, None)?;
                    n += 1;
                    let raw = row_text(r, 1)?;
                    let data = row_text(r, 2)?;
                    if search.is_match(&raw) || search.is_match(&data) {
                        tx.execute(
                            "INSERT INTO selection_refs VALUES(?1,?2,?3)",
                            params![id, count as i64, r.get::<_, String>(0)?],
                        )?;
                        count += 1;
                    }
                }
                Ok(count)
            })?
        } else if lazy {
            with_progress(&tx, ctx, || {
                Ok(tx.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {where_sql}"),
                    rusqlite::params_from_iter(&args),
                    |r| r.get::<_, i64>(0),
                )? as usize)
            })?
        } else {
            let sql = format!(
                "INSERT INTO selection_refs SELECT {id},ROW_NUMBER() OVER(ORDER BY {})-1,r.id FROM {table} WHERE {where_sql}",
                order_sql
            );
            with_progress(&tx, ctx, || {
                Ok(tx.execute(&sql, rusqlite::params_from_iter(args.iter()))?)
            })?
        };
        tx.execute(
            "UPDATE selections SET count=?1 WHERE id=?2",
            params![count as i64, id],
        )?;
        ctx.check()?;
        tx.commit()?;
        Ok(RecordSelection {
            session_id,
            ids: vec![],
            stored: Some(Arc::new(StoredSelection {
                db: self.clone(),
                id,
                count,
                ids: Default::default(),
                lazy: lazy.then_some(SqlSelection {
                    predicate: where_sql,
                    arguments: args,
                    index,
                }),
                order: filter.order,
                pager: Mutex::default(),
                process_rows: Mutex::default(),
                flow_index: Mutex::default(),
                materialized: Default::default(),
            })),
        })
    }
    pub fn overview(&self, ctx: &ExecutionContext) -> Result<SessionOverview> {
        ctx.check()?;
        let c = self.lock()?;
        let revision = crate::project::content_revision(&c)?;
        let mut cache = self
            .overview_cache
            .lock()
            .map_err(|_| anyhow!("The project statistics cache is unavailable"))?;
        if let Some((old, overview)) = cache.as_ref()
            && *old == revision
        {
            return Ok(overview.clone());
        }
        let out = with_progress(&c, ctx, || Self::compute_overview(&c, ctx))?;
        *cache = Some((revision, out.clone()));
        Ok(out)
    }
    pub(crate) fn compute_overview(
        c: &Connection,
        ctx: &ExecutionContext,
    ) -> Result<SessionOverview> {
        let mut out = SessionOverview {
            sources: scalar(c, "SELECT COUNT(*) FROM sources")?,
            records: scalar(c, "SELECT COUNT(*) FROM records")?,
            flows: scalar(c, "SELECT COUNT(*) FROM flows")?,
            suspicious: scalar(
                c,
                "SELECT COUNT(DISTINCT e.record_id) FROM finding_refs e JOIN findings f ON f.id=e.finding_id WHERE f.origin LIKE 'local:%'",
            )?,
            ..Default::default()
        };
        // Separate covering indices avoid reading every multi-kilobyte evidence row.
        let mut s = c.prepare("SELECT kind,COUNT(*) FROM records GROUP BY kind")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            ctx.check()?;
            let n = r.get::<_, i64>(1)? as usize;
            match r.get::<_, String>(0)?.as_str() {
                "log" => out.logs += n,
                "process" => out.processes += n,
                "packet" => out.packets += n,
                _ => {}
            }
        }
        let mut s = c.prepare("SELECT status,COUNT(*) FROM records GROUP BY status")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            ctx.check()?;
            let n = r.get::<_, i64>(1)? as usize;
            match decode::<ParseStatus>(r.get(0)?)? {
                ParseStatus::Parsed => out.parse_counts[0] += n,
                ParseStatus::Unrecognized => out.parse_counts[1] += n,
                ParseStatus::Malformed => out.parse_counts[2] += n,
            }
        }
        let mut s=c.prepare("SELECT severity,origin LIKE 'local:%',COUNT(*) FROM findings GROUP BY severity,origin LIKE 'local:%'")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            let n = r.get::<_, i64>(2)? as usize;
            out.risks[r.get::<_, i64>(0).map(|n| n as usize)?] += n;
            if r.get::<_, bool>(1)? {
                out.local_findings += n
            } else {
                out.ai_findings += n
            }
        }
        for (sql, target) in [
            (
                "SELECT DISTINCT category FROM records WHERE category<>'' ORDER BY category",
                &mut out.categories,
            ),
            (
                "SELECT DISTINCT protocol FROM records WHERE protocol<>'' ORDER BY protocol",
                &mut out.protocols,
            ),
        ] {
            let mut s = c.prepare(sql)?;
            *target = s
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
        }
        Ok(out)
    }
    pub fn finding_headers(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<Finding>> {
        page_limit(limit)?;
        let c = self.lock()?;
        with_progress(&c, ctx, || {
            let origin = match filter.origin {
                FindingOrigin::All => "1=1",
                FindingOrigin::Local => "origin LIKE 'local:%'",
                FindingOrigin::Ai => "origin NOT LIKE 'local:%'",
            };
            let condition = format!("severity=? AND {origin}");
            let mut counts = vec![];
            for rank in (0..=4).rev() {
                if filter.severity.as_ref().is_some_and(|s| s.rank() != rank) {
                    continue;
                }
                let args = vec![rusqlite::types::Value::Integer(rank as i64)];
                let count = self.cached_count(
                    &c,
                    &format!("SELECT COUNT(*) FROM findings WHERE {condition}"),
                    &args,
                )?;
                counts.push((args, count));
            }
            let total = counts.iter().map(|(_, n)| *n).sum();
            let mut skip = offset;
            let mut items = vec![];
            for (mut args, count) in counts {
                if skip >= count {
                    skip -= count;
                    continue;
                }
                let boundary = self
                    .page_boundary(
                        &c, "findings", &condition, &args, "ordinal", false, count, skip,
                    )?
                    .unwrap_or(i64::MAX);
                args.push(boundary.into());
                args.push(((limit - items.len()) as i64).into());
                items.extend(values::<Finding>(&c,&format!("SELECT json FROM findings WHERE {condition} AND ordinal>=? ORDER BY ordinal LIMIT ?"),rusqlite::params_from_iter(args))?);
                skip = 0;
                if items.len() == limit {
                    break;
                }
            }
            Ok(Page {
                offset,
                total,
                items,
            })
        })
    }
    pub fn finding_page(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Page<Finding>> {
        let page = self.finding_headers(filter, offset, limit, &ExecutionContext::default())?;
        let c = self.lock()?;
        let items = page
            .items
            .into_iter()
            .map(|finding| Self::finding(&c, json(&finding)?))
            .collect::<Result<Vec<_>>>()?;
        Ok(Page {
            offset,
            total: page.total,
            items,
        })
    }
    pub fn reference_page(&self, id: &str, offset: usize, limit: usize) -> Result<Page<String>> {
        page_limit(limit)?;
        let c = self.lock()?;
        if !c.query_row(
            "SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1)",
            [id],
            |r| r.get::<_, bool>(0),
        )? {
            bail!("The finding does not belong to the current project");
        }
        let revision = crate::project::content_revision(&c)?;
        let mut cache = self
            .read_cache
            .lock()
            .map_err(|_| anyhow!("The reference pagination cache is unavailable"))?;
        cache.update(revision);
        c.execute_batch("CREATE TEMP TABLE IF NOT EXISTS page_references(finding_id TEXT NOT NULL,ordinal INTEGER NOT NULL,record_id TEXT NOT NULL,PRIMARY KEY(finding_id,ordinal));")?;
        if !cache.references.contains_key(id) {
            if cache.references.len() >= 8 {
                cache.references.clear();
            }
            if cache.references.is_empty() {
                c.execute("DELETE FROM page_references", [])?;
            }
            let total = with_progress(&c, &ExecutionContext::default(), || {
                Ok(c.execute("INSERT INTO page_references SELECT ?1,ROW_NUMBER() OVER(ORDER BY ordinal,record_id)-1,record_id FROM finding_refs WHERE finding_id=?1",[id])?)
            })?;
            cache.references.insert(id.into(), total);
        }
        let total = cache.references[id];
        let mut stmt=c.prepare("SELECT record_id FROM page_references WHERE finding_id=?1 AND ordinal>=?2 ORDER BY ordinal LIMIT ?3")?;
        let items = stmt
            .query_map(
                params![id, offset.min(i64::MAX as usize) as i64, limit as i64],
                |r| r.get(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Page {
            offset,
            total,
            items,
        })
    }
    pub fn source_page(&self, offset: usize, limit: usize) -> Result<Page<Source>> {
        page_limit(limit)?;
        let c = self.lock()?;
        Ok(Page {
            offset,
            total: self.cached_count(&c, "SELECT COUNT(*) FROM sources", &[])?,
            items: values(
                &c,
                "SELECT json FROM sources WHERE rowid>=?1 ORDER BY rowid LIMIT ?2",
                params![
                    self.page_boundary(
                        &c,
                        "sources",
                        "1=1",
                        &[],
                        "rowid",
                        false,
                        self.cached_count(&c, "SELECT COUNT(*) FROM sources", &[])?,
                        offset
                    )?
                    .unwrap_or(i64::MAX),
                    limit as i64
                ],
            )?,
        })
    }
    pub fn diagnostic_page(&self, offset: usize, limit: usize) -> Result<Page<Diagnostic>> {
        page_limit(limit)?;
        let total = self.diagnostic_count()?;
        let c = self.lock()?;
        Ok(Page {
            offset,
            total,
            items: values(
                &c,
                "SELECT json FROM diagnostics WHERE ordinal>=?1 ORDER BY ordinal LIMIT ?2",
                params![
                    self.page_boundary(
                        &c,
                        "diagnostics",
                        "1=1",
                        &[],
                        "ordinal",
                        false,
                        total,
                        offset
                    )?
                    .unwrap_or(i64::MAX),
                    limit as i64
                ],
            )?,
        })
    }
    pub fn diagnostic_count(&self) -> Result<usize> {
        let c = self.lock()?;
        let last = c.query_row(
            "SELECT COALESCE(MAX(ordinal),0) FROM diagnostics",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        let mut cache = self
            .diagnostic_count_cache
            .lock()
            .map_err(|_| anyhow!("The diagnostic count cache is unavailable"))?;
        if let Some((old, count)) = *cache
            && old == last
        {
            return Ok(count);
        }
        let count = scalar(&c, "SELECT COUNT(*) FROM diagnostics")?;
        *cache = Some((last, count));
        Ok(count)
    }
    pub fn diagnostic_levels(&self, ctx: &ExecutionContext) -> Result<(usize, usize)> {
        ctx.check()?;
        let c = self.lock()?;
        let last = c.query_row(
            "SELECT COALESCE(MAX(ordinal),0) FROM diagnostics",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        let mut cache = self
            .diagnostic_level_cache
            .lock()
            .map_err(|_| anyhow!("The diagnostic count cache is unavailable"))?;
        if let Some((old, counts)) = *cache
            && old == last
        {
            return Ok(counts);
        }
        let counts = with_progress(&c, ctx, || {
            let mut stmt = c.prepare("SELECT json_extract(eair_text(json),'$.level'),COUNT(*) FROM diagnostics GROUP BY 1")?;
            let mut rows = stmt.query([])?;
            let (mut errors, mut warnings) = (0, 0);
            while let Some(r) = rows.next()? {
                let count = r.get::<_, i64>(1)? as usize;
                if r.get::<_, String>(0)? == "error" {
                    errors += count;
                } else {
                    warnings += count;
                }
            }
            Ok((errors, warnings))
        })?;
        *cache = Some((last, counts));
        Ok(counts)
    }
    pub fn flow_page(
        &self,
        selection: Option<&StoredSelection>,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<FlowSummary>> {
        page_limit(limit)?;
        ctx.check()?;
        let c = self.lock()?;
        let (total, sql, args): (usize, String, Vec<rusqlite::types::Value>) = if let Some(
            selection,
        ) = selection
        {
            let revision = crate::project::content_revision(&c)?;
            let mut cached = selection
                .flow_index
                .lock()
                .map_err(|_| anyhow!("The network session pagination cache is unavailable"))?;
            if cached.as_ref().is_none_or(|(old, _)| *old != revision) {
                c.execute_batch("CREATE TEMP TABLE IF NOT EXISTS page_flows(selection_id INTEGER NOT NULL,ordinal INTEGER NOT NULL,flow_id INTEGER NOT NULL,matched INTEGER NOT NULL,PRIMARY KEY(selection_id,ordinal));")?;
                let membership = selection.membership();
                c.execute(
                    "DELETE FROM page_flows WHERE selection_id=?1",
                    [selection.id],
                )?;
                let mut args = vec![selection.id.into()];
                args.extend(membership.arguments);
                let total = with_progress(&c, ctx, || {
                    Ok(c.execute(&format!("INSERT INTO page_flows SELECT ?,ROW_NUMBER() OVER(ORDER BY f.ordinal)-1,f.ordinal,COUNT(*) FROM flows f JOIN flow_refs e ON e.flow_id=f.ordinal JOIN records r ON r.id=e.record_id WHERE {} GROUP BY f.ordinal",membership.predicate),rusqlite::params_from_iter(args))?)
                })?;
                *cached = Some((revision, total as i64));
            }
            let total = cached.as_ref().unwrap().1 as usize;
            (total,"SELECT f.ordinal,f.source_id,f.json,p.matched FROM page_flows p JOIN flows f ON f.ordinal=p.flow_id WHERE p.selection_id=? AND p.ordinal>=? ORDER BY p.ordinal LIMIT ?".to_string(),vec![selection.id.into(),(offset.min(i64::MAX as usize) as i64).into(),(limit as i64).into()])
        } else {
            let total = self.cached_count(&c, "SELECT COUNT(*) FROM flows", &[])?;
            let boundary = self
                .page_boundary(&c, "flows", "1=1", &[], "ordinal", false, total, offset)?
                .unwrap_or(i64::MAX);
            (total,"SELECT ordinal,source_id,json,NULL FROM flows WHERE ordinal>=? ORDER BY ordinal LIMIT ?".to_string(),vec![boundary.into(),(limit as i64).into()])
        };
        let items = with_progress(&c, ctx, || {
            let mut stmt = c.prepare(&sql)?;
            let mut rows = stmt.query(rusqlite::params_from_iter(args))?;
            let mut items = vec![];
            while let Some(row) = rows.next()? {
                ctx.check()?;
                let id: i64 = row.get(0)?;
                let flow: NetworkFlow = decode(row.get(2)?)?;
                items.push(FlowSummary {
                    key: (id - 1) as usize,
                    source_id: row.get(1)?,
                    endpoint_a: flow.endpoint_a,
                    endpoint_b: flow.endpoint_b,
                    protocol: flow.protocol,
                    packets: flow.packets,
                    matched_packets: row
                        .get::<_, Option<i64>>(3)?
                        .map_or(flow.packets, |n| n as usize),
                    bytes: flow.bytes,
                    first_seen: flow.first_seen,
                    last_seen: flow.last_seen,
                });
            }
            Ok(items)
        })?;
        Ok(Page {
            offset,
            total,
            items,
        })
    }
    pub fn flow_selection(
        self: &Arc<Self>,
        session_id: u64,
        key: usize,
        selection: Option<&StoredSelection>,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        if scalar(
            &tx,
            &format!("SELECT COUNT(*) FROM flows WHERE ordinal={}", key + 1),
        )? == 0
        {
            bail!("The network session does not exist");
        }
        tx.execute("INSERT INTO selections VALUES(NULL,0)", [])?;
        let id = tx.last_insert_rowid();
        ctx.check()?;
        let membership = selection
            .map(StoredSelection::membership)
            .unwrap_or(SqlSelection {
                predicate: "1=1".into(),
                arguments: vec![],
                index: None,
            });
        let mut args = vec![id.into(), ((key + 1) as i64).into()];
        args.extend(membership.arguments);
        let count = with_progress(&tx, ctx, || {
            Ok(tx.execute(&format!("INSERT INTO selection_refs SELECT ?,ROW_NUMBER() OVER(ORDER BY e.ordinal)-1,e.record_id FROM flow_refs e JOIN records r ON r.id=e.record_id WHERE e.flow_id=? AND {}",membership.predicate),rusqlite::params_from_iter(args))?)
        })?;
        tx.execute(
            "UPDATE selections SET count=?1 WHERE id=?2",
            params![count as i64, id],
        )?;
        tx.commit()?;
        Ok(RecordSelection {
            session_id,
            ids: vec![],
            stored: Some(Arc::new(StoredSelection {
                db: self.clone(),
                id,
                count,
                ids: Default::default(),
                lazy: None,
                order: crate::RecordOrder::default(),
                pager: Mutex::default(),
                process_rows: Mutex::default(),
                flow_index: Mutex::default(),
                materialized: Default::default(),
            })),
        })
    }
    fn process_records(&self, ctx: &ExecutionContext) -> Result<Vec<Record>> {
        let c = self.lock()?;
        with_progress(&c, ctx, || {
            let mut s=c.prepare("SELECT id,source_id,timestamp,status,'',json_remove(eair_text(data),'$.fields.command','$.fields.path','$.fields.user','$.fields.start_time','$.fields.status'),ordinal,json_extract(summary,'$.position') FROM records WHERE kind='process' ORDER BY ordinal")?;
            Ok(s.query_map([], Self::record_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|r| r.1)
                .collect())
        })
    }
    pub fn process_forest(
        &self,
        ctx: &ExecutionContext,
    ) -> Result<Arc<core::process::ProcessForest>> {
        ctx.check()?;
        let last =
            self.lock()?
                .query_row("SELECT COALESCE(MAX(ordinal),0) FROM records", [], |r| {
                    r.get::<_, i64>(0)
                })?;
        let mut cache = self
            .process_cache
            .lock()
            .map_err(|_| anyhow!("The process tree cache is unavailable"))?;
        if let Some((old, forest)) = cache.as_ref()
            && *old == last
        {
            return Ok(forest.clone());
        }
        let forest = Arc::new(core::process::process_forest_with_context(
            &self.process_records(ctx)?,
            ctx,
        )?);
        *cache = Some((last, forest.clone()));
        Ok(forest)
    }
}
impl Database {
    pub fn selected_records_after(
        &self,
        selection: i64,
        after: i64,
        limit: usize,
        payload: bool,
    ) -> Result<Vec<(i64, Record)>> {
        let c = self.lock()?;
        let fields = if payload {
            "r.raw,r.data"
        } else {
            "CASE WHEN r.kind='packet' THEN '' ELSE r.raw END,COALESCE(NULLIF(r.preview,''),r.data)"
        };
        let mut s=c.prepare(&format!("SELECT r.id,r.source_id,r.timestamp,r.status,{fields},s.ordinal,json_extract(r.summary,'$.position') FROM selection_refs s JOIN records r ON r.id=s.record_id WHERE s.selection_id=?1 AND s.ordinal>?2 ORDER BY s.ordinal LIMIT ?3"))?;
        Ok(
            s.query_map(params![selection, after, limit as i64], Self::record_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        )
    }
}

impl Drop for StoredSelection {
    fn drop(&mut self) {
        if let Ok(c) = self.db.lock() {
            let current = Database::get::<Option<i64>>(&c, "query_selection").unwrap_or(None);
            if current != Some(self.id) {
                let _ = c.execute("DELETE FROM page_flows WHERE selection_id=?1", [self.id]);
                let _ = c.execute("DELETE FROM selections WHERE id=?1", [self.id]);
            }
        }
    }
}
impl Database {
    pub fn ioc_records_after(&self, after: i64, limit: usize) -> Result<Vec<(i64, Record)>> {
        let c = self.lock()?;
        let mut s=c.prepare("SELECT id,source_id,timestamp,status,CASE WHEN kind='packet' OR category IN ('utmp','wtmp','btmp') THEN '' ELSE raw END,COALESCE(NULLIF(preview,''),data),ordinal,json_extract(summary,'$.position') FROM records WHERE ordinal>?1 ORDER BY ordinal LIMIT ?2")?;
        Ok(s.query_map(params![after, limit as i64], Self::record_row)?
            .collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
