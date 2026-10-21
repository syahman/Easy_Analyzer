//! GUI-neutral selections and bounded view models. Evidence never leaves the session wholesale.
use crate::{AnalysisSession, ExecutionContext, Page, QueryOptions, RecordSelection, core};
use anyhow::{Result, bail};
use core::{
    AiRun, Diagnostic, Finding, ParseStatus, RecordData, Severity, Source, execution::Stage,
};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordKind {
    #[default]
    All,
    Log,
    Process,
    Packet,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordFilter {
    pub query: QueryOptions,
    pub kind: RecordKind,
    pub source: Option<String>,
    pub category: Option<String>,
    pub status: Option<ParseStatus>,
    pub protocol: Option<String>,
    pub log_query: crate::LogQuery,
    pub order: crate::RecordOrder,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindingOrigin {
    #[default]
    All,
    Local,
    Ai,
}
#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    pub severity: Option<Severity>,
    pub origin: FindingOrigin,
}
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SessionOverview {
    pub sources: usize,
    pub records: usize,
    pub logs: usize,
    pub processes: usize,
    pub packets: usize,
    pub flows: usize,
    pub local_findings: usize,
    pub ai_findings: usize,
    pub suspicious: usize,
    pub risks: [usize; 5],
    pub categories: Vec<String>,
    pub protocols: Vec<String>,
    pub parse_counts: [usize; 3],
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowSummary {
    /// Stable within a session, includes capture source through the underlying flow index.
    pub key: usize,
    pub source_id: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub protocol: String,
    pub packets: usize,
    pub matched_packets: usize,
    pub bytes: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessRow {
    pub record_id: String,
    pub depth: usize,
    pub context: bool,
    pub orphan: bool,
    pub cyclic: bool,
    pub has_children: bool,
}

fn page<T>(all: Vec<T>, offset: usize, limit: usize) -> Result<Page<T>> {
    if !(1..=1000).contains(&limit) {
        bail!("Page size must be between 1 and 1000");
    }
    let total = all.len();
    Ok(Page {
        offset,
        total,
        items: all.into_iter().skip(offset).take(limit).collect(),
    })
}

fn page_slice<T: Clone>(all: &[T], offset: usize, limit: usize) -> Result<Page<T>> {
    if !(1..=1000).contains(&limit) {
        bail!("Page size must be between 1 and 1000");
    }
    Ok(Page {
        offset,
        total: all.len(),
        items: all[offset.min(all.len())..offset.saturating_add(limit).min(all.len())].to_vec(),
    })
}

impl AnalysisSession {
    pub fn select_records(
        &self,
        filter: &RecordFilter,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        let log_query = filter.log_query.prepare()?;
        if let Some(db) = &self.0.store {
            ctx.check()?;
            let version = {
                let c = db.lock()?;
                if filter.query.suspicious {
                    (crate::project::content_revision(&c)?, true)
                } else {
                    (
                        c.query_row("SELECT COALESCE(MAX(ordinal),0) FROM records", [], |r| {
                            r.get::<_, i64>(0).map(|n| n as u64)
                        })?,
                        false,
                    )
                }
            };
            let mut cache = self
                .0
                .selections
                .lock()
                .map_err(|_| anyhow::anyhow!("The filter cache is unavailable"))?;
            if let Some(index) = cache
                .iter()
                .position(|(old, f, _)| old == &version && f == filter)
            {
                let entry = cache.remove(index);
                let selected = entry.2.clone();
                cache.push(entry);
                return Ok(selected);
            }
            drop(cache);
            let selected = db.select(self.id(), filter, ctx)?;
            ctx.check()?;
            let mut cache = self
                .0
                .selections
                .lock()
                .map_err(|_| anyhow::anyhow!("The filter cache is unavailable"))?;
            if cache.len() >= 4 {
                cache.remove(0);
            }
            cache.push((version, filter.clone(), selected.clone()));
            return Ok(selected);
        }
        let selection = self.query(&filter.query, ctx)?;
        self.with_report(|r| {
            let mut ids = Vec::new();
            for (i, id) in selection.ids().iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(selection.len()))?;
                let record = &r.records[self.0.index[id]];
                let kind = match record.data {
                    RecordData::Log(_) => RecordKind::Log,
                    RecordData::Process(_) => RecordKind::Process,
                    RecordData::Packet(_) => RecordKind::Packet,
                };
                if filter.kind != RecordKind::All && filter.kind != kind {
                    continue;
                }
                if filter
                    .source
                    .as_ref()
                    .is_some_and(|s| s != &record.source_id)
                    || filter.status.as_ref().is_some_and(|s| s != &record.status)
                {
                    continue;
                }
                if let Some(category) = &filter.category
                    && !matches!(&record.data, RecordData::Log(l) if &l.category == category)
                {
                    continue;
                }
                if let Some(protocol) = &filter.protocol
                    && !matches!(&record.data, RecordData::Packet(p) if &p.protocol == protocol)
                {
                    continue;
                }
                if !log_query.matches(record) {
                    continue;
                }
                ids.push(id.clone());
            }
            match filter.order {
                crate::RecordOrder::OriginalAsc => {}
                crate::RecordOrder::OriginalDesc => ids.reverse(),
                order => {
                    let mut sorted = ids
                        .into_iter()
                        .enumerate()
                        .map(|(i, id)| {
                            ctx.tick(Stage::Query, None, i, Some(selection.len()))?;
                            let record = &r.records[self.0.index[&id]];
                            Ok((log_query.time(record), self.0.index[&id], id))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    sorted.sort_by(|(a, ai, _), (b, bi, _)| match (a, b) {
                        (Some(a), Some(b)) => {
                            if order == crate::RecordOrder::TimeAsc {
                                a.cmp(b).then(ai.cmp(bi))
                            } else {
                                b.cmp(a).then(bi.cmp(ai))
                            }
                        }
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        _ => {
                            if order == crate::RecordOrder::TimeAsc {
                                ai.cmp(bi)
                            } else {
                                bi.cmp(ai)
                            }
                        }
                    });
                    ctx.check()?;
                    ids = sorted.into_iter().map(|(_, _, id)| id).collect();
                }
            }
            self.select_ids(ids)
        })?
    }
    pub fn overview(&self, ctx: &ExecutionContext) -> Result<SessionOverview> {
        if let Some(db) = &self.0.store {
            return db.overview(ctx);
        }
        self.with_report(|r| {
            let mut o = SessionOverview {
                sources: r.sources.len(),
                records: r.records.len(),
                flows: r.flows.len(),
                suspicious: self.0.local_suspicious.len(),
                ..Default::default()
            };
            let mut categories = BTreeMap::new();
            let mut protocols = BTreeMap::new();
            for (i, record) in r.records.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(r.records.len()))?;
                o.parse_counts[match record.status {
                    ParseStatus::Parsed => 0,
                    ParseStatus::Unrecognized => 1,
                    ParseStatus::Malformed => 2,
                }] += 1;
                match &record.data {
                    RecordData::Log(l) => {
                        o.logs += 1;
                        categories.insert(l.category.clone(), ());
                    }
                    RecordData::Process(_) => o.processes += 1,
                    RecordData::Packet(p) => {
                        o.packets += 1;
                        protocols.insert(p.protocol.clone(), ());
                    }
                }
            }
            for (i, finding) in r.findings.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(r.findings.len()))?;
                o.risks[finding.severity.rank() as usize] += 1;
                if finding.origin.starts_with("local:") {
                    o.local_findings += 1;
                } else {
                    o.ai_findings += 1;
                }
            }
            o.categories = categories.into_keys().collect();
            o.protocols = protocols.into_keys().collect();
            Ok(o)
        })?
    }
    pub fn finding_page(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<Finding>> {
        if let Some(db) = &self.0.store {
            ctx.check()?;
            return db.finding_page(filter, offset, limit);
        }
        self.with_report(|r| {
            if !(1..=1000).contains(&limit) {
                bail!("Page size must be between 1 and 1000");
            }
            let mut all = Vec::new();
            let mut total = 0;
            for (i, f) in r.findings.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(r.findings.len()))?;
                let local = f.origin.starts_with("local:");
                if filter.severity.as_ref().is_some_and(|s| s != &f.severity)
                    || (filter.origin == FindingOrigin::Local && !local)
                    || (filter.origin == FindingOrigin::Ai && local)
                {
                    continue;
                }
                if total >= offset && total < offset.saturating_add(limit) {
                    all.push(f.clone());
                }
                total += 1;
            }
            Ok(Page {
                offset,
                total,
                items: all,
            })
        })?
    }
    pub fn locate_record(
        &self,
        selection: Option<&RecordSelection>,
        id: &str,
    ) -> Result<Option<usize>> {
        if let Some(db) = &self.0.store {
            if let Some(s) = selection {
                self.validate_selection(s)?;
            }
            if let Some(s) = selection.and_then(|s| s.stored.as_ref())
                && s.lazy.is_some()
            {
                return db.locate_lazy_record(s, id);
            }
            let key = selection
                .map(|s| s.stored_id(&ExecutionContext::default()))
                .transpose()?
                .flatten();
            let c = db.lock()?;
            use rusqlite::OptionalExtension;
            let position = if let Some(key) = key {
                c.query_row(
                    "SELECT ordinal FROM selection_refs WHERE selection_id=?1 AND record_id=?2",
                    rusqlite::params![key, id],
                    |r| r.get::<_, i64>(0).map(|n| n as usize),
                )
                .optional()?
            } else {
                c.query_row("SELECT ordinal-1 FROM records WHERE id=?1", [id], |r| {
                    r.get::<_, i64>(0).map(|n| n as usize)
                })
                .optional()?
            };
            return Ok(position);
        }
        if let Some(s) = selection {
            self.validate_selection(s)?;
            return Ok(s.ids().iter().position(|candidate| candidate == id));
        }
        Ok(self.0.index.get(id).copied())
    }
    pub fn source(&self, id: &str) -> Result<Option<Source>> {
        if let Some(db) = &self.0.store {
            let c = db.lock()?;
            let items: Vec<Source> =
                crate::storage::values(&c, "SELECT json FROM sources WHERE id=?1", [id])?;
            return Ok(items.into_iter().next());
        }
        self.with_report(|r| r.sources.iter().find(|s| s.id == id).cloned())
    }
    pub fn source_page(&self, offset: usize, limit: usize) -> Result<Page<Source>> {
        if let Some(db) = &self.0.store {
            return db.source_page(offset, limit);
        }
        self.with_report(|r| page_slice(&r.sources, offset, limit))?
    }
    pub fn diagnostic_page(&self, offset: usize, limit: usize) -> Result<Page<Diagnostic>> {
        if let Some(db) = &self.0.store {
            return db.diagnostic_page(offset, limit);
        }
        self.with_report(|r| page_slice(&r.diagnostics, offset, limit))?
    }
    pub fn diagnostic_count(&self) -> Result<usize> {
        if let Some(db) = &self.0.store {
            return db.diagnostic_count();
        }
        self.with_report(|r| r.diagnostics.len())
    }
    /// Local AI summaries for the displayed history page, without paging through diagnostics.
    pub fn ai_local_summaries(
        &self,
        run_indices: &[usize],
        ctx: &ExecutionContext,
    ) -> Result<BTreeMap<String, String>> {
        ctx.check()?;
        if run_indices.is_empty() {
            return Ok(BTreeMap::new());
        }
        let positions: HashSet<_> = run_indices
            .iter()
            .map(|n| format!("ai-run:{}", n + 1))
            .collect();
        if let Some(db) = &self.0.store {
            let c = db.lock()?;
            let revision: u64 = c.query_row(
                "SELECT COALESCE(MAX(ordinal),0) FROM diagnostics",
                [],
                |r| r.get::<_, i64>(0).map(|n| n as u64),
            )?;
            let mut cache = db
                .ai_summary_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("The AI summary cache is unavailable"))?;
            if cache.as_ref().is_none_or(|(old, _)| *old != revision) {
                let summaries = crate::storage::with_progress(&c, ctx, || {
                    let mut stmt = c.prepare("SELECT json_extract(eair_text(json),'$.position'),json_extract(eair_text(json),'$.message') FROM diagnostics WHERE json_extract(eair_text(json),'$.source')='AI local recap' AND json_extract(eair_text(json),'$.position') IS NOT NULL ORDER BY ordinal")?;
                    Ok(stmt
                        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?)
                })?;
                *cache = Some((revision, summaries));
            }
            return Ok(cache
                .as_ref()
                .unwrap()
                .1
                .iter()
                .filter(|(position, _)| positions.contains(*position))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect());
        }
        self.with_report(|report| {
            let mut summaries = BTreeMap::new();
            for (n, diagnostic) in report.diagnostics.iter().enumerate() {
                ctx.tick(
                    Stage::Query,
                    Some("AI local recap"),
                    n,
                    Some(report.diagnostics.len()),
                )?;
                if diagnostic.source == "AI local recap"
                    && let Some(position) = &diagnostic.position
                    && positions.contains(position)
                {
                    summaries.insert(position.clone(), diagnostic.message.clone());
                }
            }
            Ok(summaries)
        })?
    }
    pub fn ai_runs(&self) -> Result<Vec<AiRun>> {
        if let Some(db) = &self.0.store {
            return crate::storage::Database::ai(&*db.lock()?);
        }
        self.with_report(|r| r.ai_runs.clone())
    }
    pub fn related_findings(&self, id: &str) -> Result<Vec<Finding>> {
        if let Some(db) = &self.0.store {
            let c = db.lock()?;
            let rows: Vec<Finding> = crate::storage::values(
                &c,
                "SELECT f.json FROM findings f JOIN finding_refs e ON e.finding_id=f.id WHERE e.record_id=?1 ORDER BY f.severity DESC",
                [id],
            )?;
            return rows
                .into_iter()
                .map(|f| crate::storage::Database::finding(&c, crate::storage::json(&f)?))
                .collect();
        }
        self.with_report(|r| {
            r.findings
                .iter()
                .filter(|f| f.evidence_ids.iter().any(|e| e == id))
                .cloned()
                .collect()
        })
    }
    pub fn flow_page(
        &self,
        selection: Option<&RecordSelection>,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<FlowSummary>> {
        if let Some(s) = selection {
            self.validate_selection(s)?;
        }
        if let Some(db) = &self.0.store {
            ctx.check()?;
            return db.flow_page(
                selection.and_then(|s| s.stored.as_deref()),
                offset,
                limit,
                ctx,
            );
        }
        let selected = selection.map(|s| s.ids().iter().collect::<HashSet<_>>());
        self.with_report(|r| {
            let mut all = Vec::new();
            for (key, f) in r.flows.iter().enumerate() {
                ctx.tick(Stage::Flows, None, key, Some(r.flows.len()))?;
                let mut matched = 0;
                for (i, id) in f.evidence_ids.iter().enumerate() {
                    ctx.tick(Stage::Flows, None, i, Some(f.evidence_ids.len()))?;
                    if selected.as_ref().is_none_or(|s| s.contains(id)) {
                        matched += 1;
                    }
                }
                if matched == 0 {
                    continue;
                }
                all.push(FlowSummary {
                    key,
                    source_id: f
                        .evidence_ids
                        .first()
                        .and_then(|id| self.0.index.get(id))
                        .map(|i| r.records[*i].source_id.clone())
                        .unwrap_or_default(),
                    endpoint_a: f.endpoint_a.clone(),
                    endpoint_b: f.endpoint_b.clone(),
                    protocol: f.protocol.clone(),
                    packets: f.packets,
                    matched_packets: matched,
                    bytes: f.bytes,
                    first_seen: f.first_seen.clone(),
                    last_seen: f.last_seen.clone(),
                });
            }
            page(all, offset, limit)
        })?
    }
    pub fn flow_selection(
        &self,
        key: usize,
        selection: Option<&RecordSelection>,
        ctx: &ExecutionContext,
    ) -> Result<RecordSelection> {
        if let Some(s) = selection {
            self.validate_selection(s)?;
        }
        if let Some(db) = &self.0.store {
            return db.flow_selection(
                self.id(),
                key,
                selection.and_then(|s| s.stored.as_deref()),
                ctx,
            );
        }
        let selected = selection.map(|s| s.ids().iter().collect::<HashSet<_>>());
        self.with_report(|r| {
            let f = r
                .flows
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("The network session does not exist"))?;
            let mut ids = Vec::new();
            for (i, id) in f.evidence_ids.iter().enumerate() {
                ctx.tick(Stage::Flows, None, i, Some(f.evidence_ids.len()))?;
                if selected.as_ref().is_none_or(|s| s.contains(id)) {
                    ids.push(id.clone());
                }
            }
            self.select_ids(ids)
        })?
    }
    /// Iterative traversal with explicit context ancestors. No recursive stack growth on deep trees.
    pub fn process_rows(
        &self,
        selection: &RecordSelection,
        ctx: &ExecutionContext,
    ) -> Result<Vec<ProcessRow>> {
        Ok(self.cached_process_rows(selection, ctx)?.as_ref().clone())
    }
    pub fn process_row_page(
        &self,
        selection: &RecordSelection,
        offset: usize,
        limit: usize,
        collapsed: &HashSet<String>,
        focus: Option<&str>,
        ctx: &ExecutionContext,
    ) -> Result<Page<ProcessRow>> {
        crate::storage::page_limit(limit)?;
        let all = self.cached_process_rows(selection, ctx)?;
        if collapsed.is_empty() || focus.is_some() {
            let offset = focus
                .and_then(|id| all.iter().position(|row| row.record_id == id))
                .map_or(offset, |index| index / limit * limit);
            return page_slice(&all, offset, limit);
        }
        let mut hidden = None;
        let mut rows = Vec::new();
        for (i, row) in all.iter().enumerate() {
            ctx.tick(Stage::Query, None, i, Some(all.len()))?;
            if hidden.is_some_and(|depth| row.depth > depth) {
                continue;
            }
            hidden = None;
            if focus.is_none() && collapsed.contains(&row.record_id) {
                hidden = Some(row.depth);
            }
            rows.push(row);
        }
        let offset = focus
            .and_then(|id| rows.iter().position(|row| row.record_id == id))
            .map_or(offset, |index| index / limit * limit);
        Ok(Page {
            offset,
            total: rows.len(),
            items: rows.into_iter().skip(offset).take(limit).cloned().collect(),
        })
    }
    pub fn process_list_rows(
        &self,
        selection: &RecordSelection,
        ids: &[String],
        ctx: &ExecutionContext,
    ) -> Result<Vec<ProcessRow>> {
        let rows = self.cached_process_rows(selection, ctx)?;
        let ids = ids.iter().collect::<HashSet<_>>();
        let mut out = Vec::new();
        for (i, row) in rows.iter().enumerate() {
            ctx.tick(Stage::Query, None, i, Some(rows.len()))?;
            if ids.contains(&row.record_id) {
                let mut row = row.clone();
                row.depth = 0;
                row.has_children = false;
                row.context = false;
                out.push(row);
            }
        }
        Ok(out)
    }
    fn cached_process_rows(
        &self,
        selection: &RecordSelection,
        ctx: &ExecutionContext,
    ) -> Result<std::sync::Arc<Vec<ProcessRow>>> {
        self.validate_selection(selection)?;
        ctx.check()?;
        let version = if let Some(db) = &self.0.store {
            crate::project::content_revision(&*db.lock()?)?
        } else {
            0
        };
        let stored = selection.stored.as_ref();
        if let Some(stored) = stored {
            let cache = stored
                .process_rows
                .lock()
                .map_err(|_| anyhow::anyhow!("The process pagination cache is unavailable"))?;
            if let Some((old, rows)) = &*cache
                && *old == version
            {
                return Ok(rows.clone());
            }
        }
        let forest = if let Some(db) = &self.0.store {
            db.process_forest(ctx)?
        } else {
            std::sync::Arc::new(
                self.with_report(|r| core::process::process_forest_with_context(&r.records, ctx))??,
            )
        };
        let selected = if let Some(db) = &self.0.store {
            let c = db.lock()?;
            let membership = selection
                .stored
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Filter unavailable"))?
                .membership();
            let mut stmt = c.prepare(&format!(
                "SELECT r.id FROM records r WHERE r.kind='process' AND {}",
                membership.predicate
            ))?;
            crate::storage::with_progress(&c, ctx, || {
                Ok(stmt
                    .query_map(rusqlite::params_from_iter(&membership.arguments), |r| {
                        r.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<HashSet<_>>>()?)
            })?
        } else {
            selection.ids().iter().cloned().collect::<HashSet<_>>()
        };
        let mut rows = Vec::new();
        for tree in &forest.trees {
            let nodes = tree
                .nodes
                .iter()
                .map(|n| (&n.record_id, n))
                .collect::<BTreeMap<_, _>>();
            let mut visible = HashSet::new();
            let mut expanded = HashSet::new();
            for (i, node) in tree.nodes.iter().enumerate() {
                ctx.tick(Stage::Query, None, i, Some(tree.nodes.len()))?;
                if !selected.contains(&node.record_id) {
                    continue;
                }
                visible.insert(node.record_id.clone());
                let mut parent = node.parent_id.as_ref();
                let mut walked = HashSet::new();
                while let Some(id) = parent {
                    ctx.check()?;
                    if !walked.insert(id) || !expanded.insert(id) {
                        break;
                    }
                    // An already included ancestor has had its ancestors included as well.
                    visible.insert(id.clone());
                    parent = nodes.get(id).and_then(|n| n.parent_id.as_ref());
                }
            }
            let mut stack = tree
                .roots
                .iter()
                .chain(&tree.cycle_roots)
                .rev()
                .map(|id| (id, 0usize))
                .collect::<Vec<_>>();
            let mut visited = HashSet::new();
            while let Some((id, depth)) = stack.pop() {
                ctx.check()?;
                if !visited.insert(id) || !visible.contains(id) {
                    continue;
                }
                let n = nodes[id];
                rows.push(ProcessRow {
                    record_id: id.clone(),
                    depth,
                    context: !selected.contains(id),
                    orphan: n.orphan,
                    cyclic: n.cyclic,
                    has_children: !n.children.is_empty(),
                });
                stack.extend(n.children.iter().rev().map(|c| (c, depth + 1)));
            }
        }
        let rows = std::sync::Arc::new(rows);
        if let Some(stored) = stored {
            *stored
                .process_rows
                .lock()
                .map_err(|_| anyhow::anyhow!("The process pagination cache is unavailable"))? =
                Some((version, rows.clone()));
        }
        Ok(rows)
    }
}

/// Lightweight finding for a table or inspector; full references are queried separately.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FindingPreview {
    #[serde(flatten)]
    pub finding: Finding,
    pub evidence_count: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub table_preview: bool,
}
fn is_false(value: &bool) -> bool {
    !value
}
impl AnalysisSession {
    pub fn finding_references(
        &self,
        id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Page<String>> {
        crate::storage::page_limit(limit)?;
        if let Some(db) = &self.0.store {
            db.reference_page(id, offset, limit)
        } else {
            self.with_report(|r| {
                let f = r
                    .findings
                    .iter()
                    .find(|f| f.id == id)
                    .ok_or_else(|| anyhow::anyhow!("The finding does not exist"))?;
                Ok(Page {
                    offset,
                    total: f.evidence_ids.len(),
                    items: f
                        .evidence_ids
                        .iter()
                        .skip(offset)
                        .take(limit)
                        .cloned()
                        .collect(),
                })
            })?
        }
    }
    pub fn finding_table_page(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<FindingPreview>> {
        self.finding_previews_inner(filter, offset, limit, ctx, true)
    }
    pub fn finding_preview(&self, id: &str) -> Result<FindingPreview> {
        let mut finding = if let Some(db) = &self.0.store {
            let c = db.lock()?;
            crate::storage::values::<Finding>(&c, "SELECT json FROM findings WHERE id=?1", [id])?
                .into_iter()
                .next()
        } else {
            self.with_report(|r| r.findings.iter().find(|f| f.id == id).cloned())?
        }
        .ok_or_else(|| anyhow::anyhow!("The finding does not exist"))?;
        let refs = self.finding_references(id, 0, 100)?;
        finding.evidence_ids = refs.items;
        Ok(FindingPreview {
            finding,
            evidence_count: refs.total,
            table_preview: false,
        })
    }
    pub fn finding_previews(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
    ) -> Result<Page<FindingPreview>> {
        self.finding_previews_inner(filter, offset, limit, ctx, false)
    }
    fn finding_previews_inner(
        &self,
        filter: &FindingFilter,
        offset: usize,
        limit: usize,
        ctx: &ExecutionContext,
        table: bool,
    ) -> Result<Page<FindingPreview>> {
        crate::storage::page_limit(limit)?;
        ctx.check()?;
        if let Some(db) = &self.0.store {
            let page = db.finding_headers(filter, offset, limit, ctx)?;
            let total = page.total;
            let headers = page.items;
            let mut items = vec![];
            for mut finding in headers {
                ctx.check()?;
                let count = if table {
                    let c = db.lock()?;
                    db.cached_count(
                        &c,
                        "SELECT COUNT(*) FROM finding_refs WHERE finding_id=?1",
                        &[finding.id.clone().into()],
                    )?
                } else {
                    let refs = self.finding_references(&finding.id, 0, 100)?;
                    finding.evidence_ids = refs.items;
                    refs.total
                };
                if table {
                    finding.evidence_ids.clear();
                    finding.description.clear();
                    finding.recommendations.clear();
                }
                items.push(FindingPreview {
                    finding,
                    evidence_count: count,
                    table_preview: table,
                });
            }
            Ok(Page {
                offset,
                total,
                items,
            })
        } else {
            let page = self.finding_page(filter, offset, limit, ctx)?;
            Ok(Page {
                offset,
                total: page.total,
                items: page
                    .items
                    .into_iter()
                    .map(|mut finding| {
                        let count = finding.evidence_ids.len();
                        finding.evidence_ids.truncate(100);
                        if table {
                            finding.evidence_ids.clear();
                            finding.description.clear();
                            finding.recommendations.clear();
                        }
                        FindingPreview {
                            finding,
                            evidence_count: count,
                            table_preview: table,
                        }
                    })
                    .collect(),
            })
        }
    }
    pub fn related_finding_previews(&self, record: &str) -> Result<Vec<FindingPreview>> {
        if let Some(db) = &self.0.store {
            let headers: Vec<Finding> = {
                let c = db.lock()?;
                crate::storage::values(
                    &c,
                    "SELECT f.json FROM findings f WHERE EXISTS(SELECT 1 FROM finding_refs r WHERE r.finding_id=f.id AND r.record_id=?1) ORDER BY severity DESC,ordinal LIMIT 100",
                    [record],
                )?
            };
            let mut items = vec![];
            for mut finding in headers {
                let refs = self.finding_references(&finding.id, 0, 100)?;
                finding.evidence_ids = refs.items;
                items.push(FindingPreview {
                    finding,
                    evidence_count: refs.total,
                    table_preview: false,
                });
            }
            Ok(items)
        } else {
            Ok(self
                .related_findings(record)?
                .into_iter()
                .map(|mut finding| {
                    let count = finding.evidence_ids.len();
                    finding.evidence_ids.truncate(100);
                    FindingPreview {
                        finding,
                        evidence_count: count,
                        table_preview: false,
                    }
                })
                .collect())
        }
    }
}
