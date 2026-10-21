use super::*;

fn project() -> AnalysisSession {
    ProjectService::create(ProjectInfo::new("Synthetic performance check", "synthetic client")).unwrap()
}
fn append(session: &AnalysisSession, label: &str, text: &str) {
    ProjectService::append(
        session,
        &AnalysisRequest {
            inputs: vec![AnalysisInput::Bytes {
                label: label.into(),
                bytes: text.as_bytes().into(),
            }],
            ..Default::default()
        },
        &ExecutionContext::default(),
    )
    .unwrap();
}

#[test]
#[ignore = "set EASY_ANALYZER_BENCH_PROJECT to a local .eair file"]
fn verify_large_project_page_consistency() {
    use rusqlite::types::Value;
    use std::time::Instant;
    let path = std::env::var_os("EASY_ANALYZER_BENCH_PROJECT").expect("project path required");
    let ctx = ExecutionContext::default();
    let session = ProjectService::open(std::path::Path::new(&path), &ctx).unwrap();
    let overview = session.overview(&ctx).unwrap();
    let source = session.source_page(0, 1).unwrap().items.remove(0).id;
    let category = overview.categories.first().cloned().unwrap_or_default();
    let db = session.0.store.as_ref().unwrap();
    let mut checks = 0;
    let mut maximum = 0.0_f64;
    for dimension in ["all", "source", "category", "status"] {
        for order in [RecordOrder::OriginalAsc, RecordOrder::OriginalDesc] {
            let filter = RecordFilter {
                kind: RecordKind::Log,
                source: (dimension == "source").then(|| source.clone()),
                category: (dimension == "category").then(|| category.clone()),
                status: (dimension == "status").then_some(core::ParseStatus::Parsed),
                order,
                ..Default::default()
            };
            let start = Instant::now();
            let selected = session.select_records(&filter, &ctx).unwrap();
            let selection_seconds = start.elapsed().as_secs_f64();
            let mut dimension_maximum = 0.0_f64;
            let (condition, args): (&str, Vec<Value>) = match dimension {
                "source" => ("source_id=?", vec![source.clone().into()]),
                "category" => ("category=?", vec![category.clone().into()]),
                "status" => (
                    "status=?",
                    vec![json(&core::ParseStatus::Parsed).unwrap().into()],
                ),
                _ => ("1=1", vec![]),
            };
            let direction = if order == RecordOrder::OriginalAsc {
                "ASC"
            } else {
                "DESC"
            };
            let total = {
                let c = db.lock().unwrap();
                c.query_row(
                    &format!("SELECT COUNT(*) FROM records WHERE kind='log' AND {condition}"),
                    rusqlite::params_from_iter(&args),
                    |r| r.get::<_, i64>(0).map(|n| n as usize),
                )
                .unwrap()
            };
            assert_eq!(selected.len(), total);
            for limit in [50, 100, 200] {
                let last = total.saturating_sub(1) / limit * limit;
                for offset in [
                    last,
                    total / 2 / limit * limit,
                    limit,
                    0,
                    total / 3 / limit * limit,
                ] {
                    ctx.check().unwrap();
                    let start = Instant::now();
                    let page = session
                        .page_metadata(Some(&selected), offset, limit)
                        .unwrap();
                    let seconds = start.elapsed().as_secs_f64();
                    maximum = maximum.max(seconds);
                    dimension_maximum = dimension_maximum.max(seconds);
                    let expected = {
                        let c = db.lock().unwrap();
                        let mut params = args.clone();
                        params
                            .extend([Value::Integer(limit as i64), Value::Integer(offset as i64)]);
                        c.prepare(&format!("SELECT id FROM records WHERE kind='log' AND {condition} ORDER BY ordinal {direction} LIMIT ? OFFSET ?"))
                            .unwrap().query_map(rusqlite::params_from_iter(params), |r| r.get::<_, String>(0))
                            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
                    };
                    assert_eq!(page.offset, offset);
                    assert_eq!(page.total, total);
                    assert_eq!(
                        page.items.iter().map(|r| &r.id).collect::<Vec<_>>(),
                        expected.iter().collect::<Vec<_>>(),
                        "{dimension} {order:?} {offset}/{limit}"
                    );
                    checks += 1;
                }
                assert!(
                    session
                        .page_metadata(Some(&selected), total, limit)
                        .unwrap()
                        .items
                        .is_empty()
                );
                assert!(
                    session
                        .page_metadata(Some(&selected), usize::MAX, limit)
                        .unwrap()
                        .items
                        .is_empty()
                );
                checks += 2;
            }
            println!(
                "large_project_dimension={dimension} order={order:?} total={total} selection_seconds={selection_seconds:.4} maximum_page_seconds={dimension_maximum:.4}"
            );
        }
    }
    println!(
        "large_project_consistency_checks={checks} records={} maximum_page_seconds={maximum:.4}",
        overview.records
    );
}

#[test]
fn typed_selection_is_lazy_frozen_and_materializes_only_when_requested() {
    let session = project();
    append(&session, "first.log", "alpha\nbeta\ngamma");
    let ctx = ExecutionContext::default();
    let selected = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Log,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    let db = session.0.store.as_ref().unwrap();
    assert_eq!(selected.len(), 3);
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        0
    );
    let page = session.page_metadata(Some(&selected), 1, 2).unwrap();
    assert_eq!(
        session
            .locate_record(Some(&selected), &page.items[1].id)
            .unwrap(),
        Some(2)
    );
    append(&session, "later.log", "delta");
    let current = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Log,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(current.len(), 4);
    assert_eq!(selected.len(), 3);
    assert!(
        session
            .page(Some(&selected), 3, 1)
            .unwrap()
            .items
            .is_empty()
    );
    let last = session.page(Some(&current), 3, 1).unwrap().items.remove(0);
    assert_eq!(
        session.locate_record(Some(&selected), &last.id).unwrap(),
        None
    );
    let token = CancellationToken::default();
    token.cancel();
    assert!(
        selected
            .stored_id(&ExecutionContext::new(token, |_| {}))
            .is_err()
    );
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        0
    );
    session.set_selection(Some(&selected), &ctx).unwrap();
    assert_eq!(selected.try_ids().unwrap().len(), 3);
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        3
    );
    let mut report = Vec::new();
    ExportPlan {
        format: OutputFormat::Json,
        ..Default::default()
    }
    .write_primary(&session, &mut report, &ctx)
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(report["query_matches"].as_array().unwrap().len(), 3);
    assert_eq!(report["records"].as_array().unwrap().len(), 4);
}

#[test]
fn a_small_source_page_does_not_scan_the_larger_kind_index() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let session = project();
    append(
        &session,
        "wide.log",
        &(0..10000)
            .map(|i| format!("wide record {i}\n"))
            .collect::<String>(),
    );
    append(
        &session,
        "narrow.log",
        "narrow one\nnarrow two\nnarrow three",
    );
    let source = session.source_page(1, 1).unwrap().items.remove(0).id;
    let ctx = ExecutionContext::default();
    for order in [RecordOrder::OriginalAsc, RecordOrder::OriginalDesc] {
        let selected = session
            .select_records(
                &RecordFilter {
                    kind: RecordKind::Log,
                    source: Some(source.clone()),
                    order,
                    ..Default::default()
                },
                &ctx,
            )
            .unwrap();
        assert_eq!(selected.len(), 3);
        let work = Arc::new(AtomicUsize::new(0));
        let count = work.clone();
        let db = session.0.store.as_ref().unwrap();
        db.lock()
            .unwrap()
            .progress_handler(
                1000,
                Some(move || {
                    count.fetch_add(1, Ordering::Relaxed);
                    false
                }),
            )
            .unwrap();
        let page = session.page_metadata(Some(&selected), 2, 1).unwrap();
        db.lock()
            .unwrap()
            .progress_handler(0, None::<fn() -> bool>)
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].source_id, source);
        assert_eq!(
            work.load(Ordering::Relaxed),
            0,
            "a tiny source page must not examine thousands of unrelated log records"
        );
    }
}

#[test]
fn selection_cache_is_bounded_refreshes_and_does_not_retain_closed_projects() {
    let session = project();
    append(
        &session,
        "cache.log",
        "needle0 example.com\nneedle1\nneedle2\nneedle3\nneedle4\nneedle5",
    );
    let weak = Arc::downgrade(session.0.store.as_ref().unwrap());
    let ctx = ExecutionContext::default();
    let query = QueryOptions {
        expression: Some("needle0".into()),
        ..Default::default()
    };
    let first = session.query(&query, &ctx).unwrap();
    session.overview(&ctx).unwrap();
    let content_version = session
        .0
        .store
        .as_ref()
        .unwrap()
        .overview_cache
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .0;
    let id = session.page(Some(&first), 0, 1).unwrap().items[0]
        .id
        .clone();
    ProjectService::note(&session, &id, "note-only update", &ctx).unwrap();
    ProjectService::save_view_state(&session, &serde_json::json!({"offset":100})).unwrap();
    session.overview(&ctx).unwrap();
    assert_eq!(
        session
            .0
            .store
            .as_ref()
            .unwrap()
            .overview_cache
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .0,
        content_version
    );
    let again = session.query(&query, &ctx).unwrap();
    assert!(Arc::ptr_eq(
        first.stored.as_ref().unwrap(),
        again.stored.as_ref().unwrap()
    ));
    append(&session, "later.log", "needle0");
    let fresh = session.query(&query, &ctx).unwrap();
    assert_eq!(fresh.len(), 2);
    assert_eq!(first.len(), 1);
    let suspicious = session
        .query(
            &QueryOptions {
                suspicious: true,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    IocService::add_value(&session, "example.com", None, "", &ctx).unwrap();
    IocService::scan(&session, true, &ctx).unwrap();
    assert!(
        session
            .query(
                &QueryOptions {
                    suspicious: true,
                    ..Default::default()
                },
                &ctx
            )
            .unwrap()
            .len()
            > suspicious.len()
    );
    drop((first, again, fresh, suspicious));
    for i in 0..6 {
        session
            .query(
                &QueryOptions {
                    expression: Some(format!("needle{i}")),
                    ..Default::default()
                },
                &ctx,
            )
            .unwrap();
    }
    assert_eq!(session.0.selections.lock().unwrap().len(), 4);
    assert_eq!(
        scalar(
            &session.0.store.as_ref().unwrap().lock().unwrap(),
            "SELECT COUNT(*) FROM selections"
        )
        .unwrap(),
        4
    );
    drop(session);
    assert!(weak.upgrade().is_none());
}

#[test]
fn process_and_flow_views_use_frozen_predicates_and_refresh_the_forest() {
    let session = project();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let ctx = ExecutionContext::default();
    ProjectService::append(
        &session,
        &AnalysisRequest {
            inputs: vec![
                AnalysisInput::File(root.join("processes.json")),
                AnalysisInput::File(root.join("sample.pcapng")),
            ],
            ..Default::default()
        },
        &ctx,
    )
    .unwrap();
    let packets = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Packet,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    let flows = session.flow_page(Some(&packets), 0, 100, &ctx).unwrap();
    assert!(!flows.items.is_empty());
    assert_eq!(
        flows.items.iter().map(|f| f.matched_packets).sum::<usize>(),
        packets.len()
    );
    let flow = session
        .flow_selection(flows.items[0].key, Some(&packets), &ctx)
        .unwrap();
    assert_eq!(flow.len(), flows.items[0].matched_packets);
    drop(flow);
    let processes = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Process,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(
        session.process_rows(&processes, &ctx).unwrap().len(),
        processes.len()
    );
    let db = session.0.store.as_ref().unwrap();
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        0
    );
    let forest = db.process_forest(&ctx).unwrap();
    assert!(Arc::ptr_eq(&forest, &db.process_forest(&ctx).unwrap()));
    let old_count = forest.trees.iter().map(|t| t.nodes.len()).sum::<usize>();
    append(
        &session,
        "additional-process.json",
        r#"[{"pid":999,"name":"synthetic-process","parent_pid":null,"command":[]}]"#,
    );
    let fresh = db.process_forest(&ctx).unwrap();
    assert_eq!(
        fresh.trees.iter().map(|t| t.nodes.len()).sum::<usize>(),
        old_count + 1
    );
    assert!(!Arc::ptr_eq(&forest, &fresh));
}

#[test]
fn diagnostic_caches_and_paged_ai_headers_refresh_without_loading_replies() {
    let session = project();
    let db = session.0.store.as_ref().unwrap();
    let ctx = ExecutionContext::default();
    assert_eq!(db.diagnostic_levels(&ctx).unwrap(), (0, 0));
    assert_eq!(session.diagnostic_count().unwrap(), 0);
    {
        let c = db.lock().unwrap();
        for i in 0..45 {
            let run = core::AiRun {
                model: format!("synthetic-{i}"),
                endpoint: "https://api.invalid".into(),
                batches: 1,
                analyzed_records: 0,
                include_payload: false,
                completed_batches: Some(0),
                selected_records: Some(0),
                batch_results: vec![],
            };
            c.execute(
                "INSERT INTO ai_runs(json) VALUES(?1)",
                [json(&run).unwrap()],
            )
            .unwrap();
        }
        c.execute(
            "INSERT INTO diagnostics(json) VALUES(?1)",
            [packed_json(&core::Diagnostic {
                level: DiagnosticLevel::Error,
                source: "Synthetic diagnostics".into(),
                position: None,
                message: "synthetic error diagnostic".repeat(100),
            })
            .unwrap()],
        )
        .unwrap();
    }
    assert_eq!(session.diagnostic_count().unwrap(), 1);
    assert_eq!(db.diagnostic_levels(&ctx).unwrap(), (1, 0));
    let page = session.ai_run_header_page(20, 20).unwrap();
    assert_eq!(page.total, 45);
    assert_eq!(page.items.len(), 20);
    assert_eq!(page.items[0].0, 24);
    assert_eq!(page.items[19].0, 5);
    assert!(page.items.iter().all(|(_, r)| r.batch_results.is_empty()));
    assert!(
        session
            .ai_run_header_page(999, 20)
            .unwrap()
            .items
            .is_empty()
    );
    let token = CancellationToken::default();
    token.cancel();
    assert!(
        db.diagnostic_levels(&ExecutionContext::new(token, |_| {}))
            .is_err()
    );
}

#[test]
fn findings_and_reference_pages_preserve_order_refresh_after_writes_and_save_cleanly() {
    let session = project();
    let text = (0..150)
        .map(|i| format!("synthetic record {i}\n"))
        .collect::<String>();
    append(&session, "synthetic-pagination.log", &text);
    let ids = session
        .page_metadata(None, 0, 200)
        .unwrap()
        .items
        .into_iter()
        .map(|r| r.id)
        .collect::<Vec<_>>();
    let ctx = ExecutionContext::default();
    let db = session.0.store.as_ref().unwrap();
    let base = core::Finding {
        id: "finding-0".into(),
        origin: "local:synthetic".into(),
        severity: core::Severity::Info,
        title: "Synthetic finding".into(),
        description: "Complete explanation retained".into(),
        evidence_ids: ids[..125].to_vec(),
        confidence: 0.5,
        recommendations: vec!["Read-only investigation".into()],
    };
    {
        let c = db.lock().unwrap();
        for i in 0..125 {
            let finding = core::Finding {
                id: format!("finding-{i}"),
                origin: if i % 2 == 0 {
                    "local:synthetic"
                } else {
                    "ai:synthetic"
                }
                .into(),
                severity: [
                    core::Severity::Info,
                    core::Severity::Low,
                    core::Severity::Medium,
                    core::Severity::High,
                    core::Severity::Critical,
                ][i % 5]
                    .clone(),
                evidence_ids: if i == 0 {
                    ids[..125].to_vec()
                } else {
                    vec![ids[i].clone()]
                },
                ..base.clone()
            };
            Database::insert_finding(&c, &finding).unwrap();
        }
        crate::project::touch(&c).unwrap();
    }
    for origin in [FindingOrigin::All, FindingOrigin::Local, FindingOrigin::Ai] {
        let filter = FindingFilter {
            origin,
            ..Default::default()
        };
        let expected = {
            let c = db.lock().unwrap();
            let clause = match origin {
                FindingOrigin::All => "1=1",
                FindingOrigin::Local => "origin LIKE 'local:%'",
                FindingOrigin::Ai => "origin NOT LIKE 'local:%'",
            };
            c.prepare(&format!(
                "SELECT id FROM findings WHERE {clause} ORDER BY severity DESC,ordinal"
            ))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };
        for offset in [0, 25, 50, 100, 125, 999] {
            let page = session
                .finding_table_page(&filter, offset, 50, &ctx)
                .unwrap();
            assert_eq!(page.total, expected.len());
            assert_eq!(
                page.items
                    .iter()
                    .map(|f| f.finding.id.clone())
                    .collect::<Vec<_>>(),
                expected
                    .iter()
                    .skip(offset)
                    .take(50)
                    .cloned()
                    .collect::<Vec<_>>()
            );
            assert!(page.items.iter().all(|f| f.table_preview
                && f.finding.evidence_ids.is_empty()
                && f.finding.description.is_empty()));
        }
    }
    let tail = session.finding_references("finding-0", 100, 50).unwrap();
    assert_eq!(tail.total, 125);
    assert_eq!(tail.items, ids[100..125]);
    {
        let c = db.lock().unwrap();
        Database::insert_finding(
            &c,
            &core::Finding {
                evidence_ids: ids.clone(),
                ..base
            },
        )
        .unwrap();
        crate::project::touch(&c).unwrap();
    }
    assert_eq!(
        session
            .finding_references("finding-0", 100, 50)
            .unwrap()
            .items,
        ids[100..]
    );
    let full = session.finding_preview("finding-0").unwrap();
    assert_eq!(full.evidence_count, 150);
    assert_eq!(full.finding.evidence_ids.len(), 100);
    assert_eq!(full.finding.description, "Complete explanation retained");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pagination.eair");
    ProjectService::save(
        &session,
        &path,
        &dir.path().join("config.toml"),
        false,
        &ctx,
    )
    .unwrap();
    let reopened = ProjectService::open(&path, &ctx).unwrap();
    assert_eq!(
        reopened
            .finding_references("finding-0", 100, 50)
            .unwrap()
            .items,
        ids[100..]
    );
}

#[test]
fn ioc_pages_refresh_after_rescans_replace_sparse_matches() {
    let session = project();
    let ctx = ExecutionContext::default();
    let text = (0..225)
        .map(|i| {
            format!(
                "record {i} {}\n",
                if i % 9 == 0 {
                    "example.test"
                } else {
                    "sub.example.test"
                }
            )
        })
        .collect::<String>();
    append(&session, "synthetic-ioc-pages.log", &text);
    IocService::add_value(&session, "example.test", None, "synthetic", &ctx).unwrap();
    for (subdomains, total) in [(true, 225), (false, 25), (true, 225)] {
        assert!(
            IocService::scan(&session, subdomains, &ctx)
                .unwrap()
                .complete
        );
        let db = session.0.store.as_ref().unwrap();
        let expected = {
            let c = db.lock().unwrap();
            c.prepare("SELECT record_id FROM ioc_matches ORDER BY ordinal")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(expected.len(), total);
        for offset in [200, 100, 0, 24, 20, 25, usize::MAX] {
            let page = IocService::matches(&session, offset, 100).unwrap();
            assert_eq!(page.total, total);
            assert_eq!(
                page.items
                    .iter()
                    .map(|hit| &hit.record_id)
                    .collect::<Vec<_>>(),
                expected.iter().skip(offset).take(100).collect::<Vec<_>>()
            );
        }
    }
}
