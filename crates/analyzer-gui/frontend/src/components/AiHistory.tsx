import { useState, useRef, useEffect } from "react";
import {
  History,
  ChevronDown,
  CheckCircle2,
  AlertCircle,
  LoaderCircle,
} from "lucide-react";
import { api } from "../lib/api";
import { number } from "../lib/utils";
import { Pagination } from "./Pagination";
import { AiLocalSummary } from "./AiLocalSummary";
import type { RunSummary, AiBatch, Page } from "../types";
export function AiHistory({
  runs,
  sessionId,
  onOffset,
  onError,
  initiallyOpen = false,
  busy = false,
}: {
  initiallyOpen?: boolean;
  busy?: boolean;
  runs: Page<RunSummary> | undefined;
  sessionId: number;
  onOffset: (v: number) => void;
  onError: (s: string) => void;
}) {
  const [open, setOpen] = useState(initiallyOpen),
    [expanded, setExpanded] = useState<number | null>(null),
    [batches, setBatches] = useState<Page<AiBatch> | null>(null),
    [loading, setLoading] = useState(false);
  const revision = useRef(0);
  useEffect(
    () => () => {
      revision.current++;
    },
    [sessionId],
  );
  async function load(run: number, offset = 0) {
    const current = ++revision.current;
    setExpanded(run);
    if (expanded !== run) setBatches(null);
    setLoading(true);
    try {
      const page = await api.batches(sessionId, run, offset);
      if (current === revision.current) setBatches(page);
    } catch (e) {
      if (current === revision.current) onError(String(e));
    } finally {
      if (current === revision.current) setLoading(false);
    }
  }
  return (
    <div className="history-panel">
      <button className="history-toggle" onClick={() => setOpen(!open)}>
        <History size={14} />
        <span>Run history</span>
        <span className="small-badge">{runs?.total || 0}</span>
        {runs?.items[0] && (
          <small>
            Latest: {runs.items[0].completed}/{runs.items[0].batches} batches ·{" "}
            {number(runs.items[0].analyzed)} records
          </small>
        )}
        <ChevronDown size={13} className={open ? "rotated" : ""} />
      </button>
      {open && (
        <div className="history-scroll">
          {runs?.items.map((run) => (
            <div key={run.index} className="run-item">
              <button
                onClick={() =>
                  expanded === run.index ? setExpanded(null) : load(run.index)
                }
              >
                {run.completed === run.batches ? (
                  <CheckCircle2 size={14} className="success" />
                ) : (
                  <AlertCircle size={14} className="warning" />
                )}
                <strong>#{run.index + 1}</strong>
                <span>{run.model}</span>
                <small>
                  Analyzed {number(run.analyzed)}/{number(run.selected)} records
                  · {run.completed}/{run.batches} batches
                </small>
                <ChevronDown size={12} />
              </button>
              {expanded === run.index && (
                <div className="batch-list">
                  {run.local_summary && (
                    <AiLocalSummary text={run.local_summary} />
                  )}
                  {loading ? (
                    <LoaderCircle className="spin" size={15} />
                  ) : (
                    batches?.items.map((batch) => (
                      <details key={batch.index}>
                        <summary>
                          Batch {batch.index} · {batch.evidence_ids.length}{" "}
                          records · {batch.attempts.length} replies
                          {batch.error && (
                            <span className="warning"> incomplete</span>
                          )}
                        </summary>
                        {batch.error && (
                          <p className="warning">{batch.error}</p>
                        )}
                        {batch.attempts.map((a, i) => (
                          <details className="raw-reply" key={i}>
                            <summary>Raw reply {i + 1}</summary>
                            {a.error && <p className="warning">{a.error}</p>}
                            <pre>{a.response || "No reply content"}</pre>
                          </details>
                        ))}
                      </details>
                    ))
                  )}
                  {batches && (
                    <Pagination
                      label="AI batch"
                      offset={batches.offset}
                      total={batches.total}
                      limit={10}
                      loading={loading || busy}
                      onPage={(offset) => void load(run.index, offset)}
                    />
                  )}
                </div>
              )}
            </div>
          ))}
          {!runs?.items.length && (
            <p className="muted">No AI analysis has run yet.</p>
          )}
          {runs && (
            <Pagination
              label="AI runs"
              offset={runs.offset}
              total={runs.total}
              limit={20}
              loading={busy}
              onPage={(offset) => {
                revision.current++;
                setExpanded(null);
                setBatches(null);
                onOffset(offset);
              }}
            />
          )}
        </div>
      )}
    </div>
  );
}
