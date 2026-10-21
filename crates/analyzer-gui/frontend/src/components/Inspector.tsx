import {
  FileText,
  Link2,
  PanelRightClose,
  ShieldCheck,
  ExternalLink,
  LoaderCircle,
} from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { Button } from "./ui/button";
import { api } from "../lib/api";
import { Pagination } from "./Pagination";
import { Tabs } from "./ui/tabs";
import { basename, bytes } from "../lib/utils";
import { logFieldLabel } from "../lib/field-labels";
import {
  severityLabel,
  statusLabel,
  type Source,
  type Finding,
  type DetailResponse,
} from "../types";
export function Risk({ finding }: { finding: Finding }) {
  return (
    <span className={`risk risk-${finding.severity}`}>
      <span className="risk-dot" />
      {severityLabel[finding.severity]}
    </span>
  );
}
function Field({
  name,
  value,
  mono = false,
  originalName,
}: {
  name: string;
  value: string | null | undefined;
  mono?: boolean;
  originalName?: string;
}) {
  return (
    <div className="detail-field">
      <span title={originalName}>{name}</span>
      <div className={mono ? "mono" : ""}>{value || "Unknown"}</div>
    </div>
  );
}
export function Inspector({
  finding,
  detail,
  loading,
  onJump,
  onFinding,
  onClose,
  onSaveNote,
  sessionId,
}: {
  finding: Finding | null;
  detail: DetailResponse | null;
  loading: boolean;
  onJump: (id: string) => void;
  onFinding: (f: Finding) => void;
  onClose: () => void;
  onSaveNote?: (text: string) => Promise<void>;
  sessionId?: number | null;
}) {
  const [refs, setRefs] = useState(finding?.evidence_ids ?? []);
  const [refOffset, setRefOffset] = useState(0);
  const [refError, setRefError] = useState("");
  const [refsLoading, setRefsLoading] = useState(false);
  const refsRevision = useRef(0);
  useEffect(() => {
    refsRevision.current++;
    setRefs(finding?.evidence_ids ?? []);
    setRefOffset(0);
    setRefError("");
    setRefsLoading(false);
    return () => {
      refsRevision.current++;
    };
  }, [finding?.id, finding?.evidence_ids, sessionId]);
  const loadRefs = async (offset: number) => {
    if (!finding || sessionId == null) return;
    const revision = ++refsRevision.current;
    setRefsLoading(true);
    setRefError("");
    try {
      const page = await api.findingRefs(sessionId, finding.id, offset);
      if (revision !== refsRevision.current) return;
      setRefs(page.items);
      setRefOffset(page.offset);
    } catch (e) {
      if (revision === refsRevision.current) setRefError(String(e));
    } finally {
      if (revision === refsRevision.current) setRefsLoading(false);
    }
  };
  const [note, setNote] = useState(detail?.note ?? "");
  const [savingNote, setSavingNote] = useState(false);
  useEffect(
    () => setNote(detail?.note ?? ""),
    [detail?.record.id, detail?.note],
  );
  const [tab, setTab] = useState("explanation");
  useEffect(
    () => setTab(finding ? "explanation" : "fields"),
    [finding?.id, detail?.record.id],
  );
  const fields = detail?.record.data;
  return (
    <div className="inspector-content">
      <div className="inspector-heading">
        <span>
          <FileText size={15} />
          Evidence details
        </span>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Collapse details"
          onClick={onClose}
        >
          <PanelRightClose size={15} />
        </Button>
      </div>
      {!finding && !detail ? (
        <div className="inspector-empty">
          {loading ? (
            <LoaderCircle className="spin" size={25} />
          ) : (
            <FileText size={30} strokeWidth={1} />
          )}
          <strong>
            {loading
              ? "Reading evidence"
              : "Select a finding or evidence record"}
          </strong>
          <p>
            Review the explanation and raw records,
            <br />
            tracing each analysis result.
          </p>
        </div>
      ) : (
        <>
          <Tabs
            value={tab}
            onChange={setTab}
            items={
              finding
                ? [
                    { value: "explanation", label: "Explanation" },
                    { value: "references", label: "Evidence references" },
                  ]
                : [
                    { value: "fields", label: "Fields" },
                    { value: "raw", label: "Raw" },
                    { value: "source", label: "Source" },
                    ...(onSaveNote ? [{ value: "note", label: "Note" }] : []),
                  ]
            }
          />
          <div className="inspector-scroll">
            {loading && finding?.table_preview && (
              <p className="muted">Reading finding details…</p>
            )}
            {finding &&
              (tab === "references" || tab === "explanation") &&
              (finding.evidence_count ?? 0) > 100 && (
                <Pagination
                  label="Evidence references"
                  offset={refOffset}
                  total={finding.evidence_count || 0}
                  limit={100}
                  loading={loading || refsLoading}
                  onPage={(offset) => void loadRefs(offset)}
                />
              )}
            {refError && <p role="alert">{refError}</p>}

            {detail && tab === "note" && onSaveNote && (
              <div className="evidence-note">
                <label>
                  Evidence note
                  <textarea
                    aria-label="Evidence note"
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </label>
                <Button
                  disabled={savingNote}
                  onClick={() => {
                    setSavingNote(true);
                    void onSaveNote(note).finally(() => setSavingNote(false));
                  }}
                >
                  Save note
                </Button>
              </div>
            )}
            {finding && tab === "explanation" && (
              <>
                <div className="detail-eyebrow">
                  <Risk finding={finding} />
                  <span className="small-badge">
                    {finding.origin.startsWith("local:")
                      ? "Local rules"
                      : "AI finding"}
                  </span>
                </div>
                <h3>{finding.title}</h3>
                <p className="detail-description">{finding.description}</p>
                <div className="detail-section">
                  <h4>
                    <ShieldCheck size={14} />
                    Recommended checks
                  </h4>
                  {finding.recommendations.map((r, i) => (
                    <div className="recommendation" key={i}>
                      <span>{i + 1}</span>
                      <p>{r}</p>
                    </div>
                  ))}
                </div>
                <div className="detail-section">
                  <h4>
                    <Link2 size={14} />
                    Linked evidence{" "}
                    <small>
                      {finding.evidence_count ?? finding.evidence_ids.length}
                    </small>
                  </h4>
                  {refs.map((id) => (
                    <button
                      className="evidence-link"
                      key={id}
                      onClick={() => onJump(id)}
                    >
                      <span className="mono">{id}</span>
                      <ExternalLink size={12} />
                    </button>
                  ))}
                </div>
                <Field name="Finding origin" value={finding.origin} mono />
                <div className="detail-note">
                  Analysis results are leads to verify; confirm them against the
                  raw evidence.
                </div>
              </>
            )}
            {finding && tab === "references" && (
              <>
                <p className="muted">
                  Click a reference to jump to and locate the raw record.
                </p>
                {refs.map((id) => (
                  <button
                    className="evidence-link"
                    key={id}
                    onClick={() => onJump(id)}
                  >
                    <span className="mono">{id}</span>
                    <ExternalLink size={12} />
                  </button>
                ))}
              </>
            )}
            {detail && tab === "fields" && (
              <>
                <div className="detail-eyebrow">
                  <span className="small-badge">
                    {statusLabel[detail.record.status]}
                  </span>
                  <span className="muted">
                    {basename(detail.source?.path || "")}
                  </span>
                </div>
                <Field name="Evidence ID" value={detail.record.id} mono />
                <Field name="Time" value={detail.record.timestamp} mono />
                <Field name="Position" value={detail.record.position} mono />
                {fields?.kind === "log" && (
                  <>
                    <Field name="Category" value={fields.fields.category} />
                    {Object.entries(fields.fields.fields).map(([k, v]) => (
                      <Field
                        key={k}
                        name={logFieldLabel(k)}
                        originalName={k}
                        value={v}
                        mono
                      />
                    ))}
                  </>
                )}
                {fields?.kind === "process" && (
                  <>
                    <div className="detail-pair">
                      <Field
                        name="PID"
                        value={String(fields.fields.pid)}
                        mono
                      />
                      <Field
                        name="Parent PID"
                        value={
                          fields.fields.parent_pid === null
                            ? "Unknown"
                            : String(fields.fields.parent_pid)
                        }
                        mono
                      />
                    </div>
                    <Field name="Name" value={fields.fields.name} />
                    <Field name="Path" value={fields.fields.path} mono />
                    <Field
                      name="Command line"
                      value={fields.fields.command.join(" ")}
                      mono
                    />
                    <Field name="User" value={fields.fields.user} />
                  </>
                )}
                {fields?.kind === "packet" && (
                  <>
                    <Field
                      name="Source endpoint"
                      value={`${fields.fields.source || "Unknown"}:${fields.fields.source_port ?? "—"}`}
                      mono
                    />
                    <Field
                      name="Destination endpoint"
                      value={`${fields.fields.destination || "Unknown"}:${fields.fields.destination_port ?? "—"}`}
                      mono
                    />
                    <div className="detail-pair">
                      <Field name="Protocol" value={fields.fields.protocol} />
                      <Field
                        name="Bytes"
                        value={`${fields.fields.captured_bytes} / ${fields.fields.original_bytes}`}
                        mono
                      />
                    </div>
                    {Object.entries(fields.fields.application).map(([k, v]) => (
                      <Field key={k} name={k} value={v} mono />
                    ))}
                    {fields.fields.payload_hex && (
                      <details className="raw-reply">
                        <summary>Payload hex</summary>
                        <pre>{fields.fields.payload_hex}</pre>
                      </details>
                    )}
                  </>
                )}
                {detail.related.length > 0 && (
                  <div className="detail-section">
                    <h4>
                      Related findings <small>{detail.related.length}</small>
                    </h4>
                    {detail.related.map((f) => (
                      <button
                        className="related-finding"
                        key={f.id}
                        onClick={() => onFinding(f)}
                      >
                        <Risk finding={f} />
                        <span>{f.title}</span>
                      </button>
                    ))}
                  </div>
                )}
              </>
            )}
            {detail && tab === "raw" && (
              <>
                <div className="detail-note">
                  {fields?.kind === "packet"
                    ? "Raw captured packet · hex"
                    : "Raw record · preserved as captured"}
                </div>
                <pre className="raw-evidence">{detail.record.raw}</pre>
              </>
            )}
            {detail && tab === "source" && (
              <>
                <Field name="Source path" value={detail.source?.path} mono />
                <Field name="Format" value={detail.source?.format} />
                <Field
                  name="Size"
                  value={detail.source ? bytes(detail.source.bytes) : null}
                />
                <Field name="SHA-256" value={detail.source?.sha256} mono />
                <Field name="Source ID" value={detail.record.source_id} mono />
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export function SourceInspector({
  source,
  onClose,
}: {
  source: Source;
  onClose: () => void;
}) {
  return (
    <div className="inspector-content">
      <div className="inspector-heading">
        <span>
          <FileText size={15} />
          Source details
        </span>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Collapse details"
          onClick={onClose}
        >
          <PanelRightClose size={15} />
        </Button>
      </div>
      <div className="inspector-scroll">
        <div className="detail-eyebrow">
          <span className="small-badge">{source.format}</span>
        </div>
        <h3>{basename(source.path)}</h3>
        <Field name="Full path" value={source.path} mono />
        <Field name="Format" value={source.format} />
        <Field
          name="Size"
          value={`${bytes(source.bytes)} · ${source.bytes.toLocaleString()} bytes`}
          mono
        />
        <Field name="SHA-256" value={source.sha256} mono />
        <Field name="Source ID" value={source.id} mono />
        <div className="detail-note">
          Hashes are computed from the original file. Exported reports keep all
          sources and complete evidence.
        </div>
      </div>
    </div>
  );
}
