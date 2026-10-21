import {
  UploadCloud,
  Plus,
  X,
  FileText,
  FolderOpen,
  ChevronDown,
  ArrowRight,
  ShieldCheck,
} from "lucide-react";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
import { Select } from "./ui/select";
import { basename } from "../lib/utils";
import type { ImportRequest } from "../types";
export function ImportView({
  request,
  onChange,
  busy,
  platform,
  onPick,
  onStart,
  dragging,
  elevated,
  elevationError,
  elevationBusy,
  onElevate,
}: {
  request: ImportRequest;
  onChange: (v: ImportRequest) => void;
  busy: boolean;
  platform: string;
  onPick: (kind: string) => void;
  onStart: () => void;
  dragging: boolean;
  elevated: boolean | null;
  elevationError: string | null;
  elevationBusy: boolean;
  onElevate: () => void;
}) {
  return (
    <div className="import-page">
      <div className="import-scroll">
        <button
          className={`drop-zone ${dragging ? "dragging" : ""}`}
          onClick={() => onPick("inputs")}
          disabled={busy}
        >
          <div className="drop-icon">
            <UploadCloud size={23} strokeWidth={1.5} />
          </div>
          <div>
            <strong>Drop evidence files to start analysis</strong>
            <p>EVTX, system logs, web logs, process snapshots, PCAP / PCAPNG</p>
          </div>
          <span className="btn btn-secondary">
            <Plus size={14} />
            Select files
          </span>
        </button>
        <div className="collection-row">
          <Checkbox
            label="Capture local processes"
            checked={request.live}
            disabled={busy}
            onChange={(live) => onChange({ ...request, live })}
          />
          <span
            title={
              platform === "macos"
                ? "macOS does not yet support local generic log collection; import offline logs."
                : ""
            }
          >
            <Checkbox
              label="Load local logs"
              checked={request.auto_logs}
              disabled={busy || platform === "macos"}
              onChange={(auto_logs) => onChange({ ...request, auto_logs })}
            />
          </span>
          <Button
            variant="ghost"
            size="sm"
            disabled={busy}
            onClick={() => onPick("capture")}
          >
            <FolderOpen size={14} />
            Capture output directory
          </Button>
        </div>
        {platform === "windows" && (
          <div className="collection-permissions">
            <div>
              <span className="small-badge" title={elevationError || undefined}>
                <ShieldCheck size={13} />
                {elevated === true
                  ? "Administrator"
                  : elevated === false
                    ? "Standard user"
                    : "Unknown privilege level"}
              </span>
              <p>
                {elevated === true
                  ? "Debug privileges are requested during capture; protected or exited processes may still miss fields."
                  : "Elevated privileges help read more paths, command lines, and account details. The new window starts an empty session while current evidence is kept."}
              </p>
            </div>
            {elevated !== true && (
              <Button
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={onElevate}
              >
                <ShieldCheck size={14} />
                {elevationBusy ? "Waiting for UAC…" : "Launch as administrator"}
              </Button>
            )}
          </div>
        )}
        <div className="capture-path mono" title={request.capture_dir}>
          {request.capture_dir}
        </div>
        <div className="section-label">
          <span>
            Files to analyze <small>{request.paths.length}</small>
          </span>
          <Button
            variant="ghost"
            size="sm"
            disabled={busy || !request.paths.length}
            onClick={() => onChange({ ...request, paths: [] })}
          >
            Clear
          </Button>
        </div>
        <div className="file-list">
          {request.paths.map((path) => (
            <div className="file-item" key={path}>
              <FileText size={17} />
              <div title={path}>
                <strong>{basename(path)}</strong>
                <span className="mono">{path}</span>
              </div>
              <span className="small-badge">Auto-detect</span>
              <Button
                variant="ghost"
                size="icon"
                disabled={busy}
                aria-label={`Remove ${basename(path)}`}
                onClick={() =>
                  onChange({
                    ...request,
                    paths: request.paths.filter((p) => p !== path),
                  })
                }
              >
                <X size={13} />
              </Button>
            </div>
          ))}
          {!request.paths.length && (
            <div className="file-empty">
              <FileText size={24} strokeWidth={1.2} />
              <span>No files added yet</span>
              <p>
                Select files or drag them onto the window; local process capture
                is also available.
              </p>
            </div>
          )}
        </div>
        <details className="advanced-import">
          <summary>
            <ChevronDown size={13} />
            Advanced options{" "}
            <span>formats, input limits, and web definitions</span>
          </summary>
          <div className="advanced-grid">
            <label>
              Batch format
              <Select
                label="Batch format"
                disabled={busy}
                value={request.format}
                onChange={(format) => onChange({ ...request, format })}
                options={[
                  "auto",
                  "evtx",
                  "utmp",
                  "wtmp",
                  "btmp",
                  "web",
                  "text",
                  "processes",
                  "pcap",
                ].map((value) => ({
                  value,
                  label:
                    value === "auto" ? "Auto-detect (mixed import)" : value,
                }))}
              />
            </label>
            <label>
              Max MiB per file
              <input
                className="input"
                type="number"
                min={1}
                max={8192}
                disabled={busy}
                value={request.max_file_bytes / 1048576}
                onChange={(e) =>
                  onChange({
                    ...request,
                    max_file_bytes: Number(e.target.value) * 1048576,
                  })
                }
              />
            </label>
            <label>
              Max records per input
              <input
                className="input"
                type="number"
                min={1}
                max={10000000}
                disabled={busy}
                value={request.max_records}
                onChange={(e) =>
                  onChange({ ...request, max_records: Number(e.target.value) })
                }
              />
            </label>
            <label className="wide">
              Web format definition
              <div className="input-action">
                <input
                  className="input mono"
                  disabled={busy}
                  value={request.web_format || ""}
                  onChange={(e) =>
                    onChange({ ...request, web_format: e.target.value })
                  }
                  placeholder="Optional Apache / Nginx format definition file"
                />
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => onPick("web")}
                >
                  Pick
                </Button>
              </div>
            </label>
          </div>
        </details>
      </div>
      <div className="import-action">
        <span>
          <span className="status-dot" />
          Local analysis runs by default; evidence is never sent automatically.
        </span>
        <Button
          disabled={
            busy ||
            (!request.paths.length && !request.live && !request.auto_logs)
          }
          onClick={onStart}
        >
          Start local analysis
          <ArrowRight size={14} />
        </Button>
      </div>
    </div>
  );
}
