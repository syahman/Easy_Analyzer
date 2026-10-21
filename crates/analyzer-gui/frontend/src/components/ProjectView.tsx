import { useState, useEffect, useRef } from "react";
import { LoaderCircle, Pencil } from "lucide-react";
import { api } from "../lib/api";
import type { ProjectEntry, ProjectInfo, ProjectStatus } from "../types";
import { Button } from "./ui/button";
import { Pagination } from "./Pagination";
import { Dialog } from "./ui/dialog";
export function localTimestamp() {
  const now = new Date();
  const offset = -now.getTimezoneOffset();
  const sign = offset >= 0 ? "+" : "-";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}${sign}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
}
export function newProject(): ProjectInfo {
  const time = localTimestamp();
  return {
    id: crypto.randomUUID(),
    name: "",
    client: "",
    response_start: time,
    response_end: null,
    location: "",
    responders: "",
    description: "",
    created_at: time,
    updated_at: time,
  };
}
export function ProjectEditor({
  info,
  mode = "create",
  busy,
  onClose,
  onSave,
}: {
  info: ProjectInfo;
  mode?: "create" | "edit";
  busy: boolean;
  onClose: () => void;
  onSave: (v: ProjectInfo) => Promise<void>;
}) {
  const [value, setValue] = useState(info);
  const [nameEdited, setNameEdited] = useState(Boolean(info.name.trim()));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const pending = useRef(false);
  const locked = busy || submitting;
  const validTime = (text: string) =>
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(
      text,
    ) && !Number.isNaN(Date.parse(text));
  const fields: [keyof ProjectInfo, string, boolean][] = [
    ["client", "Client organization", true],
    ["name", "Project name", false],
    ["response_start", "Response start (with time zone)", true],
    ["response_end", "Response end (with time zone)", false],
    ["location", "Response location", false],
    ["responders", "Responders", false],
  ];
  const submit = async () => {
    if (busy || pending.current) return;
    const name = value.name.trim() || value.client.trim();
    const start = value.response_start.trim();
    const end = value.response_end?.trim() || null;
    if (!value.client.trim()) {
      setError("Enter the client organization");
      return;
    }
    if (!validTime(start)) {
      setError("Response start must include a date, time, and time zone");
      return;
    }
    if (end && !validTime(end)) {
      setError("Response end must include a date, time, and time zone");
      return;
    }
    if (end && Date.parse(end) < Date.parse(start)) {
      setError("Response end must not be earlier than the start");
      return;
    }
    setError("");
    pending.current = true;
    setSubmitting(true);
    try {
      await onSave({
        ...value,
        name,
        client: value.client.trim(),
        response_start: start,
        response_end: end,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      pending.current = false;
      setSubmitting(false);
    }
  };
  return (
    <Dialog
      open
      onOpenChange={(v) => {
        if (!v && !locked) onClose();
      }}
      title={
        mode === "edit"
          ? "Edit project details"
          : "New incident response project"
      }
      className="project-editor-dialog"
      description={
        mode === "edit"
          ? "Edit the project details, then click Save at the top to write the project file."
          : "A single response can last several days and accept repeated evidence imports."
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
        className="project-form"
      >
        {fields.map(([key, label, required]) => (
          <label key={key}>
            {label}
            {required ? " *" : ""}
            <input
              disabled={locked}
              required={required}
              value={value[key] ?? ""}
              placeholder={
                key === "name"
                  ? "Defaults to the client organization; editable"
                  : key.includes("response_")
                    ? "2026-10-05T09:00:00+08:00"
                    : ""
              }
              onChange={(e) => {
                const next = e.target.value;
                if (key === "name") setNameEdited(Boolean(next.trim()));
                setValue((v) => ({
                  ...v,
                  [key]: next || (key === "response_end" ? null : ""),
                  ...(key === "client" && !nameEdited ? { name: next } : {}),
                }));
              }}
            />
          </label>
        ))}
        <label className="full">
          Project description
          <textarea
            disabled={locked}
            value={value.description}
            onChange={(e) =>
              setValue((v) => ({ ...v, description: e.target.value }))
            }
          />
        </label>
        {error && (
          <p role="alert" className="error-text full">
            {error}
          </p>
        )}
        <div className="dialog-actions full">
          <Button
            variant="ghost"
            type="button"
            onClick={onClose}
            disabled={locked}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={locked}>
            {submitting && <LoaderCircle size={14} className="spin" />}
            {submitting
              ? "Applying…"
              : mode === "edit"
                ? "Apply changes"
                : "Confirm project details"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
export function ProjectHome({
  busy,
  current = null,
  onEdit,
  onNew,
  onOpen,
  onPick,
  onError,
}: {
  busy: boolean;
  current?: ProjectStatus | null;
  onEdit?: () => void;
  onNew: () => void;
  onOpen: (path: string) => void;
  onPick: () => void;
  onError: (e: string) => void;
}) {
  const projectScroll = useRef<HTMLDivElement>(null);
  const browserPanel = useRef<HTMLElement>(null);
  const shownPage = useRef("0:50");
  const [text, setText] = useState("");
  const [client, setClient] = useState("");
  const [from, setFrom] = useState("");
  const [until, setUntil] = useState("");
  const [rows, setRows] = useState<ProjectEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [offset, setOffset] = useState(0);
  const [shownOffset, setShownOffset] = useState(0);
  const [limit, setLimit] = useState(50);
  const [total, setTotal] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [removal, setRemoval] = useState<ProjectEntry | null>(null);
  const [removing, setRemoving] = useState(false);
  const [removeError, setRemoveError] = useState("");
  const lastSearch = useRef(JSON.stringify(["", "", "", ""]));
  useEffect(() => {
    let stale = false;
    const key = JSON.stringify([text, client, from, until]);
    const delay = key === lastSearch.current ? 0 : 200;
    setLoading(true);
    const timeout = setTimeout(() => {
      lastSearch.current = key;
      api
        .projectsPage(
          { text, client, from: from || null, until: until || null },
          offset,
          limit,
        )
        .then((v) => {
          if (!stale) {
            setRows(v?.items ?? []);
            setTotal(v?.total ?? 0);
            setShownOffset(v?.offset ?? 0);
            const pageKey = `${v?.offset ?? 0}:${limit}`;
            if (pageKey !== shownPage.current) {
              shownPage.current = pageKey;
              requestAnimationFrame(() => {
                const root = projectScroll.current;
                const panel = browserPanel.current;
                if (root && panel)
                  root.scrollTop +=
                    panel.getBoundingClientRect().top -
                    root.getBoundingClientRect().top;
              });
            }
            if (v && v.offset !== offset) setOffset(v.offset);
          }
        })
        .catch((e) => {
          if (!stale) onError(String(e));
        })
        .finally(() => {
          if (!stale) setLoading(false);
        });
    }, delay);
    return () => {
      stale = true;
      clearTimeout(timeout);
    };
  }, [
    offset,
    limit,
    text,
    client,
    from,
    until,
    refresh,
    current?.info.id,
    current?.path,
    current?.dirty,
  ]);
  const remove = async () => {
    if (!removal || busy || removing) return;
    setRemoving(true);
    setRemoveError("");
    try {
      await api.removeProject(removal.info.id, removal.path);
      setRows((v) => v.filter((row) => row.info.id !== removal.info.id));
      setRemoval(null);
      setRefresh((v) => v + 1);
    } catch (e) {
      setRemoveError(String(e));
      setRefresh((v) => v + 1);
    } finally {
      setRemoving(false);
    }
  };
  return (
    <div className="project-page" ref={projectScroll}>
      {current && (
        <section
          className="project-current"
          aria-labelledby="project-current-title"
        >
          <div className="project-current-heading">
            <div>
              <h3 id="project-current-title">Current project details</h3>
              <p>{current.dirty ? "Unsaved changes" : "Saved"}</p>
            </div>
            <Button
              variant="secondary"
              disabled={busy || removing || !onEdit}
              onClick={onEdit}
            >
              <Pencil size={14} />
              Edit project details
            </Button>
          </div>
          <dl className="project-current-fields">
            {(
              [
                ["Project name", current.info.name],
                ["Client organization", current.info.client],
                ["Response start", current.info.response_start],
                ["Response end", current.info.response_end],
                ["Response location", current.info.location],
                ["Responders", current.info.responders],
                ["Project description", current.info.description],
              ] as const
            ).map(([label, text]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{text || "Not provided"}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}
      <section className="project-start" aria-labelledby="project-start-title">
        <div>
          <h3 id="project-start-title">Start or resume incident response</h3>
          <p>
            Click New project to enter the client organization, response times,
            and other details.
          </p>
        </div>
        <div className="project-actions">
          <Button disabled={busy || removing} onClick={onNew}>
            New project
          </Button>
          <Button
            variant="secondary"
            disabled={busy || removing}
            onClick={onPick}
          >
            Open project file
          </Button>
        </div>
      </section>
      <section
        ref={browserPanel}
        className="project-browser"
        aria-labelledby="project-list-title"
      >
        <div className="project-list-heading">
          <h3 id="project-list-title">Existing projects</h3>
          <p>
            Sorted by last opened ·{" "}
            {loading
              ? "Searching…"
              : `${total} ${total === 1 ? "project" : "projects"}`}
          </p>
        </div>
        <details className="project-filters">
          <summary>Filter existing projects</summary>
          <p>The conditions below search the project list.</p>
          <div className="project-search">
            <label>
              Search project or client names
              <input
                aria-label="Project search"
                placeholder="Enter keywords to find existing projects"
                value={text}
                onChange={(e) => {
                  setText(e.target.value);
                  setOffset(0);
                }}
              />
            </label>
            <label>
              Filter by client organization
              <input
                value={client}
                placeholder="All client organizations"
                onChange={(e) => {
                  setClient(e.target.value);
                  setOffset(0);
                }}
              />
            </label>
            <label>
              Response start on or after
              <input
                type="date"
                value={from}
                onChange={(e) => {
                  setFrom(e.target.value);
                  setOffset(0);
                }}
              />
            </label>
            <label>
              Response start on or before
              <input
                type="date"
                value={until}
                onChange={(e) => {
                  setUntil(e.target.value);
                  setOffset(0);
                }}
              />
            </label>
          </div>
        </details>
        <div className="project-list">
          {rows.map((row) => (
            <article key={row.info.id}>
              <div>
                <h3>{row.info.name}</h3>
                <p>
                  {row.info.client} · {row.info.response_start}
                </p>
                <small>{row.path}</small>
                {row.missing && (
                  <p className="error-text">
                    Project file missing; reopen it from its new location
                  </p>
                )}
              </div>
              <div className="project-entry-actions">
                <Button
                  variant="secondary"
                  disabled={busy || removing || row.missing}
                  onClick={() => onOpen(row.path)}
                >
                  Resume project
                </Button>
                <Button
                  variant="ghost"
                  className="project-remove"
                  disabled={busy || removing}
                  aria-label={`Remove ${row.info.name} from the list`}
                  onClick={() => {
                    setRemoveError("");
                    setRemoval(row);
                  }}
                >
                  Remove
                </Button>
              </div>
            </article>
          ))}
          {!rows.length && !loading && (
            <p>
              {text.trim() || client.trim() || from || until
                ? "No projects match the filters; adjust them."
                : "The project list is empty. Click New project above to start a response, or open an existing .eair file."}
            </p>
          )}
        </div>
        <Pagination
          label="Projects"
          offset={shownOffset}
          total={total}
          limit={limit}
          loading={loading || busy || removing}
          onPage={(value) => {
            if (value === offset) setRefresh((v) => v + 1);
            else setOffset(value);
          }}
          onSize={(v) => {
            setLimit(v);
            setOffset(0);
          }}
        />
      </section>
      <Dialog
        open={removal !== null}
        onOpenChange={(v) => {
          if (!v && !removing) setRemoval(null);
        }}
        title="Remove project from the list"
        description="Only the entry in this machine's project list is removed; the .eair file, evidence, and IOCs are kept. Reopening or saving the project shows it here again."
      >
        {removal && (
          <div className="project-removal-details">
            <p>
              {removal.info.name} · {removal.info.client}
            </p>
            <small>{removal.path}</small>
          </div>
        )}
        {removeError && (
          <p role="alert" className="error-text">
            {removeError}
          </p>
        )}
        <div className="dialog-actions">
          <Button
            variant="ghost"
            disabled={removing}
            onClick={() => setRemoval(null)}
          >
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={busy || removing}
            onClick={() => void remove()}
          >
            {removing ? "Removing…" : "Confirm removal"}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
