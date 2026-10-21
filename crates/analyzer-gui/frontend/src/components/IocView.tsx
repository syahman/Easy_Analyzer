import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "../lib/api";
import type {
  IocView as Model,
  IocInput,
  Indicator,
  TaskMessage,
} from "../types";
import { Button } from "./ui/button";
import { Pagination } from "./Pagination";
import { Checkbox } from "./ui/checkbox";
export function IocView({
  sessionId,
  busy,
  revision,
  onTask,
  onJump,
  onChanged,
  onError,
}: {
  sessionId: number;
  busy: boolean;
  revision: number;
  onTask: (f: () => Promise<TaskMessage>) => Promise<void>;
  onJump: (id: string) => void;
  onChanged: () => Promise<void>;
  onError: (e: string) => void;
}) {
  const [view, setView] = useState<Model | null>(null);
  const [offset, setOffset] = useState(0);
  const [hitOffset, setHitOffset] = useState(0);
  const [text, setText] = useState("");
  const [csv, setCsv] = useState(false);
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [kind, setKind] = useState<Indicator["kind"] | "">("");
  const [subdomains, setSubdomains] = useState(true);
  const [issues, setIssues] = useState<string[]>([]);
  const [working, setWorking] = useState(false);
  const [loading, setLoading] = useState(false);
  const viewRequest = useRef(0);
  const indicatorScroll = useRef<HTMLDivElement>(null);
  const hitScroll = useRef<HTMLDivElement>(null);
  const policySession = useRef<number | null>(null);
  const load = useCallback(async () => {
    const request = ++viewRequest.current;
    setLoading(true);
    try {
      const next = await api.ioc(sessionId, offset, hitOffset);
      if (request !== viewRequest.current) return;
      const nextOffset = Math.min(
        offset,
        Math.floor(Math.max(0, next.indicators.total - 1) / 100) * 100,
      );
      const nextHitOffset = Math.min(
        hitOffset,
        Math.floor(Math.max(0, next.hits.total - 1) / 100) * 100,
      );
      if (nextOffset !== offset || nextHitOffset !== hitOffset) {
        setOffset(nextOffset);
        setHitOffset(nextHitOffset);
        return;
      }
      if (policySession.current !== sessionId) {
        policySession.current = sessionId;
        setSubdomains(next.status.run?.include_subdomains ?? true);
      }
      setView(next);
    } catch (e) {
      if (request === viewRequest.current) onError(String(e));
    } finally {
      if (request === viewRequest.current) setLoading(false);
    }
  }, [sessionId, offset, hitOffset]);
  useEffect(() => {
    void load();
    return () => {
      viewRequest.current++;
    };
  }, [load, revision]);
  useEffect(() => {
    if (indicatorScroll.current) indicatorScroll.current.scrollTop = 0;
  }, [view?.indicators.offset]);
  useEffect(() => {
    if (hitScroll.current) hitScroll.current.scrollTop = 0;
  }, [view?.hits.offset]);
  const add = async (input: IocInput) => {
    setWorking(true);
    try {
      const result = await api.importIoc(sessionId, input);
      setIssues(result.issues.map((e) => `Line ${e.line}: ${e.message}`));
      await load();
      await onChanged();
      if (input.text) setText("");
      if (input.value) {
        setValue("");
        setNote("");
      }
    } catch (e) {
      onError(String(e));
    } finally {
      setWorking(false);
    }
  };
  const disabled = busy || working;
  const page = (
    o: number,
    total: number,
    set: (v: number) => void,
    label: string,
  ) => (
    <Pagination
      label={label}
      offset={o}
      total={total}
      limit={100}
      loading={disabled || loading}
      onPage={set}
    />
  );
  return (
    <div className="ioc-page">
      <section className="ioc-input">
        <h2>Add IOCs</h2>
        <Button
          disabled={disabled}
          onClick={() =>
            void api
              .pick("ioc")
              .then((paths) => {
                if (paths.length) void add({ paths });
              })
              .catch((e) => onError(String(e)))
          }
        >
          Import TXT / CSV files
        </Button>
        <label>
          Paste list
          <textarea
            aria-label="IOC list"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={
              csv
                ? "type,value,note\ndomain,example.com,to verify"
                : "One IPv4 / IPv6, domain, or full HTTP/HTTPS URL per line"
            }
          />
        </label>
        <div className="project-actions">
          <Checkbox
            checked={csv}
            onChange={setCsv}
            label="CSV format (type,value, optional note)"
          />
          <Button
            disabled={disabled || !text.trim()}
            onClick={() => void add({ text, csv })}
          >
            Append pasted list
          </Button>
        </div>
        <div className="ioc-manual">
          <select
            aria-label="IOC type"
            value={kind}
            onChange={(e) => setKind(e.target.value as typeof kind)}
          >
            <option value="">Auto-detect</option>
            <option value="ip">IP address</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
          </select>
          <input
            aria-label="Manual IOC"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="IOC value"
          />
          <input
            aria-label="IOC note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Note (optional)"
          />
          <Button
            disabled={disabled || !value.trim()}
            onClick={() => void add({ value, note, ...(kind ? { kind } : {}) })}
          >
            Add manually
          </Button>
        </div>
        {issues.length > 0 && (
          <div role="alert">
            Valid entries were appended; the following entries are invalid:
            {issues.map((v, i) => (
              <p key={i}>{v}</p>
            ))}
          </div>
        )}
      </section>
      <section>
        <h2>Project IOC list</h2>
        <p>{view?.status.indicators ?? 0} IOCs · deduplicated</p>
        <p>
          The list, notes, and matches belong to this project only and are saved
          with it.
        </p>
        <div className="project-actions">
          <Checkbox
            checked={subdomains}
            onChange={setSubdomains}
            label="Domains include subdomains"
          />
          <Button
            disabled={disabled || !view?.status.indicators}
            onClick={() =>
              void onTask(() => api.scanIoc(sessionId, subdomains))
            }
          >
            Scan current project
          </Button>
        </div>
        {view?.status.needs_rescan && (
          <p className="ioc-pending">
            New evidence or list changes have not been scanned yet; rescan
            manually.
          </p>
        )}
        {view?.status.run && (
          <p>
            Last scan: {view.status.run.scanned_records} /{" "}
            {view.status.run.total_records} records ·{" "}
            {view.status.run.complete
              ? "complete"
              : "incomplete; valid hits retained"}{" "}
            ·{" "}
            {view.status.run.include_subdomains
              ? "subdomains included"
              : "exact domains"}
          </p>
        )}
        <div className="ioc-table-scroll" ref={indicatorScroll}>
          <table className="project-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {view?.indicators.items.map((i) => (
                <tr key={i.id}>
                  <td>{i.kind}</td>
                  <td className="mono">{i.value}</td>
                  <td>
                    <input
                      aria-label={`Note ${i.value}`}
                      disabled={disabled}
                      defaultValue={i.note}
                      key={`${i.id}:${i.note}`}
                      onBlur={(e) => {
                        if (e.target.value !== i.note)
                          void api
                            .iocNote(sessionId, i.id, e.target.value)
                            .then(async () => {
                              await load();
                              await onChanged();
                            })
                            .catch((e) => onError(String(e)));
                      }}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {view &&
          page(
            view.indicators.offset,
            view.indicators.total,
            (next) => {
              if (next === offset) void load();
              else setOffset(next);
            },
            "IOC list",
          )}
      </section>
      <section>
        <h2>Match results · leads to verify</h2>
        <div className="ioc-table-scroll" ref={hitScroll}>
          <table className="project-table">
            <thead>
              <tr>
                <th>IOC</th>
                <th>Matched value / position</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {view?.hits.items.map((hit, i) => (
                <tr key={`${hit.record_id}:${hit.indicator_id}:${i}`}>
                  <td>
                    {hit.value}
                    <small>{hit.note}</small>
                  </td>
                  <td>
                    {hit.matched_value}
                    <small>
                      {hit.field}
                      {hit.byte_offset !== null
                        ? ` · byte offset ${hit.byte_offset}`
                        : ""}
                    </small>
                  </td>
                  <td>
                    <Button
                      variant="ghost"
                      onClick={() => onJump(hit.record_id)}
                    >
                      {hit.position}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {view &&
          page(
            view.hits.offset,
            view.hits.total,
            (next) => {
              if (next === hitOffset) void load();
              else setHitOffset(next);
            },
            "IOC hits",
          )}
      </section>
    </div>
  );
}
