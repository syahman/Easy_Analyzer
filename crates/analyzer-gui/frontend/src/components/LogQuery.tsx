import { useState, useRef } from "react";
import { Plus, X, LoaderCircle } from "lucide-react";
import { Dialog } from "./ui/dialog";
import { Select } from "./ui/select";
import { Button } from "./ui/button";
import { localTimeInput, queryTime, validateLogQuery } from "../lib/log-query";
import { defaultLogQuery, type LogQuery as Query } from "../types";

export function LogQueryFields({
  value,
  onChange,
  disabled = false,
}: {
  value: Query;
  onChange: (v: Query) => void;
  disabled?: boolean;
}) {
  const change = (patch: Partial<Query>) => onChange({ ...value, ...patch });
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return (
    <div className="log-query-fields">
      <div className="log-query-grid">
        {(
          [
            ["time_from", "Start time (local)"],
            ["time_until", "End time (local)"],
          ] as const
        ).map(([key, label]) => (
          <label key={key} className="form-field">
            {label}
            <input
              className="input"
              type="datetime-local"
              step="1"
              aria-label={label}
              value={localTimeInput(value[key])}
              disabled={disabled}
              onInput={(e) =>
                change({ [key]: queryTime(e.currentTarget.value) })
              }
              onChange={(e) => change({ [key]: queryTime(e.target.value) })}
            />
          </label>
        ))}
        {(
          [
            ["log_level", "Log level", "e.g. ERROR, WARN, SEVERE"],
            ["client_ip", "Client IP", "full address, e.g. 192.0.2.10"],
            ["http_status", "HTTP status", "e.g. 403, 404, 500"],
            ["method", "Request method", "e.g. GET, POST"],
            ["uri", "Request path", "contains, e.g. /api/ or .jsp"],
            ["logger", "Logger class", "contains, e.g. org.apache.catalina"],
            ["host", "Host / computer", "contains the host name"],
          ] as const
        ).map(([key, label, placeholder]) => (
          <label key={key} className="form-field">
            {label}
            <input
              className="input"
              aria-label={label}
              value={value[key]}
              disabled={disabled}
              placeholder={placeholder}
              onChange={(e) => change({ [key]: e.target.value })}
            />
          </label>
        ))}
        <label className="form-field">
          Time zone for logs without one
          <Select
            label="Time zone for logs without one"
            value={value.time_offset === null ? "" : String(value.time_offset)}
            disabled={disabled}
            onChange={(v) =>
              change({ time_offset: v === "" ? null : Number(v) })
            }
            options={[
              { value: "", label: "Unspecified (time unknown)" },
              ...Array.from(
                new Set([
                  0,
                  -new Date().getTimezoneOffset(),
                  ...(value.time_offset === null ? [] : [value.time_offset]),
                  ...Array.from({ length: 113 }, (_, i) => (i - 56) * 15),
                ]),
              )
                .sort((a, b) => a - b)
                .map((minutes) => ({
                  value: String(minutes),
                  label: `UTC${minutes < 0 ? "-" : "+"}${String(Math.floor(Math.abs(minutes) / 60)).padStart(2, "0")}:${String(Math.abs(minutes) % 60).padStart(2, "0")}${minutes === -new Date().getTimezoneOffset() ? " (local)" : ""}`,
                })),
            ]}
          />
        </label>
      </div>
      <p className="log-query-hint">
        Query bounds use the local time zone {timezone} and include both
        endpoints. When Nginx/Tomcat-style logs do not state a time zone, choose
        one based on the evidence source; raw times stay unchanged, and times
        missing a year remain unknown. Log level, HTTP status, and request
        method accept comma-separated lists matching any value, and all
        conditions must hold. Client IP matches exactly; path, logger, and host
        match by containment.
      </p>
      <details className="log-query-windows">
        <summary>Windows event conditions</summary>
        <div className="log-query-grid">
          <label className="form-field">
            Windows event IDs
            <input
              className="input"
              aria-label="Windows event IDs"
              value={value.event_ids}
              disabled={disabled}
              placeholder="e.g. 4624, 4625, 4688"
              onChange={(e) => change({ event_ids: e.target.value })}
            />
          </label>
          <label className="form-field">
            Windows event level
            <Select
              label="Windows event level"
              value={value.level || ""}
              disabled={disabled}
              onChange={(v) => change({ level: v || null })}
              options={[
                { value: "", label: "All levels" },
                ...[
                  "Unspecified / audit event (0)",
                  "Critical (1)",
                  "Error (2)",
                  "Warning (3)",
                  "Information (4)",
                  "Verbose (5)",
                ].map((label, i) => ({ value: String(i), label })),
              ]}
            />
          </label>
          {(
            [
              [
                "provider",
                "Event provider",
                "e.g. Microsoft-Windows-Security-Auditing",
              ],
              ["channel", "Log channel", "e.g. Security / System"],
            ] as const
          ).map(([key, label, placeholder]) => (
            <label key={key} className="form-field">
              {label}
              <input
                className="input"
                aria-label={label}
                value={value[key]}
                disabled={disabled}
                placeholder={placeholder}
                onChange={(e) => change({ [key]: e.target.value })}
              />
            </label>
          ))}
        </div>
      </details>
      <div className="log-query-custom-heading">
        <strong>Custom field conditions</strong>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={disabled || value.fields.length >= 16}
          onClick={() =>
            change({
              fields: [
                ...value.fields,
                { field: "", value: "", mode: "contains" },
              ],
            })
          }
        >
          <Plus size={14} />
          Add condition
        </Button>
      </div>
      <p className="log-query-hint">
        Field names may come from details such as thread, duration, user, or
        action; raw field paths also work. Names and values are
        case-insensitive, and all conditions must hold.
      </p>
      {value.fields.map((field, index) => (
        <div className="log-query-custom-row" key={index}>
          <input
            className="input"
            aria-label={`Query field ${index + 1}`}
            placeholder="Field name"
            value={field.field}
            disabled={disabled}
            onChange={(e) =>
              change({
                fields: value.fields.map((f, i) =>
                  i === index ? { ...f, field: e.target.value } : f,
                ),
              })
            }
          />
          <Select
            label={`Field match mode ${index + 1}`}
            value={field.mode}
            disabled={disabled}
            options={[
              { value: "contains", label: "Contains" },
              { value: "equals", label: "Equals" },
            ]}
            onChange={(mode) =>
              change({
                fields: value.fields.map((f, i) =>
                  i === index
                    ? { ...f, mode: mode as "contains" | "equals" }
                    : f,
                ),
              })
            }
          />
          <input
            className="input"
            aria-label={`Query field value ${index + 1}`}
            placeholder="Field value"
            value={field.value}
            disabled={disabled}
            onChange={(e) =>
              change({
                fields: value.fields.map((f, i) =>
                  i === index ? { ...f, value: e.target.value } : f,
                ),
              })
            }
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            aria-label={`Remove condition ${index + 1}`}
            disabled={disabled}
            onClick={() =>
              change({ fields: value.fields.filter((_, i) => i !== index) })
            }
          >
            <X size={14} />
          </Button>
        </div>
      ))}
    </div>
  );
}
export function LogQueryDialog({
  initial,
  busy,
  onApply,
  onClose,
}: {
  initial: Query;
  busy: boolean;
  onApply: (v: Query) => Promise<void>;
  onClose: () => void;
}) {
  const [value, setValue] = useState(() => structuredClone(initial));
  const [error, setError] = useState("");
  const [composing, setComposing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const pending = useRef(false);
  const locked = busy || submitting;
  return (
    <Dialog
      open
      title="Multi-dimensional log query"
      description="Combine conditions across the full log collection, regardless of the current page."
      className="log-query-dialog"
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <form
        onCompositionStart={() => setComposing(true)}
        onCompositionEnd={() => setComposing(false)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (composing || e.nativeEvent.isComposing))
            e.preventDefault();
        }}
        onSubmit={async (e) => {
          e.preventDefault();
          if (locked || composing || pending.current) return;
          setError("");
          try {
            validateLogQuery(value);
            pending.current = true;
            setSubmitting(true);
            await onApply(value);
          } catch (e) {
            setError(String(e));
          } finally {
            pending.current = false;
            setSubmitting(false);
          }
        }}
      >
        <div className="log-query-body">
          <LogQueryFields value={value} onChange={setValue} disabled={locked} />
        </div>
        {error && (
          <div role="alert" className="warning-note">
            {error}. The last valid query is kept.
          </div>
        )}
        <div className="dialog-actions">
          <Button
            type="button"
            variant="ghost"
            disabled={locked}
            onClick={() => setValue(defaultLogQuery())}
          >
            Clear conditions
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            {locked ? "Cancel query" : "Cancel"}
          </Button>
          <Button type="submit" disabled={locked}>
            {locked && <LoaderCircle size={14} className="spin" />}
            {locked ? "Querying…" : "Apply query"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
