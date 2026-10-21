import { useRef, useState } from "react";
import { LoaderCircle } from "lucide-react";
import { Dialog } from "./ui/dialog";
import { Select } from "./ui/select";
import { Checkbox } from "./ui/checkbox";
import { Button } from "./ui/button";
import { LogQueryFields } from "./LogQuery";
import { validateLogQuery, logTypeLabel } from "../lib/log-query";
import { basename } from "../lib/utils";
import {
  defaultFilters,
  statusLabel,
  type Filters,
  type SessionScreen,
  type Source,
} from "../types";

export interface EvidenceFilterContext {
  screen: SessionScreen;
  filters: Filters;
}

export function AiEvidenceFilter({
  initial,
  sources,
  categories,
  protocols,
  busy,
  onApply,
  onClose,
}: {
  initial: EvidenceFilterContext;
  sources: Source[];
  categories: string[];
  protocols: string[];
  busy: boolean;
  onApply: (value: EvidenceFilterContext) => Promise<void>;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState(() => structuredClone(initial));
  const [error, setError] = useState<string | null>(null);
  const composing = useRef(false);
  const change = (value: Partial<Filters>) =>
    setDraft((v) => ({ ...v, filters: { ...v.filters, ...value } }));
  const apply = async () => {
    if (busy || composing.current) return;
    setError(null);
    try {
      if (draft.screen === "logs") validateLogQuery(draft.filters.log_query);
      await onApply(draft);
    } catch (e) {
      setError(String(e));
    }
  };
  const f = draft.filters;
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
      title="Filter evidence to send"
      description="Query the full evidence collection locally; applying it updates the current filter. This does not send AI requests."
      className="ai-filter-dialog"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void apply();
        }}
      >
        <fieldset disabled={busy}>
          <label className="form-field">
            Evidence type
            <Select
              label="Evidence type to send"
              value={draft.screen}
              options={[
                { value: "logs", label: "Logs" },
                { value: "processes", label: "Processes" },
                { value: "network", label: "Network packets" },
              ]}
              onChange={(screen) =>
                setDraft({
                  screen: screen as SessionScreen,
                  filters: {
                    ...defaultFilters(),
                    text: f.text,
                    regex: f.regex,
                    suspicious: f.suspicious,
                    source: f.source,
                    status: f.status,
                    limit: f.limit,
                    packets: true,
                    tree: false,
                  },
                })
              }
            />
          </label>
          <label className="form-field">
            Keyword or regular expression
            <input
              className="input"
              aria-label="Evidence query to send"
              placeholder="Enter a keyword; leave blank for all evidence of this type"
              value={f.text}
              onChange={(e) => change({ text: e.target.value })}
              onCompositionStart={() => {
                composing.current = true;
              }}
              onCompositionEnd={() => {
                composing.current = false;
              }}
              onKeyDown={(e) => {
                if (
                  e.key === "Enter" &&
                  (composing.current ||
                    e.nativeEvent.isComposing ||
                    e.keyCode === 229)
                )
                  e.preventDefault();
              }}
            />
          </label>
          <div className="filter-row">
            <Checkbox
              label="Regular expression"
              checked={f.regex}
              onChange={(regex) => change({ regex })}
              disabled={busy}
            />
            <Checkbox
              label="Local suspicious only"
              checked={f.suspicious}
              onChange={(suspicious) => change({ suspicious })}
              disabled={busy}
            />
          </div>
          <div className="ai-filter-fields">
            <Select
              label="Evidence source to send"
              value={f.source || ""}
              onChange={(source) => change({ source: source || null })}
              options={[
                { value: "", label: "All sources" },
                ...sources.map((s) => ({
                  value: s.id,
                  label: basename(s.path),
                })),
                ...(f.source && !sources.some((s) => s.id === f.source)
                  ? [{ value: f.source, label: "Selected source" }]
                  : []),
              ]}
            />
            <Select
              label="Parse status to send"
              value={f.status || ""}
              onChange={(status) =>
                change({ status: (status as Filters["status"]) || null })
              }
              options={[
                { value: "", label: "All statuses" },
                ...Object.entries(statusLabel).map(([value, label]) => ({
                  value,
                  label,
                })),
              ]}
            />
            {draft.screen === "logs" && (
              <Select
                label="Log category to send"
                value={f.category || ""}
                onChange={(category) => change({ category: category || null })}
                options={[
                  { value: "", label: "All categories" },
                  ...categories.map((value) => ({
                    value,
                    label: logTypeLabel(value),
                  })),
                ]}
              />
            )}
            {draft.screen === "network" && (
              <Select
                label="Protocol to send"
                value={f.protocol || ""}
                onChange={(protocol) => change({ protocol: protocol || null })}
                options={[
                  { value: "", label: "All protocols" },
                  ...protocols.map((value) => ({ value, label: value })),
                ]}
              />
            )}
          </div>
          {draft.screen === "logs" && (
            <details className="ai-log-query">
              <summary>Multi-dimensional log query conditions</summary>
              <LogQueryFields
                value={f.log_query}
                onChange={(log_query) => change({ log_query })}
                disabled={busy}
              />
            </details>
          )}
          {f.flow !== null && (
            <div className="ai-filter-flow">
              Restricted to network session #{f.flow + 1}
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => change({ flow: null })}
              >
                Remove session restriction
              </Button>
            </div>
          )}
        </fieldset>
        {error && (
          <div className="warning-note" role="alert">
            {error}. The last valid filter is kept.
          </div>
        )}
        <div className="dialog-actions">
          <Button
            type="button"
            variant="ghost"
            disabled={busy}
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={busy}>
            {busy && <LoaderCircle size={14} className="spin" />}
            {busy ? "Querying…" : "Apply filter"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
