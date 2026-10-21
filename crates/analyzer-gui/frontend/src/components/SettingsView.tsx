import {
  KeyRound,
  FolderOpen,
  PlugZap,
  Save,
  CheckCircle2,
  EyeOff,
} from "lucide-react";
import { Button } from "./ui/button";
import { Select } from "./ui/select";
import type { ConfigInput, PublicConfig } from "../types";
export function SettingsView({
  config,
  draft,
  onChange,
  path,
  onPath,
  busy,
  checkStatus,
  onPick,
  onApply,
  onSave,
  onLoad,
  onCheck,
}: {
  config: PublicConfig;
  draft: ConfigInput;
  onChange: (v: ConfigInput) => void;
  path: string;
  onPath: (v: string) => void;
  busy: boolean;
  checkStatus: string;
  onPick: () => void;
  onApply: () => void;
  onSave: () => void;
  onLoad: () => void;
  onCheck: () => void;
}) {
  return (
    <div className="settings-page">
      <div className="settings-scroll">
        <div className="form-section">
          <h3>Configuration file</h3>
          <p>
            An existing CLI configuration can be reused; it is written to disk
            only when saved.
          </p>
          <div className="input-action">
            <input
              className="input mono"
              aria-label="Configuration file path"
              value={path}
              onChange={(e) => onPath(e.target.value)}
              disabled={busy}
            />
            <Button
              variant="outline"
              size="icon"
              aria-label="Pick configuration"
              disabled={busy}
              onClick={onPick}
            >
              <FolderOpen size={15} />
            </Button>
            <Button variant="outline" disabled={busy} onClick={onLoad}>
              Load
            </Button>
          </div>
        </div>
        <div className="form-section">
          <h3>AI service</h3>
          <p>Services and models compatible with OpenAI Chat Completions.</p>
          <label className="form-field">
            Service URL
            <input
              className="input"
              aria-label="Service URL"
              placeholder="https://api.example.com/v1"
              value={draft.base_url}
              disabled={busy}
              onChange={(e) => onChange({ ...draft, base_url: e.target.value })}
            />
          </label>
          <label className="form-field">
            Model
            <input
              className="input"
              aria-label="Model"
              value={draft.model}
              disabled={busy}
              onChange={(e) => onChange({ ...draft, model: e.target.value })}
            />
          </label>
          <label className="form-field">
            <span>
              API key{" "}
              <span
                className={`key-status ${config.api_key_configured ? "configured" : ""}`}
              >
                {config.api_key_configured ? (
                  <>
                    <CheckCircle2 size={11} />
                    Configured
                  </>
                ) : (
                  <>
                    <KeyRound size={11} />
                    Not configured
                  </>
                )}
              </span>
            </span>
            <div className="key-input">
              <input
                className="input"
                aria-label="New API key"
                type="password"
                autoComplete="new-password"
                placeholder={
                  config.api_key_configured
                    ? "Leave blank to keep the existing key"
                    : "Enter a new API key"
                }
                disabled={busy}
                value={draft.key_value}
                onChange={(e) =>
                  onChange({
                    ...draft,
                    key_value: e.target.value,
                    key_action: e.target.value ? "replace" : "keep",
                  })
                }
              />
              <EyeOff size={14} />
            </div>
          </label>
          <div className="key-actions">
            <span>The saved key is never returned to the UI.</span>
            {config.api_key_configured && (
              <button
                disabled={busy}
                onClick={() =>
                  onChange({
                    ...draft,
                    key_action: draft.key_action === "clear" ? "keep" : "clear",
                    key_value: "",
                  })
                }
              >
                {draft.key_action === "clear"
                  ? "Undo clear"
                  : "Clear saved key"}
              </button>
            )}
          </div>
        </div>
        <div className="form-section">
          <h3>Send planning</h3>
          <label className="form-field">
            Planning mode
            <Select
              label="Send planning mode"
              value={draft.context_tokens === null ? "bytes" : "context"}
              disabled={busy}
              onChange={(value) =>
                onChange({
                  ...draft,
                  context_tokens: value === "context" ? 1000000 : null,
                })
              }
              options={[
                {
                  value: "context",
                  label: "Automatic: budget by model context",
                },
                { value: "bytes", label: "Compatible: budget bytes per batch" },
              ]}
            />
          </label>
          {draft.context_tokens !== null && (
            <label className="form-field">
              Model context limit / tokens
              <input
                className="input"
                type="number"
                aria-label="Model context limit"
                min="4096"
                step="1024"
                value={draft.context_tokens}
                disabled={busy}
                onChange={(e) =>
                  onChange({ ...draft, context_tokens: Number(e.target.value) })
                }
              />
            </label>
          )}
          <p>
            Set this to the actual limit of the current model and service; 1M
            means 1000000. Automatic mode reserves output plus a 20% safety
            margin, batches only when over budget, then synthesizes clues across
            batches. Token counts are conservative local estimates.
          </p>
        </div>
        <details className="form-section advanced-settings">
          <summary>Advanced parameters</summary>
          <div className="advanced-grid">
            <label>
              Timeout / seconds
              <input
                className="input"
                type="number"
                aria-label="Timeout seconds"
                value={draft.timeout_seconds}
                disabled={busy}
                onChange={(e) =>
                  onChange({
                    ...draft,
                    timeout_seconds: Number(e.target.value),
                  })
                }
              />
            </label>
            <label>
              Batch byte budget (compatible mode)
              <input
                className="input"
                type="number"
                value={draft.batch_bytes}
                disabled={busy || draft.context_tokens !== null}
                onChange={(e) =>
                  onChange({ ...draft, batch_bytes: Number(e.target.value) })
                }
              />
            </label>
            <label>
              Output token limit
              <input
                className="input"
                type="number"
                value={draft.max_output_tokens}
                disabled={busy}
                onChange={(e) =>
                  onChange({
                    ...draft,
                    max_output_tokens: Number(e.target.value),
                  })
                }
              />
            </label>
            <label>
              Response format
              <Select
                label="Response format"
                value={draft.response_format}
                disabled={busy}
                onChange={(response_format) =>
                  onChange({ ...draft, response_format })
                }
                options={["json_object", "json_schema", "none"].map(
                  (value) => ({ value, label: value }),
                )}
              />
            </label>
            <label>
              Token parameter
              <Select
                label="Token parameter"
                value={draft.token_parameter}
                disabled={busy}
                onChange={(token_parameter) =>
                  onChange({ ...draft, token_parameter })
                }
                options={["max_tokens", "max_completion_tokens"].map(
                  (value) => ({ value, label: value }),
                )}
              />
            </label>
            <label className="wide">
              Key environment variable
              <input
                className="input mono"
                aria-label="Key environment variable"
                value={draft.api_key_env}
                disabled={busy}
                onChange={(e) =>
                  onChange({ ...draft, api_key_env: e.target.value })
                }
              />
            </label>
          </div>
        </details>
        <div className="font-credit">
          Chinese font: Noto Sans CJK SC · SIL Open Font License 1.1
          <br />
          The font ships with the app; no download is needed.
        </div>
      </div>
      <div className="settings-actions">
        <span className="check-status">{checkStatus}</span>
        <Button variant="ghost" disabled={busy} onClick={onApply}>
          Apply settings
        </Button>
        <Button variant="outline" disabled={busy} onClick={onCheck}>
          <PlugZap size={14} />
          Check connection
        </Button>
        <Button disabled={busy} onClick={onSave}>
          <Save size={14} />
          Save config
        </Button>
      </div>
    </div>
  );
}
