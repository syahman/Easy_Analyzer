import { version as appVersion } from "../package.json";
import {
  useState,
  useEffect,
  useRef,
  useCallback,
  type CSSProperties,
} from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import {
  Upload,
  LayoutDashboard,
  FileText,
  GitFork,
  Network,
  Sparkles,
  Files,
  Settings2,
  Sun,
  Moon,
  ChevronRight,
  ChevronDown,
  Plus,
  Download,
  Search,
  PanelRight,
  ArrowLeft,
  X,
  LoaderCircle,
  ShieldCheck,
  CircleAlert,
  ArrowUpRight,
  Check,
  Minus,
  Square,
  Keyboard,
  FolderOpen,
  SlidersHorizontal,
  History,
  Terminal,
  Pencil,
} from "lucide-react";
import type { ColumnDef } from "@tanstack/react-table";
import { api } from "./lib/api";
import { basename, bytes, number } from "./lib/utils";
import {
  defaultFilters,
  defaultLogQuery,
  evidenceScreen,
  screens,
  sessionScreens,
  titles,
  statusLabel,
  severityLabel,
  type Screen,
  type SessionScreen,
  type ProjectInfo,
  type Bootstrap,
  type ViewResponse,
  type Filters,
  type DetailResponse,
  type Finding,
  type RecordSummary,
  type Flow,
  type Source,
  type ConfigInput,
  type AiPreview,
  type Preferences,
  type ImportRequest,
  type TaskMessage,
  type SelectionInfo,
  type Severity,
  type LogQuery,
  type RecordOrder,
} from "./types";
import { Button } from "./components/ui/button";
import { Select } from "./components/ui/select";
import { Checkbox } from "./components/ui/checkbox";
import { Dialog } from "./components/ui/dialog";
import { Tooltip, TooltipProvider } from "./components/ui/tooltip";
import { Tabs } from "./components/ui/tabs";
import { Pagination } from "./components/Pagination";
import { DataTable } from "./components/DataTable";
import { Inspector, SourceInspector, Risk } from "./components/Inspector";
import { ImportView } from "./components/ImportView";
import { SettingsView } from "./components/SettingsView";
import { AiHistory } from "./components/AiHistory";
import { AiLocalSummary } from "./components/AiLocalSummary";
import { AiEvidenceFilter } from "./components/AiEvidenceFilter";
import { LogQueryDialog } from "./components/LogQuery";
import {
  displayRecordLogTime,
  logQueryCount,
  logTypeLabel,
  logDetail,
} from "./lib/log-query";
import {
  ProjectHome,
  ProjectEditor,
  newProject,
} from "./components/ProjectView";
import { IocView } from "./components/IocView";
import { CommandsView } from "./components/CommandsView";
const icons = {
  projects: FolderOpen,
  commands: Terminal,
  ioc: ShieldCheck,
  import: Upload,
  overview: LayoutDashboard,
  logs: FileText,
  processes: GitFork,
  network: Network,
  ai: Sparkles,
  reports: Files,
  settings: Settings2,
};
const hints: Record<Screen, string> = {
  projects:
    "Each incident response is saved independently; resume an existing project or create one",
  commands: "View and copy common triage and forensics commands",
  ioc: "Import, paste, or enter IOCs manually to find leads in the current project",
  import: "Collect offline evidence and start local analysis",
  overview: "Trace evidence from findings and verify each lead",
  logs: "Full-collection queries · raw records preserved",
  processes:
    "Relations built from snapshot sources; identify orphans and cycles",
  network: "Offline network sessions and packets with full session statistics",
  ai: "Choose the evidence scope deliberately and review validated results",
  reports: "Sources remain traceable; exports keep complete evidence",
  settings:
    "Configuration is saved on demand; connection checks run only when you start them",
};
const initialPreferences: Preferences = {
  dark: false,
  inspector: true,
  inspector_width: 320,
  config_path: "",
  window_width: 1280,
  window_height: 720,
};
const initialImport: ImportRequest = {
  paths: [],
  live: false,
  auto_logs: false,
  capture_dir: "",
  format: "auto",
  max_file_bytes: 536870912,
  max_records: 1000000,
  web_format: null,
};
const emptySelection: SelectionInfo = { id: 0, count: 0, label: "" };
const draftOf = (c: Bootstrap["config"]): ConfigInput => ({
  ...c,
  key_action: "keep",
  key_value: "",
});
const initialFilters = (saved?: Bootstrap["filters"]) =>
  Object.fromEntries(
    sessionScreens.map((s) => [
      s,
      {
        ...defaultFilters(),
        ...saved?.[s],
        log_query: { ...defaultLogQuery(), ...saved?.[s]?.log_query },
      },
    ]),
  ) as Record<SessionScreen, Filters>;
const statusText: Record<string, string> = {
  running: "In progress",
  cancelling: "Cancelling; waiting for the current request to return",
  completed: "Completed",
  partial: "Partially completed",
  cancelled: "Cancelled; results are incomplete",
  failed: "Failed",
};
interface ScopeContext {
  screen: SessionScreen;
  filters: Filters;
}
interface Bookmark {
  screen: SessionScreen;
  filters: Record<SessionScreen, Filters>;
  finding: Finding | null;
  detail: DetailResponse | null;
  selectedId: string | null;
  scopeContext: ScopeContext | null;
}
export function App() {
  const [editor, setEditor] = useState<ProjectInfo | null>(null);
  const [editing, setEditing] = useState(false);
  const [projectSubmitting, setProjectSubmitting] = useState(false);
  const [dirtyOpen, setDirtyOpen] = useState(false);
  const pendingAction = useRef<(() => void) | null>(null);
  const afterSave = useRef<(() => void) | null>(null);
  const projectRef = useRef<Bootstrap["project"]>(null);
  const guardRef = useRef<(action: () => void) => void>(() => {});
  const [boot, setBoot] = useState<Bootstrap | null>(null),
    [prefs, setPrefs] = useState(initialPreferences),
    [screen, setScreen] = useState<Screen>("projects"),
    [filters, setFilters] = useState(initialFilters),
    [views, setViews] = useState<Partial<Record<Screen, ViewResponse>>>({}),
    [lastView, setLastView] = useState<ViewResponse | null>(null),
    [selection, setSelection] = useState(emptySelection),
    [loading, setLoading] = useState(false),
    [detailLoading, setDetailLoading] = useState(false),
    [detail, setDetail] = useState<DetailResponse | null>(null),
    [selectedSource, setSelectedSource] = useState<Source | null>(null),
    [finding, setFinding] = useState<Finding | null>(null),
    [selectedId, setSelectedId] = useState<string | null>(null),
    [focus, setFocus] = useState<string | null>(null),
    [drawer, setDrawer] = useState(false),
    [back, setBack] = useState<Bookmark[]>([]),
    [error, setError] = useState<string | null>(null),
    [notice, setNotice] = useState("Ready"),
    [task, setTask] = useState<TaskMessage | null>(null),
    [request, setRequest] = useState(initialImport),
    [dragging, setDragging] = useState(false),
    [elevationBusy, setElevationBusy] = useState(false),
    [aiSending, setAiSending] = useState(false),
    [aiFilter, setAiFilter] = useState<ScopeContext | null>(null),
    [aiFilterBusy, setAiFilterBusy] = useState(false),
    [logQueryOpen, setLogQueryOpen] = useState(false),
    [aiHistoryOpen, setAiHistoryOpen] = useState(false),
    [aiPreview, setAiPreview] = useState<{
      key: string;
      value: AiPreview;
    } | null>(null),
    [aiPreviewError, setAiPreviewError] = useState<{
      key: string;
      message: string;
    } | null>(null),
    [aiPreviewAttempt, setAiPreviewAttempt] = useState(0),
    [scope, setScope] = useState("suspicious"),
    [payload, setPayload] = useState(false),
    [exportOpen, setExportOpen] = useState(false),
    [exportPath, setExportPath] = useState(""),
    [exportHtml, setExportHtml] = useState(true),
    [exportJson, setExportJson] = useState(false),
    [overwrite, setOverwrite] = useState(false),
    [newOpen, setNewOpen] = useState(false),
    [closeOpen, setCloseOpen] = useState(false),
    [draft, setDraft] = useState<ConfigInput | null>(null),
    [checkStatus, setCheckStatus] = useState("Not checked yet"),
    [width, setWidth] = useState(window.innerWidth),
    [sourceOffset, setSourceOffset] = useState(0),
    [diagnosticOffset, setDiagnosticOffset] = useState(0),
    [runOffset, setRunOffset] = useState(0);
  const session = useRef<number | null>(null),
    viewRevision = useRef(0),
    detailRevision = useRef(0),
    scopeContext = useRef<ScopeContext | null>(null),
    ended = useRef(new Set<number>()),
    closing = useRef(false),
    composingQuery = useRef(false),
    lifecycle = useRef(0),
    taskRef = useRef<TaskMessage | null>(null),
    currentScreen = useRef(screen),
    currentFilters = useRef(filters),
    currentFocus = useRef(focus),
    prefsRef = useRef(prefs),
    requestRef = useRef(request),
    refreshRef = useRef<
      (
        s?: Screen,
        f?: Filters,
        focusId?: string | null,
        commit?: boolean,
      ) => Promise<string | undefined>
    >(async () => {}),
    qaAiStarted = useRef(false);
  projectRef.current = boot?.project;
  currentScreen.current = screen;
  currentFilters.current = filters;
  currentFocus.current = focus;
  prefsRef.current = prefs;
  requestRef.current = request;
  taskRef.current = task;
  const data = views[screen],
    overview = data?.overview || lastView?.overview,
    active = screen === "commands" ? defaultFilters() : filters[screen],
    hasSession = boot?.session_id !== null && !!boot,
    busy =
      !!task || elevationBusy || aiSending || aiFilterBusy || projectSubmitting,
    narrow = width < 1200,
    compact = width < 1024;
  const refresh = useCallback(
    async (
      next: Screen = currentScreen.current,
      filter?: Filters,
      focusId: string | null = null,
      commit = true,
    ) => {
      const sid = session.current;
      if (
        sid === null ||
        next === "projects" ||
        next === "ioc" ||
        next === "commands"
      )
        return;
      filter ??= currentFilters.current[next];
      const revision = ++viewRevision.current;
      setLoading(true);
      try {
        const value = await api.view({
          session_id: sid,
          revision,
          screen: next,
          filters: filter,
          focus_id: focusId,
          commit_selection: commit,
          source_offset: sourceOffset,
          diagnostic_offset: diagnosticOffset,
          run_offset: runOffset,
        });
        if (
          revision !== viewRevision.current ||
          value.session_id !== session.current
        )
          return "Session or query changed; apply the query again";
        if (value.project)
          setBoot((v) => (v ? { ...v, project: value.project } : v));
        setViews((v) => ({ ...v, [next]: value }));
        setLastView(value);
        setSelection(value.selection);
        if (evidenceScreen(next) && commit && !focusId)
          scopeContext.current = {
            screen: next,
            filters: structuredClone(filter),
          };
        if (value.offset !== filter.offset)
          setFilters((v) => ({
            ...v,
            [next]: { ...v[next], offset: value.offset },
          }));
        setError(null);
      } catch (e) {
        if (
          revision === viewRevision.current &&
          !String(e).includes("Ignored") &&
          !String(e).includes("cancelled")
        )
          setError(String(e));
        return String(e);
      } finally {
        if (revision === viewRevision.current) setLoading(false);
      }
    },
    [sourceOffset, diagnosticOffset, runOffset],
  );
  refreshRef.current = refresh;
  const launch = async (run: () => Promise<TaskMessage>) => {
    lifecycle.current++;
    setError(null);
    try {
      const value = await run();
      if (!ended.current.has(value.task_id)) setTask(value);
    } catch (e) {
      setError(String(e));
    }
  };
  const updatePreferences = async (value: Preferences) => {
    setPrefs(value);
    try {
      await api.preferences(value);
    } catch (e) {
      setError(`Failed to save preferences: ${String(e)}`);
    }
  };
  useEffect(() => {
    document.documentElement.classList.toggle("dark", prefs.dark);
  }, [prefs.dark]);
  useEffect(() => {
    const resize = () => setWidth(window.innerWidth);
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);
  useEffect(() => {
    let disposed = false;
    let stopTask: (() => void) | undefined,
      stopDrop: (() => void) | undefined,
      stopClose: (() => void) | undefined;
    const initialize = async () => {
      try {
        stopTask = await listen<TaskMessage>("analysis-task", async (event) => {
          const value = event.payload;
          if (disposed) return;
          if (["running", "cancelling"].includes(value.status)) {
            if (!ended.current.has(value.task_id)) setTask(value);
            return;
          }
          ended.current.add(value.task_id);
          setTask((current) =>
            current?.task_id === value.task_id ? null : current,
          );
          setNotice(
            value.saved_paths.length
              ? `Saved: ${value.saved_paths.join(", ")}`
              : statusText[value.status] || value.status,
          );
          if (value.error) setError(value.error);
          if (value.kind === "config_check")
            setCheckStatus(value.error ? "Connection failed" : "Connection OK");
          const generation = lifecycle.current;
          const fresh = await api.initialize();
          if (disposed || generation !== lifecycle.current) return;
          const changed = fresh.session_id !== session.current;
          session.current = fresh.session_id;
          setBoot(fresh);
          setSelection(fresh.selection);
          setPrefs(fresh.preferences);
          if (value.kind.startsWith("config_")) setDraft(draftOf(fresh.config));
          if (changed) {
            viewRevision.current++;
            detailRevision.current++;
            setViews({});
            setAiFilter(null);
            setLogQueryOpen(false);
            setAiPreview(null);
            setExportPath("");
            setFilters(initialFilters(fresh.filters));
            setDetail(null);
            setFinding(null);
            setSelectedId(null);
            setSelectedSource(null);
            setFocus(null);
            setBack([]);
            scopeContext.current = null;
            const next =
              currentScreen.current === "commands"
                ? "commands"
                : value.kind === "project_create"
                  ? "import"
                  : "overview";
            setScreen(next);
            await refreshRef.current(next, defaultFilters(), null, false);
          } else if (fresh.session_id !== null) {
            if (value.kind === "import") {
              setFilters(
                (old) =>
                  Object.fromEntries(
                    Object.entries(old).map(([key, filter]) => [
                      key,
                      { ...filter, flow: null },
                    ]),
                  ) as Record<SessionScreen, Filters>,
              );
              setAiFilter(null);
              setAiPreview(null);
              setDetail(null);
              setFocus(null);
              setSelectedId(null);
              setFinding(null);
              setBack([]);
              scopeContext.current = null;
              setRequest((v) => ({ ...v, paths: [] }));
            }
            await refreshRef.current(
              currentScreen.current,
              currentScreen.current === "commands"
                ? undefined
                : currentFilters.current[currentScreen.current],
              value.kind === "import" ? null : currentFocus.current,
              evidenceScreen(currentScreen.current) &&
                (value.kind === "import" || !currentFocus.current),
            );
          }
          if (
            fresh.qa_ai &&
            !qaAiStarted.current &&
            value.kind === "import" &&
            fresh.session_id !== null
          ) {
            qaAiStarted.current = true;
            const preview = await api.previewAi(
              fresh.session_id!,
              "suspicious",
              null,
              false,
            );
            await launch(() =>
              api.ai(fresh.session_id!, "suspicious", null, false, preview.id),
            );
          }
          if (value.kind === "project_save" && value.status === "completed") {
            const action = afterSave.current;
            afterSave.current = null;
            action?.();
          }
          if (value.kind === "project_save" && value.status !== "completed")
            afterSave.current = null;
          if (value.error) setError(value.error);
        });
        const fresh = await api.initialize();
        if (disposed) return;
        setBoot(fresh);
        setFilters(initialFilters(fresh.filters));
        if (fresh.qa) setScreen("import");
        setPrefs(fresh.preferences);
        setDraft(draftOf(fresh.config));
        setSelection(fresh.selection);
        setTask(fresh.busy);
        session.current = fresh.session_id;
        setRequest((v) => ({
          ...v,
          capture_dir: fresh.capture_dir,
          paths: fresh.inputs,
          live: fresh.live_processes,
        }));
        if (fresh.config_error) setError(fresh.config_error);
        const win = getCurrentWebviewWindow();
        stopDrop = await win.onDragDropEvent(({ payload }) => {
          if (payload.type === "over" || payload.type === "enter")
            setDragging(true);
          else if (payload.type === "leave") setDragging(false);
          else if (payload.type === "drop") {
            setDragging(false);
            if (!taskRef.current) {
              setRequest((v) => ({
                ...v,
                paths: [...new Set([...v.paths, ...payload.paths])],
              }));
              setScreen("import");
            }
          }
        });
        stopClose = await win.onCloseRequested(async (event) => {
          if (closing.current) {
            event.preventDefault();
            return;
          }
          if (taskRef.current) {
            event.preventDefault();
            setCloseOpen(true);
          } else if (projectRef.current?.dirty) {
            event.preventDefault();
            guardRef.current(() => {
              closing.current = true;
              void win.destroy();
            });
          } else {
            closing.current = true;
            try {
              await api.preferences(prefsRef.current);
              // Tauri destroys the window after this awaited handler returns.
            } catch (e) {
              event.preventDefault();
              closing.current = false;
              setError(`Failed to save preferences: ${String(e)}`);
            }
          }
        });
        if (fresh.inputs.length && !fresh.qa && !fresh.project) {
          setEditing(false);
          setEditor(newProject());
          setScreen("import");
        } else if (fresh.inputs.length)
          await launch(() =>
            api.import({
              ...initialImport,
              capture_dir: fresh.capture_dir,
              paths: fresh.inputs,
            }),
          );
      } catch (e) {
        if (!disposed)
          setError(`Desktop API initialization failed: ${String(e)}`);
      }
    };
    void initialize();
    return () => {
      disposed = true;
      stopTask?.();
      stopDrop?.();
      stopClose?.();
    };
  }, []);
  useEffect(() => {
    if (session.current !== null)
      void refresh(
        screen,
        screen === "commands" ? undefined : filters[screen],
        focus,
        focus === null,
      );
  }, [screen, sourceOffset, diagnosticOffset, runOffset]);
  const navigate = (next: Screen) => {
    if (next === screen) return;
    setLogQueryOpen(false);
    if (next === "commands" || screen === "commands") {
      viewRevision.current++;
      setLoading(false);
    }
    detailRevision.current++;
    setScreen(next);
    setSelectedSource(null);
    setFocus(null);
    setDetail(null);
    setDetailLoading(false);
    setFinding(null);
    setSelectedId(null);
    setError(null);
    setDrawer(false);
  };
  const changeFilters = (patch: Partial<Filters>, reset = true) => {
    if (screen === "commands") return;
    const updated = { ...active, ...patch, ...(reset ? { offset: 0 } : {}) };
    setFilters((v) => ({ ...v, [screen]: updated }));
    setFocus(null);
    void refresh(screen, updated, null, true);
  };
  const applyLogQuery = async (log_query: LogQuery) => {
    if (screen !== "logs" || busy) return;
    const filter = { ...active, log_query, offset: 0 };
    const error = await refresh("logs", filter, null, true);
    if (error) throw new Error(error);
    setFilters((v) => ({ ...v, logs: filter }));
    setFocus(null);
    setLogQueryOpen(false);
  };
  const closeLogQuery = () => {
    setLogQueryOpen(false);
    if (loading) {
      const previous =
        scopeContext.current?.screen === "logs"
          ? scopeContext.current.filters
          : currentFilters.current.logs;
      setFilters((v) => ({ ...v, logs: structuredClone(previous) }));
      setFocus(null);
      // A new view revision cancels the previous native read and restores the
      // last valid selection, including a query that finished just before cancellation.
      void refresh("logs", previous, null, true);
      setNotice("Log query cancelled; the last valid scope is kept");
    }
  };
  const editAiFilter = () => {
    if (!hasSession || busy) return;
    const saved = scopeContext.current;
    setAiFilter(
      saved
        ? structuredClone(saved)
        : {
            screen: overview?.logs
              ? "logs"
              : overview?.processes
                ? "processes"
                : overview?.packets
                  ? "network"
                  : "logs",
            filters: defaultFilters(),
          },
    );
  };
  const applyAiFilter = async (draft: ScopeContext) => {
    if (busy || session.current === null) return;
    const sid = session.current;
    const revision = ++viewRevision.current;
    const filter = {
      ...draft.filters,
      offset: 0,
      tree: false,
      packets: true,
      collapsed: [],
    };
    setAiFilterBusy(true);
    try {
      const value = await api.view({
        session_id: sid,
        revision,
        screen: draft.screen,
        filters: filter,
        focus_id: null,
        commit_selection: true,
        source_offset: sourceOffset,
        diagnostic_offset: diagnosticOffset,
        run_offset: runOffset,
      });
      if (
        revision !== viewRevision.current ||
        value.session_id !== session.current
      )
        throw new Error("Session or view changed; apply the filter again");
      scopeContext.current = {
        screen: draft.screen,
        filters: structuredClone(filter),
      };
      setFilters((v) => ({ ...v, [draft.screen]: filter }));
      setViews((v) => ({ ...v, [draft.screen]: value }));
      setLastView(value);
      setSelection(value.selection);
      setScope("matches");
      setAiFilter(null);
      setError(null);
      await refresh("ai", currentFilters.current.ai, null, false);
    } finally {
      setAiFilterBusy(false);
    }
  };
  const requestElevation = async () => {
    if (busy || boot?.platform !== "windows") return;
    setElevationBusy(true);
    setError(null);
    setNotice("Waiting for UAC");
    try {
      const result = await api.elevate();
      setNotice(
        result === "launched"
          ? "Administrator window launched; the original window and evidence remain. Start local collection in the new window"
          : result === "cancelled"
            ? "UAC cancelled; still using the current window"
            : "The current window already has administrator privileges",
      );
    } catch (error) {
      setNotice("Elevation did not complete; the current session stays");
      setError(`Could not launch the administrator window: ${String(error)}`);
    } finally {
      setElevationBusy(false);
    }
  };
  const pick = async (kind: string) => {
    try {
      const paths = await api.pick(kind);
      if (!paths.length) return;
      if (kind === "inputs") {
        setRequest((v) => ({
          ...v,
          paths: [...new Set([...v.paths, ...paths])],
        }));
        navigate("import");
      } else if (kind === "capture")
        setRequest((v) => ({ ...v, capture_dir: paths[0] }));
      else if (kind === "web")
        setRequest((v) => ({ ...v, web_format: paths[0] }));
      else if (kind === "config") {
        setPrefs((v) => ({ ...v, config_path: paths[0] }));
        await launch(() => api.config("load", paths[0]));
      } else if (kind === "export") {
        setExportPath(paths[0]);
        setOverwrite(false);
      }
    } catch (e) {
      setError(String(e));
    }
  };
  const selectRecord = async (id: string, jump = false) => {
    if (screen === "commands") return;
    const sid = session.current;
    if (sid === null) return;
    if (jump)
      setBack((v) => [
        ...v,
        {
          screen,
          filters: structuredClone(filters),
          finding,
          detail,
          selectedId,
          scopeContext: scopeContext.current
            ? structuredClone(scopeContext.current)
            : null,
        },
      ]);
    const revision = ++detailRevision.current;
    setSelectedId(id);
    setFinding(null);
    setDetail(null);
    setDetailLoading(true);
    setDrawer(true);
    void updatePreferences({ ...prefsRef.current, inspector: true });
    try {
      const result = await api.detail(sid, id);
      if (revision !== detailRevision.current || sid !== session.current)
        return;
      setDetail(result);
      if (jump) {
        const next: SessionScreen =
          result.record.data.kind === "log"
            ? "logs"
            : result.record.data.kind === "process"
              ? "processes"
              : "network";
        setScreen(next);
        setFocus(id);
        if (next === "network")
          setFilters((v) => ({
            ...v,
            network: { ...v.network, packets: true },
          }));
        await refresh(
          next,
          {
            ...filters[next],
            ...(next === "network" ? { packets: true } : {}),
          },
          id,
          false,
        );
      }
    } catch (e) {
      if (revision === detailRevision.current) setError(String(e));
    } finally {
      if (revision === detailRevision.current) setDetailLoading(false);
    }
  };
  const selectFinding = (value: Finding) => {
    detailRevision.current++;
    setDetailLoading(false);
    setFinding(value);
    if (value.table_preview && session.current !== null) {
      const sid = session.current,
        revision = ++detailRevision.current;
      setDetailLoading(true);
      void api
        .finding(sid, value.id)
        .then((full) => {
          if (session.current === sid && detailRevision.current === revision)
            setFinding(full);
        })
        .catch((e) => {
          if (detailRevision.current === revision) setError(String(e));
        })
        .finally(() => {
          if (detailRevision.current === revision) setDetailLoading(false);
        });
    }
    setDetail(null);
    setSelectedId(null);
    setDrawer(true);
    void updatePreferences({ ...prefsRef.current, inspector: true });
  };
  const goBack = async () => {
    const previous = back.at(-1);
    if (!previous) return;
    detailRevision.current++;
    setBack((v) => v.slice(0, -1));
    setFilters(previous.filters);
    setScreen(previous.screen);
    setFocus(null);
    setFinding(previous.finding);
    setDetail(previous.detail);
    setSelectedId(previous.selectedId);
    scopeContext.current = previous.scopeContext;
    if (previous.scopeContext)
      await refresh(
        previous.scopeContext.screen,
        previous.scopeContext.filters,
        null,
        true,
      );
    await refresh(
      previous.screen,
      previous.filters[previous.screen],
      null,
      false,
    );
  };
  const applyConfig = async () => {
    if (!draft) return;
    const config = await api.applyConfig(draft);
    setBoot((v) => (v ? { ...v, config } : v));
    setDraft(draftOf(config));
    return config;
  };
  const configOperation = async (operation: string) => {
    try {
      if (operation !== "load") await applyConfig();
      await launch(() => api.config(operation, prefs.config_path));
      await api.preferences(prefs);
    } catch (e) {
      setError(String(e));
    }
  };
  const aiCount =
    scope === "matches"
      ? selection.count
      : scope === "all"
        ? overview?.records || 0
        : overview?.suspicious || 0;
  const aiPlanKey = JSON.stringify([
    boot?.session_id,
    scope,
    scope === "matches" ? selection.id : null,
    payload,
    boot?.config,
  ]);
  const currentAiPreview =
    aiPreview?.key === aiPlanKey ? aiPreview.value : null;
  const currentAiPreviewError =
    aiPreviewError?.key === aiPlanKey ? aiPreviewError.message : null;
  useEffect(() => {
    if (
      screen !== "ai" ||
      busy ||
      !boot?.config_loaded ||
      boot.session_id === null ||
      !aiCount
    )
      return;
    let disposed = false;
    setAiPreview(null);
    setAiPreviewError(null);
    void api
      .previewAi(
        boot.session_id,
        scope,
        scope === "matches" ? selection.id : null,
        payload,
      )
      .then((value) => {
        if (!disposed) setAiPreview({ key: aiPlanKey, value });
      })
      .catch((e) => {
        if (!disposed)
          setAiPreviewError({ key: aiPlanKey, message: String(e) });
      });
    return () => {
      disposed = true;
    };
  }, [screen, busy, boot?.config_loaded, aiPlanKey, aiCount, aiPreviewAttempt]);
  const startAI = async () => {
    const sid = session.current;
    if (sid === null || !currentAiPreview || busy) return;
    const includePayload = payload;
    setAiSending(true);
    try {
      await launch(() =>
        api.ai(
          sid,
          scope,
          scope === "matches" ? selection.id : null,
          includePayload,
          currentAiPreview.id,
        ),
      );
    } finally {
      setPayload(false);
      setAiSending(false);
      setAiPreview(null);
    }
  };

  const updateProject = async () => {
    const sid = session.current;
    const fresh = await api.initialize();
    if (fresh.session_id === sid) setBoot(fresh);
  };
  const guarded = (action: () => void) => {
    if (projectRef.current?.dirty) {
      pendingAction.current = action;
      setDirtyOpen(true);
    } else action();
  };
  guardRef.current = guarded;
  const createProject = () =>
    guarded(() => {
      setEditing(false);
      setEditor(newProject());
    });
  const editProject = () => {
    const project = projectRef.current;
    if (busy || !project) return;
    setEditing(true);
    setEditor(structuredClone(project.info));
  };
  const openProject = (path: string) =>
    guarded(() => void launch(() => api.openProject(path)));
  const pickProject = async () => {
    try {
      const paths = await api.pick("project_open");
      if (paths.length) openProject(paths[0]);
    } catch (e) {
      setError(String(e));
    }
  };
  const saveProject = async (saveAs = false, action?: () => void) => {
    const sid = session.current;
    const project = projectRef.current;
    if (sid === null || !project) return;
    try {
      let path = project.path;
      let overwrite = false;
      if (saveAs || !path) {
        const paths = await api.pick("project_save");
        if (!paths.length) return;
        path = paths[0];
        overwrite = true;
      }
      afterSave.current = action ?? null;
      lifecycle.current++;
      setError(null);
      const job = await api.saveProject(sid, path!, overwrite);
      if (!ended.current.has(job.task_id)) setTask(job);
    } catch (e) {
      afterSave.current = null;
      setError(String(e));
    }
  };
  const submitProject = async (info: ProjectInfo) => {
    if (busy) throw new Error("Wait for the current operation to finish");
    setProjectSubmitting(true);
    try {
      if (editing) {
        const sid = session.current;
        if (sid === null || projectRef.current?.info.id !== info.id)
          throw new Error(
            "The current project changed; reopen the editor and try again",
          );
        const project = await api.editProject(sid, info);
        if (session.current !== sid)
          throw new Error(
            "The current project changed; reopen the editor and try again",
          );
        setBoot((v) => (v ? { ...v, project } : v));
        setNotice("Project details changed; save the project");
      } else {
        lifecycle.current++;
        const job = await api.createProject(info);
        if (!ended.current.has(job.task_id)) setTask(job);
      }
      setEditor(null);
    } finally {
      setProjectSubmitting(false);
    }
  };
  useEffect(() => {
    const sid = boot?.session_id;
    if (sid == null || !boot?.project || busy) return;
    let stale = false;
    const timeout = setTimeout(() => {
      api
        .projectFilters(sid, filters)
        .then((project) => {
          if (!stale && session.current === sid)
            setBoot((v) => (v ? { ...v, project } : v));
        })
        .catch((e) => {
          if (!stale) setError(String(e));
        });
    }, 500);
    return () => {
      stale = true;
      clearTimeout(timeout);
    };
  }, [filters, boot?.session_id, busy]);
  const reset = async () => {
    lifecycle.current++;
    try {
      await api.reset();
      session.current = null;
      viewRevision.current++;
      detailRevision.current++;
      setBoot((v) => (v ? { ...v, session_id: null, project: null } : v));
      setViews({});
      setSelectedSource(null);
      setLastView(null);
      setSelection(emptySelection);
      setFilters(initialFilters());
      setFinding(null);
      setDetail(null);
      setSelectedId(null);
      setFocus(null);
      setBack([]);
      scopeContext.current = null;
      setRequest((v) => ({ ...v, paths: [] }));
      setScreen("projects");
      setNotice("Ready");
      setNewOpen(false);
    } catch (e) {
      setError(String(e));
    }
  };
  const doExport = async () => {
    const sid = session.current;
    if (sid === null) return;
    setError(null);
    try {
      lifecycle.current++;
      const job = await api.export(
        sid,
        selection.id || null,
        exportPath,
        exportHtml,
        exportJson,
        overwrite,
      );
      setExportOpen(false);
      setOverwrite(false);
      if (!ended.current.has(job.task_id)) setTask(job);
    } catch (e) {
      if (String(e).includes("already exists")) setOverwrite(true);
      else setError(String(e));
    }
  };
  const resizeInspector = (e: React.PointerEvent) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    const start = e.clientX,
      original = prefs.inspector_width;
    const move = (event: PointerEvent) =>
      setPrefs((v) => ({
        ...v,
        inspector_width: Math.max(
          280,
          Math.min(440, original + start - event.clientX),
        ),
      }));
    const end = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", end);
      void api.preferences(prefsRef.current);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", end);
  };
  const findingsColumns: ColumnDef<Finding>[] = [
    {
      id: "risk",
      header: "Risk",
      size: 72,
      cell: ({ row }) => <Risk finding={row.original} />,
    },
    {
      accessorKey: "title",
      header: "Finding",
      cell: ({ row }) => (
        <span className="truncate table-primary" title={row.original.title}>
          {row.original.title}
        </span>
      ),
    },
    {
      id: "origin",
      header: "Origin",
      size: 78,
      cell: ({ row }) => (
        <span className="origin-badge">
          {row.original.origin.startsWith("local:") ? "Local rules" : "AI"}
        </span>
      ),
    },
    {
      id: "evidence",
      header: "Evidence",
      size: 53,
      cell: ({ row }) => (
        <span className="mono table-muted">
          {row.original.evidence_count ?? row.original.evidence_ids.length}
        </span>
      ),
    },
    {
      id: "confidence",
      header: "Confidence",
      size: 64,
      cell: ({ row }) => (
        <span className="table-muted">
          {Math.round(row.original.confidence * 100)}%
        </span>
      ),
    },
  ];
  const logEventColumn: ColumnDef<RecordSummary>[] =
    screen === "logs"
      ? [
          {
            id: "event_id",
            header: "Level / status / event",
            size: 105,
            cell: ({ row }) => (
              <span className="mono table-muted">
                {logDetail(row.original)}
              </span>
            ),
          },
        ]
      : [];
  const recordsColumns: ColumnDef<RecordSummary>[] = [
    {
      id: "time",
      header: screen === "processes" ? "PID / PPID" : "Time",
      size: screen === "processes" ? 85 : screen === "logs" ? 160 : 115,
      cell: ({ row }) => {
        const r = row.original;
        return (
          <span
            className="mono truncate table-muted"
            title={
              screen === "logs" ? displayRecordLogTime(r) : r.timestamp || ""
            }
          >
            {r.data.kind === "process"
              ? `${r.data.fields.pid} / ${r.data.fields.parent_pid ?? "—"}`
              : screen === "logs"
                ? displayRecordLogTime(r)
                : r.timestamp?.slice(5, 19).replace("T", " ") || "Unknown"}
          </span>
        );
      },
    },
    ...logEventColumn,
    {
      id: "source",
      header: screen === "processes" ? "Snapshot source" : "Source",
      size: 99,
      cell: ({ row }) => (
        <span
          className="truncate table-muted"
          title={data?.record_sources[row.original.source_id]}
        >
          {basename(
            data?.record_sources[row.original.source_id] ||
              row.original.source_id.slice(0, 8),
          )}
        </span>
      ),
    },
    {
      id: "kind",
      header:
        screen === "processes"
          ? "Relations"
          : screen === "network"
            ? "Protocol"
            : "Event type",
      size: screen === "network" ? 56 : 87,
      cell: ({ row }) => {
        const r = row.original;
        const node = data?.process_rows.find((n) => n.record_id === r.id);
        return r.data.kind === "process" ? (
          <span className="relation-tags">
            {node?.orphan && <span className="tag-warning">Orphan</span>}
            {node?.cyclic && <span className="tag-warning">Cycle</span>}
            {node?.context && <span>Context</span>}
            {!node?.orphan && !node?.cyclic && !node?.context && (
              <span className="table-muted">Normal</span>
            )}
          </span>
        ) : (
          <span
            className="truncate table-muted"
            title={
              r.data.kind === "log"
                ? r.data.fields.category
                : r.data.fields.protocol
            }
          >
            {r.data.kind === "log"
              ? logTypeLabel(r.data.fields.category)
              : r.data.fields.protocol}
          </span>
        );
      },
    },
    {
      id: "summary",
      header:
        screen === "processes"
          ? "Process name"
          : screen === "network"
            ? "Endpoints / summary"
            : "Key fields",
      cell: ({ row }) => {
        const r = row.original;
        const node = data?.process_rows.find((n) => n.record_id === r.id);
        return (
          <div
            className="process-name"
            style={
              r.data.kind === "process"
                ? { paddingLeft: Math.min(node?.depth || 0, 8) * 12 }
                : undefined
            }
          >
            {node?.has_children && (
              <button
                className="tree-toggle"
                aria-label={`${active.collapsed.includes(r.id) ? "Expand" : "Collapse"} ${r.data.kind === "process" ? r.data.fields.name : ""}`}
                onClick={(e) => {
                  e.stopPropagation();
                  changeFilters({
                    collapsed: active.collapsed.includes(r.id)
                      ? active.collapsed.filter((id) => id !== r.id)
                      : [...active.collapsed, r.id],
                  });
                }}
              >
                {active.collapsed.includes(r.id) ? (
                  <ChevronRight size={12} />
                ) : (
                  <ChevronDown size={12} />
                )}
              </button>
            )}
            <span
              className="truncate table-primary"
              title={r.data.kind === "process" ? r.data.fields.name : r.summary}
            >
              {r.data.kind === "process"
                ? r.data.fields.name
                : r.data.kind === "log" && r.status !== "parsed"
                  ? "Click to view the raw record"
                  : r.summary}
            </span>
          </div>
        );
      },
    },
    {
      id: "status",
      header: screen === "network" ? "Bytes" : "Status",
      size: 66,
      cell: ({ row }) =>
        row.original.data.kind === "packet" ? (
          <span className="mono table-muted">
            {bytes(row.original.data.fields.original_bytes)}
          </span>
        ) : (
          <span className={`parse-status parse-${row.original.status}`}>
            {statusLabel[row.original.status]}
          </span>
        ),
    },
  ];
  const flowColumns: ColumnDef<Flow>[] = [
    {
      accessorKey: "endpoint_a",
      header: "Endpoint A",
      cell: ({ row }) => (
        <span
          className="mono truncate table-primary"
          title={row.original.endpoint_a}
        >
          {row.original.endpoint_a}
        </span>
      ),
    },
    {
      accessorKey: "endpoint_b",
      header: "Endpoint B",
      cell: ({ row }) => (
        <span className="mono truncate" title={row.original.endpoint_b}>
          {row.original.endpoint_b}
        </span>
      ),
    },
    { accessorKey: "protocol", header: "Protocol", size: 64 },
    {
      id: "packets",
      header: "Matched / total packets",
      size: 110,
      cell: ({ row }) => (
        <span className="mono">
          {row.original.matched_packets} / {row.original.packets}
        </span>
      ),
    },
    {
      id: "bytes",
      header: "Bytes",
      size: 74,
      cell: ({ row }) => (
        <span className="mono table-muted">{bytes(row.original.bytes)}</span>
      ),
    },
  ];
  const sourceColumns: ColumnDef<Source>[] = [
    {
      accessorKey: "path",
      header: "Source path",
      cell: ({ row }) => (
        <span className="truncate mono" title={row.original.path}>
          {basename(row.original.path)}
        </span>
      ),
    },
    {
      accessorKey: "format",
      header: "Format",
      size: 76,
      cell: ({ row }) => (
        <span className="small-badge">{row.original.format}</span>
      ),
    },
    {
      id: "size",
      header: "Size",
      size: 80,
      cell: ({ row }) => (
        <span className="mono table-muted">{bytes(row.original.bytes)}</span>
      ),
    },
    {
      accessorKey: "sha256",
      header: "SHA-256",
      size: 128,
      cell: ({ row }) => (
        <span className="mono truncate table-muted" title={row.original.sha256}>
          {row.original.sha256}
        </span>
      ),
    },
  ];
  const riskControls = (
    <div className="filter-row">
      <Select
        label="Risk level"
        value={active.severity || ""}
        onChange={(v) => changeFilters({ severity: (v as Severity) || null })}
        options={[
          { value: "", label: "All risks" },
          ...Object.entries(severityLabel).map(([value, label]) => ({
            value,
            label,
          })),
        ]}
      />
      {screen !== "ai" && (
        <Select
          label="Finding origin"
          value={active.origin}
          onChange={(v) => changeFilters({ origin: v || "all" })}
          options={[
            { value: "all", label: "All findings" },
            { value: "local", label: "Local rules" },
            { value: "ai", label: "AI findings" },
          ]}
        />
      )}
      <span className="filter-count">
        {number(data?.findings?.total || 0)} findings
      </span>
    </div>
  );
  const findingsTable = (
    <DataTable
      page={data?.findings || null}
      columns={
        screen === "ai"
          ? findingsColumns.filter((c) => c.id !== "origin")
          : findingsColumns
      }
      id={(v) => v.id}
      selected={finding?.id}
      onSelect={selectFinding}
      loading={loading}
      empty={
        hasSession
          ? screen === "ai"
            ? "No AI findings for the current risk filter; select evidence and run AI analysis"
            : "No findings for the current filter"
          : "Analysis results appear after evidence is imported"
      }
      limit={active.limit}
      onPage={(offset) => changeFilters({ offset }, false)}
      onSize={(limit) => changeFilters({ limit })}
    />
  );
  const closeInspector = () => {
    setDrawer(false);
    void updatePreferences({ ...prefs, inspector: false });
  };
  const inspector =
    screen === "reports" && selectedSource ? (
      <SourceInspector source={selectedSource} onClose={closeInspector} />
    ) : (
      <Inspector
        sessionId={boot?.session_id ?? null}
        onSaveNote={
          boot?.project
            ? async (text: string) => {
                if (!detail) return;
                const sid = detail.session_id;
                const record = detail.record.id;
                try {
                  const project = await api.note(sid, record, text);
                  if (session.current === sid) {
                    setBoot((v) => (v ? { ...v, project } : v));
                    setDetail((v) =>
                      v?.record.id === record ? { ...v, note: text } : v,
                    );
                    setNotice(
                      "Evidence note written; persist it by saving the project",
                    );
                  }
                } catch (e) {
                  setError(String(e));
                }
              }
            : undefined
        }
        finding={finding}
        detail={detail}
        loading={detailLoading}
        onJump={(id) => void selectRecord(id, true)}
        onFinding={selectFinding}
        onClose={closeInspector}
      />
    );

  return (
    <TooltipProvider>
      <div
        className={`application ${boot?.platform === "macos" ? "macos" : ""}`}
        style={
          { "--inspector-width": `${prefs.inspector_width}px` } as CSSProperties
        }
      >
        <header
          className="toolbar"
          onMouseDown={(event) => {
            if (
              event.button === 0 &&
              !(event.target as HTMLElement).closest("button,input,select")
            ) {
              void getCurrentWebviewWindow().startDragging();
            }
          }}
        >
          <div className="brand">
            <img
              className="brand-mark"
              src="/easy-analyzer.svg"
              alt=""
              aria-hidden="true"
            />
            <strong>Easy Analyzer</strong>
          </div>
          <div className="toolbar-session">
            <span className="session-symbol">
              <Files size={13} />
            </span>
            <button
              className="toolbar-project"
              title={boot?.project ? "Edit project details" : undefined}
              disabled={busy || !boot?.project}
              onClick={editProject}
            >
              {boot?.project
                ? `${boot.project.info.name} · ${boot.project.info.client}${boot.project.dirty ? " *" : ""}`
                : hasSession
                  ? "Evidence analysis session"
                  : "New project"}
            </button>
            <ChevronRight size={12} />
            <span className="toolbar-current">{titles[screen]}</span>
            {hasSession && (
              <span className="session-badge">
                <span className="status-dot" />
                {boot?.project ? "Incident response project" : "Local session"}
              </span>
            )}
          </div>
          <div className="toolbar-actions">
            {boot?.project && (
              <>
                <Button variant="ghost" disabled={busy} onClick={editProject}>
                  <Pencil size={14} />
                  Edit details
                </Button>
                <Button
                  variant="ghost"
                  disabled={busy}
                  onClick={() => void saveProject()}
                >
                  Save{boot.project.dirty ? " *" : ""}
                </Button>
                <Button
                  variant="ghost"
                  disabled={busy}
                  onClick={() => void saveProject(true)}
                >
                  Save as
                </Button>
              </>
            )}
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() =>
                boot?.qa
                  ? hasSession
                    ? setNewOpen(true)
                    : navigate("import")
                  : createProject()
              }
            >
              <Plus size={14} />
              <span>New project</span>
            </Button>
            <Button
              variant="ghost"
              disabled={!hasSession}
              onClick={() => navigate("ai")}
            >
              <Sparkles size={14} />
              <span>AI analysis</span>
            </Button>
            <Button
              variant="secondary"
              disabled={!hasSession || busy || loading}
              onClick={() => {
                setExportOpen(true);
                setOverwrite(false);
              }}
            >
              <Download size={14} />
              <span>Export report</span>
            </Button>
          </div>
          {boot?.platform !== "macos" && (
            <div className="window-actions">
              <Button
                variant="ghost"
                size="icon"
                aria-label="Minimize"
                onClick={() => void getCurrentWebviewWindow().minimize()}
              >
                <Minus size={13} />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Maximize"
                onClick={() => void getCurrentWebviewWindow().toggleMaximize()}
              >
                <Square size={11} />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Close window"
                onClick={() =>
                  void getCurrentWebviewWindow()
                    .close()
                    .catch((e) =>
                      setError(`Failed to close the window: ${String(e)}`),
                    )
                }
              >
                <X size={14} />
              </Button>
            </div>
          )}
        </header>
        <div className="workbench">
          <aside className="sidebar">
            <div className="sidebar-navigation">
              <div className="sidebar-section">Workbench</div>
              {screens
                .filter((s) => s !== "settings")
                .map((s) => {
                  const Icon = icons[s];
                  return (
                    <div key={s}>
                      {s === "import" && (
                        <div className="sidebar-section">Evidence</div>
                      )}
                      {s === "processes" && (
                        <div className="sidebar-section">
                          Analysis and output
                        </div>
                      )}
                      <Tooltip text={titles[s]}>
                        <button
                          className={`nav-item ${screen === s ? "active" : ""}`}
                          aria-label={titles[s]}
                          aria-current={screen === s ? "page" : undefined}
                          onClick={() => navigate(s)}
                        >
                          <Icon size={16} strokeWidth={1.7} />
                          <span>{titles[s]}</span>
                          {s === "overview" && overview && (
                            <small>
                              {overview.local_findings + overview.ai_findings}
                            </small>
                          )}
                        </button>
                      </Tooltip>
                    </div>
                  );
                })}
            </div>
            <div className="sidebar-bottom">
              {hasSession && (
                <div className="sidebar-session">
                  <span className="session-symbol">
                    <Files size={14} />
                  </span>
                  <div>
                    <strong>
                      {number(overview?.records || 0)} evidence records
                    </strong>
                    <span>
                      {overview?.sources || 0} sources ·{" "}
                      {boot?.project ? ".eair project" : "temporary session"}
                    </span>
                  </div>
                </div>
              )}
              <Tooltip text="Settings">
                <button
                  className={`nav-item ${screen === "settings" ? "active" : ""}`}
                  onClick={() => navigate("settings")}
                  aria-label="Settings"
                >
                  <Settings2 size={16} />
                  <span>Settings</span>
                </button>
              </Tooltip>
              <Tooltip
                text={
                  prefs.dark
                    ? "Switch to the light theme"
                    : "Switch to the dark theme"
                }
              >
                <button
                  className="nav-item theme-toggle"
                  aria-label={
                    prefs.dark
                      ? "Switch to the light theme"
                      : "Switch to the dark theme"
                  }
                  onClick={() =>
                    void updatePreferences({ ...prefs, dark: !prefs.dark })
                  }
                >
                  {prefs.dark ? <Sun size={16} /> : <Moon size={16} />}
                  <span>{prefs.dark ? "Light theme" : "Dark theme"}</span>
                </button>
              </Tooltip>
              <div className="sidebar-version">
                Easy Analyzer <span>{appVersion}</span>
              </div>
            </div>
          </aside>
          <main className="workspace">
            <div className="page-heading">
              <div>
                <div className="title-line">
                  {screen !== "commands" && back.length > 0 && (
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label="Back to previous view"
                      onClick={() => void goBack()}
                    >
                      <ArrowLeft size={16} />
                    </Button>
                  )}
                  <h1>{titles[screen]}</h1>
                  {loading && <LoaderCircle size={14} className="spin muted" />}
                </div>
                <p>{hints[screen]}</p>
              </div>
              {screen !== "commands" && (
                <Tooltip
                  text={
                    narrow
                      ? "Open evidence details"
                      : prefs.inspector
                        ? "Collapse details"
                        : "Expand details"
                  }
                >
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Toggle details"
                    onClick={() =>
                      narrow
                        ? setDrawer(true)
                        : void updatePreferences({
                            ...prefs,
                            inspector: !prefs.inspector,
                          })
                    }
                  >
                    <PanelRight size={17} />
                  </Button>
                </Tooltip>
              )}
            </div>
            {error && (
              <div className="error-banner">
                <CircleAlert size={14} />
                <span>{error}</span>
                <button
                  aria-label="Dismiss error"
                  onClick={() => setError(null)}
                >
                  <X size={13} />
                </button>
              </div>
            )}
            <div
              className={`page-body ${screen === "ai" ? "ai-page-body" : ""}`}
            >
              {screen === "commands" && <CommandsView />}
              {screen === "projects" && (
                <ProjectHome
                  busy={busy}
                  current={boot?.project}
                  onEdit={editProject}
                  onNew={createProject}
                  onOpen={openProject}
                  onPick={() => void pickProject()}
                  onError={setError}
                />
              )}
              {screen === "ioc" &&
                (boot?.project && boot.session_id !== null ? (
                  <IocView
                    key={boot.session_id}
                    sessionId={boot.session_id}
                    revision={boot.project.revision}
                    busy={busy}
                    onTask={launch}
                    onJump={(id) => void selectRecord(id, true)}
                    onChanged={updateProject}
                    onError={setError}
                  />
                ) : (
                  <p>Create or open an incident response project first.</p>
                ))}
              {screen === "import" && (
                <ImportView
                  request={request}
                  onChange={setRequest}
                  busy={busy}
                  platform={boot?.platform || "macos"}
                  elevated={boot?.elevated ?? null}
                  elevationError={boot?.elevation_error ?? null}
                  elevationBusy={elevationBusy}
                  onElevate={() => void requestElevation()}
                  onPick={(k) => void pick(k)}
                  onStart={() => {
                    if (!boot?.project && !boot?.qa) {
                      createProject();
                    } else void launch(() => api.import(request));
                  }}
                  dragging={dragging}
                />
              )}
              {screen === "overview" && (
                <>
                  <div className="statistics">
                    {[
                      {
                        label: "Evidence sources",
                        value: overview?.sources || 0,
                        sub: "distinct sources",
                        icon: Files,
                      },
                      {
                        label: "Evidence records",
                        value: overview?.records || 0,
                        sub: "complete evidence set",
                        icon: FileText,
                      },
                      {
                        label: "Local findings",
                        value: overview?.local_findings || 0,
                        sub: "rule analysis",
                        icon: ShieldCheck,
                      },
                      {
                        label: "AI findings",
                        value: overview?.ai_findings || 0,
                        sub: "validated",
                        icon: Sparkles,
                      },
                    ].map((item) => (
                      <div key={item.label}>
                        <span>
                          <item.icon size={13} />
                          {item.label}
                        </span>
                        <strong>{number(item.value)}</strong>
                        <small>{item.sub}</small>
                      </div>
                    ))}
                  </div>
                  <div className="table-section-heading">
                    <span>Findings to verify</span>
                    <small>ordered by risk level</small>
                  </div>
                  {riskControls}
                  {findingsTable}
                </>
              )}
              {evidenceScreen(screen) && (
                <>
                  <form
                    className="search-row"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (composingQuery.current) return;
                      changeFilters({});
                    }}
                  >
                    <div className="search-input">
                      <Search size={15} />
                      <input
                        aria-label="Query evidence"
                        placeholder="Search keywords or a regular expression…"
                        value={active.text}
                        onCompositionStart={() => {
                          composingQuery.current = true;
                        }}
                        onCompositionEnd={() => {
                          composingQuery.current = false;
                        }}
                        onKeyDown={(e) => {
                          // WebKit may report keyCode 229 while committing an IME candidate.
                          if (
                            e.key === "Enter" &&
                            (composingQuery.current ||
                              e.nativeEvent.isComposing ||
                              e.nativeEvent.keyCode === 229)
                          )
                            e.preventDefault();
                        }}
                        onChange={(e) =>
                          setFilters((v) => ({
                            ...v,
                            [screen]: { ...v[screen], text: e.target.value },
                          }))
                        }
                      />
                      <span className="search-key">
                        <Keyboard size={12} />↵
                      </span>
                    </div>
                    <Button
                      variant="secondary"
                      type="submit"
                      disabled={!hasSession || loading}
                    >
                      Query
                    </Button>
                    <Button
                      variant="ghost"
                      type="button"
                      onClick={() => {
                        const f = defaultFilters();
                        setFilters((v) => ({ ...v, [screen]: f }));
                        setFocus(null);
                        void refresh(screen, f);
                      }}
                    >
                      Reset
                    </Button>
                  </form>
                  <div className="filter-row evidence-filters">
                    {screen === "logs" && (
                      <>
                        <Button
                          type="button"
                          variant="secondary"
                          disabled={!hasSession || busy || loading}
                          onClick={() => setLogQueryOpen(true)}
                        >
                          <SlidersHorizontal size={14} />
                          Multi-dim query
                          {logQueryCount(active.log_query) > 0
                            ? ` (${logQueryCount(active.log_query)})`
                            : ""}
                        </Button>
                        <Select
                          label="Log order"
                          value={active.order}
                          disabled={loading || busy}
                          onChange={(order) =>
                            changeFilters({ order: order as RecordOrder })
                          }
                          options={[
                            {
                              value: "original_asc",
                              label: "Original order (forward)",
                            },
                            {
                              value: "original_desc",
                              label: "Original order (reverse)",
                            },
                            {
                              value: "time_asc",
                              label: "Time ascending (old → new)",
                            },
                            {
                              value: "time_desc",
                              label: "Time descending (new → old)",
                            },
                          ]}
                        />
                      </>
                    )}
                    <Checkbox
                      label="Regex"
                      checked={active.regex}
                      onChange={(regex) => changeFilters({ regex })}
                    />
                    <Checkbox
                      label="Local suspicious only"
                      checked={active.suspicious}
                      onChange={(suspicious) => changeFilters({ suspicious })}
                    />
                    <span className="filter-separator" />
                    <Select
                      label="Evidence source"
                      value={active.source || ""}
                      onChange={(source) =>
                        changeFilters({ source: source || null })
                      }
                      options={[
                        { value: "", label: "All sources" },
                        ...(data?.sources.items || []).map((s) => ({
                          value: s.id,
                          label: basename(s.path),
                        })),
                        ...(active.source &&
                        !data?.sources.items.some((s) => s.id === active.source)
                          ? [{ value: active.source, label: "Selected source" }]
                          : []),
                      ]}
                    />
                    {screen === "logs" && (
                      <Select
                        label="Event type / log category"
                        value={active.category || ""}
                        onChange={(category) =>
                          changeFilters({ category: category || null })
                        }
                        options={[
                          { value: "", label: "All event types" },
                          ...(overview?.categories || []).map((value) => ({
                            value,
                            label: logTypeLabel(value),
                          })),
                        ]}
                      />
                    )}
                    <Select
                      label="Parse status"
                      value={active.status || ""}
                      onChange={(status) =>
                        changeFilters({
                          status: (status as Filters["status"]) || null,
                        })
                      }
                      options={[
                        { value: "", label: "All statuses" },
                        ...Object.entries(statusLabel).map(
                          ([value, label]) => ({ value, label }),
                        ),
                      ]}
                    />
                    {screen === "network" && (
                      <Select
                        label="Protocol"
                        value={active.protocol || ""}
                        onChange={(protocol) =>
                          changeFilters({ protocol: protocol || null })
                        }
                        options={[
                          { value: "", label: "All protocols" },
                          ...(overview?.protocols || []).map((value) => ({
                            value,
                            label: value,
                          })),
                        ]}
                      />
                    )}
                  </div>
                  {data && data.sources.total > 100 && (
                    <Pagination
                      label="Filtered sources"
                      offset={data.sources.offset}
                      total={data.sources.total}
                      limit={100}
                      loading={loading}
                      onPage={(offset) => {
                        if (offset === sourceOffset) void refresh();
                        else setSourceOffset(offset);
                      }}
                    />
                  )}
                  {screen === "processes" && (
                    <div className="view-mode">
                      <Tabs
                        value={active.tree ? "tree" : "list"}
                        onChange={(v) => changeFilters({ tree: v === "tree" })}
                        items={[
                          { value: "tree", label: "Process tree" },
                          { value: "list", label: "List" },
                        ]}
                      />
                      <span>
                        Snapshots group separately · ancestors shown as context
                      </span>
                    </div>
                  )}
                  {screen === "network" && (
                    <div className="view-mode">
                      <Tabs
                        value={active.packets ? "packets" : "flows"}
                        onChange={(v) =>
                          changeFilters({
                            packets: v === "packets",
                            flow: null,
                          })
                        }
                        items={[
                          { value: "flows", label: "Network sessions" },
                          { value: "packets", label: "Packets" },
                        ]}
                      />
                      <span>
                        {active.flow !== null
                          ? `Session #${active.flow + 1} · filter intersection`
                          : "Session statistics cover all packets and bytes"}
                      </span>
                      {active.flow !== null && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => changeFilters({ flow: null })}
                        >
                          All packets
                        </Button>
                      )}
                    </div>
                  )}
                  {data?.outside && (
                    <div className="focus-banner">
                      <ArrowUpRight size={13} />
                      Evidence outside the current filter is focused; the
                      original view returns when you go back.
                    </div>
                  )}
                  {screen === "network" && !active.packets ? (
                    <DataTable
                      page={data?.flows || null}
                      columns={flowColumns}
                      id={(v) => String(v.key)}
                      loading={loading}
                      onSelect={(f) =>
                        changeFilters({ flow: f.key, packets: true })
                      }
                      onPage={(offset) => changeFilters({ offset }, false)}
                      onSize={(limit) => changeFilters({ limit })}
                      limit={active.limit}
                    />
                  ) : (
                    <DataTable
                      page={data?.records || null}
                      columns={recordsColumns}
                      id={(v) => v.id}
                      selected={selectedId}
                      onSelect={(r) => void selectRecord(r.id)}
                      loading={loading}
                      onPage={(offset) => changeFilters({ offset }, false)}
                      onSize={(limit) => changeFilters({ limit })}
                      limit={active.limit}
                      empty={
                        hasSession
                          ? "No evidence matches; adjust the filters"
                          : "Import evidence first, then query and verify it here"
                      }
                    />
                  )}
                </>
              )}
              {screen === "ai" && (
                <>
                  <div className="ai-controls">
                    <div className="ai-scope-row">
                      <span className="section-label-text">Evidence scope</span>
                      <div className="segmented">
                        {[
                          {
                            value: "suspicious",
                            label: "Local suspicious items",
                          },
                          { value: "matches", label: "Current filter" },
                          { value: "all", label: "All evidence" },
                        ].map((s) => (
                          <button
                            key={s.value}
                            disabled={busy || !hasSession}
                            className={scope === s.value ? "active" : ""}
                            onClick={() => {
                              if (s.value === "matches" && !selection.id)
                                editAiFilter();
                              else setScope(s.value);
                            }}
                          >
                            {scope === s.value && <Check size={12} />} {s.label}
                          </button>
                        ))}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!hasSession || busy}
                        onClick={editAiFilter}
                      >
                        <SlidersHorizontal size={13} />
                        Edit filter
                      </Button>
                    </div>
                    <div className="ai-summary">
                      <div className="ai-summary-main">
                        <span className="ai-symbol">
                          <Sparkles size={18} />
                        </span>
                        <div>
                          <strong>
                            {number(aiCount)} <small>records</small>
                          </strong>
                          <p title={scope === "matches" ? selection.label : ""}>
                            {scope === "matches"
                              ? selection.label
                              : scope === "suspicious"
                                ? "Evidence matched by local rules"
                                : "All evidence in the current session"}
                          </p>
                        </div>
                        <Button
                          disabled={
                            !hasSession ||
                            busy ||
                            loading ||
                            !aiCount ||
                            !boot?.config_loaded ||
                            !currentAiPreview
                          }
                          onClick={() => void startAI()}
                        >
                          <Sparkles size={14} />
                          Run AI analysis
                        </Button>
                      </div>
                      <div className="ai-service">
                        <span>
                          Model{" "}
                          <strong>
                            {boot?.config.model || "Not configured"}
                          </strong>
                        </span>
                        <span
                          className="truncate"
                          title={boot?.config.base_url}
                        >
                          Service{" "}
                          <strong>
                            {boot?.config.base_url || "Not configured"}
                          </strong>
                        </span>
                        <button onClick={() => navigate("settings")}>
                          Configure
                          <ArrowUpRight size={11} />
                        </button>
                      </div>
                    </div>
                    {boot?.config_loaded && hasSession && !!aiCount && (
                      <div className="ai-plan-preview" aria-live="polite">
                        {currentAiPreview ? (
                          <>
                            <strong>Send preview</strong>
                            <details className="ai-budget-details">
                              <summary>Budget details</summary>
                              <div>
                                <span>
                                  {number(
                                    currentAiPreview.plan.selected_records,
                                  )}{" "}
                                  records · evidence ≈{" "}
                                  {number(
                                    currentAiPreview.plan.evidence_tokens,
                                  )}{" "}
                                  tokens · prompt + reserve ≈{" "}
                                  {number(currentAiPreview.plan.prompt_tokens)}{" "}
                                  token
                                </span>
                                <small>
                                  Conservative local estimate, not the
                                  provider's exact count; nothing is sent
                                  automatically.
                                  {currentAiPreview.plan.context_tokens === null
                                    ? "Context budget planning can be enabled in settings."
                                    : "Output cap and a 20% safety margin are reserved."}
                                </small>
                              </div>
                            </details>
                            <span>
                              {currentAiPreview.plan.evidence_batches === 1
                                ? "Single full send"
                                : `Split into ${number(currentAiPreview.plan.evidence_batches)} evidence batches`}
                              {currentAiPreview.plan.summary_planned
                                ? ", followed by cross-batch synthesis (in rounds as needed)"
                                : ""}
                              {currentAiPreview.plan.input_budget_tokens !==
                              null
                                ? ` · ${number(currentAiPreview.plan.input_budget_tokens)} token input budget per request`
                                : " · byte-compatible mode"}
                            </span>
                          </>
                        ) : currentAiPreviewError ? (
                          <>
                            <span className="warning">
                              Preview failed: {currentAiPreviewError}
                            </span>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={busy}
                              onClick={() => setAiPreviewAttempt((v) => v + 1)}
                            >
                              Recalculate
                            </Button>
                          </>
                        ) : (
                          <span>
                            {busy
                              ? "The send preview updates once the current task finishes"
                              : "Computing the send scope and budget locally…"}
                          </span>
                        )}
                      </div>
                    )}
                    <div className="ai-privacy">
                      <Checkbox
                        label="Include raw packets and payloads this run"
                        checked={payload}
                        disabled={busy}
                        onChange={setPayload}
                      />
                      <span>
                        <CircleAlert size={12} />
                        Evidence is not redacted automatically
                      </span>
                    </div>
                    {!boot?.config_loaded && (
                      <div className="muted text-small">
                        Load or save a configuration on the settings page first.
                      </div>
                    )}
                    {data?.runs.items[0]?.local_summary && (
                      <AiLocalSummary text={data.runs.items[0].local_summary} />
                    )}
                  </div>
                  <section
                    className="ai-results"
                    aria-label="Validated AI findings"
                  >
                    <div className="ai-results-heading">
                      <span title="Only AI results that passed reply and evidence validation are shown">
                        Validated AI findings
                      </span>
                      {riskControls}
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={!hasSession}
                        onClick={() => setAiHistoryOpen(true)}
                      >
                        <History size={13} />
                        Run history {data?.runs.total || 0}
                      </Button>
                    </div>
                    {findingsTable}
                  </section>
                </>
              )}
              {screen === "reports" && (
                <>
                  <div className="report-summary">
                    <div>
                      <span className="report-icon">
                        <Files size={20} />
                      </span>
                      <div>
                        <strong>Full evidence report</strong>
                        <p>
                          {overview?.sources || 0} sources ·{" "}
                          {number(overview?.records || 0)} evidence records ·{" "}
                          {number(
                            (overview?.local_findings || 0) +
                              (overview?.ai_findings || 0),
                          )}{" "}
                          findings
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="secondary"
                      disabled={!hasSession || busy || loading}
                      onClick={() => setExportOpen(true)}
                    >
                      <Download size={14} />
                      Export report
                    </Button>
                  </div>
                  <div className="table-section-heading">
                    <span>Evidence sources</span>
                    <small>original file hashes · SHA-256</small>
                  </div>
                  <div className="sources-table">
                    <DataTable
                      page={data?.sources || null}
                      columns={sourceColumns}
                      id={(v) => v.id}
                      selected={selectedSource?.id}
                      onSelect={(source) => {
                        setSelectedSource(source);
                        setDrawer(true);
                        void updatePreferences({
                          ...prefsRef.current,
                          inspector: true,
                        });
                      }}
                      empty="No sources imported yet"
                    />
                  </div>
                  <Pagination
                    label="Sources"
                    offset={data?.sources.offset || 0}
                    total={data?.sources.total || 0}
                    limit={100}
                    loading={loading || !data}
                    onPage={(offset) => {
                      if (offset === sourceOffset) void refresh();
                      else setSourceOffset(offset);
                    }}
                  />
                  <div className="table-section-heading">
                    <span>
                      Diagnostics <small>{data?.diagnostics.total || 0}</small>
                    </span>
                    <small>unfinished scopes and parse issues are kept</small>
                  </div>
                  <div className="diagnostic-list" key={diagnosticOffset}>
                    {data?.diagnostics.items.map((d, i) => (
                      <div
                        key={i}
                        className={`diagnostic diagnostic-${d.level}`}
                      >
                        <CircleAlert size={13} />
                        <span className="diagnostic-source" title={d.source}>
                          {basename(d.source)}
                        </span>
                        <span title={d.message}>{d.message}</span>
                      </div>
                    ))}
                    {!data?.diagnostics.items.length && (
                      <div className="diagnostic-empty">
                        <ShieldCheck size={17} />
                        No diagnostics
                      </div>
                    )}
                  </div>
                  <Pagination
                    label="Diagnostics"
                    offset={data?.diagnostics.offset || 0}
                    total={data?.diagnostics.total || 0}
                    limit={50}
                    loading={loading || !data}
                    onPage={(offset) => {
                      if (offset === diagnosticOffset) void refresh();
                      else setDiagnosticOffset(offset);
                    }}
                  />
                </>
              )}
              {screen === "settings" && draft && boot && (
                <SettingsView
                  config={boot.config}
                  draft={draft}
                  onChange={setDraft}
                  path={prefs.config_path}
                  onPath={(config_path) =>
                    setPrefs((v) => ({ ...v, config_path }))
                  }
                  busy={busy}
                  checkStatus={checkStatus}
                  onPick={() => void pick("config")}
                  onApply={() =>
                    void applyConfig()
                      .then(() => setNotice("Settings applied; not saved yet"))
                      .catch((e) => setError(String(e)))
                  }
                  onSave={() => void configOperation("save")}
                  onLoad={() => void configOperation("load")}
                  onCheck={() => void configOperation("check")}
                />
              )}
            </div>
          </main>
          {screen !== "commands" && !narrow && prefs.inspector && (
            <aside className="inspector">
              <div
                className="inspector-resize"
                onPointerDown={resizeInspector}
              />
              {inspector}
            </aside>
          )}
        </div>
        <footer className="statusbar">
          <div>
            {task ? (
              <>
                <LoaderCircle size={12} className="spin" />
                <span>
                  {task.status === "cancelling"
                    ? statusText.cancelling
                    : task.label}
                </span>
                {task.stage && (
                  <span className="status-muted">
                    {task.stage}
                    {task.completed !== null
                      ? ` · ${number(task.completed)}${task.total !== null ? ` / ${number(task.total)}` : ""}`
                      : ""}
                  </span>
                )}
                {task.kind !== "ai" &&
                  task.total !== null &&
                  task.total > 0 && (
                    <span className="progress-track">
                      <i
                        style={{
                          width: `${Math.min(100, ((task.completed || 0) / task.total) * 100)}%`,
                        }}
                      />
                    </span>
                  )}
                <button onClick={() => void api.cancel(task.task_id)}>
                  Cancel
                </button>
              </>
            ) : (
              <>
                {elevationBusy ? (
                  <LoaderCircle size={12} className="spin" />
                ) : (
                  <span className="status-dot" />
                )}
                <span className="status-notice" title={notice}>
                  {notice}
                </span>
                {hasSession && (
                  <>
                    <span className="status-separator" />
                    <span className="status-muted">
                      {number(overview?.records || 0)} evidence records
                    </span>
                    <button onClick={() => navigate("reports")}>
                      {lastView?.diagnostics.total || 0} diagnostics
                    </button>
                  </>
                )}
              </>
            )}
          </div>
          <span className="status-muted">
            Local workbench
            <span className="status-separator" />
            {boot?.project ? "manual project saves" : "temporary session"}
          </span>
        </footer>
        <Dialog
          drawer
          open={screen !== "commands" && narrow && drawer}
          onOpenChange={setDrawer}
          title="Evidence details"
        >
          {inspector}
        </Dialog>
        <Dialog
          open={exportOpen}
          onOpenChange={setExportOpen}
          title="Export report"
          description="Keeps the complete evidence and findings, unaffected by the current filter or pagination."
        >
          <div className="export-options">
            <Checkbox
              label="HTML report"
              checked={exportHtml}
              onChange={setExportHtml}
            />
            <Checkbox
              label="JSON data"
              checked={exportJson}
              onChange={setExportJson}
            />
          </div>
          <label className="form-field">
            Export path
            <div className="input-action">
              <input
                className="input mono"
                aria-label="Export path"
                value={exportPath}
                onChange={(e) => {
                  setExportPath(e.target.value);
                  setOverwrite(false);
                }}
                placeholder="Choose where to save the report"
              />
              <Button
                variant="outline"
                size="icon"
                aria-label="Pick export path"
                onClick={() => void pick("export")}
              >
                <FolderOpen size={15} />
              </Button>
            </div>
          </label>
          {overwrite && (
            <div className="warning-note">
              A report with this name already exists. Clicking again will
              overwrite it; evidence and configuration paths stay protected.
            </div>
          )}
          <div className="dialog-actions">
            <Button variant="ghost" onClick={() => setExportOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={
                busy ||
                loading ||
                (!exportHtml && !exportJson) ||
                !exportPath.trim()
              }
              onClick={() => void doExport()}
            >
              <Download size={14} />
              {overwrite
                ? "Confirm overwrite and export"
                : "Export full report"}
            </Button>
          </div>
        </Dialog>
        <Dialog
          open={aiHistoryOpen}
          onOpenChange={setAiHistoryOpen}
          title="AI run history"
          description="View batches, valid replies, and unfinished scopes."
          className="ai-history-dialog"
        >
          {hasSession && (
            <AiHistory
              key={boot!.session_id}
              initiallyOpen
              runs={data?.runs || views.ai?.runs}
              busy={loading}
              sessionId={boot!.session_id!}
              onOffset={(offset) => {
                if (offset === runOffset) void refresh();
                else setRunOffset(offset);
              }}
              onError={setError}
            />
          )}
        </Dialog>
        {aiFilter && (
          <AiEvidenceFilter
            initial={aiFilter}
            sources={data?.sources.items || lastView?.sources.items || []}
            categories={overview?.categories || []}
            protocols={overview?.protocols || []}
            busy={aiFilterBusy}
            onApply={applyAiFilter}
            onClose={() => setAiFilter(null)}
          />
        )}
        {logQueryOpen && screen === "logs" && (
          <LogQueryDialog
            initial={active.log_query}
            busy={loading || busy}
            onApply={applyLogQuery}
            onClose={closeLogQuery}
          />
        )}

        {editor && (
          <ProjectEditor
            key={editor.id + String(editing)}
            info={editor}
            mode={editing ? "edit" : "create"}
            busy={busy}
            onClose={() => setEditor(null)}
            onSave={submitProject}
          />
        )}
        <Dialog
          open={dirtyOpen}
          onOpenChange={setDirtyOpen}
          title="Project has unsaved changes"
          description="Save the current project before switching, or discard these unsaved changes. The original project file is kept."
        >
          <div className="dialog-actions">
            <Button
              variant="ghost"
              onClick={() => {
                pendingAction.current = null;
                setDirtyOpen(false);
              }}
            >
              Back to project
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setDirtyOpen(false);
                const action = pendingAction.current;
                pendingAction.current = null;
                action?.();
              }}
            >
              Discard and continue
            </Button>
            <Button
              onClick={() =>
                void saveProject(false, () => {
                  setDirtyOpen(false);
                  const action = pendingAction.current;
                  pendingAction.current = null;
                  action?.();
                })
              }
            >
              Save and continue
            </Button>
          </div>
        </Dialog>
        <Dialog
          open={newOpen}
          onOpenChange={setNewOpen}
          title="New analysis"
          description="The current session only lives in memory. Export any report you want to keep first."
        >
          <div className="dialog-actions">
            <Button variant="ghost" onClick={() => setNewOpen(false)}>
              Back to current session
            </Button>
            <Button onClick={() => void reset()}>New empty session</Button>
          </div>
        </Dialog>
        <Dialog
          open={closeOpen}
          onOpenChange={setCloseOpen}
          title="Task still running"
          description="Cancelling keeps valid results; sent requests must return or time out."
        >
          <div className="dialog-actions">
            <Button variant="ghost" onClick={() => setCloseOpen(false)}>
              Keep waiting
            </Button>
            <Button
              onClick={() => {
                if (task) void api.cancel(task.task_id);
                setCloseOpen(false);
              }}
            >
              Cancel task and keep results
            </Button>
          </div>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}
