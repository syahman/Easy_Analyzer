import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
  act,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import { App } from "../App";
import { DataTable } from "../components/DataTable";
import { Inspector, SourceInspector } from "../components/Inspector";
import { SettingsView } from "../components/SettingsView";
import capability from "../../../capabilities/main.json";
import type {
  Bootstrap,
  ViewRequest,
  ViewResponse,
  RecordSummary,
  DetailResponse,
} from "../types";
const mock = vi.hoisted(() => ({
  invoke: vi.fn(),
  event: vi.fn(),
  window: {
    onDragDropEvent: vi.fn(),
    onCloseRequested: vi.fn(),
    startDragging: vi.fn(),
    close: vi.fn(),
    destroy: vi.fn(),
    minimize: vi.fn(),
    toggleMaximize: vi.fn(),
  },
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: mock.invoke }));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: (text: string) =>
    mock.invoke("plugin:clipboard-manager|write_text", { text }),
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: mock.event }));
vi.mock("@tauri-apps/api/webviewWindow", () => ({
  getCurrentWebviewWindow: () => mock.window,
}));
const boot: Bootstrap = {
  preferences: {
    dark: false,
    inspector: true,
    inspector_width: 320,
    config_path: "/tmp/gui-config.toml",
    window_width: 1280,
    window_height: 720,
  },
  config: {
    base_url: "http://127.0.0.1:9999",
    model: "synthetic-model",
    api_key_configured: true,
    api_key_env: "",
    timeout_seconds: 10,
    batch_bytes: 8192,
    context_tokens: null,
    max_output_tokens: 1000,
    response_format: "json_object",
    token_parameter: "max_tokens",
  },
  config_loaded: true,
  config_error: null,
  session_id: 7,
  selection: { id: 11, count: 150, label: "Logs · Local suspicious items" },
  busy: null,
  platform: "macos",
  elevated: null,
  elevation_error: null,
  live_processes: false,
  capture_dir: "/tmp/captured",
  inputs: [],
  qa: false,
  qa_ai: false,
};
const record: RecordSummary = {
  id: "evidence-one",
  source_id: "source-one",
  position: "line:1",
  timestamp: "2026-10-01T10:00:00Z",
  status: "parsed",
  data: {
    kind: "log",
    fields: { category: "login", fields: { user: "synthetic user" } },
  },
  summary: "Synthetic evidence record",
};
function response(r: ViewRequest): ViewResponse {
  return {
    session_id: 7,
    revision: r.revision,
    overview: {
      sources: 1,
      records: 150,
      logs: 150,
      processes: 0,
      packets: 0,
      flows: 0,
      local_findings: 0,
      ai_findings: 0,
      suspicious: 3,
      risks: [0, 0, 0, 0, 0],
      categories: ["login"],
      protocols: [],
      parse_counts: [150, 0, 0],
    },
    records:
      r.screen === "logs"
        ? { items: [record], total: 150, offset: r.filters.offset }
        : null,
    findings: { items: [], total: 0, offset: 0 },
    flows: null,
    process_rows: [],
    sources: {
      items: [
        {
          id: "source-one",
          path: "/tmp/sample.log",
          format: "text",
          sha256: "abc",
          bytes: 500,
        },
      ],
      total: 1,
      offset: 0,
    },
    record_sources: { "source-one": "/tmp/sample.log" },
    diagnostics: { items: [], total: 0, offset: 0 },
    runs: { items: [], total: 0, offset: 0 },
    outside: false,
    offset: r.filters.offset,
    selection: boot.selection,
  };
}
beforeEach(() => {
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    value: 1280,
  });
  vi.clearAllMocks();
  mock.event.mockResolvedValue(() => {});
  mock.window.onDragDropEvent.mockResolvedValue(() => {});
  mock.window.onCloseRequested.mockResolvedValue(() => {});
  mock.invoke.mockImplementation(async (command: string, args: any) => {
    if (command === "initialize") return structuredClone(boot);
    if (command === "get_view") {
      if (args.request.filters.regex && args.request.filters.text === "[")
        throw "regex parse error";
      return response(args.request);
    }
    if (command === "prepare_ai")
      return {
        id: 42,
        session_id: 7,
        plan: {
          selected_records: 3,
          evidence_tokens: 300,
          prompt_tokens: 100,
          input_budget_tokens: null,
          context_tokens: null,
          evidence_batches: 1,
          summary_planned: false,
        },
      };
    if (command === "start_ai")
      return {
        task_id: 99,
        session_id: 7,
        epoch: 0,
        revision: 1,
        kind: "ai",
        status: "running",
        label: "AI",
        stage: null,
        completed: null,
        total: null,
        error: null,
        saved_paths: [],
      };
    return undefined;
  });
});
afterEach(cleanup);
it("shows the local recap after partial AI failure as escaped text without sending again", async () => {
  const original = mock.invoke.getMockImplementation()!;
  const recap =
    "Local result recap (not new AI correlation reasoning)\nSucceeded 2/3, failed evidence batches: 2\n<script>unsafe()</script>\nEvidence: evidence-one";
  mock.invoke.mockImplementation((command, args) => {
    if (command === "get_view") {
      const view = response(args.request);
      view.runs = {
        total: 1,
        offset: 0,
        items: [
          {
            index: 0,
            model: "synthetic-model",
            endpoint: "http://127.0.0.1:9999",
            batches: 4,
            completed: 3,
            analyzed: 100,
            selected: 150,
            include_payload: false,
            local_summary: recap,
          },
        ],
      };
      return Promise.resolve(view);
    }
    return original(command, args);
  });
  const { container } = render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  await screen.findByText("Local result recap · partially completed");
  expect(container.querySelector(".local-ai-summary pre")?.textContent).toBe(
    recap,
  );
  expect(container.querySelector(".local-ai-summary script")).toBeNull();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: /Run history/ }));
  fireEvent.click(screen.getByRole("button", { name: /#1\s*synthetic-model/ }));
  await waitFor(() =>
    expect(document.querySelectorAll(".local-ai-summary")).toHaveLength(2),
  );
});
describe("AI batch progress", () => {
  it("shows current/total batches and resets the count for each summary round", async () => {
    const task = {
      task_id: 99,
      session_id: 7,
      epoch: 0,
      revision: 1,
      kind: "ai",
      status: "running",
      label: "AI analysis",
      stage: "AI batch",
      completed: 1,
      total: 7,
      error: null,
      saved_paths: [],
    };
    const invoke = mock.invoke.getMockImplementation()!;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve({ ...boot, busy: task })
        : invoke(command, args),
    );
    const { container } = render(<App />);
    await screen.findByText("AI batch · 1 / 7");
    const listener = mock.event.mock.calls.find(
      ([name]) => name === "analysis-task",
    )![1];
    await act(async () => listener({ payload: { ...task, completed: 7 } }));
    await screen.findByText("AI batch · 7 / 7");
    // The last batch is still awaiting its response, not 100% complete.
    expect(container.querySelector(".statusbar .progress-track")).toBeNull();
    await act(async () =>
      listener({
        payload: {
          ...task,
          stage: "Cross-batch synthesis (round 1)",
          completed: 1,
          total: 3,
        },
      }),
    );
    await screen.findByText("Cross-batch synthesis (round 1) · 1 / 3");
    await act(async () =>
      listener({
        payload: {
          ...task,
          stage: "Cross-batch synthesis (round 2)",
          completed: 1,
          total: 1,
        },
      }),
    );
    await screen.findByText("Cross-batch synthesis (round 2) · 1 / 1");
  });
});
describe("window closing", () => {
  function desktopClose() {
    const invoke = mock.invoke.getMockImplementation()!;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve({ ...boot, platform: "windows", elevated: false })
        : invoke(command, args),
    );
    // Reproduce the installed Tauri onCloseRequested contract: await the
    // handler, then destroy only when it did not prevent the close event.
    const requestClose = async () => {
      const handler = mock.window.onCloseRequested.mock.calls.at(-1)![0];
      const event = { preventDefault: vi.fn() };
      await handler(event);
      if (!event.preventDefault.mock.calls.length) {
        if (!capability.permissions.includes("core:window:allow-destroy"))
          throw new Error("window.destroy not allowed");
        await mock.window.destroy();
      }
      return event;
    };
    mock.window.close.mockImplementation(requestClose);
    return requestClose;
  }
  it("saves preferences and closes from the titlebar without another close event", async () => {
    desktopClose();
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Close window" }));
    await waitFor(() => expect(mock.window.destroy).toHaveBeenCalledOnce());
    expect(mock.window.close).toHaveBeenCalledOnce();
    expect(
      mock.invoke.mock.calls.filter(([c]) => c === "save_preferences"),
    ).toHaveLength(1);
  });
  it("also completes the operating system close request", async () => {
    const requestClose = desktopClose();
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    await act(requestClose);
    expect(mock.window.destroy).toHaveBeenCalledOnce();
    expect(mock.window.close).not.toHaveBeenCalled();
  });
  it("allows retry after preferences fail and ignores repeated clicks while saving", async () => {
    desktopClose();
    const invoke = mock.invoke.getMockImplementation()!;
    let rejectSave!: (reason: string) => void;
    mock.invoke.mockImplementation((command, args) =>
      command === "save_preferences"
        ? new Promise<void>((_, reject) => {
            rejectSave = reject;
          })
        : invoke(command, args),
    );
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    const close = screen.getByRole("button", { name: "Close window" });
    fireEvent.click(close);
    fireEvent.click(close);
    expect(
      mock.invoke.mock.calls.filter(([c]) => c === "save_preferences"),
    ).toHaveLength(1);
    expect(mock.window.destroy).not.toHaveBeenCalled();
    await act(async () => rejectSave("cannot write"));
    await screen.findByText("Failed to save preferences: cannot write");
    mock.invoke.mockImplementation(invoke);
    fireEvent.click(close);
    await waitFor(() => expect(mock.window.destroy).toHaveBeenCalledOnce());
  });
  it("keeps the window open while cancelling an active task to preserve results", async () => {
    const requestClose = desktopClose();
    const invoke = mock.invoke.getMockImplementation()!;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve({
            ...boot,
            platform: "windows",
            busy: {
              task_id: 99,
              session_id: 7,
              epoch: 0,
              revision: 1,
              kind: "ai",
              status: "running",
              label: "AI",
              stage: null,
              completed: null,
              total: null,
              error: null,
              saved_paths: [],
            },
          })
        : invoke(command, args),
    );
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    await act(requestClose);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Cancel task and keep results",
      }),
    );
    await waitFor(() =>
      expect(mock.invoke).toHaveBeenCalledWith("cancel_task", { taskId: 99 }),
    );
    expect(mock.window.destroy).not.toHaveBeenCalled();
    expect(mock.invoke.mock.calls.some(([c]) => c === "save_preferences")).toBe(
      false,
    );
  });
});
describe("Windows UAC collection", () => {
  function windowsBoot(elevated = false) {
    return { ...boot, platform: "windows", elevated, live_processes: elevated };
  }
  it("requires an explicit click and cancellation preserves the current session", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot();
      if (command === "get_view") return response(args.request);
      if (command === "request_elevation") return "cancelled";
    });
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Import analysis" }),
    );
    const button = await screen.findByRole("button", {
      name: "Launch as administrator",
    });
    expect(
      mock.invoke.mock.calls.some(
        ([command]) => command === "request_elevation",
      ),
    ).toBe(false);
    fireEvent.click(button);
    await screen.findByText("UAC cancelled; still using the current window");
    expect(button).toBeEnabled();
    expect(
      mock.invoke.mock.calls.some(([command]) =>
        ["reset_session", "start_import", "start_ai"].includes(command),
      ),
    ).toBe(false);
    expect(mock.window.close).not.toHaveBeenCalled();
    expect(screen.getByText("Standard user")).toBeInTheDocument();
  });
  it("keeps the old window open after an elevated window starts", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot();
      if (command === "get_view") return response(args.request);
      if (command === "request_elevation") return "launched";
    });
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Import analysis" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Launch as administrator" }),
    );
    await screen.findByText(
      "Administrator window launched; the original window and evidence remain. Start local collection in the new window",
    );
    expect(mock.window.close).not.toHaveBeenCalled();
    expect(screen.getByText("Standard user")).toBeInTheDocument();
  });
  it("shows elevated status without prompting again or collecting automatically", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot(true);
      if (command === "get_view") return response(args.request);
    });
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Import analysis" }),
    );
    await screen.findByText("Administrator");
    expect(
      screen.queryByRole("button", { name: "Launch as administrator" }),
    ).toBeNull();
    expect(
      screen.getByRole("checkbox", { name: "Capture local processes" }),
    ).toBeChecked();
    expect(
      mock.invoke.mock.calls.some(([command]) =>
        ["request_elevation", "start_import", "start_ai"].includes(command),
      ),
    ).toBe(false);
  });
  it("re-enables the UAC button after a launch error without clearing evidence", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot();
      if (command === "get_view") return response(args.request);
      if (command === "request_elevation") throw "Simulated launch failure";
    });
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Import analysis" }),
    );
    const button = await screen.findByRole("button", {
      name: "Launch as administrator",
    });
    fireEvent.click(button);
    await screen.findByText(
      "Could not launch the administrator window: Simulated launch failure",
    );
    expect(button).toBeEnabled();
    expect(mock.window.close).not.toHaveBeenCalled();
    expect(
      mock.invoke.mock.calls.some(([command]) => command === "reset_session"),
    ).toBe(false);
  });
});
it("normal startup has no evidence, imports or automatic AI requests", async () => {
  mock.invoke.mockImplementation(async (c: string) =>
    c === "initialize"
      ? { ...boot, session_id: null, selection: { id: 0, count: 0, label: "" } }
      : undefined,
  );
  render(<App />);
  await screen.findByText(
    "Each incident response is saved independently; resume an existing project or create one",
  );
  await waitFor(() => expect(mock.window.onDragDropEvent).toHaveBeenCalled());
  expect(
    mock.invoke.mock.calls.some(([v]) =>
      ["start_import", "start_ai"].includes(v),
    ),
  ).toBe(false);
  expect(screen.getByRole("button", { name: "Export report" })).toBeDisabled();
});
it("renders every table field, preserves backend total and requests next offset", () => {
  const onPage = vi.fn();
  render(
    <DataTable
      page={{ items: [record], total: 100000, offset: 0 }}
      columns={[
        { accessorKey: "timestamp", header: "Time" },
        { accessorKey: "source_id", header: "Source" },
        { accessorKey: "status", header: "Status" },
        { accessorKey: "summary", header: "Summary" },
        { accessorKey: "position", header: "Position" },
      ]}
      id={(v) => v.id}
      limit={100}
      onPage={onPage}
    />,
  );
  expect(screen.getAllByRole("cell")).toHaveLength(5);
  expect(screen.getByText("Synthetic evidence record")).toBeInTheDocument();
  expect(screen.getByText("100,000 items · Page 1 / 1000")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  expect(onPage).toHaveBeenCalledWith(100);
});
it("invalid regex retains previous valid records and scope; paging is sent to Rust", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
  await screen.findByText("Synthetic evidence record");
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "get_view",
      expect.objectContaining({
        request: expect.objectContaining({
          filters: expect.objectContaining({ offset: 100 }),
        }),
      }),
    ),
  );
  fireEvent.change(screen.getByRole("textbox", { name: "Query evidence" }), {
    target: { value: "[" },
  });
  fireEvent.click(screen.getByRole("checkbox", { name: "Regex" }));
  await screen.findByText("regex parse error");
  expect(screen.getByText("Synthetic evidence record")).toBeInTheDocument();
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  await screen.findByText("synthetic-model");
  expect(
    mock.invoke.mock.calls.filter((v) => v[0] === "start_ai"),
  ).toHaveLength(0);
});
it("IME candidate confirmation does not submit an incomplete evidence query", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
  await screen.findByText("Synthetic evidence record");
  const input = screen.getByRole("textbox", { name: "Query evidence" });
  const form = input.closest("form")!;
  const before = mock.invoke.mock.calls.filter(
    (v) => v[0] === "get_view",
  ).length;
  fireEvent.compositionStart(input);
  fireEvent.change(input, { target: { value: "keyword check" } });
  expect(fireEvent.keyDown(input, { key: "Enter", isComposing: true })).toBe(
    false,
  );
  fireEvent.submit(form);
  expect(
    mock.invoke.mock.calls.filter((v) => v[0] === "get_view"),
  ).toHaveLength(before);
  fireEvent.compositionEnd(input);
  expect(fireEvent.keyDown(input, { key: "Enter", keyCode: 229 })).toBe(false);
  fireEvent.submit(form);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "get_view",
      expect.objectContaining({
        request: expect.objectContaining({
          filters: expect.objectContaining({ text: "keyword check" }),
        }),
      }),
    ),
  );
});
it("native dropped files populate the pending list without importing or sending AI", async () => {
  mock.invoke.mockImplementation(async (c: string) =>
    c === "initialize"
      ? { ...boot, session_id: null, selection: { id: 0, count: 0, label: "" } }
      : undefined,
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onDragDropEvent).toHaveBeenCalled());
  const handler = mock.window.onDragDropEvent.mock.calls[0][0];
  await act(async () =>
    handler({
      payload: {
        type: "drop",
        paths: [
          "/tmp/evidence.log",
          "/tmp/evidence.log",
          "/tmp/network.pcapng",
        ],
      },
    }),
  );
  expect(screen.getAllByText("evidence.log")).toHaveLength(1);
  expect(screen.getByText("network.pcapng")).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Start local analysis" }),
  ).toBeEnabled();
  expect(
    mock.invoke.mock.calls.some(([v]) =>
      ["start_import", "start_ai"].includes(v),
    ),
  ).toBe(false);
});
it("AI starts only explicitly and raw payload is opt-in", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  await screen.findByText("synthetic-model");
  const button = screen.getByRole("button", { name: "Run AI analysis" });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "suspicious",
        selection_id: null,
        include_payload: false,
        plan_id: 42,
      },
    }),
  );
});
it("failed local planning blocks sending and offers a retry", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((c, args) =>
    c === "prepare_ai"
      ? Promise.reject("context budget too small")
      : original(c, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  await screen.findByText("Preview failed: context budget too small");
  expect(
    screen.getByRole("button", { name: "Run AI analysis" }),
  ).toBeDisabled();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  mock.invoke.mockImplementation(original);
  fireEvent.click(screen.getByRole("button", { name: "Recalculate" }));
  await screen.findByText("Single full send · byte-compatible mode");
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Run AI analysis" }),
    ).toBeEnabled(),
  );
});
it("ignores stale previews and only sends the latest explicitly selected payload plan", async () => {
  const original = mock.invoke.getMockImplementation()!;
  const pending: { args: any; resolve: (v: any) => void }[] = [];
  mock.invoke.mockImplementation((c, args) =>
    c === "prepare_ai"
      ? new Promise((resolve) => pending.push({ args, resolve }))
      : original(c, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  await waitFor(() => expect(pending).toHaveLength(1));
  fireEvent.click(
    screen.getByRole("checkbox", {
      name: "Include raw packets and payloads this run",
    }),
  );
  await waitFor(() => expect(pending).toHaveLength(2));
  const preview = {
    id: 83,
    session_id: 7,
    plan: {
      selected_records: 3,
      evidence_tokens: 400,
      prompt_tokens: 100,
      input_budget_tokens: 700000,
      context_tokens: 1000000,
      evidence_batches: 2,
      summary_planned: true,
    },
  };
  await act(async () => pending[1].resolve(preview));
  await screen.findByText(/Split into 2 evidence batches/);
  await act(async () =>
    pending[0].resolve({
      ...preview,
      id: 82,
      plan: { ...preview.plan, evidence_batches: 1 },
    }),
  );
  expect(screen.queryByText(/Single full send/)).not.toBeInTheDocument();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  expect(pending[1].args.request.include_payload).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Run AI analysis" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "suspicious",
        selection_id: null,
        include_payload: true,
        plan_id: 83,
      },
    }),
  );
});
it("localizes nested Windows attributes while preserving their keys and values", () => {
  const key = "Event.System.Execution.#attributes.ThreadID";
  const detail: DetailResponse = {
    session_id: 7,
    record: {
      ...record,
      raw: `${key}=0042`,
      data: {
        kind: "log",
        fields: { category: "windows_event", fields: { [key]: "0042" } },
      },
    },
    source: null,
    related: [],
  };
  render(
    <Inspector
      detail={detail}
      finding={null}
      loading={false}
      onJump={() => {}}
      onFinding={() => {}}
      onClose={() => {}}
    />,
  );
  expect(screen.getByText("Execution thread ID")).toHaveAttribute("title", key);
  expect(screen.getByText("0042")).toBeInTheDocument();
  expect(detail.record.raw).toBe(`${key}=0042`);
  expect(detail.record.data).toMatchObject({
    fields: { fields: { [key]: "0042" } },
  });
});
it("raw evidence is displayed as text and cannot render HTML", async () => {
  const detail: DetailResponse = {
    session_id: 7,
    record: { ...record, raw: "<img src=x onerror=alert(1)> raw text" },
    source: null,
    related: [],
  };
  const { container } = render(
    <Inspector
      detail={detail}
      finding={null}
      loading={false}
      onJump={() => {}}
      onFinding={() => {}}
      onClose={() => {}}
    />,
  );
  await userEvent.click(screen.getByRole("tab", { name: "Raw" }));
  expect(
    screen.getByText("<img src=x onerror=alert(1)> raw text"),
  ).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
});
it("existing keys are status-only; replacement remains masked and explicit", () => {
  const onChange = vi.fn();
  render(
    <SettingsView
      config={boot.config}
      draft={{ ...boot.config, key_action: "keep", key_value: "" }}
      onChange={onChange}
      path="/tmp/gui.toml"
      onPath={() => {}}
      busy={false}
      checkStatus="Not checked yet"
      onPick={() => {}}
      onApply={() => {}}
      onSave={() => {}}
      onLoad={() => {}}
      onCheck={() => {}}
    />,
  );
  expect(screen.getByText("Configured")).toBeInTheDocument();
  const input = screen.getByLabelText("New API key");
  expect(input).toHaveAttribute("type", "password");
  expect(input).toHaveValue("");
  fireEvent.change(input, { target: { value: "sk-synthetic" } });
  expect(onChange).toHaveBeenCalledWith(
    expect.objectContaining({
      key_action: "replace",
      key_value: "sk-synthetic",
    }),
  );
});
it("current-filter AI sends the full selection token and resets payload after each run", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
  await screen.findByText("Synthetic evidence record");
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  await screen.findByText("synthetic-model");
  fireEvent.click(screen.getByRole("button", { name: "Current filter" }));
  expect(screen.getByText("150")).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("checkbox", {
      name: "Include raw packets and payloads this run",
    }),
  );
  const runButton = screen.getByRole("button", { name: "Run AI analysis" });
  await waitFor(() => expect(runButton).toBeEnabled());
  fireEvent.click(runButton);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "matches",
        selection_id: 11,
        include_payload: true,
        plan_id: 42,
      },
    }),
  );
  expect(
    screen.getByRole("checkbox", {
      name: "Include raw packets and payloads this run",
    }),
  ).not.toBeChecked();
  await mock.event.mock.calls[0][1]({
    payload: {
      task_id: 99,
      session_id: 7,
      epoch: 0,
      revision: 1,
      kind: "ai",
      status: "partial",
      label: "AI",
      stage: null,
      completed: 1,
      total: null,
      error: "Later batches failed; valid findings are retained.",
      saved_paths: [],
    },
  });
  await screen.findByText("Later batches failed; valid findings are retained.");
  expect(
    screen.getByRole("checkbox", {
      name: "Include raw packets and payloads this run",
    }),
  ).not.toBeChecked();
});
it("evidence references locate records and return restores the original finding", async () => {
  const original = mock.invoke.getMockImplementation()!;
  const finding = {
    id: "f-one",
    origin: "local:test",
    severity: "high",
    title: "Synthetic finding",
    description: "for testing only",
    evidence_ids: ["evidence-one"],
    confidence: 0.8,
    recommendations: [],
  };
  mock.invoke.mockImplementation(async (c: string, args: any) => {
    if (c === "get_view") {
      const v = response(args.request);
      if (args.request.screen === "overview")
        v.findings = { items: [finding as any], total: 1, offset: 0 };
      return v;
    }
    if (c === "get_detail")
      return {
        session_id: 7,
        record: { ...record, raw: "synthetic raw" },
        source: null,
        related: [],
      };
    return original(c, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Analysis overview" }));
  await screen.findByText("Synthetic finding");
  fireEvent.click(screen.getByText("Synthetic finding"));
  fireEvent.click(screen.getByRole("button", { name: "evidence-one" }));
  await screen.findByRole("button", { name: "Back to previous view" });
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "get_view",
      expect.objectContaining({
        request: expect.objectContaining({
          screen: "logs",
          focus_id: "evidence-one",
          commit_selection: false,
        }),
      }),
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Back to previous view" }),
  );
  await screen.findByRole("heading", { name: "Synthetic finding" });
  expect(
    screen.getByRole("heading", { name: "Analysis overview" }),
  ).toBeInTheDocument();
});

it("source details preserve full paths and hashes despite compact table labels", () => {
  const source = {
    id: "source-demo",
    path: "/long/synthetic/path/sample.log",
    format: "text",
    bytes: 1024,
    sha256: "a".repeat(64),
  };
  render(<SourceInspector source={source} onClose={() => {}} />);
  expect(screen.getByText("sample.log")).toBeInTheDocument();
  expect(screen.getByText(source.path)).toBeInTheDocument();
  expect(screen.getByText(source.sha256)).toBeInTheDocument();
});

it("AI edits a full evidence selection locally and sends the new selection only explicitly", async () => {
  const original = mock.invoke.getMockImplementation()!;
  let selected = {
    id: 22,
    count: 250,
    label: "Logs · Keyword: synthetic group A",
  };
  mock.invoke.mockImplementation((c, args) => {
    if (c === "initialize")
      return { ...boot, selection: { id: null, count: 0, label: "" } };
    if (
      c === "get_view" &&
      args.request.screen === "logs" &&
      args.request.filters.text === "synthetic group A"
    )
      return {
        ...response(args.request),
        selection: selected,
        records: { items: [record], total: 250, offset: 0 },
      };
    if (c === "get_view" && args.request.screen === "ai")
      return { ...response(args.request), selection: selected };
    return original(c, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  fireEvent.click(await screen.findByRole("button", { name: "Edit filter" }));
  fireEvent.change(
    screen.getByRole("textbox", { name: "Evidence query to send" }),
    {
      target: { value: "synthetic group A" },
    },
  );
  fireEvent.click(screen.getByRole("button", { name: "Apply filter" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(mock.invoke).toHaveBeenCalledWith("get_view", {
    request: expect.objectContaining({
      screen: "logs",
      commit_selection: true,
      focus_id: null,
      filters: expect.objectContaining({
        text: "synthetic group A",
        offset: 0,
        limit: 100,
      }),
    }),
  });
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  expect(
    screen.queryByRole("combobox", { name: "Finding origin" }),
  ).not.toBeInTheDocument();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Run AI analysis" }),
    ).toBeEnabled(),
  );
  expect(
    screen.getByText("Logs · Keyword: synthetic group A"),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Run AI analysis" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: expect.objectContaining({
        scope: "matches",
        selection_id: 22,
        include_payload: false,
      }),
    }),
  );
});

it("AI current selection has an editor even when no previous evidence selection exists", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((c, args) => {
    if (c === "initialize")
      return { ...boot, selection: { id: null, count: 0, label: "" } };
    if (c === "get_view")
      return {
        ...response(args.request),
        selection: { id: null, count: 0, label: "" },
      };
    return original(c, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  fireEvent.click(
    await screen.findByRole("button", { name: "Current filter" }),
  );
  expect(
    screen.getByRole("dialog", { name: "Filter evidence to send" }),
  ).toBeInTheDocument();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
});

it("invalid AI filter keeps the previous selection and Chinese composition does not submit", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI analysis" })[1]);
  fireEvent.click(
    await screen.findByRole("button", { name: "Current filter" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Edit filter" }));
  const input = screen.getByRole("textbox", { name: "Evidence query to send" });
  fireEvent.change(input, { target: { value: "[" } });
  fireEvent.click(screen.getByRole("checkbox", { name: "Regular expression" }));
  const before = mock.invoke.mock.calls.length;
  fireEvent.compositionStart(input);
  expect(
    fireEvent.keyDown(input, { key: "Enter", keyCode: 229, isComposing: true }),
  ).toBe(false);
  fireEvent.submit(input.closest("form")!);
  expect(mock.invoke.mock.calls.length).toBe(before);
  fireEvent.compositionEnd(input);
  fireEvent.click(screen.getByRole("button", { name: "Apply filter" }));
  await screen.findByRole("alert");
  expect(screen.getByRole("alert")).toHaveTextContent(
    "The last valid filter is kept.",
  );
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(screen.getByText("Logs · Local suspicious items")).toBeInTheDocument();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Run AI analysis" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Run AI analysis" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: expect.objectContaining({ scope: "matches", selection_id: 11 }),
    }),
  );
});

function dirtyProjectBoot(): Bootstrap {
  return {
    ...boot,
    project: {
      info: {
        id: "synthetic-project-id",
        name: "Client A response",
        client: "Client A",
        response_start: "2026-10-05T09:00:00+08:00",
        response_end: null,
        location: "",
        responders: "",
        description: "",
        created_at: "2026-10-05T09:00:00+08:00",
        updated_at: "2026-10-05T09:00:00+08:00",
      },
      path: "/tmp/synthetic.eair",
      dirty: true,
      revision: 2,
    },
  };
}
it("protects dirty projects when switching and waits for a successful save", async () => {
  const original = mock.invoke.getMockImplementation()!;
  let fresh = dirtyProjectBoot();
  const job = {
    task_id: 123,
    session_id: 7,
    epoch: 0,
    revision: 2,
    kind: "project_save",
    status: "running",
    label: "Save project",
    stage: null,
    completed: null,
    total: null,
    error: null,
    saved_paths: [],
  };
  mock.invoke.mockImplementation((cmd, args) =>
    cmd === "initialize"
      ? Promise.resolve(structuredClone(fresh))
      : cmd === "project_save"
        ? Promise.resolve(job)
        : original(cmd, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "New project" })[0]);
  await screen.findByText("Project has unsaved changes");
  fireEvent.click(screen.getByRole("button", { name: "Save and continue" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("project_save", {
      sessionId: 7,
      path: "/tmp/synthetic.eair",
      overwrite: false,
    }),
  );
  expect(
    screen.queryByText("New incident response project"),
  ).not.toBeInTheDocument();
  const listener = mock.event.mock.calls.find(
    ([name]) => name === "analysis-task",
  )![1];
  await act(async () =>
    listener({
      payload: { ...job, status: "failed", error: "Synthetic save failure" },
    }),
  );
  expect(screen.getByText("Project has unsaved changes")).toBeInTheDocument();
  expect(
    screen.queryByText("New incident response project"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save and continue" }));
  fresh = { ...fresh, project: { ...fresh.project!, dirty: false } };
  await act(async () =>
    listener({
      payload: {
        ...job,
        task_id: 124,
        status: "completed",
        saved_paths: ["/tmp/synthetic.eair"],
      },
    }),
  );
  await screen.findByText("New incident response project");
});
it("prevents closing a dirty project until the user resolves unsaved changes", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((cmd, args) =>
    cmd === "initialize"
      ? Promise.resolve(dirtyProjectBoot())
      : original(cmd, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  const event = { preventDefault: vi.fn() };
  await act(async () =>
    mock.window.onCloseRequested.mock.calls.at(-1)![0](event),
  );
  expect(event.preventDefault).toHaveBeenCalled();
  await screen.findByText("Project has unsaved changes");
  expect(mock.window.destroy).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  await waitFor(() => expect(mock.window.destroy).toHaveBeenCalledTimes(1));
});

it("edits all project details through explicit entries and restores them after saving", async () => {
  const original = mock.invoke.getMockImplementation()!;
  let fresh = dirtyProjectBoot();
  fresh.project!.dirty = false;
  const identity = {
    id: fresh.project!.info.id,
    created_at: fresh.project!.info.created_at,
  };
  let catalogInfo = structuredClone(fresh.project!.info);
  const job = {
    task_id: 300,
    session_id: 7,
    epoch: 0,
    revision: 3,
    kind: "project_save",
    status: "running",
    label: "Save project",
    stage: null,
    completed: null,
    total: null,
    error: null,
    saved_paths: [],
  };
  mock.invoke.mockImplementation(async (cmd, args) => {
    if (cmd === "initialize") return structuredClone(fresh);
    if (cmd === "project_list_page")
      return {
        offset: 0,
        total: 1,
        items: [
          {
            info: catalogInfo,
            path: "/tmp/synthetic.eair",
            last_opened: "2026-10-14T15:00:00+08:00",
            missing: false,
          },
        ],
      };
    if (cmd === "project_filters") return structuredClone(fresh.project);
    if (cmd === "project_edit") {
      fresh = {
        ...fresh,
        project: {
          ...fresh.project!,
          info: args.info,
          dirty: true,
          revision: 3,
        },
      };
      return structuredClone(fresh.project);
    }
    if (cmd === "project_save") return job;
    return original(cmd, args);
  });
  const { unmount } = render(<App />);
  await screen.findByRole("heading", { name: "Current project details" });
  fireEvent.click(screen.getByRole("button", { name: "Edit details" }));
  await screen.findByRole("dialog", { name: "Edit project details" });
  const values = [
    ["Project name", "Updated response"],
    ["Client organization *", "Updated client"],
    ["Response start (with time zone) *", "2026-10-13T09:00:00+08:00"],
    ["Response end (with time zone)", "2026-10-14T18:00:00+08:00"],
    ["Response location", "Synthetic location"],
    ["Responders", "Synthetic responders"],
    ["Project description", "Updated project description"],
  ];
  for (const [label, value] of values)
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  fireEvent.click(screen.getByRole("button", { name: "Apply changes" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(mock.invoke).toHaveBeenCalledWith("project_edit", {
    sessionId: 7,
    info: expect.objectContaining({
      ...identity,
      name: "Updated response",
      client: "Updated client",
      response_start: "2026-10-13T09:00:00+08:00",
      response_end: "2026-10-14T18:00:00+08:00",
      location: "Synthetic location",
      responders: "Synthetic responders",
      description: "Updated project description",
    }),
  });
  const card = screen.getByRole("region", { name: "Current project details" });
  expect(within(card).getByText("Unsaved changes")).toBeVisible();
  for (const [, value] of values)
    expect(within(card).getByText(value)).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Save *" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("project_save", {
      sessionId: 7,
      path: "/tmp/synthetic.eair",
      overwrite: false,
    }),
  );
  fresh.project!.dirty = false;
  catalogInfo = structuredClone(fresh.project!.info);
  const listener = mock.event.mock.calls.find(
    ([name]) => name === "analysis-task",
  )![1];
  await act(async () =>
    listener({
      payload: {
        ...job,
        status: "completed",
        saved_paths: ["/tmp/synthetic.eair"],
      },
    }),
  );
  await waitFor(() => expect(within(card).getByText("Saved")).toBeVisible());
  await screen.findByRole("heading", { name: "Updated response" });
  unmount();
  render(<App />);
  await screen.findByRole("heading", { name: "Current project details" });
  fireEvent.click(screen.getByRole("button", { name: "Edit project details" }));
  await screen.findByRole("dialog", { name: "Edit project details" });
  for (const [label, value] of values)
    expect(screen.getByLabelText(label)).toHaveValue(value);
  expect(mock.invoke.mock.calls.some(([cmd]) => cmd === "project_create")).toBe(
    false,
  );
});

describe("response command navigation", () => {
  it("opens without a project and copies without loading evidence", async () => {
    const original = mock.invoke.getMockImplementation()!;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve({ ...boot, session_id: null, project: null })
        : command === "project_list_page"
          ? Promise.resolve({ offset: 0, total: 0, items: [] })
          : original(command, args),
    );
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Incident response commands" }),
    );
    expect(
      screen.getByRole("heading", { name: "Incident response commands" }),
    ).toBeVisible();
    expect(screen.getByRole("tab", { name: "Windows" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(
      screen.queryByRole("button", { name: "Toggle details" }),
    ).not.toBeInTheDocument();
    expect(document.querySelector(".inspector")).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "Copy Show system information" }),
    );
    await screen.findByText("Full command copied");
    expect(mock.invoke).toHaveBeenCalledWith(
      "plugin:clipboard-manager|write_text",
      { text: "systeminfo" },
    );
    expect(
      mock.invoke.mock.calls.some(([command]) =>
        ["get_view", "project_filters", "start_import", "start_ai"].includes(
          command,
        ),
      ),
    ).toBe(false);
  });

  it("keeps command searches out of project filters and preserves the existing evidence query", async () => {
    const original = mock.invoke.getMockImplementation()!;
    const fresh = dirtyProjectBoot();
    fresh.project!.dirty = false;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve(structuredClone(fresh))
        : command === "project_filters"
          ? Promise.resolve(fresh.project)
          : command === "project_list_page"
            ? Promise.resolve({ offset: 0, total: 0, items: [] })
            : original(command, args),
    );
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
    await screen.findByText("Synthetic evidence record");
    fireEvent.change(screen.getByLabelText("Query evidence"), {
      target: { value: "192.0.2.10" },
    });
    fireEvent.submit(screen.getByLabelText("Query evidence").closest("form")!);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 600));
    });
    const views = mock.invoke.mock.calls.filter(
      ([command]) => command === "get_view",
    ).length;
    const saves = mock.invoke.mock.calls.filter(
      ([command]) => command === "project_filters",
    ).length;
    const savedFilters = mock.invoke.mock.calls
      .filter(([command]) => command === "project_filters")
      .at(-1)![1].filters;
    expect(savedFilters).not.toHaveProperty("commands");
    fireEvent.click(
      screen.getByRole("button", { name: "Incident response commands" }),
    );
    fireEvent.change(
      screen.getByLabelText("Search incident response commands"),
      {
        target: { value: "systeminfo" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Copy Show system information" }),
    );
    await screen.findByText("Full command copied");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 600));
    });
    expect(
      mock.invoke.mock.calls.filter(([command]) => command === "get_view"),
    ).toHaveLength(views);
    expect(
      mock.invoke.mock.calls.filter(
        ([command]) => command === "project_filters",
      ),
    ).toHaveLength(saves);
    expect(screen.getByText("Client A response · Client A")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
    expect(screen.getByLabelText("Query evidence")).toHaveValue("192.0.2.10");
  });

  it.each([false, true])(
    "stays on the command page when import finishes (session changed: %s)",
    async (changed) => {
      const original = mock.invoke.getMockImplementation()!;
      const job = {
        task_id: 222,
        session_id: 7,
        epoch: 0,
        revision: 1,
        kind: "import",
        status: "running",
        label: "Local analysis",
        stage: null,
        completed: null,
        total: null,
        error: null,
        saved_paths: [],
      };
      let fresh: Bootstrap = { ...boot, busy: job };
      mock.invoke.mockImplementation((command, args) =>
        command === "initialize"
          ? Promise.resolve(structuredClone(fresh))
          : original(command, args),
      );
      render(<App />);
      await waitFor(() =>
        expect(mock.window.onCloseRequested).toHaveBeenCalled(),
      );
      fireEvent.click(
        screen.getByRole("button", { name: "Incident response commands" }),
      );
      fireEvent.mouseDown(screen.getByRole("tab", { name: "Linux" }), {
        button: 0,
        ctrlKey: false,
      });
      const views = mock.invoke.mock.calls.filter(
        ([command]) => command === "get_view",
      ).length;
      const listener = mock.event.mock.calls.find(
        ([name]) => name === "analysis-task",
      )![1];
      fresh = { ...fresh, busy: null, session_id: changed ? 8 : 7 };
      await act(async () =>
        listener({ payload: { ...job, status: "completed" } }),
      );
      expect(
        screen.getByRole("heading", { name: "Incident response commands" }),
      ).toBeVisible();
      expect(screen.getByRole("tab", { name: "Linux" })).toHaveAttribute(
        "aria-selected",
        "true",
      );
      expect(
        mock.invoke.mock.calls.filter(([command]) => command === "get_view"),
      ).toHaveLength(views);
      expect(
        screen.getByRole("button", { name: "Copy Show OS version" }),
      ).toBeEnabled();
    },
  );
});

it("preserves combined log dimensions across order changes and pagination", async () => {
  const user = userEvent.setup();
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
  await screen.findByText("Synthetic evidence record");
  fireEvent.click(screen.getByRole("button", { name: "Multi-dim query" }));
  fireEvent.change(screen.getByLabelText("Windows event IDs"), {
    target: { value: "4624,4625" },
  });
  fireEvent.change(screen.getByLabelText("Log channel"), {
    target: { value: "Security" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply query" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(mock.invoke).toHaveBeenCalledWith("get_view", {
    request: expect.objectContaining({
      screen: "logs",
      commit_selection: true,
      filters: expect.objectContaining({
        offset: 0,
        log_query: expect.objectContaining({
          event_ids: "4624,4625",
          channel: "Security",
        }),
      }),
    }),
  });
  await user.click(screen.getByRole("combobox", { name: "Log order" }));
  await user.click(
    screen.getByRole("option", { name: "Time descending (new → old)" }),
  );
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("get_view", {
      request: expect.objectContaining({
        filters: expect.objectContaining({ order: "time_desc", offset: 0 }),
      }),
    }),
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("get_view", {
      request: expect.objectContaining({
        filters: expect.objectContaining({
          order: "time_desc",
          offset: 100,
          log_query: expect.objectContaining({
            event_ids: "4624,4625",
            channel: "Security",
          }),
        }),
      }),
    }),
  );
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
});

it("restores legacy log filters with defaults for new query dimensions", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((command, args) =>
    command === "initialize"
      ? Promise.resolve({
          ...boot,
          filters: {
            logs: {
              text: "legacy filter",
              regex: false,
              suspicious: false,
              source: null,
              category: null,
              status: null,
              protocol: null,
              offset: 0,
              limit: 100,
              tree: true,
              packets: false,
              flow: null,
              collapsed: [],
              severity: null,
              origin: "all",
            },
          },
        })
      : original(command, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
  await screen.findByText("Synthetic evidence record");
  expect(screen.getByLabelText("Query evidence")).toHaveValue("legacy filter");
  expect(screen.getByRole("combobox", { name: "Log order" })).toHaveTextContent(
    "Original order (forward)",
  );
  fireEvent.click(screen.getByRole("button", { name: "Multi-dim query" }));
  expect(screen.getByLabelText("Windows event IDs")).toHaveValue("");
});

it("cancels a pending multidimensional query and ignores its late result", async () => {
  const original = mock.invoke.getMockImplementation()!;
  let complete!: () => void;
  mock.invoke.mockImplementation((command, args) => {
    if (
      command === "get_view" &&
      args.request.filters.log_query.event_ids === "4624"
    )
      return new Promise((resolve) => {
        complete = () => resolve(response(args.request));
      });
    return original(command, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
  await screen.findByText("Synthetic evidence record");
  fireEvent.click(screen.getByRole("button", { name: "Multi-dim query" }));
  fireEvent.change(screen.getByLabelText("Windows event IDs"), {
    target: { value: "4624" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply query" }));
  fireEvent.click(await screen.findByRole("button", { name: "Cancel query" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  await act(async () => complete());
  expect(screen.getByRole("button", { name: "Multi-dim query" })).toBeVisible();
  expect(screen.getByText("Synthetic evidence record")).toBeVisible();
  const requests = mock.invoke.mock.calls.filter(
    ([command]) => command === "get_view",
  );
  expect(requests.at(-1)![1].request.filters.log_query.event_ids).toBe("");
});

it("loads finding details on demand and ignores replies for a previous selection", async () => {
  const make = (id: string) => ({
    id,
    origin: "local:synthetic",
    severity: "low" as const,
    title: `Synthetic finding ${id}`,
    description: "",
    evidence_ids: [] as string[],
    confidence: 0.5,
    recommendations: [],
    table_preview: true,
    evidence_count: 150,
  });
  const a = make("A"),
    b = make("B");
  const pending: Record<string, (value: any) => void> = {};
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((command, args) => {
    if (command === "get_view")
      return {
        ...response(args.request),
        findings: { items: [a, b], total: 2, offset: 0 },
      };
    if (command === "get_finding")
      return new Promise((resolve) => {
        pending[args.id] = resolve;
      });
    return original(command, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Analysis overview" }));
  fireEvent.click(await screen.findByText("Synthetic finding A"));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("get_finding", {
      sessionId: 7,
      id: "A",
    }),
  );
  fireEvent.click(screen.getByText("Synthetic finding B"));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("get_finding", {
      sessionId: 7,
      id: "B",
    }),
  );
  await act(async () =>
    pending.B({
      ...b,
      table_preview: false,
      description: "full description B",
      evidence_ids: ["evidence-b"],
    }),
  );
  await screen.findByText("full description B");
  expect(
    await screen.findByRole("button", { name: "evidence-b" }),
  ).toBeVisible();
  await act(async () =>
    pending.A({
      ...a,
      table_preview: false,
      description: "stale description A",
      evidence_ids: ["evidence-a"],
    }),
  );
  expect(screen.queryByText("stale description A")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "evidence-b" })).toBeVisible();
});

it("keeps parsed log summaries visible when list fields are compacted", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((command, args) => {
    if (command === "get_view")
      return {
        ...response(args.request),
        records: {
          offset: 0,
          total: 1,
          items: [
            {
              ...record,
              data: {
                kind: "log",
                fields: { category: "auth_text", fields: {} },
              },
              summary: "user=synthetic user · source=192.0.2.10",
            },
          ],
        },
      };
    return original(command, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Log evidence" }));
  expect(
    await screen.findByText("user=synthetic user · source=192.0.2.10"),
  ).toBeVisible();
});
