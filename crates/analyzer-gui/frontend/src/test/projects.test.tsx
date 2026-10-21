import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
  within,
  act,
} from "@testing-library/react";
import { afterEach, beforeEach, it, vi, expect } from "vitest";
import {
  ProjectHome,
  ProjectEditor,
  newProject,
} from "../components/ProjectView";
import { IocView } from "../components/IocView";
import type { ProjectEntry } from "../types";
const mock = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: mock.invoke }));
afterEach(cleanup);
beforeEach(() => mock.invoke.mockReset());
it("defaults the project name to the client and saves a blank name using the client", async () => {
  const save = vi.fn().mockResolvedValue(undefined);
  render(
    <ProjectEditor
      info={newProject()}
      busy={false}
      onClose={() => {}}
      onSave={save}
    />,
  );
  fireEvent.change(screen.getByLabelText("Client organization *"), {
    target: { value: "Synthetic client A" },
  });
  expect(screen.getByLabelText("Project name")).toHaveValue(
    "Synthetic client A",
  );
  fireEvent.change(screen.getByLabelText("Client organization *"), {
    target: { value: "Synthetic client B" },
  });
  expect(screen.getByLabelText("Project name")).toHaveValue(
    "Synthetic client B",
  );
  fireEvent.change(screen.getByLabelText("Project name"), {
    target: { value: " " },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm project details" }),
  );
  await waitFor(() =>
    expect(save).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Synthetic client B",
        client: "Synthetic client B",
      }),
    ),
  );
});
it("preserves custom and existing project names when the client changes", () => {
  const { unmount } = render(
    <ProjectEditor
      info={newProject()}
      busy={false}
      onClose={() => {}}
      onSave={vi.fn()}
    />,
  );
  fireEvent.change(screen.getByLabelText("Project name"), {
    target: { value: "Custom response name" },
  });
  fireEvent.change(screen.getByLabelText("Client organization *"), {
    target: { value: "Synthetic client A" },
  });
  expect(screen.getByLabelText("Project name")).toHaveValue(
    "Custom response name",
  );
  unmount();
  render(
    <ProjectEditor
      info={{
        ...newProject(),
        name: "Synthetic client A",
        client: "Synthetic client A",
      }}
      busy={false}
      onClose={() => {}}
      onSave={vi.fn()}
    />,
  );
  fireEvent.change(screen.getByLabelText("Client organization *"), {
    target: { value: "Synthetic client B" },
  });
  expect(screen.getByLabelText("Project name")).toHaveValue(
    "Synthetic client A",
  );
});
it("validates response times and preserves metadata until accepted", async () => {
  const save = vi
    .fn()
    .mockRejectedValue("Response time must include a time zone");
  render(
    <ProjectEditor
      info={newProject()}
      busy={false}
      onClose={() => {}}
      onSave={save}
    />,
  );
  fireEvent.change(screen.getByLabelText("Project name"), {
    target: { value: "Synthetic project" },
  });
  fireEvent.change(screen.getByLabelText("Client organization *"), {
    target: { value: "Synthetic client" },
  });
  fireEvent.change(screen.getByLabelText("Response end (with time zone)"), {
    target: { value: "2000-01-01T00:00:00Z" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm project details" }),
  );
  await screen.findByText("Response end must not be earlier than the start");
  expect(save).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText("Response end (with time zone)"), {
    target: { value: "" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm project details" }),
  );
  await screen.findByText("Response time must include a time zone");
  expect(screen.getByLabelText("Project name")).toHaveValue(
    "Synthetic project",
  );
});
it("searches project metadata and clearly identifies missing files", async () => {
  mock.invoke.mockResolvedValue({
    offset: 0,
    total: 1,
    items: [
      {
        info: {
          ...newProject(),
          name: "Synthetic response",
          client: "Synthetic client",
        },
        path: "/tmp/moved.eair",
        last_opened: "2026-10-05T10:00:00Z",
        missing: true,
      },
    ],
  });
  render(
    <ProjectHome
      busy={false}
      onNew={() => {}}
      onOpen={() => {}}
      onPick={() => {}}
      onError={() => {}}
    />,
  );
  await screen.findByText(
    "Project file missing; reopen it from its new location",
  );
  expect(screen.getByRole("button", { name: "Resume project" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Project search"), {
    target: { value: "Synthetic" },
  });
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "project_list_page",
      expect.objectContaining({
        search: expect.objectContaining({ text: "Synthetic" }),
      }),
    ),
  );
});

it.each([
  [
    "Response start (with time zone) *",
    "2026-10-14T09:00:00",
    "Response start",
  ],
  ["Response end (with time zone)", "invalid", "Response end"],
])(
  "rejects invalid editing time in %s before applying",
  async (label, value, error) => {
    const save = vi.fn();
    render(
      <ProjectEditor
        mode="edit"
        info={{
          ...newProject(),
          name: "Synthetic response",
          client: "Synthetic client",
        }}
        busy={false}
        onClose={() => {}}
        onSave={save}
      />,
    );
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Apply changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(error);
    expect(save).not.toHaveBeenCalled();
  },
);

it("blocks duplicate editing requests and preserves the draft on failure", async () => {
  let reject!: (reason: string) => void;
  const save = vi.fn(
    () =>
      new Promise<void>((_, fail) => {
        reject = fail;
      }),
  );
  const close = vi.fn();
  render(
    <ProjectEditor
      mode="edit"
      info={{
        ...newProject(),
        name: "Synthetic response",
        client: "Synthetic client",
      }}
      busy={false}
      onClose={close}
      onSave={save}
    />,
  );
  const name = screen.getByLabelText("Project name");
  fireEvent.change(name, { target: { value: "Updated response" } });
  fireEvent.submit(name.closest("form")!);
  fireEvent.submit(name.closest("form")!);
  expect(save).toHaveBeenCalledTimes(1);
  expect(name).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Close" }));
  expect(close).not.toHaveBeenCalled();
  await act(async () => reject("synthetic apply failure"));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "synthetic apply failure",
  );
  expect(name).toHaveValue("Updated response");
  expect(screen.getByRole("button", { name: "Apply changes" })).toBeEnabled();
});

it("cancels project edits without modifying the original metadata", () => {
  const info = {
    ...newProject(),
    name: "Original project",
    client: "Original client",
  };
  const close = vi.fn();
  const save = vi.fn();
  render(
    <ProjectEditor
      mode="edit"
      info={info}
      busy={false}
      onClose={close}
      onSave={save}
    />,
  );
  fireEvent.change(screen.getByLabelText("Project name"), {
    target: { value: "Cancelled edit" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(close).toHaveBeenCalledTimes(1);
  expect(save).not.toHaveBeenCalled();
  expect(info.name).toBe("Original project");
});
function projectEntry(name: string): ProjectEntry {
  return {
    info: { ...newProject(), name, client: `${name} client` },
    path: `/tmp/${name}.eair`,
    last_opened: "2026-10-07T09:00:00+08:00",
    missing: false,
  };
}
const homeProps = {
  busy: false,
  onNew: () => {},
  onOpen: () => {},
  onPick: () => {},
  onError: () => {},
};
it("requires confirmation to remove only the selected catalog entry and refreshes the list", async () => {
  const a = projectEntry("Synthetic response A");
  const b = projectEntry("Synthetic response B");
  let entries = [a, b];
  mock.invoke.mockImplementation(async (command: string) => {
    if (command === "project_list_page")
      return { offset: 0, total: entries.length, items: entries };
    if (command === "project_remove") entries = [b];
  });
  render(<ProjectHome {...homeProps} />);
  const button = await screen.findByRole("button", {
    name: "Remove Synthetic response A from the list",
  });
  fireEvent.click(button);
  const dialog = screen.getByRole("dialog", {
    name: "Remove project from the list",
  });
  expect(
    within(dialog).getByText(/the \.eair file, evidence, and IOCs are kept/),
  ).toBeVisible();
  expect(within(dialog).getByText(a.path)).toBeVisible();
  fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
  expect(
    mock.invoke.mock.calls.some(([command]) => command === "project_remove"),
  ).toBe(false);
  expect(screen.getByText(a.info.name)).toBeVisible();
  fireEvent.click(button);
  fireEvent.click(screen.getByRole("button", { name: "Confirm removal" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("project_remove", {
      id: a.info.id,
      path: a.path,
    }),
  );
  await waitFor(() =>
    expect(screen.queryByText(a.info.name)).not.toBeInTheDocument(),
  );
  expect(screen.getByText(b.info.name)).toBeVisible();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  await screen.findByText("Sorted by last opened · 1 project");
  await waitFor(() =>
    expect(
      mock.invoke.mock.calls.filter(
        ([command]) => command === "project_list_page",
      ),
    ).toHaveLength(2),
  );
});
it("preserves the list and displays errors when removal fails", async () => {
  const entry = projectEntry("Synthetic response");
  mock.invoke.mockImplementation(async (command: string) => {
    if (command === "project_list_page")
      return { offset: 0, total: 1, items: [entry] };
    if (command === "project_remove")
      throw new Error("Project directory unavailable");
  });
  render(<ProjectHome {...homeProps} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Remove Synthetic response from the list",
    }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Confirm removal" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Project directory unavailable",
  );
  expect(screen.getByRole("button", { name: "Confirm removal" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.getByText(entry.info.name)).toBeVisible();
});
it("allows missing entries to be removed and prevents duplicate requests while pending", async () => {
  const entry = { ...projectEntry("Missing project"), missing: true };
  let finish!: () => void;
  let entries = [entry];
  mock.invoke.mockImplementation((command: string) => {
    if (command === "project_list_page")
      return Promise.resolve({
        offset: 0,
        total: entries.length,
        items: entries,
      });
    if (command === "project_remove")
      return new Promise<void>((resolve) => {
        finish = () => {
          entries = [];
          resolve();
        };
      });
  });
  const { rerender } = render(<ProjectHome {...homeProps} busy />);
  const remove = await screen.findByRole("button", {
    name: "Remove Missing project from the list",
  });
  expect(remove).toBeDisabled();
  expect(screen.getByRole("button", { name: "Resume project" })).toBeDisabled();
  rerender(<ProjectHome {...homeProps} />);
  expect(remove).toBeEnabled();
  fireEvent.click(remove);
  fireEvent.click(screen.getByRole("button", { name: "Confirm removal" }));
  const pending = screen.getByRole("button", { name: "Removing…" });
  expect(pending).toBeDisabled();
  fireEvent.click(pending);
  expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  expect(
    mock.invoke.mock.calls.filter(([command]) => command === "project_remove"),
  ).toHaveLength(1);
  finish();
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  await screen.findByText(/project list is empty/);
});
it("mixes IOC paste and manual inputs and explicitly scans with exact domain policy", async () => {
  mock.invoke.mockImplementation(async (c: string) => {
    if (c === "get_ioc")
      return {
        status: { indicators: 1, records: 150, needs_rescan: true, run: null },
        indicators: { offset: 0, total: 1, items: [] },
        hits: { offset: 0, total: 0, items: [] },
      };
    if (c === "import_ioc")
      return { indicators: [], issues: [{ line: 2, message: "Invalid IOC" }] };
    if (c === "start_ioc_scan") return { task_id: 1 };
  });
  const onTask = vi.fn(async (f: () => Promise<unknown>) => {
    await f();
  });
  render(
    <IocView
      sessionId={7}
      revision={1}
      busy={false}
      onTask={onTask}
      onJump={() => {}}
      onChanged={async () => {}}
      onError={() => {}}
    />,
  );
  await screen.findByText(
    "New evidence or list changes have not been scanned yet; rescan manually.",
  );
  fireEvent.change(screen.getByLabelText("Manual IOC"), {
    target: { value: "2001:db8::1" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Add manually" }));
  await screen.findByText("Line 2: Invalid IOC");
  expect(mock.invoke).toHaveBeenCalledWith(
    "import_ioc",
    expect.objectContaining({
      sessionId: 7,
      input: expect.objectContaining({ value: "2001:db8::1" }),
    }),
  );
  fireEvent.change(screen.getByLabelText("IOC list"), {
    target: { value: "type,value\ndomain,example.com" },
  });
  fireEvent.click(
    screen.getByRole("checkbox", {
      name: "CSV format (type,value, optional note)",
    }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Append pasted list" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "import_ioc",
      expect.objectContaining({
        input: expect.objectContaining({ csv: true }),
      }),
    ),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Scan current project" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("checkbox", { name: "Domains include subdomains" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Scan current project" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ioc_scan", {
      sessionId: 7,
      includeSubdomains: false,
    }),
  );
});

it("returns IOC hits to the last valid page after a rescan reduces their total", async () => {
  let total = 225;
  mock.invoke.mockImplementation(async (command: string, args: any) => {
    if (command !== "get_ioc") return undefined;
    return {
      status: { indicators: 1, records: 225, needs_rescan: false, run: null },
      indicators: { offset: args.offset, total: 1, items: [] },
      hits: {
        offset: args.hitOffset,
        total,
        items: Array.from(
          { length: Math.min(100, Math.max(0, total - args.hitOffset)) },
          (_, i) => ({
            record_id: `r${args.hitOffset + i}`,
            indicator_id: "ioc",
            value: "example.com",
            note: "",
            matched_value: "example.com",
            field: "uri",
            byte_offset: null,
            position: `hit-${args.hitOffset + i}`,
          }),
        ),
      },
    };
  });
  const props = {
    sessionId: 7,
    revision: 1,
    busy: false,
    onTask: async () => {},
    onJump: () => {},
    onChanged: async () => {},
    onError: vi.fn(),
  };
  const { rerender, container } = render(<IocView {...props} />);
  await screen.findByRole("button", { name: "hit-0" });
  const scroll = container.querySelectorAll(".ioc-table-scroll")[1];
  scroll.scrollTop = 500;
  fireEvent.click(screen.getByRole("button", { name: "IOC hits Last page" }));
  await screen.findByRole("button", { name: "hit-224" });
  expect(scroll.scrollTop).toBe(0);
  total = 125;
  rerender(<IocView {...props} revision={2} />);
  await screen.findByRole("button", { name: "hit-124" });
  expect(mock.invoke).toHaveBeenLastCalledWith("get_ioc", {
    sessionId: 7,
    offset: 0,
    hitOffset: 100,
  });
  await waitFor(() =>
    expect(
      screen.getByRole("spinbutton", { name: "IOC hits Page number" }),
    ).toHaveValue(2),
  );
  total = 0;
  rerender(<IocView {...props} revision={3} />);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenLastCalledWith("get_ioc", {
      sessionId: 7,
      offset: 0,
      hitOffset: 0,
    }),
  );
  expect(
    await within(
      screen.getByRole("navigation", { name: "IOC hits pagination" }),
    ).findByText(/0 items · Page 0 \/ 0/),
  ).toBeVisible();
  expect(props.onError).not.toHaveBeenCalled();
});

it("retries failed IOC pages and ignores a response superseded by a refresh", async () => {
  const makeView = (offset: number, suffix = "") => ({
    status: { indicators: 225, records: 1, needs_rescan: false, run: null },
    indicators: {
      offset,
      total: 225,
      items: [
        {
          id: `ioc-${offset}`,
          kind: "domain",
          value: `item-${offset}${suffix}.test`,
          note: "",
        },
      ],
    },
    hits: { offset: 0, total: 0, items: [] },
  });
  let attempts = 0;
  let finishStale!: (value: ReturnType<typeof makeView>) => void;
  mock.invoke.mockImplementation((command: string, args: any) => {
    if (command !== "get_ioc") return Promise.resolve();
    if (args.offset === 100) {
      attempts++;
      if (attempts === 1)
        return Promise.reject(new Error("Simulated IOC page failure"));
      if (attempts === 2)
        return new Promise((resolve) => {
          finishStale = resolve;
        });
      return Promise.resolve(makeView(100, "-fresh"));
    }
    return Promise.resolve(makeView(args.offset));
  });
  const props = {
    sessionId: 7,
    revision: 1,
    busy: false,
    onTask: async () => {},
    onJump: () => {},
    onChanged: async () => {},
    onError: vi.fn(),
  };
  const { rerender, container } = render(<IocView {...props} />);
  await screen.findByLabelText("Note item-0.test");
  const scroll = container.querySelector(".ioc-table-scroll")!;
  scroll.scrollTop = 500;
  fireEvent.click(screen.getByRole("button", { name: "IOC list Next page" }));
  await waitFor(() => expect(props.onError).toHaveBeenCalledTimes(1));
  expect(screen.getByLabelText("Note item-0.test")).toBeVisible();
  expect(scroll.scrollTop).toBe(500);
  fireEvent.click(screen.getByRole("button", { name: "IOC list Next page" }));
  await waitFor(() => expect(attempts).toBe(2));
  expect(
    screen.getByRole("button", { name: "IOC list Next page" }),
  ).toBeDisabled();
  rerender(<IocView {...props} revision={2} />);
  await screen.findByLabelText("Note item-100-fresh.test");
  expect(scroll.scrollTop).toBe(0);
  await act(async () => finishStale(makeView(100, "-stale")));
  expect(
    screen.queryByLabelText("Note item-100-stale.test"),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText("Note item-100-fresh.test")).toBeVisible();
  expect(props.onError).toHaveBeenCalledTimes(1);
});

it("pages projects on the server and resets the page after filtering", async () => {
  const entries = Array.from({ length: 125 }, (_, i) =>
    projectEntry(`Synthetic project ${i}`),
  );
  mock.invoke.mockImplementation(async (command: string, args: any) =>
    command === "project_list_page"
      ? {
          offset: args.offset,
          total: 125,
          items: entries.slice(args.offset, args.offset + args.limit),
        }
      : undefined,
  );
  render(<ProjectHome {...homeProps} />);
  await screen.findByText("Synthetic project 0");
  fireEvent.click(screen.getByRole("button", { name: "Projects Next page" }));
  await screen.findByText("Synthetic project 50");
  expect(mock.invoke).toHaveBeenCalledWith(
    "project_list_page",
    expect.objectContaining({ offset: 50, limit: 50 }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Projects Last page" }));
  await screen.findByText("Synthetic project 124");
  fireEvent.change(screen.getByLabelText("Project search"), {
    target: { value: "filter" },
  });
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "project_list_page",
      expect.objectContaining({
        offset: 0,
        search: expect.objectContaining({ text: "filter" }),
      }),
    ),
  );
});

it("keeps the displayed project page after failure and retries the same next page", async () => {
  const entries = Array.from({ length: 75 }, (_, i) =>
    projectEntry(`project ${i}`),
  );
  const error = vi.fn();
  let failed = false;
  mock.invoke.mockImplementation(async (command: string, args: any) => {
    if (command !== "project_list_page") return undefined;
    if (args.offset === 50 && !failed) {
      failed = true;
      throw new Error("Simulated pagination failure");
    }
    return {
      offset: args.offset,
      total: entries.length,
      items: entries.slice(args.offset, args.offset + args.limit),
    };
  });
  render(<ProjectHome {...homeProps} onError={error} />);
  await screen.findByText("project 0");
  fireEvent.click(screen.getByRole("button", { name: "Projects Next page" }));
  await waitFor(() => expect(error).toHaveBeenCalled());
  expect(screen.getByText("project 0")).toBeVisible();
  expect(
    screen.getByRole("spinbutton", { name: "Projects Page number" }),
  ).toHaveValue(1);
  fireEvent.click(screen.getByRole("button", { name: "Projects Next page" }));
  await screen.findByText("project 50");
  await waitFor(() =>
    expect(
      screen.getByRole("spinbutton", { name: "Projects Page number" }),
    ).toHaveValue(2),
  );
});
