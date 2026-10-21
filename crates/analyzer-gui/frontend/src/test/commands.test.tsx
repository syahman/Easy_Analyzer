import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CommandsView } from "../components/CommandsView";
import { commandCategories, responseCommands } from "../lib/commands";
import capability from "../../../capabilities/main.json";

const clipboard = vi.hoisted(() => ({ writeText: vi.fn() }));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => clipboard);
beforeEach(() => {
  clipboard.writeText.mockReset().mockResolvedValue(undefined);
});
afterEach(cleanup);

describe("offline response commands", () => {
  it("ships the agreed coverage with environment and permissions for every command", () => {
    expect(new Set(responseCommands.map((item) => item.id)).size).toBe(48);
    for (const platform of ["windows", "linux"]) {
      const items = responseCommands.filter(
        (item) => item.platform === platform,
      );
      expect(items).toHaveLength(24);
      for (const category of commandCategories) {
        expect(
          items.filter((item) => item.category === category.value),
        ).toHaveLength(4);
      }
      for (const item of items) {
        expect(item.command.trim()).not.toBe("");
        expect(item.permission.trim()).not.toBe("");
        expect(item.notes.trim()).not.toBe("");
        expect(item.shell).toMatch(
          platform === "windows" ? /^(PowerShell|CMD)$/ : /^Bash$/,
        );
      }
    }
    expect(
      capability.permissions.filter((value) =>
        value.startsWith("clipboard-manager:"),
      ),
    ).toEqual(["clipboard-manager:allow-write-text"]);
  });

  it("defaults to Windows and switches the available commands to Linux", () => {
    render(<CommandsView />);
    expect(screen.getByRole("tab", { name: "Windows" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByText("24 commands")).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Show local user accounts" }),
    ).toBeVisible();
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Linux" }), {
      button: 0,
      ctrlKey: false,
    });
    expect(
      screen.getByRole("heading", { name: "Show system account list" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Show local user accounts" }),
    ).not.toBeInTheDocument();
  });

  it("combines category filtering with case-insensitive title, purpose and command searches", async () => {
    const user = userEvent.setup();
    render(<CommandsView />);
    await user.click(
      screen.getByRole("combobox", { name: "Command category" }),
    );
    await user.click(screen.getByRole("option", { name: "Network triage" }));
    expect(screen.getByText("4 commands")).toBeVisible();
    fireEvent.change(
      screen.getByLabelText("Search incident response commands"),
      {
        target: { value: "get-nettcpconnection" },
      },
    );
    expect(screen.getByText("1 command")).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Show TCP connections" }),
    ).toBeVisible();
    fireEvent.change(
      screen.getByLabelText("Search incident response commands"),
      {
        target: { value: "UDP addresses" },
      },
    );
    expect(
      screen.getByRole("heading", { name: "Show UDP endpoints" }),
    ).toBeVisible();
    fireEvent.change(
      screen.getByLabelText("Search incident response commands"),
      {
        target: { value: "DNS cache" },
      },
    );
    expect(
      screen.getByRole("heading", { name: "Show the DNS cache" }),
    ).toBeVisible();
    fireEvent.change(
      screen.getByLabelText("Search incident response commands"),
      {
        target: { value: "<script>no-match</script>" },
      },
    );
    expect(
      screen.getByText(
        "No matching commands; adjust the category or search text.",
      ),
    ).toBeVisible();
    expect(document.querySelector("script")).toBeNull();
    await user.click(
      screen.getByRole("button", { name: "Clear command search" }),
    );
    expect(screen.getByText("4 commands")).toBeVisible();
  });

  it("copies the full multiline command without description or altered backslashes", async () => {
    render(<CommandsView />);
    const command = responseCommands.find(
      (item) => item.id === "windows-run-keys",
    )!;
    fireEvent.click(
      screen.getByRole("button", { name: `Copy ${command.title}` }),
    );
    await screen.findByText("Full command copied");
    expect(clipboard.writeText).toHaveBeenCalledExactlyOnceWith(
      command.command,
    );
    expect(command.command).toContain("\n");
    expect(command.command).toContain("HKLM:\\Software");
    expect(
      screen.getByRole("button", { name: `Copy ${command.title}` }),
    ).toHaveTextContent("Copied");
  });

  it("keeps the command selectable and allows retry when the clipboard fails", async () => {
    clipboard.writeText.mockRejectedValueOnce("clipboard unavailable");
    render(<CommandsView />);
    const button = screen.getByRole("button", {
      name: "Copy Show system information",
    });
    fireEvent.click(button);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Copy failed: clipboard unavailable",
    );
    expect(
      screen.getByLabelText("Show system information command text"),
    ).toHaveTextContent("systeminfo");
    expect(button).toBeEnabled();
    fireEvent.click(button);
    await screen.findByText("Full command copied");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("ignores a late copy result after switching the platform", async () => {
    let complete!: () => void;
    clipboard.writeText.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          complete = resolve;
        }),
    );
    render(<CommandsView />);
    fireEvent.click(
      screen.getByRole("button", { name: "Copy Show system information" }),
    );
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Linux" }), {
      button: 0,
      ctrlKey: false,
    });
    complete();
    await waitFor(() =>
      expect(screen.queryByText("Full command copied")).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("heading", { name: "Show OS version" }),
    ).toBeVisible();
  });
});
