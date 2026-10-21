import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LogQueryDialog } from "../components/LogQuery";
import { defaultLogQuery } from "../types";
import { localTimeInput, queryTime, displayLogTime } from "../lib/log-query";
afterEach(cleanup);
it("submits combined dimensions with timezone-bearing bounds", async () => {
  const apply = vi.fn().mockResolvedValue(undefined);
  render(
    <LogQueryDialog
      initial={defaultLogQuery()}
      busy={false}
      onApply={apply}
      onClose={() => {}}
    />,
  );
  fireEvent.change(screen.getByLabelText("Start time (local)"), {
    target: { value: "2026-10-14T09:00:00" },
  });
  fireEvent.change(screen.getByLabelText("End time (local)"), {
    target: { value: "2026-10-14T18:00:00" },
  });
  fireEvent.change(screen.getByLabelText("Windows event IDs"), {
    target: { value: "4624,4625" },
  });
  fireEvent.change(screen.getByLabelText("Log channel"), {
    target: { value: "Security" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Add condition" }));
  fireEvent.change(screen.getByLabelText("Query field 1"), {
    target: { value: "user" },
  });
  fireEvent.change(screen.getByLabelText("Query field value 1"), {
    target: { value: "userA" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply query" }));
  await waitFor(() =>
    expect(apply).toHaveBeenCalledWith(
      expect.objectContaining({
        time_from: queryTime("2026-10-14T09:00:00"),
        time_until: queryTime("2026-10-14T18:00:00"),
        event_ids: "4624,4625",
        channel: "Security",
        fields: [{ field: "user", value: "userA", mode: "contains" }],
      }),
    ),
  );
});
it("rejects reversed time ranges and leaves the last query unchanged", async () => {
  const apply = vi.fn();
  render(
    <LogQueryDialog
      initial={defaultLogQuery()}
      busy={false}
      onApply={apply}
      onClose={() => {}}
    />,
  );
  fireEvent.change(screen.getByLabelText("Start time (local)"), {
    target: { value: "2026-10-14T18:00:00" },
  });
  fireEvent.change(screen.getByLabelText("End time (local)"), {
    target: { value: "2026-10-14T09:00:00" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply query" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "End time must not be earlier than start time",
  );
  expect(apply).not.toHaveBeenCalled();
});
it("retains a failed query draft and does not submit during Chinese composition", async () => {
  const apply = vi.fn().mockRejectedValue("synthetic query error");
  render(
    <LogQueryDialog
      initial={defaultLogQuery()}
      busy={false}
      onApply={apply}
      onClose={() => {}}
    />,
  );
  const field = screen.getByLabelText("Event provider");
  fireEvent.change(field, { target: { value: "Security" } });
  fireEvent.compositionStart(field);
  fireEvent.submit(field.closest("form")!);
  expect(apply).not.toHaveBeenCalled();
  fireEvent.compositionEnd(field);
  fireEvent.click(screen.getByRole("button", { name: "Apply query" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The last valid query is kept.",
  );
  expect(field).toHaveValue("Security");
});
it("converts local bounds consistently and keeps timezone-less evidence unknown", () => {
  expect(localTimeInput(queryTime("2026-10-14T09:00:00"))).toBe(
    "2026-10-14T09:00:00",
  );
  expect(displayLogTime("2026-10-14 00:00:00 UTC")).toBe(
    displayLogTime("2026-10-14T00:00:00Z"),
  );
  expect(displayLogTime("2026-10-14 09:00:00")).toBe("Unknown");
  expect(displayLogTime(null)).toBe("Unknown");
});

it("submits middleware dimensions and an explicit source timezone", async () => {
  const apply = vi.fn().mockResolvedValue(undefined);
  render(
    <LogQueryDialog
      initial={{ ...defaultLogQuery(), time_offset: 400 }}
      busy={false}
      onApply={apply}
      onClose={() => {}}
    />,
  );
  expect(
    screen.getByRole("combobox", { name: "Time zone for logs without one" }),
  ).toHaveTextContent("UTC+06:40");
  for (const [label, value] of [
    ["Log level", "ERROR, SEVERE"],
    ["Client IP", "192.0.2.10"],
    ["HTTP status", "500,403"],
    ["Request method", "POST"],
    ["Request path", "/api/"],
    ["Logger class", "org.apache.catalina"],
  ]) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  }
  fireEvent.input(screen.getByLabelText("Start time (local)"), {
    target: { value: "2026-10-14T09:00:00" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply query" }));
  await waitFor(() =>
    expect(apply).toHaveBeenCalledWith(
      expect.objectContaining({
        log_level: "ERROR, SEVERE",
        client_ip: "192.0.2.10",
        http_status: "500,403",
        method: "POST",
        uri: "/api/",
        logger: "org.apache.catalina",
        time_offset: 400,
        time_from: queryTime("2026-10-14T09:00:00"),
      }),
    ),
  );
});
it("rejects invalid HTTP codes without applying", async () => {
  const apply = vi.fn();
  render(
    <LogQueryDialog
      initial={defaultLogQuery()}
      busy={false}
      onApply={apply}
      onClose={() => {}}
    />,
  );
  fireEvent.change(screen.getByLabelText("HTTP status"), {
    target: { value: "999" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply query" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "HTTP status must be integers from 100 to 599",
  );
  expect(apply).not.toHaveBeenCalled();
});
