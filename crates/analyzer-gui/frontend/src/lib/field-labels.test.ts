import { describe, expect, it } from "vitest";
import { logFieldLabel } from "./field-labels";

describe("Windows event field labels", () => {
  it.each([
    ["Execution.#attributes.ThreadID", "Execution thread ID"],
    ["Execution.#attributes.ProcessID", "Execution process ID"],
    ["Provider.#attributes.Name", "Event provider"],
    ["Provider.#attributes.Guid", "Provider GUID"],
    ["Provider.#attributes.EventSourceName", "Event source name"],
    ["TimeCreated.#attributes.SystemTime", "Record time"],
    ["Correlation.#attributes.ActivityID", "Activity ID"],
    ["Correlation.#attributes.RelatedActivityID", "Related activity ID"],
    ["Security.#attributes.UserID", "User SID"],
    ["EventID.#attributes.Qualifiers", "Event qualifiers"],
  ])("localizes actual EVTX XML attribute path %s", (field, label) => {
    expect(logFieldLabel(`Event.System.${field}`)).toBe(label);
    expect(logFieldLabel(`System.${field}`)).toBe(label);
  });

  it("accepts plain and older attribute paths and text nodes", () => {
    for (const field of [
      "Execution.ThreadID",
      "Execution._attributes.ThreadID",
      "Execution_attributes.ThreadID",
    ]) {
      expect(logFieldLabel(`Event.System.${field}`)).toBe(
        "Execution thread ID",
      );
    }
    expect(logFieldLabel("Event.System.EventID.#text")).toBe("Event ID");
    expect(logFieldLabel("Event.EventData.FailureReason.#text")).toBe(
      "Failure reason",
    );
  });

  it("retains unknown names and fields outside the Windows event namespaces", () => {
    for (const field of [
      "Event.System.Execution.#attributes.UnknownAttribute",
      "Event.System.Unknown.#attributes.ThreadID",
      "Event.EventData.Unknown.#text",
      "custom.Execution.#attributes.ThreadID",
      "__proto__",
    ]) {
      expect(logFieldLabel(field)).toBe(field);
    }
  });
});
