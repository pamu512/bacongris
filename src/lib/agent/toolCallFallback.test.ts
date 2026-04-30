import { describe, it, expect } from "vitest";
import { canonicalizeHallucinatedToolName } from "./toolCallFallback";

describe("canonicalizeHallucinatedToolName", () => {
  it("strips tool: prefix and maps analysis_* alias to analyze_workspace_run_requirements", () => {
    expect(
      canonicalizeHallucinatedToolName("tool:analysis_workspace_run_requirements", {
        input: "intelx",
      }),
    ).toBe("analyze_workspace_run_requirements");
  });

  it("strips TOOL: uppercase prefix", () => {
    expect(
      canonicalizeHallucinatedToolName("TOOL:ANALYSIS_WORKSPACE_RUN_REQUIREMENTS", {}),
    ).toBe("analyze_workspace_run_requirements");
  });

  it("strips assistant channel noise before list_directory", () => {
    expect(
      canonicalizeHallucinatedToolName("assistant<|channel|>list_directory", {
        path: "Intelx_Crawler/csv_output",
      }),
    ).toBe("list_directory");
  });

  it("maps bare assistant: + path to list_directory", () => {
    expect(
      canonicalizeHallucinatedToolName("assistant:", {
        path: "Intelx_Crawler/csv_output",
      }),
    ).toBe("list_directory");
  });
});
