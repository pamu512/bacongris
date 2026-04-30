import { describe, it, expect } from "vitest";
import { resolveRunCommandProgramAndArgv } from "./toolArgs";

describe("resolveRunCommandProgramAndArgv", () => {
  it("maps cmd + shell line to bash -c", () => {
    const r = resolveRunCommandProgramAndArgv({
      cmd: "ls -la\n",
      cwd: "Ransomware_live_event_victim",
    });
    expect(r).toEqual({ program: "bash", argv: ["-c", "ls -la"] });
  });

  it("keeps program + args when both set", () => {
    expect(
      resolveRunCommandProgramAndArgv({
        program: "python3",
        args: ["-c", "print(1)"],
      }),
    ).toEqual({ program: "python3", argv: ["-c", "print(1)"] });
  });

  it("wraps a spaced program token with no args as bash -c", () => {
    expect(
      resolveRunCommandProgramAndArgv({
        program: "ls -la",
      }),
    ).toEqual({ program: "bash", argv: ["-c", "ls -la"] });
  });
});
