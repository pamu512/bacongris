import { describe, it, expect } from "vitest";
import {
  normalizeToolCallsForWire,
  normalizeToolArgumentsForWire,
  stripMarkdownCodeFenceFromToolArgs,
} from "./ollamaMessages";
import type { OllamaToolCall } from "./types";

describe("normalizeToolCallsForWire", () => {
  it("drops directory-listing rows mistaken for tool_calls", () => {
    const bad = [
      { type: "function" as const, function: { name: "README.md", isDir: false, modifiedMs: 1 } },
    ] as unknown as OllamaToolCall[];
    expect(normalizeToolCallsForWire(bad)).toBeUndefined();
  });

  it("drops top-level rows without function", () => {
    const bad = [{ name: "x", isDir: true }] as unknown as OllamaToolCall[];
    expect(normalizeToolCallsForWire(bad)).toBeUndefined();
  });

  it("keeps real list_directory calls", () => {
    const good: OllamaToolCall[] = [
      {
        id: "1",
        type: "function",
        function: { name: "list_directory", arguments: { path: "./" } },
      },
    ];
    const out = normalizeToolCallsForWire(good);
    expect(out?.length).toBe(1);
    expect(out![0].function.name).toBe("list_directory");
  });
});

describe("normalizeToolArgumentsForWire", () => {
  it("wraps array arguments in an object", () => {
    const out = normalizeToolArgumentsForWire([{ a: 1 }]);
    expect(out._host_array_arguments).toBe(true);
    expect(Array.isArray(out.items)).toBe(true);
  });

  it("strips markdown json fences before parse", () => {
    const raw = '```json\n{\n  "name": "get_environment",\n  "arguments": {}\n}\n```';
    expect(stripMarkdownCodeFenceFromToolArgs(raw)).toBe(
      '{\n  "name": "get_environment",\n  "arguments": {}\n}',
    );
    const out = normalizeToolArgumentsForWire(raw);
    expect(out.name).toBe("get_environment");
    expect(out.arguments).toEqual({});
  });
});
