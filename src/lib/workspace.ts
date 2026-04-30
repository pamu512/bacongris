export type WorkspaceInfo = {
  effectivePath: string;
  scriptsPath: string;
  isCustomLocation: boolean;
  pathAccessible: boolean;
  pathError?: string;
};

export type WorkspaceProfile = {
  id: string;
  name: string;
  path: string;
  lastOpened: number;
  extraRoots: string[];
  extraExecutables: string[];
  userRules: string;
};

export type AgentInfo = {
  id: string;
  profileId: string;
  title: string;
  createdAt: number;
  updatedAt: number;
};

export type AppStateV2 = {
  activeProfileId: string | null;
  activeAgentId: string | null;
};

/** `bind_workspace_venv_pip` (camelCase from Rust). */
export type PipBindFailure = {
  project: string;
  error: string;
};

export type VenvPipBindReport = {
  ok: boolean;
  summary: string;
  skippedNoPyproject: boolean;
  projects: string[];
  succeeded: string[];
  failed: PipBindFailure[];
};

/** localStorage key: one successful bind per workspace path. */
export const pipVenvBoundStorageKey = (effectivePath: string) =>
  `bacongris_pip_venv_bound:${effectivePath}`;
