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
