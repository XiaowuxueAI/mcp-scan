import fs from 'fs-extra';
import path from 'path';
import os from 'os';

export interface McpConfig {
  filePath: string;
  client: string;
  servers: McpServerConfig[];
}

export interface McpServerConfig {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: 'stdio' | 'sse' | 'http';
  disabled?: boolean;
  raw: Record<string, unknown>;
}

const CLIENTS: { name: string; paths: string[] }[] = [
  {
    name: 'Claude Desktop',
    paths: [
      path.join(os.homedir(), 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'),
      path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      path.join(os.homedir(), '.claude', 'claude_desktop_config.json'),
    ],
  },
  {
    name: 'Claude Code',
    paths: [
      path.join(os.homedir(), '.claude.json'),
      path.join(os.homedir(), '.claude', 'settings.json'),
    ],
  },
  {
    name: 'Cursor',
    paths: [
      path.join(os.homedir(), '.cursor', 'mcp.json'),
      path.join(os.homedir(), '.cursor', 'mcp_settings.json'),
    ],
  },
  {
    name: 'VS Code',
    paths: [
      path.join(os.homedir(), '.vscode', 'mcp.json'),
      path.join(os.homedir(), 'AppData', 'Roaming', 'Code', 'User', 'mcp.json'),
    ],
  },
  {
    name: 'Windsurf',
    paths: [
      path.join(os.homedir(), '.windsurf', 'mcp.json'),
      path.join(os.homedir(), '.codeium', 'windsurf', 'mcp.json'),
    ],
  },
  {
    name: 'OpenClaw / Clawd',
    paths: [
      path.join(os.homedir(), '.clawd', 'mcp.json'),
      path.join(os.homedir(), '.openclaw', 'mcp.json'),
    ],
  },
  {
    name: 'Generic .mcp.json',
    paths: [
      path.join(process.cwd(), '.mcp.json'),
    ],
  },
];

export function discoverConfigs(): McpConfig[] {
  const configs: McpConfig[] = [];

  for (const client of CLIENTS) {
    for (const p of client.paths) {
      if (fs.existsSync(p)) {
        try {
          const raw = fs.readJsonSync(p);
          const servers = parseServers(raw, client.name);
          if (servers.length > 0) {
            configs.push({
              filePath: p,
              client: client.name,
              servers,
            });
          }
        } catch {
          // skip unreadable configs
        }
      }
    }
  }

  return configs;
}

function parseServers(raw: Record<string, unknown>, client: string): McpServerConfig[] {
  let mcpServers: Record<string, unknown> = {};

  if (raw.mcpServers) {
    mcpServers = raw.mcpServers as Record<string, unknown>;
  } else if (client === 'Claude Code' && raw.mcpServers) {
    mcpServers = raw.mcpServers as Record<string, unknown>;
  } else if (raw.servers) {
    mcpServers = raw.servers as Record<string, unknown>;
  }

  const result: McpServerConfig[] = [];

  for (const [name, config] of Object.entries(mcpServers)) {
    if (!config || typeof config !== 'object') continue;
    const c = config as Record<string, unknown>;

    result.push({
      name,
      command: c.command as string | undefined,
      args: c.args as string[] | undefined,
      env: c.env as Record<string, string> | undefined,
      url: c.url as string | undefined,
      transport: (c.transport as 'stdio' | 'sse' | 'http') || (c.url ? 'http' : 'stdio'),
      disabled: (c.disabled as boolean) || false,
      raw: c,
    });
  }

  return result;
}
