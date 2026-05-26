import { McpServerConfig } from './discovery';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  serverName: string;
  detail: string;
  suggestion: string;
  owaspRef?: string;
}

interface Rule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  check: (server: McpServerConfig) => Finding | null;
}

export function runAllRules(server: McpServerConfig): Finding[] {
  return RULES.map((rule) => rule.check(server)).filter((f): f is Finding => f !== null);
}

const RULES: Rule[] = [
  // ============ CRITICAL ============
  {
    id: 'MCP-001',
    severity: 'CRITICAL',
    title: '命令注入风险 — 用户输入拼接到命令行',
    description: 'args 中包含用户可控的输入，未做转义处理，攻击者可通过构造输入执行任意命令',
    check(server) {
      if (!server.args) return null;
      const dangerous = server.args.filter(
        (a) => typeof a === 'string' && /\$\(/.test(a) || /`/.test(a)
      );
      if (dangerous.length === 0) return null;
      return {
        ruleId: 'MCP-001',
        severity: 'CRITICAL',
        title: '命令注入风险',
        description: 'args 中包含 Shell 命令替换语法，可能导致命令注入',
        serverName: server.name,
        detail: `危险参数: ${dangerous.join(', ')}`,
        suggestion: '使用参数化方式传递用户输入，避免直接拼接 Shell 命令。使用 execFile 代替 exec。',
        owaspRef: 'A03:2021 – Injection',
      };
    },
  },

  {
    id: 'MCP-002',
    severity: 'CRITICAL',
    title: '硬编码密钥/Token',
    description: '命令环境变量中包含疑似 API 密钥、Token 或密码的硬编码值',
    check(server) {
      if (!server.env) return null;
      const sensitiveKeys = Object.keys(server.env).filter(
        (k) =>
          /token|key|secret|password|passwd|auth|credential/i.test(k)
      );
      if (sensitiveKeys.length === 0) return null;
      const leaked = sensitiveKeys.filter((k) => {
        const v = server.env![k];
        return v && v.length > 20 && !v.startsWith('$') && !v.startsWith('${');
      });
      if (leaked.length === 0) return null;
      return {
        ruleId: 'MCP-002',
        severity: 'CRITICAL',
        title: '硬编码密钥泄露',
        description: `环境变量中包含疑似硬编码的密钥: ${leaked.join(', ')}`,
        serverName: server.name,
        detail: `在 ${server.name} 的 MCP 配置中发现 ${leaked.length} 个硬编码密钥。这些密钥可能被提交到 Git 仓库或通过日志泄露。`,
        suggestion: '将密钥移到 .env 文件或系统密钥管理（如 keyring、1Password CLI），用 ${ENV_VAR} 引用。',
        owaspRef: 'A07:2021 – Identification and Authentication Failures',
      };
    },
  },

  {
    id: 'MCP-003',
    severity: 'CRITICAL',
    title: 'Shell 命令执行权限过大',
    description: 'MCP 服务器使用 bash/sh/cmd.exe 等通用 Shell 作为命令，攻击者可执行任意系统命令',
    check(server) {
      const dangerousCommands = ['bash', 'sh', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'pwsh'];
      if (!server.command) return null;
      const cmd = server.command.toLowerCase().replace(/\.exe$/, '');
      if (!dangerousCommands.includes(cmd)) return null;
      return {
        ruleId: 'MCP-003',
        severity: 'CRITICAL',
        title: '通用 Shell 作为 MCP 命令',
        description: `MCP 服务器使用 ${server.command} 作为命令，这意味着任何能调用该工具的人都可以执行任意系统命令`,
        serverName: server.name,
        detail: `命令: ${server.command} ${(server.args || []).join(' ')}`,
        suggestion: '将通用 Shell 替换为具体的、受限的程序。例如用 "node script.js" 代替 "bash -c ..."。',
        owaspRef: 'A01:2021 – Broken Access Control',
      };
    },
  },

  // ============ HIGH ============
  {
    id: 'MCP-004',
    severity: 'HIGH',
    title: '路径遍历漏洞',
    description: 'args 中包含文件路径参数，但未限制路径范围',
    check(server) {
      if (!server.args) return null;
      const pathArgs = server.args.filter(
        (a) => typeof a === 'string' && (a.includes('..') || a.includes('~') || a === '.' || a === '/')
      );
      if (pathArgs.length === 0) return null;
      return {
        ruleId: 'MCP-004',
        severity: 'HIGH',
        title: '潜在路径遍历风险',
        description: '命令参数中使用了相对路径或绝对路径，未限制访问范围',
        serverName: server.name,
        detail: `路径参数: ${pathArgs.join(', ')}`,
        suggestion: '限制文件访问到特定目录（如项目根目录），禁止 ../ 和绝对路径。使用 path.resolve 后验证路径前缀。',
        owaspRef: 'A01:2021 – Broken Access Control',
      };
    },
  },

  {
    id: 'MCP-005',
    severity: 'HIGH',
    title: 'MCP 服务器无认证',
    description: 'HTTP/SSE 传输的 MCP 服务器没有配置认证，任何知道 URL 的人都可以访问',
    check(server) {
      if (server.transport !== 'sse' && server.transport !== 'http') return null;
      if (!server.url) return null;
      const hasAuth = server.url.includes('@') || server.env?.API_KEY || server.env?.AUTH_TOKEN;
      if (hasAuth) return null;
      return {
        ruleId: 'MCP-005',
        severity: 'HIGH',
        title: '远程 MCP 服务器无认证',
        description: `HTTP MCP 服务器 ${server.url} 未发现认证配置`,
        serverName: server.name,
        detail: '任何人都可以向该 MCP 服务器发送请求并调用工具',
        suggestion: '添加 API Key 认证。大多数 MCP 网关支持 Bearer Token 或 X-API-Key 头。',
        owaspRef: 'A07:2021 – Identification and Authentication Failures',
      };
    },
  },

  {
    id: 'MCP-006',
    severity: 'HIGH',
    title: '使用 HTTP 明文传输',
    description: '远程 MCP 服务使用 HTTP 而非 HTTPS，通信可被中间人窃听和篡改',
    check(server) {
      if (!server.url) return null;
      if (!server.url.startsWith('http://')) return null;
      return {
        ruleId: 'MCP-006',
        severity: 'HIGH',
        title: '不安全的 HTTP 传输',
        description: `MCP 服务器 ${server.url} 使用 HTTP 明文传输`,
        serverName: server.name,
        detail: 'HTTP 协议下所有传输内容（包括 API Key、数据）均可被网络中间人截获',
        suggestion: '改用 HTTPS。如果是本地开发，至少使用 localhost 并配置 TLS。',
        owaspRef: 'A02:2021 – Cryptographic Failures',
      };
    },
  },

  {
    id: 'MCP-007',
    severity: 'HIGH',
    title: 'curl/wget 参数未验证',
    description: '命令中包含 curl 或 wget，可能被用于 SSRF 攻击',
    check(server) {
      const dangerousCommands = ['curl', 'wget', 'nc', 'netcat', 'telnet'];
      if (!server.command) return null;
      const cmd = server.command.toLowerCase();
      if (!dangerousCommands.some((d) => cmd.includes(d))) return null;
      return {
        ruleId: 'MCP-007',
        severity: 'HIGH',
        title: '网络工具未限制访问范围',
        description: `MCP 服务器使用 ${server.command}，可能被用于 SSRF 攻击访问内网资源`,
        serverName: server.name,
        detail: `命令: ${server.command} ${(server.args || []).join(' ')}`,
        suggestion: '添加 URL 白名单检查，禁止访问内网地址（127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16）。',
        owaspRef: 'SSRF – Server-Side Request Forgery',
      };
    },
  },

  // ============ MEDIUM ============
  {
    id: 'MCP-008',
    severity: 'MEDIUM',
    title: '环境变量泄露风险',
    description: 'MCP 服务器传递了系统环境变量，可能泄露敏感信息',
    check(server) {
      if (!server.env) return null;
      const leaked = Object.keys(server.env).filter(
        (k) => /^[A-Z_]+$/.test(k) && !/^PATH$|^HOME$|^USER$|^LANG$|^NODE_ENV$/.test(k)
      );
      if (leaked.length < 3) return null;
      return {
        ruleId: 'MCP-008',
        severity: 'MEDIUM',
        title: '大量环境变量被传递',
        description: `${leaked.length} 个环境变量被传递给 MCP 服务器，可能包含敏感信息`,
        serverName: server.name,
        detail: `传递的环境变量: ${leaked.join(', ')}`,
        suggestion: '只传递必要的环境变量，使用白名单方式管理。敏感信息使用专门的 Secret 管理工具。',
      };
    },
  },

  {
    id: 'MCP-009',
    severity: 'MEDIUM',
    title: 'MCP 服务器已禁用但配置仍存在',
    description: '发现 disabled:true 的 MCP 服务器，建议清理无用配置',
    check(server) {
      if (!server.disabled) return null;
      return {
        ruleId: 'MCP-009',
        severity: 'MEDIUM',
        title: '发现已禁用的 MCP 服务器配置',
        description: `${server.name} 已禁用但配置仍在配置文件中`,
        serverName: server.name,
        detail: '禁用的配置增加了攻击面 — 如果被重新启用，可能存在未知风险',
        suggestion: '如果不打算使用该服务器，建议从配置文件中删除。',
      };
    },
  },

  {
    id: 'MCP-010',
    severity: 'MEDIUM',
    title: 'npm/npx/pip 作为 MCP 命令',
    description: '使用包管理器作为 MCP 命令，可能被供应链攻击利用',
    check(server) {
      const pkgManagers = ['npx', 'npm', 'yarn', 'pnpm', 'pip', 'pip3', 'python', 'python3', 'node'];
      if (!server.command) return null;
      const cmd = server.command.toLowerCase();
      if (!pkgManagers.some((m) => cmd === m || cmd.startsWith(m + ' '))) return null;
      return {
        ruleId: 'MCP-010',
        severity: 'MEDIUM',
        title: '包管理器作为 MCP 命令',
        description: `${server.command} 作为 MCP 命令，注意供应链安全`,
        serverName: server.name,
        detail: '包管理器可能安装未经验证的依赖，存在供应链攻击风险',
        suggestion: '锁定包版本，定期审计依赖。考虑使用 Docker 容器隔离 MCP 服务器。',
      };
    },
  },

  // ============ LOW ============
  {
    id: 'MCP-011',
    severity: 'LOW',
    title: 'MCP 服务器缺少描述',
    description: '未提供 description 字段，不利于安全审计和文档化',
    check(server) {
      const hasDesc = typeof server.raw?.description === 'string' && server.raw.description.length > 0;
      if (hasDesc) return null;
      return {
        ruleId: 'MCP-011',
        severity: 'LOW',
        title: '缺少服务器描述',
        description: `${server.name} 没有提供 description 字段`,
        serverName: server.name,
        detail: '缺少文档使得其他开发者难以理解该 MCP 服务器的用途和安全边界',
        suggestion: '在配置中添加 "description" 字段，说明该服务器的用途和安全假设。',
      };
    },
  },

  // ============ INFO ============
  {
    id: 'MCP-012',
    severity: 'INFO',
    title: 'STDIO 传输方式',
    description: '该服务器使用 STDIO 传输，通信限于本地',
    check(server) {
      if (server.transport !== 'stdio') return null;
      return {
        ruleId: 'MCP-012',
        severity: 'INFO',
        title: '本地 STDIO 通信',
        description: `${server.name} 使用 STDIO 协议，仅限本地进程通信`,
        serverName: server.name,
        detail: 'STDIO 传输最安全 — 通信在本地进行，不暴露到网络',
        suggestion: '保持 STDIO 方式，除非确实需要远程访问。',
      };
    },
  },
];
