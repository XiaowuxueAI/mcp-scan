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

  // ============ 新增规则 v0.2.0 ============

  {
    id: 'MCP-013',
    severity: 'HIGH',
    title: '不安全的文件系统访问范围',
    description: 'args 中包含根目录或系统敏感路径',
    check(server) {
      if (!server.args) return null;
      const sensitivePaths = ['/etc/', '/root/', '/proc/', '/sys/', 'C:\\Windows\\', '/var/log/'];
      const dangerous = server.args.filter((a) =>
        typeof a === 'string' && sensitivePaths.some((p) => a.includes(p))
      );
      if (dangerous.length === 0) return null;
      return {
        ruleId: 'MCP-013',
        severity: 'HIGH',
        title: '访问系统敏感路径',
        description: `命令参数包含系统敏感路径: ${dangerous.join(', ')}`,
        serverName: server.name,
        detail: 'MCP 服务器可以访问 /etc/、/proc/ 等系统敏感目录，存在信息泄露和提权风险',
        suggestion: '将文件访问限制在工作目录内，禁止访问系统敏感路径。',
        owaspRef: 'A01:2021 – Broken Access Control',
      };
    },
  },

  {
    id: 'MCP-014',
    severity: 'MEDIUM',
    title: '命令缺少超时配置',
    description: 'MCP 服务器命令没有设置超时，可能导致资源耗尽',
    check(server) {
      if (!server.command) return null;
      const hasTimeout = server.args?.some((a) =>
        typeof a === 'string' && /timeout|--timeout|-t\s+\d+/.test(a)
      );
      if (hasTimeout) return null;
      return {
        ruleId: 'MCP-014',
        severity: 'MEDIUM',
        title: '缺少命令超时限制',
        description: `${server.name} 的命令未配置超时参数`,
        serverName: server.name,
        detail: '长时间运行的命令可能导致 CPU/内存资源耗尽',
        suggestion: '在命令参数中添加超时配置，例如 --timeout 30 或使用 timeout 命令包装。',
      };
    },
  },

  {
    id: 'MCP-015',
    severity: 'MEDIUM',
    title: '容器逃逸风险',
    description: '检测 Docker Socket 挂载或其他容器逃逸路径',
    check(server) {
      if (!server.args) return null;
      const escapePaths = ['/var/run/docker.sock', '/run/docker.sock', '/proc/1/ns/'];
      const dangerous = server.args.filter((a) =>
        typeof a === 'string' && escapePaths.some((p) => a.includes(p))
      );
      if (dangerous.length === 0) return null;
      return {
        ruleId: 'MCP-015',
        severity: 'MEDIUM',
        title: '潜在的容器逃逸风险',
        description: `命令参数引用了 Docker Socket 或容器命名空间: ${dangerous.join(', ')}`,
        serverName: server.name,
        detail: '访问 Docker Socket 或 /proc 命名空间可能让攻击者逃逸容器',
        suggestion: '移除 Docker Socket 挂载，使用 Docker-in-Docker 或无服务器容器方案。',
        owaspRef: 'A01:2021 – Broken Access Control',
      };
    },
  },

  {
    id: 'MCP-016',
    severity: 'MEDIUM',
    title: '调试模式可能被启用',
    description: '检测 debug/verbose/trace 等调试标志',
    check(server) {
      if (!server.args) return null;
      const debugFlags = server.args.filter((a) =>
        typeof a === 'string' && /^(--debug|--verbose|-vvv|--trace|--log-level\s*=\s*debug)$/i.test(a)
      );
      if (debugFlags.length === 0) return null;
      return {
        ruleId: 'MCP-016',
        severity: 'MEDIUM',
        title: '调试模式已启用',
        description: `${server.name} 启用了调试标志: ${debugFlags.join(', ')}`,
        serverName: server.name,
        detail: '调试模式可能输出敏感信息到日志（API Key、用户数据等）',
        suggestion: '生产环境关闭调试模式，使用 INFO 或 WARN 日志级别。',
      };
    },
  },

  {
    id: 'MCP-017',
    severity: 'HIGH',
    title: 'Python/Node eval 执行风险',
    description: '检测 python -c / node -e 等动态代码执行',
    check(server) {
      if (!server.command || !server.args) return null;
      const evalPatterns = [
        { cmd: 'python', flag: '-c' },
        { cmd: 'python3', flag: '-c' },
        { cmd: 'node', flag: '-e' },
        { cmd: 'ruby', flag: '-e' },
        { cmd: 'perl', flag: '-e' },
      ];
      const cmd = server.command.toLowerCase();
      const match = evalPatterns.find((p) => cmd.includes(p.cmd));
      if (!match) return null;
      const hasEval = server.args.some((a) => a === match.flag);
      if (!hasEval) return null;
      return {
        ruleId: 'MCP-017',
        severity: 'HIGH',
        title: '动态代码执行风险',
        description: `${server.command} ${match.flag} 允许执行任意代码`,
        serverName: server.name,
        detail: 'python -c 或 node -e 可以执行任意代码，与直接暴露 Shell 风险相当',
        suggestion: '用独立的脚本文件代替 -c/-e 动态执行，并限制脚本内容。',
        owaspRef: 'A03:2021 – Injection',
      };
    },
  },

  {
    id: 'MCP-018',
    severity: 'LOW',
    title: 'WebSocket 明文连接',
    description: '检测 ws:// 不安全的 WebSocket 连接',
    check(server) {
      if (!server.url) return null;
      if (!server.url.startsWith('ws://')) return null;
      return {
        ruleId: 'MCP-018',
        severity: 'LOW',
        title: '不安全的 WebSocket 连接',
        description: `${server.url} 使用 ws:// 明文协议`,
        serverName: server.name,
        detail: 'WebSocket 明文传输可被中间人攻击截获和篡改',
        suggestion: '使用 wss:// 加密 WebSocket 连接。',
        owaspRef: 'A02:2021 – Cryptographic Failures',
      };
    },
  },

  {
    id: 'MCP-019',
    severity: 'MEDIUM',
    title: '检测 git 命令操作',
    description: 'MCP 服务器使用 git 命令，可能泄露源码',
    check(server) {
      if (!server.command) return null;
      if (!server.command.includes('git')) return null;
      return {
        ruleId: 'MCP-019',
        severity: 'MEDIUM',
        title: 'Git 命令作为 MCP 工具',
        description: `${server.name} 使用 git 命令，可能泄露源码和提交历史`,
        serverName: server.name,
        detail: 'Git 操作可以读取完整源码、提交历史、分支信息',
        suggestion: '限制 Git 操作为只读，禁止 push --force 和访问 .git/config。',
      };
    },
  },

  {
    id: 'MCP-020',
    severity: 'HIGH',
    title: '检测 sudo/root 权限',
    description: 'MCP 命令使用了 sudo 或以 root 身份运行',
    check(server) {
      if (!server.command && !server.args) return null;
      const cmd = (server.command || '') + ' ' + (server.args || []).join(' ');
      if (!/\bsudo\b|\bdoas\b|\broot\b/.test(cmd)) return null;
      return {
        ruleId: 'MCP-020',
        severity: 'HIGH',
        title: '以超级用户权限运行',
        description: `${server.name} 的命令使用了 sudo/root 权限`,
        serverName: server.name,
        detail: '以 root 权限运行的 MCP 服务器可以做任何事 — 安装软件、修改系统配置、删除文件',
        suggestion: '以普通用户身份运行 MCP 服务器，使用最小权限原则。',
        owaspRef: 'A01:2021 – Broken Access Control',
      };
    },
  },

  {
    id: 'MCP-021',
    severity: 'MEDIUM',
    title: '检测数据库直接操作',
    description: 'MCP 工具命令包含数据库客户端',
    check(server) {
      const dbClients = ['mysql', 'psql', 'sqlite3', 'mongo', 'redis-cli', 'pg_dump', 'mysqldump'];
      if (!server.command) return null;
      const cmd = server.command.toLowerCase();
      if (!dbClients.some((d) => cmd.includes(d))) return null;
      return {
        ruleId: 'MCP-021',
        severity: 'MEDIUM',
        title: '数据库直接访问',
        description: `${server.command} 作为 MCP 命令，可直接操作数据库`,
        serverName: server.name,
        detail: '直接数据库访问可以读取/修改/删除数据，应通过 API 层控制权限',
        suggestion: '使用只读数据库账号，通过 API 中间层控制访问，添加 SQL 审计日志。',
      };
    },
  },

  {
    id: 'MCP-022',
    severity: 'LOW',
    title: '检测不安全的权限标志',
    description: '命令参数中包含 --allow-everything 或类似的不安全标志',
    check(server) {
      if (!server.args) return null;
      const unsafeFlags = server.args.filter((a) =>
        typeof a === 'string' && /--allow-\(all\|everything\)|--no-sandbox|--disable-security|--insecure/i.test(a)
      );
      if (unsafeFlags.length === 0) return null;
      return {
        ruleId: 'MCP-022',
        severity: 'LOW',
        title: '使用了不安全的安全标志',
        description: `${server.name} 启用了不安全标志: ${unsafeFlags.join(', ')}`,
        serverName: server.name,
        detail: '--allow-all 等标志禁用了安全限制，增加了攻击面',
        suggestion: '使用白名单方式精确授权需要的权限，避免使用 --allow-all。',
      };
    },
  },

  {
    id: 'MCP-023',
    severity: 'INFO',
    title: 'MCP 配置使用相对路径',
    description: '命令使用相对路径而非绝对路径',
    check(server) {
      if (!server.command) return null;
      if (server.command.includes('/') || server.command.includes('\\')) return null;
      if (['npx', 'npm', 'node', 'python', 'python3', 'uvx', 'pip'].some((c) => server.command?.startsWith(c))) return null;
      return {
        ruleId: 'MCP-023',
        severity: 'INFO',
        title: '使用相对路径命令',
        description: `${server.command} 可能是相对路径，依赖 PATH 环境变量`,
        serverName: server.name,
        detail: '依赖 PATH 的命令可能被 PATH 劫持攻击替代',
        suggestion: '使用绝对路径指定命令，例如 /usr/bin/node 代替 node。',
      };
    },
  },

  {
    id: 'MCP-024',
    severity: 'MEDIUM',
    title: '检测 Docker 命令',
    description: 'MCP 服务器使用 docker 命令，可能操作容器',
    check(server) {
      if (!server.command) return null;
      if (!server.command.includes('docker') && !server.command.includes('podman')) return null;
      const dangerousArgs = (server.args || []).filter((a) =>
        typeof a === 'string' && /rm|stop|kill|prune|exec|run\s+--privileged/i.test(a)
      );
      return {
        ruleId: 'MCP-024',
        severity: 'MEDIUM',
        title: 'Docker 命令操作权限',
        description: `${server.name} 使用 ${server.command} 操作容器`,
        serverName: server.name,
        detail: dangerousArgs.length > 0
          ? `包含危险操作: ${dangerousArgs.join(', ')}`
          : 'Docker 命令可以创建/删除/修改容器',
        suggestion: '限制 Docker 操作为只读（如 docker ps, docker logs），禁止 exec/rm/stop。',
      };
    },
  },

  {
    id: 'MCP-025',
    severity: 'LOW',
    title: 'MCP 工具名称冲突检测',
    description: '检查是否有相同名称的 MCP 服务器',
    check(server) {
      // This is a meta-rule — handled at scan level, not per-server
      return null; // Skipped at per-server level, handled in scanner
    },
  },
];
export const RULE_COUNT = RULES.length;
