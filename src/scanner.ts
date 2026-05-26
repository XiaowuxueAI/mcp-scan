import { discoverConfigs, McpConfig, McpServerConfig } from './discovery';
import { runAllRules, Finding, Severity } from './rules';

export interface ScanResult {
  configCount: number;
  serverCount: number;
  activeServerCount: number;
  findings: Finding[];
  configs: McpConfig[];
}

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEVERITY_SCORE: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0,
};

export function scan(): ScanResult {
  const configs = discoverConfigs();
  const allServers: { server: McpServerConfig; config: McpConfig }[] = [];

  for (const config of configs) {
    for (const server of config.servers) {
      allServers.push({ server, config });
    }
  }

  const findings: Finding[] = [];
  for (const { server } of allServers) {
    findings.push(...runAllRules(server));
  }

  findings.sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity);
    const bi = SEVERITY_ORDER.indexOf(b.severity);
    return ai - bi;
  });

  const activeCount = allServers.filter((s) => !s.server.disabled).length;

  return {
    configCount: configs.length,
    serverCount: allServers.length,
    activeServerCount: activeCount,
    findings,
    configs,
  };
}

export function calculateScore(findings: Finding[]): { score: number; max: number; grade: string } {
  const maxPerRule = 25;
  const maxTotal = maxPerRule * 6; // 6 critical+high rules = 150
  let score = maxTotal;

  for (const f of findings) {
    score -= SEVERITY_SCORE[f.severity];
  }

  score = Math.max(0, score);

  let grade: string;
  if (score >= 130) grade = 'A — 安全';
  else if (score >= 100) grade = 'B — 基本安全';
  else if (score >= 70) grade = 'C — 需要改进';
  else if (score >= 40) grade = 'D — 存在风险';
  else grade = 'F — 高危';

  return { score, max: maxTotal, grade };
}
