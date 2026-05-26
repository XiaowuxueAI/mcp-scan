#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { scan, calculateScore } from './scanner';
import { Severity } from './rules';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  CRITICAL: (s: string) => chalk.red.bold(s),
  HIGH: (s: string) => chalk.red(s),
  MEDIUM: (s: string) => chalk.yellow(s),
  LOW: (s: string) => chalk.blue(s),
  INFO: (s: string) => chalk.gray(s),
};

const SEVERITY_ICONS: Record<Severity, string> = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
  INFO: '⚪',
};

const program = new Command();

program
  .name('mcp-scan')
  .description('MCP安检 — MCP服务器安全扫描工具')
  .version('0.1.0')
  .option('--json', '以 JSON 格式输出结果')
  .option('--no-color', '禁用颜色输出')
  .parse(process.argv);

const options = program.opts();

function printBanner() {
  console.log('');
  console.log(chalk.cyan.bold('  ╔══════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('  ║          MCP 安检  v0.1.0           ║'));
  console.log(chalk.cyan.bold('  ║     MCP 服务器安全扫描工具            ║'));
  console.log(chalk.cyan.bold('  ╚══════════════════════════════════════╝'));
  console.log('');
}

function printSummary(result: ReturnType<typeof scan>) {
  const { score, max, grade } = calculateScore(result.findings);

  console.log(chalk.bold('📊 扫描概览'));
  console.log('━'.repeat(40));
  console.log(`  配置文件:  ${chalk.cyan(result.configCount)} 个`);
  console.log(`  MCP服务器: ${chalk.cyan(result.serverCount)} 个 (${chalk.green(result.activeServerCount)} 活跃)`);
  console.log(`  安全问题:  ${chalk.red(result.findings.filter(f => f.severity !== 'INFO').length)} 个`);
  console.log(`  安全评分:  ${chalk.cyan(score + '/' + max)} — ${chalk.bold(grade)}`);
  console.log('━'.repeat(40));
  console.log('');
}

function printFindings(result: ReturnType<typeof scan>) {
  if (result.findings.length === 0) {
    console.log(chalk.green('  ✅ 未发现安全问题！'));
    console.log('');
    return;
  }

  console.log(chalk.bold('🔍 安全问题详情'));
  console.log('━'.repeat(60));

  let lastSeverity = '';
  for (const finding of result.findings) {
    if (finding.severity !== lastSeverity) {
      lastSeverity = finding.severity;
      const label = SEVERITY_ICONS[finding.severity] + ' ' + finding.severity;
      console.log('');
      console.log(SEVERITY_COLORS[finding.severity](`  ${label}`));
    }

    console.log(`    [${chalk.dim(finding.ruleId)}] ${chalk.bold(finding.title)}`);
    console.log(`    服务器: ${chalk.cyan(finding.serverName)}`);
    console.log(`    描述: ${finding.description}`);
    console.log(`    详情: ${finding.detail}`);
    if (finding.suggestion) {
      console.log(`    建议: ${chalk.green(finding.suggestion)}`);
    }
    if (finding.owaspRef) {
      console.log(`    参考: ${chalk.dim(finding.owaspRef)}`);
    }
    console.log('');
  }
}

function printTips() {
  console.log(chalk.bold('💡 下一步建议'));
  console.log('━'.repeat(40));
  console.log('  1. 优先修复所有 CRITICAL 和 HIGH 级别问题');
  console.log('  2. 为远程 MCP 服务器添加认证');
  console.log('  3. 检查命令参数中是否有用户可控输入');
  console.log('  4. 将硬编码密钥移到环境变量或密钥管理工具');
  console.log('  5. 定期运行 mcp-scan 检查新增的 MCP 服务器');
  console.log('');
  console.log(chalk.dim('  项目地址: https://github.com/wubin28/mcp-scan'));
  console.log(chalk.dim('  反馈问题: https://github.com/wubin28/mcp-scan/issues'));
  console.log('');
}

function jsonOutput(result: ReturnType<typeof scan>) {
  const { score, max, grade } = calculateScore(result.findings);
  const output = {
    summary: {
      configCount: result.configCount,
      serverCount: result.serverCount,
      activeServerCount: result.activeServerCount,
      findingCount: result.findings.length,
      severityBreakdown: {
        critical: result.findings.filter((f) => f.severity === 'CRITICAL').length,
        high: result.findings.filter((f) => f.severity === 'HIGH').length,
        medium: result.findings.filter((f) => f.severity === 'MEDIUM').length,
        low: result.findings.filter((f) => f.severity === 'LOW').length,
        info: result.findings.filter((f) => f.severity === 'INFO').length,
      },
      score,
      max,
      grade,
    },
    configs: result.configs.map((c) => ({
      client: c.client,
      path: c.filePath,
      servers: c.servers.map((s) => ({ name: s.name, transport: s.transport, disabled: s.disabled })),
    })),
    findings: result.findings,
  };
  console.log(JSON.stringify(output, null, 2));
}

function main() {
  const result = scan();

  if (options.json) {
    jsonOutput(result);
    return;
  }

  printBanner();
  printSummary(result);
  printFindings(result);
  printTips();
}

main();
