#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { validatePath } from './validator.js';

const usage = `用法: node src/cli.js <input.json>

输入 JSON 字段:
  segmentList   段列表(执行顺序)
  behaviors     SID -> { node, type, nextHop?, vrf?, usidBlock?, segmentList? }
  adjacency     节点 -> 邻居列表
  vrfs          节点 -> VRF 列表
  encap         { type: H.Encaps|H.Encaps.Red|H.Insert|H.Insert.Red, packetSize? }
  mtu           路径 MTU
  returnPolicy  { symmetric, path }
  packetDst     内层报文目的地址
  vrf           期望解封装 VRF
`;

const file = process.argv[2];
if (!file) {
  process.stderr.write(usage);
  process.exit(2);
}

const input = JSON.parse(await readFile(file, 'utf8'));
const report = validatePath(input);

console.log('=== 逐跳推演 ===');
for (const hop of report.hops) {
  console.log(
    [
      `hop=${hop.hop}`,
      `node=${hop.node ?? '-'}`,
      `sid=${hop.sid}`,
      `SL=${hop.slBefore}->${hop.slAfter ?? '-'}`,
      `behavior=${hop.behavior ?? '未知'}`,
      `nextHop=${hop.nextHop ?? '-'}`,
      `encap=${hop.encapsulated ? '封装中' : '已解封装'}`,
      `segmentsLeft=[${hop.segmentsLeft.join(', ')}]`,
      hop.status === 'failed' ? 'STATUS=FAILED' : '',
    ]
      .filter(Boolean)
      .join(' '),
  );
}

console.log('\n=== 结论 ===');
console.log(`ok=${report.ok} failureNode=${report.failureNode ?? '-'}`);
for (const failure of report.failures) {
  console.log(`[${failure.code}] node=${failure.node ?? '-'} sid=${failure.sid ?? '-'} ${failure.message}`);
}

if (report.repairOrder.length > 0) {
  console.log('\n=== 修复顺序 ===');
  for (const step of report.repairOrder) {
    console.log(`${step.order}. [${step.code}] ${step.action}`);
  }
}

process.exit(report.ok ? 0 : 1);
