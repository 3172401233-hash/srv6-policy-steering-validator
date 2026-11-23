import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validatePath, encapOverhead } from '../src/validator.js';

const baseInput = () => ({
  segmentList: ['fc00:1::a', 'fc00:2::b', 'fc00:3::c'],
  behaviors: {
    'fc00:1::a': { node: 'N1', type: 'End.X', nextHop: 'N2' },
    'fc00:2::b': { node: 'N2', type: 'End.X', nextHop: 'N3' },
    'fc00:3::c': { node: 'N3', type: 'End.DT4', vrf: 'RED' },
  },
  adjacency: { N1: ['N2'], N2: ['N3'], N3: [] },
  vrfs: { N3: ['RED', 'BLUE'] },
  encap: { type: 'H.Encaps.Red', packetSize: 1400 },
  mtu: 1500,
  returnPolicy: { symmetric: true, path: ['N3', 'N2', 'N1'] },
  packetDst: '10.0.0.1',
  vrf: 'RED',
});

test('完整路径:End.X 链 + End.DT4 解封装,全部通过', () => {
  const report = validatePath(baseInput());
  assert.equal(report.ok, true);
  assert.equal(report.failures.length, 0);
  assert.equal(report.hops.length, 3);
  assert.deepEqual(
    report.hops.map((hop) => hop.behavior),
    ['End.X', 'End.X', 'End.DT4'],
  );
  assert.deepEqual(report.hops.map((hop) => hop.slBefore), [2, 1, 0]);
  assert.equal(report.hops[0].nextHop, 'N2');
  assert.equal(report.hops[2].encapsulated, false);
  assert.deepEqual(report.forwardNodes, ['N1', 'N2', 'N3']);
  assert.equal(report.repairOrder.length, 0);
});

test('End:策略中段命中普通 End,失去转发语义', () => {
  const input = baseInput();
  input.behaviors['fc00:2::b'] = { node: 'N2', type: 'End' };
  const report = validatePath(input);
  assert.equal(report.ok, false);
  const failure = report.failures.find((f) => f.code === 'LOST_FORWARDING_SEMANTICS');
  assert.ok(failure);
  assert.equal(failure.node, 'N2');
  assert.equal(report.failureNode, 'N2');
  assert.equal(report.hops[1].status, 'failed');
  assert.equal(report.repairOrder[0].code, 'LOST_FORWARDING_SEMANTICS');
});

test('End.X:邻接表缺少下一跳时报 ADJACENCY_MISSING', () => {
  const input = baseInput();
  input.adjacency.N1 = ['N9'];
  const report = validatePath(input);
  assert.equal(report.ok, false);
  const failure = report.failures.find((f) => f.code === 'ADJACENCY_MISSING');
  assert.ok(failure);
  assert.equal(failure.node, 'N1');
  assert.equal(report.hops[0].nextHop, 'N2');
});

test('End.DT4:使用节点上未配置的 VRF 时报 END_DT_WRONG_VRF', () => {
  const input = baseInput();
  input.behaviors['fc00:3::c'] = { node: 'N3', type: 'End.DT4', vrf: 'GREEN' };
  const report = validatePath(input);
  assert.equal(report.ok, false);
  const failure = report.failures.find((f) => f.code === 'END_DT_WRONG_VRF');
  assert.ok(failure);
  assert.equal(failure.node, 'N3');
});

test('End.DT4:IPv6 报文目的地址与 DT4 地址族不匹配', () => {
  const input = baseInput();
  input.packetDst = '2001:db8::1';
  const report = validatePath(input);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.code === 'END_DT_WRONG_VRF'));
});

test('uSID:容器剩余槽位全零但段列表未耗尽,报 USID_MISALIGNMENT', () => {
  const input = baseInput();
  input.segmentList = ['fc00:a001::', 'fc00:a001:0001::'];
  input.behaviors = {
    'fc00:a001::': { node: 'N1', type: 'End.uSID', usidBlock: 'fc00:a001:' },
    'fc00:a001:0001::': { node: 'N2', type: 'End.uSID', usidBlock: 'fc00:a001:' },
  };
  input.returnPolicy = { symmetric: true, path: ['N2', 'N1'] };
  const report = validatePath(input);
  assert.equal(report.ok, false);
  const failure = report.failures.find((f) => f.code === 'USID_MISALIGNMENT');
  assert.ok(failure);
  assert.equal(failure.node, 'N1');
});

test('uSID:块前缀不匹配同样报 USID_MISALIGNMENT', () => {
  const input = baseInput();
  input.segmentList = ['fc00:b002:0001::'];
  input.behaviors = {
    'fc00:b002:0001::': { node: 'N1', type: 'End.uSID', usidBlock: 'fc00:a001:' },
  };
  input.returnPolicy = { symmetric: true, path: ['N1'] };
  const report = validatePath(input);
  assert.ok(report.failures.some((f) => f.code === 'USID_MISALIGNMENT'));
});

test('回程:路径不经过对称策略时报 ASYMMETRIC_RETURN', () => {
  const input = baseInput();
  input.returnPolicy = { symmetric: true, path: ['N3', 'N1'] };
  const report = validatePath(input);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.code === 'ASYMMETRIC_RETURN'));
});

test('回程:对称路径与去程镜像一致时通过', () => {
  const report = validatePath(baseInput());
  assert.ok(!report.failures.some((f) => f.code === 'ASYMMETRIC_RETURN'));
});

test('MTU 丢失:未配置 MTU 时报 MTU_NOT_CONFIGURED', () => {
  const input = baseInput();
  delete input.mtu;
  const report = validatePath(input);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.code === 'MTU_NOT_CONFIGURED'));
  assert.equal(report.mtu.configured, false);
});

test('MTU 不足:封装开销挤压报文空间时报 MTU_EXCEEDED', () => {
  const input = baseInput();
  input.mtu = 1440;
  const report = validatePath(input);
  assert.equal(report.ok, false);
  const failure = report.failures.find((f) => f.code === 'MTU_EXCEEDED');
  assert.ok(failure);
  assert.equal(report.mtu.overheadBytes, encapOverhead('H.Encaps.Red', 3));
});

test('未知行为:SID 未注册时报 UNKNOWN_BEHAVIOR 并停止推演', () => {
  const input = baseInput();
  delete input.behaviors['fc00:2::b'];
  const report = validatePath(input);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.code === 'UNKNOWN_BEHAVIOR'));
  assert.equal(report.hops.length, 2);
});

test('段列表递归:绑定 SID 循环引用报 SEGMENT_LIST_RECURSION', () => {
  const input = baseInput();
  input.behaviors['fc00:9::x'] = { node: 'N9', type: 'End.B6', segmentList: ['fc00:9::y'] };
  input.behaviors['fc00:9::y'] = { node: 'N9', type: 'End.B6', segmentList: ['fc00:9::x'] };
  const report = validatePath(input);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((f) => f.code === 'SEGMENT_LIST_RECURSION'));
});

test('修复顺序:未知行为优先于 VRF 与回程修复', () => {
  const input = baseInput();
  input.behaviors['fc00:2::b'] = { node: 'N2', type: 'End' };
  input.behaviors['fc00:3::c'] = { node: 'N3', type: 'End.DT4', vrf: 'GREEN' };
  input.returnPolicy = { symmetric: true, path: ['N3', 'N1'] };
  const report = validatePath(input);
  const codes = report.repairOrder.map((step) => step.code);
  assert.deepEqual(codes, ['LOST_FORWARDING_SEMANTICS', 'END_DT_WRONG_VRF', 'ASYMMETRIC_RETURN']);
  assert.ok(report.repairOrder.every((step, i) => step.order === i + 1));
});
