/**
 * SRv6 路径校验器(控制面仿真)。
 *
 * 输入段列表、节点行为、邻接表、VRF、封装类型、MTU、回程策略与报文目的地址,
 * 逐跳计算剩余段列表、SL、下一跳与封装状态,识别:
 *   - 未知行为(UNKNOWN_BEHAVIOR)
 *   - 段列表递归(SEGMENT_LIST_RECURSION)
 *   - uSID 错位(USID_MISALIGNMENT)
 *   - MTU 不足 / 丢失(MTU_EXCEEDED / MTU_NOT_CONFIGURED)
 *   - End.DT 使用错误 VRF(END_DT_WRONG_VRF)
 *   - 回程不经过对称策略(ASYMMETRIC_RETURN)
 *   - 中途丢失转发语义(LOST_FORWARDING_SEMANTICS,普通 End 出现在策略中段)
 *
 * 本模块只做控制面推演,不生成真实 IPv6 报文。
 */

export const IPV6_HEADER_BYTES = 40;
export const SRH_BASE_BYTES = 8;
export const SRH_SEGMENT_BYTES = 16;

export const FAILURE_PRIORITY = Object.freeze({
  UNKNOWN_BEHAVIOR: 10,
  LOST_FORWARDING_SEMANTICS: 20,
  SEGMENT_LIST_RECURSION: 30,
  USID_MISALIGNMENT: 40,
  ADJACENCY_MISSING: 50,
  DECAP_TOO_EARLY: 55,
  END_DT_WRONG_VRF: 60,
  MTU_NOT_CONFIGURED: 70,
  MTU_EXCEEDED: 71,
  ASYMMETRIC_RETURN: 80,
});

const REPAIR_ACTIONS = Object.freeze({
  UNKNOWN_BEHAVIOR: '在控制面为该 SID 注册行为(End.X / End.DT* / End.uSID),或从段列表移除',
  LOST_FORWARDING_SEMANTICS: '将中段 SID 的普通 End 改为 End.X(或带 PSP/USP 的 uSID 行为),恢复转发语义',
  SEGMENT_LIST_RECURSION: '解除绑定 SID 之间的循环引用,确保段列表展开后无环',
  USID_MISALIGNMENT: '对齐 uSID 容器与节点 uSID 块前缀,保证移位后活动 uSID 非零',
  ADJACENCY_MISSING: '在邻接表中补充 End.X 指向的下一跳邻接',
  DECAP_TOO_EARLY: '仅在段列表末尾(SL=0)使用 End.DT 解封装行为',
  END_DT_WRONG_VRF: '将 End.DT 绑定到节点上存在的 VRF,并匹配报文地址族',
  MTU_NOT_CONFIGURED: '为路径配置 MTU 后再校验封装开销',
  MTU_EXCEEDED: '增大路径 MTU、改用 H.Encaps.Red 或减少段列表长度',
  ASYMMETRIC_RETURN: '为回程流量部署与去程镜像的对称 SRv6 策略',
});

const ENCAP_MODES = new Set(['H.Encaps', 'H.Encaps.Red', 'H.Insert', 'H.Insert.Red']);

function fail(failures, code, node, sid, message) {
  failures.push({ code, node: node ?? null, sid: sid ?? null, message });
}

/** 计算封装开销(外层 IPv6 头 + SRH)。 */
export function encapOverhead(encapType, segmentCount) {
  const reduced = encapType.endsWith('.Red') ? 1 : 0;
  const srhBytes = SRH_BASE_BYTES + SRH_SEGMENT_BYTES * Math.max(segmentCount - reduced, 0);
  return IPV6_HEADER_BYTES + srhBytes;
}

/** 检测绑定 SID(End.B6 等)之间的段列表循环引用。 */
function detectBindingRecursion(behaviors) {
  const cycles = [];
  const visiting = new Set();
  const done = new Set();

  const dfs = (sid, trail) => {
    if (done.has(sid)) return;
    if (visiting.has(sid)) {
      cycles.push([...trail.slice(trail.indexOf(sid)), sid]);
      return;
    }
    const behavior = behaviors[sid];
    if (!behavior || !Array.isArray(behavior.segmentList)) {
      done.add(sid);
      return;
    }
    visiting.add(sid);
    trail.push(sid);
    for (const next of behavior.segmentList) dfs(next, trail);
    trail.pop();
    visiting.delete(sid);
    done.add(sid);
  };

  for (const sid of Object.keys(behaviors)) dfs(sid, []);
  return cycles;
}

/** 判断 uSID 容器中块前缀之后的剩余 uSID 槽位是否全零。 */
function usidRemainderIsZero(sid, block) {
  const rest = sid.slice(block.length);
  return rest
    .split(':')
    .filter((part) => part.length > 0)
    .every((part) => /^0+$/.test(part));
}

function isIPv4(address) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(address);
}

/**
 * 主入口:校验一条 SRv6 策略路径。
 *
 * @param {object} input
 * @param {string[]} input.segmentList  段列表,按执行顺序排列(第一个元素最先执行)
 * @param {Object<string, object>} input.behaviors  SID -> 行为定义
 * @param {Object<string, string[]>} input.adjacency  节点 -> 邻居节点列表
 * @param {Object<string, string[]>} input.vrfs  节点 -> 已配置 VRF 列表
 * @param {{type: string, packetSize?: number}} input.encap  封装类型与报文大小
 * @param {number} [input.mtu]  路径 MTU
 * @param {{symmetric?: boolean, path?: string[]}} [input.returnPolicy]  回程策略
 * @param {string} input.packetDst  内层报文目的地址
 * @param {string} [input.vrf]  期望解封装进入的 VRF
 */
export function validatePath(input) {
  const failures = [];
  const hops = [];

  const segmentList = [...(input.segmentList ?? [])];
  const behaviors = input.behaviors ?? {};
  const adjacency = input.adjacency ?? {};
  const vrfs = input.vrfs ?? {};
  const encap = input.encap ?? { type: 'H.Encaps.Red' };
  const packetDst = input.packetDst ?? '';

  if (!ENCAP_MODES.has(encap.type)) {
    fail(failures, 'UNKNOWN_BEHAVIOR', null, null, `未知封装类型: ${encap.type}`);
  }

  // MTU 检查(头端一次性计算)
  const overhead = encapOverhead(encap.type, segmentList.length);
  const packetSize = encap.packetSize ?? 1280;
  let mtuState = { configured: false, overheadBytes: overhead, headroomBytes: null };
  if (input.mtu == null) {
    fail(failures, 'MTU_NOT_CONFIGURED', null, null, '路径未配置 MTU,无法校验封装开销');
  } else {
    const headroom = input.mtu - overhead;
    mtuState = { configured: true, overheadBytes: overhead, headroomBytes: headroom, mtu: input.mtu };
    if (packetSize > headroom) {
      fail(
        failures,
        'MTU_EXCEEDED',
        null,
        null,
        `报文 ${packetSize}B 超过封装后剩余空间 ${headroom}B(MTU ${input.mtu}B,开销 ${overhead}B)`,
      );
    }
  }

  // 段列表递归(绑定 SID 循环)
  for (const cycle of detectBindingRecursion(behaviors)) {
    fail(
      failures,
      'SEGMENT_LIST_RECURSION',
      behaviors[cycle[0]]?.node ?? null,
      cycle[0],
      `绑定 SID 段列表存在循环: ${cycle.join(' -> ')}`,
    );
  }

  // SRH 中段列表逆序存放,SL 指向活动段;首跳活动 SID 为执行顺序的第一个
  const segLeft = [...segmentList].reverse();
  let sl = segLeft.length - 1;
  let encapsulated = encap.type.startsWith('H.Encaps');
  const forwardNodes = [];
  const visited = new Set();
  const maxSteps = segmentList.length * 4 + 16;

  let steps = 0;
  let stop = false;
  while (sl >= 0 && !stop) {
    steps += 1;
    const sid = segLeft[sl];
    const stateKey = `${sid}|${sl}|${segLeft.join(',')}`;
    if (visited.has(stateKey) || steps > maxSteps) {
      fail(failures, 'SEGMENT_LIST_RECURSION', null, sid, `状态 ${stateKey} 重复出现,段列表递归`);
      break;
    }
    visited.add(stateKey);

    const behavior = behaviors[sid];
    const hop = {
      hop: hops.length + 1,
      sid,
      slBefore: sl,
      segmentsLeft: [...segLeft],
      behavior: behavior?.type ?? null,
      node: behavior?.node ?? null,
      nextHop: null,
      encapsulated,
      status: 'ok',
    };

    if (!behavior) {
      fail(failures, 'UNKNOWN_BEHAVIOR', null, sid, `SID ${sid} 未注册任何行为`);
      hop.status = 'failed';
      hops.push(hop);
      break;
    }

    forwardNodes.push(behavior.node);
    const markFailed = () => {
      hop.status = 'failed';
    };

    switch (behavior.type) {
      case 'End': {
        if (sl > 0) {
          fail(
            failures,
            'LOST_FORWARDING_SEMANTICS',
            behavior.node,
            sid,
            `SID ${sid} 在策略中段命中普通 End,期望 End.X/End.DT*,报文失去转发语义`,
          );
          markFailed();
        }
        sl -= 1;
        break;
      }
      case 'End.X': {
        const nextHop = behavior.nextHop ?? null;
        hop.nextHop = nextHop;
        const neighbors = adjacency[behavior.node] ?? [];
        if (!nextHop || !neighbors.includes(nextHop)) {
          fail(
            failures,
            'ADJACENCY_MISSING',
            behavior.node,
            sid,
            `节点 ${behavior.node} 的邻接表中不存在下一跳 ${nextHop}`,
          );
          markFailed();
        }
        sl -= 1;
        break;
      }
      case 'End.DT4':
      case 'End.DT6': {
        if (sl !== 0) {
          fail(
            failures,
            'DECAP_TOO_EARLY',
            behavior.node,
            sid,
            `End.DT 在 SL=${sl} 处解封装,期望 SL=0`,
          );
          markFailed();
        }
        const vrf = behavior.vrf ?? input.vrf;
        const nodeVrfs = vrfs[behavior.node] ?? [];
        if (!vrf || !nodeVrfs.includes(vrf)) {
          fail(
            failures,
            'END_DT_WRONG_VRF',
            behavior.node,
            sid,
            `End.DT 使用 VRF ${vrf ?? '(未指定)'},但节点 ${behavior.node} 仅配置 [${nodeVrfs.join(', ')}]`,
          );
          markFailed();
        }
        const wantsV4 = behavior.type === 'End.DT4';
        if (packetDst && isIPv4(packetDst) !== wantsV4) {
          fail(
            failures,
            'END_DT_WRONG_VRF',
            behavior.node,
            sid,
            `${behavior.type} 与报文目的地址族不匹配(${packetDst})`,
          );
          markFailed();
        }
        encapsulated = false;
        sl -= 1;
        break;
      }
      case 'End.uSID': {
        const block = behavior.usidBlock ?? '';
        if (!sid.startsWith(block)) {
          fail(
            failures,
            'USID_MISALIGNMENT',
            behavior.node,
            sid,
            `SID ${sid} 不在节点 uSID 块 ${block} 内,发生错位`,
          );
          markFailed();
        } else if (sl > 0 && usidRemainderIsZero(sid, block)) {
          fail(
            failures,
            'USID_MISALIGNMENT',
            behavior.node,
            sid,
            `SID ${sid} 移位后活动 uSID 为 0,但段列表仍有 ${sl} 个剩余段`,
          );
          markFailed();
        }
        sl -= 1;
        break;
      }
      default: {
        fail(
          failures,
          'UNKNOWN_BEHAVIOR',
          behavior.node,
          sid,
          `SID ${sid} 的行为类型 ${behavior.type} 不受支持`,
        );
        markFailed();
        stop = true;
      }
    }

    hop.slAfter = Math.max(sl, 0);
    hop.encapsulated = encapsulated;
    hops.push(hop);
  }

  // 回程对称性检查
  const rp = input.returnPolicy;
  if (rp && rp.symmetric !== false) {
    const expected = [...forwardNodes].reverse();
    const actual = rp.path;
    const symmetric =
      Array.isArray(actual) &&
      actual.length === expected.length &&
      actual.every((node, index) => node === expected[index]);
    if (!symmetric) {
      fail(
        failures,
        'ASYMMETRIC_RETURN',
        null,
        null,
        `回程路径 [${(actual ?? []).join(' -> ')}] 与去程镜像 [${expected.join(' -> ')}] 不一致`,
      );
    }
  }

  const repairOrder = [...failures]
    .sort((a, b) => (FAILURE_PRIORITY[a.code] ?? 99) - (FAILURE_PRIORITY[b.code] ?? 99))
    .map((failure, index) => ({
      order: index + 1,
      code: failure.code,
      node: failure.node,
      sid: failure.sid,
      action: REPAIR_ACTIONS[failure.code] ?? '人工检查',
    }));

  return {
    ok: failures.length === 0,
    failureNode: failures.find((failure) => failure.node)?.node ?? null,
    hops,
    failures,
    repairOrder,
    mtu: mtuState,
    forwardNodes,
  };
}
