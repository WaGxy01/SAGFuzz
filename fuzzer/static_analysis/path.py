#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
path.py - 静态路径分析模块

基于 rCFG 构建的控制流图进行静态分析：
1. 找到包含 CALL/TIMESTAMP/NUMBER/DELEGATECALL/SELFDESTRUCT 的关键基本块
2. 反向遍历 CFG 获取到达关键基本块的路径
3. 从路径中提取函数签名（PUSH4 + EQ 模式）
4. 模拟执行获取 SLOAD 读取的存储槽号（排除含 SHA3 的块）
5. 输出与模糊测试 data_dependencies 格式兼容的字典

输出格式：
{
    "0x27e235e3": {"read": {0, 1}, "write": set()},
    "0x2e1a7d4d": {"read": {0}, "write": set()},
    ...
}
"""

from typing import Dict, Set, List, Tuple, Optional, Any
from collections import deque

# 导入 CFG 相关模块
from static_analysis.cfg.disassembly import generate_BBs
from static_analysis.cfg.cfg import CFG
from static_analysis.cfg.opcodes import opcodes


class PathAnalyzer:
    """
    路径分析器：基于 CFG 提取静态数据依赖
    """

    # 关键指令集（用于定义漏洞相关的关键基本块）
    CRITICAL_OPS = {'CALL', 'TIMESTAMP', 'NUMBER', 'DELEGATECALL', 'SELFDESTRUCT'}

    def __init__(self, bytecode: str):
        """
        初始化分析器

        Args:
            bytecode: 合约字节码（十六进制字符串）
        """
        self.bytecode = bytecode.replace("0x", "")
        self.code = bytes.fromhex(self.bytecode)
        self.cfg = None
        self._build_cfg()

    def _build_cfg(self) -> None:
        """构建控制流图"""
        bbs = list(generate_BBs(self.code))
        self.cfg = CFG(bbs, fix_xrefs=True)

    def _find_critical_blocks(self) -> List:
        """
        查找关键基本块

        Returns:
            包含关键指令的基本块列表
        """
        critical_bbs = []
        for bb in self.cfg.bbs:
            for ins in bb.ins:
                if ins.name in self.CRITICAL_OPS:
                    critical_bbs.append(bb)
                    break
        return critical_bbs

    def _backward_traverse(self, target_bb) -> List[List]:
        """
        反向遍历：从入口到目标块的所有路径

        Args:
            target_bb: 目标基本块

        Returns:
            路径列表（每条路径是基本块列表）
        """
        all_paths = []

        def dfs(current_bb, path, visited):
            path.append(current_bb)

            if current_bb == target_bb:
                all_paths.append(path.copy())
            else:
                for succ in current_bb.succ:
                    if succ not in visited:
                        visited.add(succ)
                        dfs(succ, path, visited)
                        visited.remove(succ)

            path.pop()

        # 从根节点开始
        root = self.cfg._bb_at.get(0)
        if root:
            visited = {root}
            dfs(root, [], visited)

        return all_paths

    def _get_critical_paths(self) -> List[List]:
        """
        获取所有到达关键块的路径

        Returns:
            路径列表
        """
        critical_bbs = self._find_critical_blocks()
        all_paths = []

        for critical_bb in critical_bbs:
            paths = self._backward_traverse(critical_bb)
            all_paths.extend(paths)

        return all_paths

    def _extract_func_sig(self, path: List) -> Optional[str]:
        """
        从路径中提取函数签名

        条件：
        - PUSH4 的参数不为 ffffffff
        - PUSH4 后有 EQ 指令
        - 路径中 PUSH4 所在块的下一个块是从该块**跳转**得到的（不是顺序执行）

        函数选择器模式：PUSH4 sig -> EQ -> PUSH2 dest -> JUMPI
        当签名匹配时，JUMPI 跳转到目标地址（函数入口）

        Args:
            path: 基本块路径

        Returns:
            "0x" + 函数签名，或 None
        """
        for i, bb in enumerate(path):
            instructions = bb.ins

            for j, ins in enumerate(instructions):
                # 查找 PUSH4
                if ins.name == 'PUSH4' and ins.arg is not None:
                    sig_hex = ins.arg.hex()

                    # 排除 ffffffff
                    if sig_hex.lower() == 'ffffffff':
                        continue

                    # 检查后续是否有 EQ 指令
                    has_eq = False
                    for k in range(j + 1, min(j + 3, len(instructions))):
                        if instructions[k].name == 'EQ':
                            has_eq = True
                            break

                    if not has_eq:
                        continue

                    # 检查路径中下一个块是否是当前块的**跳转目标**
                    # 而不是顺序执行（fall-through）
                    if i + 1 < len(path):
                        next_bb_in_path = path[i + 1]

                        # 检查当前块是否以 JUMPI 结束
                        last_ins = instructions[-1]
                        if last_ins.name == 'JUMPI':
                            # JUMPI 的跳转目标通常由之前的 PUSH 指令给出
                            # 查找 JUMPI 前面的 PUSH 指令获取跳转目标
                            jump_target = None
                            for k in range(len(instructions) - 2, -1, -1):
                                if instructions[k].name.startswith('PUSH') and instructions[k].arg is not None:
                                    jump_target = int.from_bytes(instructions[k].arg, byteorder='big')
                                    break

                            # 只有当路径中下一个块是跳转目标时，才认为签名匹配
                            if jump_target is not None and next_bb_in_path.start == jump_target:
                                return f"0x{sig_hex}"

                        # 如果不是 JUMPI 结束但 next_bb 在 succ 中，也可能是其他跳转
                        elif last_ins.name == 'JUMP':
                            if next_bb_in_path in bb.succ:
                                return f"0x{sig_hex}"

        return None

    def _has_sha3(self, bb) -> bool:
        """检查块是否包含 SHA3/KECCAK256"""
        return any(ins.name in ('SHA3', 'KECCAK256') for ins in bb.ins)

    def _simulate_for_sload(self, bb) -> Set[int]:
        """
        模拟执行基本块，提取 SLOAD 的存储槽号

        如果块中存在 SHA3，则放弃该 SLOAD，继续查找

        Args:
            bb: 基本块

        Returns:
            存储槽号集合
        """
        # 如果存在 SHA3，放弃这个块
        if self._has_sha3(bb):
            return set()

        slots = set()
        stack = []

        for ins in bb.ins:
            op = ins.op
            name = ins.name

            if name == 'SLOAD':
                # SLOAD 从栈顶取存储槽号
                if stack and isinstance(stack[-1], int):
                    slots.add(stack[-1])
                # 栈操作：弹1压1
                if stack:
                    stack.pop()
                stack.append('SLOAD_VAL')

            elif name == 'PUSH0':
                stack.append(0)

            elif name.startswith('PUSH') and len(name) > 4:
                # PUSH1-PUSH32
                if ins.arg is not None:
                    val = int.from_bytes(ins.arg, byteorder='big')
                    stack.append(val)
                else:
                    stack.append(0)

            elif name.startswith('DUP'):
                try:
                    n = int(name[3:])
                    if len(stack) >= n:
                        stack.append(stack[-n])
                    else:
                        stack.append('UNK')
                except ValueError:
                    stack.append('UNK')

            elif name.startswith('SWAP'):
                try:
                    n = int(name[4:])
                    if len(stack) > n:
                        stack[-1], stack[-(n + 1)] = stack[-(n + 1)], stack[-1]
                except (ValueError, IndexError):
                    pass

            elif name == 'POP':
                if stack:
                    stack.pop()

            elif name == 'ADD':
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    if isinstance(a, int) and isinstance(b, int):
                        stack.append(a + b)
                    else:
                        stack.append('ADD_R')
                else:
                    stack.append('ADD_R')

            elif name == 'MUL':
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    if isinstance(a, int) and isinstance(b, int):
                        stack.append(a * b)
                    else:
                        stack.append('MUL_R')
                else:
                    stack.append('MUL_R')

            elif name == 'AND':
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    if isinstance(a, int) and isinstance(b, int):
                        stack.append(a & b)
                    else:
                        stack.append('AND_R')
                else:
                    stack.append('AND_R')

            elif name == 'OR':
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    if isinstance(a, int) and isinstance(b, int):
                        stack.append(a | b)
                    else:
                        stack.append('OR_R')
                else:
                    stack.append('OR_R')

            elif name == 'XOR':
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    if isinstance(a, int) and isinstance(b, int):
                        stack.append(a ^ b)
                    else:
                        stack.append('XOR_R')
                else:
                    stack.append('XOR_R')

            elif name == 'NOT':
                if stack:
                    a = stack.pop()
                    if isinstance(a, int):
                        stack.append((1 << 256) - 1 - a)
                    else:
                        stack.append('NOT_R')
                else:
                    stack.append('NOT_R')

            elif name == 'SHL':
                if len(stack) >= 2:
                    shift, val = stack.pop(), stack.pop()
                    if isinstance(shift, int) and isinstance(val, int):
                        stack.append((val << shift) & ((1 << 256) - 1))
                    else:
                        stack.append('SHL_R')
                else:
                    stack.append('SHL_R')

            elif name == 'SHR':
                if len(stack) >= 2:
                    shift, val = stack.pop(), stack.pop()
                    if isinstance(shift, int) and isinstance(val, int):
                        stack.append(val >> shift)
                    else:
                        stack.append('SHR_R')
                else:
                    stack.append('SHR_R')

            else:
                # 其他指令：按 opcodes 表处理栈效果
                if op in opcodes:
                    ins_cnt = opcodes[op][1]  # 输入（弹出）
                    out_cnt = opcodes[op][2]  # 输出（压入）

                    for _ in range(min(ins_cnt, len(stack))):
                        stack.pop()

                    for _ in range(out_cnt):
                        stack.append(f'{name}_R')

        return slots

    def _extract_sload_slots(self, path: List) -> Set[int]:
        """
        从路径中提取所有 SLOAD 存储槽

        Args:
            path: 基本块路径

        Returns:
            存储槽号集合
        """
        all_slots = set()

        for bb in path:
            # 检查是否有 SLOAD
            if not any(ins.name == 'SLOAD' for ins in bb.ins):
                continue

            # 如果有 SHA3 则跳过该块
            if self._has_sha3(bb):
                continue

            # 模拟执行获取槽号
            slots = self._simulate_for_sload(bb)
            all_slots.update(slots)

        return all_slots

    def analyze(self) -> Dict[str, Dict[str, Set[int]]]:
        """
        主分析入口

        Returns:
            静态依赖字典：
            {
                "0x函数签名": {"read": {槽号集合}, "write": set()},
                ...
            }
        """
        paths = self._get_critical_paths()

        # 聚合结果
        deps: Dict[str, Set[int]] = {}

        for path in paths:
            func_sig = self._extract_func_sig(path)
            if func_sig is None:
                continue

            slots = self._extract_sload_slots(path)

            # 相同函数签名取并集
            if func_sig in deps:
                deps[func_sig].update(slots)
            else:
                deps[func_sig] = slots.copy()

        # 转换为最终格式
        static_dependencies = {}
        for func_sig, slots in deps.items():
            static_dependencies[func_sig] = {
                "read": slots,
                "write": set()  # write 未分析，保持为空
            }

        return static_dependencies

    def analyze_verbose(self) -> Tuple[Dict[str, Dict[str, Set[int]]], Dict[str, Any]]:
        """
        详细分析，返回额外信息

        Returns:
            (static_dependencies, analysis_info)
        """
        paths = self._get_critical_paths()

        deps: Dict[str, Set[int]] = {}
        path_details = []

        for path in paths:
            func_sig = self._extract_func_sig(path)
            slots = self._extract_sload_slots(path)

            # 收集关键指令信息
            critical = []
            for bb in path:
                for ins in bb.ins:
                    if ins.name in self.CRITICAL_OPS:
                        critical.append({'name': ins.name, 'addr': hex(ins.addr)})

            path_details.append({
                'function': func_sig,
                'slots': list(slots),
                'blocks': [hex(bb.start) for bb in path],
                'critical': critical
            })

            if func_sig:
                if func_sig in deps:
                    deps[func_sig].update(slots)
                else:
                    deps[func_sig] = slots.copy()

        static_dependencies = {}
        for func_sig, slots in deps.items():
            static_dependencies[func_sig] = {
                "read": slots,
                "write": set()
            }

        analysis_info = {
            'total_critical_blocks': len(self._find_critical_blocks()),
            'total_paths': len(paths),
            'path_details': path_details
        }

        return static_dependencies, analysis_info


def extract_static_dependencies(bytecode: str) -> Dict[str, Dict[str, Set[int]]]:
    """
    便捷函数：提取静态依赖

    Args:
        bytecode: 合约字节码

    Returns:
        静态依赖字典
    """
    analyzer = PathAnalyzer(bytecode)
    return analyzer.analyze()


# 测试代码
if __name__ == "__main__":
    # 测试字节码 - 简单的带有 CALL 指令的合约
    test_code = (
        "6080604052600436106100345760003560e01c80632e1a7d4d14610039578063b6b55f2514610074578063b9d77bfc146100a2575b600080fd5b34801561004557600080fd5b506100726004803603602081101561005c57600080fd5b81019080803590602001909291905050506100e7565b005b6100a06004803603602081101561008a57600080fd5b8101908080359060200190929190505050610277565b005b3480156100ae57600080fd5b506100e5600480360360408110156100c557600080fd5b8101908080359060200190929190803590602001909291905050506102d3565b005b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101561013257600080fd5b601e60015411801561014657506028600154105b801561015457506001600254145b1561021e5760003373ffffffffffffffffffffffffffffffffffffffff168260405180600001905060006040518083038185875af1925050503d80600081146101b9576040519150601f19603f3d011682016040523d82523d6000602084013e6101be565b606091505b50509050806101cc57600080fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555050610274565b7f92873d130824b495f22ad10f7f14028200557770e5986714318e78c54f3aa83c3382604051808373ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019250505060405180910390a15b50565b8034101561028457600080fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254019250508190555050565b8160018190555080600281905550505056fea26469706673582212207da4b65949037795ae503af285b88c147198007dc41a45296101e24f6956559664736f6c63430007000033"

    )

    print("=" * 60)
    print("静态依赖分析测试")
    print("=" * 60)

    try:
        analyzer = PathAnalyzer(test_code)

        # 查找关键块
        critical_bbs = analyzer._find_critical_blocks()
        print(f"\n关键基本块数量: {len(critical_bbs)}")
        for bb in critical_bbs:
            ops = [ins.name for ins in bb.ins if ins.name in analyzer.CRITICAL_OPS]
            print(f"  0x{bb.start:x}: {ops}")

        # 完整分析
        deps, info = analyzer.analyze_verbose()

        print(f"\n分析结果:")
        print(f"  总路径数: {info['total_paths']}")

        print(f"\n静态依赖 (static_dependencies):")
        if deps:
            for sig, d in sorted(deps.items()):
                read = sorted(d['read']) if d['read'] else []
                print(f"  {sig}: read={read}, write=[]")
        else:
            print("  未找到依赖")

        print("\n" + "=" * 60)

    except Exception as e:
        print(f"错误: {e}")
        import traceback

        traceback.print_exc()