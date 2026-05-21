#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reentrancy Attack Simulator (Fixed Version)
============================================
修复了三个导致误报的问题：
1. 候选识别阶段：过滤只有单个 withdraw 类函数的情况
2. 存储差异检查：验证重入时是否真的修改了关键状态
3. 余额变化验证：检查攻击者是否真的获利

核心逻辑：
  1. 静态分析找出"候选触发函数"——即能向外转 ETH 并可能调用接收方 fallback() 的函数
  2. 对每个候选触发函数，编译并部署一个 Agent 合约（内含 fallback 重入逻辑）
  3. 用 Agent 合约调用目标函数，观察是否真的发生了重入
  4. 重入发生后，检查是否存在"高调用层读到的状态变量，在低调用层被修改"的不一致
"""

import logging
from eth_utils import encode_hex, to_canonical_address, decode_hex
try:
    from utils.utils import initialize_logger
except ImportError:
    initialize_logger = None

# Agent 合约的 Solidity 源码模板
AGENT_CONTRACT_SOURCE = """
pragma solidity {solc_pragma};

contract AgentContract {
    address payable public target;
    bytes public reentrancy_data;
    bool public attacking;
    uint256 public reentry_count;

    constructor(address payable _target) payable {
        target = _target;
        attacking = false;
        reentry_count = 0;
    }

    function callPayable(bytes memory data) public payable {
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "callPayable failed");
    }

    function attack(bytes memory first_data, bytes memory _reentrancy_data) public payable {
        reentrancy_data = _reentrancy_data;
        attacking = true;
        reentry_count = 0;
        (bool success, ) = target.call{value: msg.value}(first_data);
        attacking = false;
    }

    fallback() external payable {
        if (attacking && reentry_count < 1) {
            reentry_count += 1;
            (bool success, ) = target.call(reentrancy_data);
        }
    }
}
"""


def _yellow(x):
    """黄色 ANSI 输出，用于"重入被保护/不可利用"结论。"""
    return "".join(['\033[93m', x, '\033[0m']) if isinstance(x, str) else x

def _blue(x):
    """蓝色 ANSI 输出，用于"无重入保护，漏洞确认"结论。"""
    return "".join(['\033[94m', x, '\033[0m']) if isinstance(x, str) else x


class ReentrancyAttackSimulator:
    """
    对单个 individual 执行完毕后，额外发起 Agent 合约重入攻击模拟。
    """

    def __init__(self, env):
        self.env = env
        if initialize_logger is not None:
            self.logger = initialize_logger("AgentSim")
        else:
            self.logger = logging.getLogger("AgentSim")
        if self.logger.level == 0 or self.logger.level > logging.INFO:
            self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            _h = logging.StreamHandler()
            _h.setLevel(logging.INFO)
            _h.setFormatter(logging.Formatter(
                "%(asctime)s - %(name)-8s - %(levelname)s - %(message)s"
            ))
            self.logger.addHandler(_h)
        self._agent_bytecode = None
        self._agent_address = None  # 记录最后部署的 Agent 地址
        self._agent_balance_before = 0  # 记录攻击前余额
        self._compile_agent()

    # ------------------------------------------------------------------
    # 编译 Agent 合约（仅编译一次）
    # ------------------------------------------------------------------

    def _compile_agent(self):
        try:
            import solcx
            import tempfile, os

            installed = solcx.get_installed_solc_versions()
            if not installed:
                raise RuntimeError("No solc version installed.")

            target_version = None
            if hasattr(self.env, 'args') and hasattr(self.env.args, 'solc'):
                raw = self.env.args.solc.lstrip("v")
                from packaging.version import Version
                target_version = next(
                    (str(v) for v in installed if str(v) == raw),
                    None
                )

            if target_version is None:
                from packaging.version import Version
                target_version = str(min(
                    installed,
                    key=lambda v: abs(Version(str(v)).major * 100 +
                                      Version(str(v)).minor - 7)
                ))

            solc_version = target_version
            self.logger.debug("Compiling Agent contract with solc %s", solc_version)

            major_minor = ".".join(solc_version.split(".")[:2])
            source = AGENT_CONTRACT_SOURCE.replace(
                "{solc_pragma}", f"^{solc_version}"
            )

            with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
                f.write(source)
                tmp_path = f.name

            output = solcx.compile_files(
                [tmp_path],
                output_values=["bin", "abi"],
                solc_version=solc_version
            )
            os.unlink(tmp_path)

            for key, val in output.items():
                if "AgentContract" in key:
                    self._agent_bytecode = val["bin"]
                    self._agent_abi = val["abi"]
                    self.logger.debug("Agent contract compiled successfully.")
                    return

        except Exception as e:
            self.logger.warning(
                "Agent contract compilation failed: %s. Falling back to trace-based simulation.", e
            )
            self._agent_bytecode = None

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def run(self, indv, contract_address: str) -> bool:
        """
        对当前 individual 执行完毕后，触发攻击模拟。
        """
        errors = getattr(self.env, "results", {}).get("errors", {})
        has_reentrancy = any(
            any(e.get("type") == "Reentrancy" for e in errs)
            for errs in errors.values()
        )
        if not has_reentrancy:
            return False

        self.logger.info("=== AgentSim.run() triggered (reentrancy in errors) ===")

        trigger_functions = self._find_trigger_functions(indv)
        self.logger.info("candidates found: %s", trigger_functions)
        if not trigger_functions:
            self.logger.info("No trigger function candidates, skipping.")
            return False

        for trigger_hash, reentry_hash in trigger_functions:
            if self._agent_bytecode:
                result = self._simulate_with_agent(
                    indv, contract_address, trigger_hash, reentry_hash
                )
            else:
                result = self._simulate_via_trace(
                    indv, trigger_hash, reentry_hash
                )
            if result:
                _r = "\033[91m"  # 红色
                _reset = "\033[0m"
                self.logger.title(_r + "-----------------------------------------------------" + _reset)
                self.logger.title(_r + "  !!! Reentrancy CONFIRMED via attack simulation !!!" + _reset)
                self.logger.title(_r + "  Trigger: {}  ReentryTarget: {}".format(trigger_hash, reentry_hash) + _reset)
                self.logger.title(_r + "-----------------------------------------------------" + _reset)
                return True
        return False

    # ------------------------------------------------------------------
    # 方法 A：部署真实 Agent 合约并执行攻击
    # ------------------------------------------------------------------

    def _simulate_with_agent(self, indv, contract_address, trigger_hash, reentry_hash) -> bool:
        """
        通用攻击模拟流程。
        """
        evm = self.env.instrumented_evm
        caller = evm.accounts[0]
        evm.create_snapshot()

        # 确保 caller 有足够余额
        _FUND = 100 * 10 ** 18
        try:
            evm.storage_emulator.set_balance(to_canonical_address(caller), _FUND)
        except Exception:
            pass

        try:
            # ── 步骤 1：从 solution 中找 trigger 的完整 calldata ──
            trigger_tx_data = None
            for sol_tx in indv.solution:
                tx = sol_tx["transaction"]
                fh = tx["data"][:10] if tx["data"].startswith("0x") else "0x" + tx["data"][:8]
                if fh == trigger_hash:
                    trigger_tx_data = tx["data"]
                    break
            if not trigger_tx_data:
                trigger_tx_data = "0x" + trigger_hash.lstrip("0x")

            # ── 步骤 2：从 solution 重放准备交易（跳过 trigger 本身）──
            for sol_tx in indv.solution:
                tx = sol_tx["transaction"]
                fh = tx["data"][:10] if tx["data"].startswith("0x") else "0x" + tx["data"][:8]
                if fh == trigger_hash:
                    continue
                if tx.get("to") is None:
                    continue
                pre = evm.deploy_transaction(sol_tx)
                if pre.is_error:
                    self.logger.debug("Pre-state tx %s skipped: %s", fh, pre._error)

            # ── 步骤 3：部署 Agent 合约 ──
            agent_address = self._deploy_agent(contract_address)
            if agent_address is None:
                return False

            # 记录 Agent 地址
            self._agent_address = agent_address

            # ── 步骤 3.5：给 Agent 账户充值 ETH ──
            fund_result = evm.deploy_transaction({
                "transaction": {
                    "from": caller,
                    "to": agent_address,
                    "gaslimit": 100_000,
                    "value": 10 ** 18,
                    "data": "0x",
                },
                "block": {"timestamp": None, "blocknumber": None},
                "global_state": {"balance": None, "call_return": {}, "extcodesize": {}},
                "environment": {"returndatasize": None},
            })
            if fund_result.is_error:
                self.logger.warning("Agent funding failed: %s", fund_result._error)

            if agent_address not in evm.accounts:
                evm.accounts.append(agent_address)

            # ── 步骤 4：给 Agent 在目标合约充值（准备状态）──
            deposit_tx_data = None
            is_self_reentry = (reentry_hash == trigger_hash)

            if is_self_reentry:
                data_deps = self.env.data_dependencies
                trigger_writes = data_deps.get(trigger_hash, {}).get("write", set())

                for sol_tx in indv.solution:
                    tx = sol_tx["transaction"]
                    fh = tx["data"][:10] if tx["data"].startswith("0x") else "0x" + tx["data"][:8]
                    if fh == trigger_hash:
                        continue
                    other_writes = data_deps.get(fh, {}).get("write", set())
                    if other_writes & trigger_writes or other_writes:
                        deposit_tx_data = tx["data"]
                        self.logger.debug("Self-reentry: using prep fn %s as deposit", fh)
                        break

                if not deposit_tx_data:
                    deposit_tx_data = "0x"
            else:
                for sol_tx in indv.solution:
                    tx = sol_tx["transaction"]
                    fh = tx["data"][:10] if tx["data"].startswith("0x") else "0x" + tx["data"][:8]
                    if fh == reentry_hash:
                        deposit_tx_data = tx["data"]
                        break

            if not deposit_tx_data:
                try:
                    from eth_abi import encode
                except ImportError:
                    from eth_abi import encode_abi as encode
                amount_arg = encode(["uint256"], [10 ** 18]).hex()
                deposit_tx_data = "0x" + reentry_hash.lstrip("0x") + amount_arg

            prep = evm.deploy_transaction({
                "transaction": {
                    "from": agent_address,
                    "to": contract_address,
                    "gaslimit": 1_000_000,
                    "value": 10 ** 18,
                    "data": deposit_tx_data,
                },
                "block": {"timestamp": None, "blocknumber": None},
                "global_state": {"balance": None, "call_return": {}, "extcodesize": {}},
                "environment": {"returndatasize": None},
            })
            if prep.is_error:
                self.logger.debug("Agent deposit tx failed: %s", prep._error)

            # ── 记录攻击前 Agent 余额 ──
            try:
                self._agent_balance_before = evm.storage_emulator.get_balance(
                    to_canonical_address(agent_address)
                )
            except Exception:
                self._agent_balance_before = 0

            # ── 步骤 5：构造 Agent.attack() 调用 ──
            first_data = bytes.fromhex(trigger_tx_data[2:])
            reentry_data = first_data

            attack_selector = self._get_function_selector("attack(bytes,bytes)")
            encoded_args = self._abi_encode_two_bytes(first_data, reentry_data)
            call_data = "0x" + (attack_selector + encoded_args).hex()

            result = evm.deploy_transaction({
                "transaction": {
                    "from": caller,
                    "to": agent_address,
                    "gaslimit": 4_500_000,
                    "value": 0,
                    "data": call_data,
                },
                "block": {"timestamp": None, "blocknumber": None},
                "global_state": {"balance": None, "call_return": {}, "extcodesize": {}},
                "environment": {"returndatasize": None},
            })

            if result.is_error:
                self.logger.debug("Attack tx failed: %s", result._error)

            confirmed = self._analyze_trace_for_reentrancy(result, contract_address)
            return confirmed

        except Exception as e:
            import traceback
            self.logger.warning("Agent simulation error: %s\n%s", e, traceback.format_exc())
            return False
        finally:
            evm.restore_from_snapshot()

    def _deploy_agent(self, target_address: str):
        """部署 AgentContract，返回部署地址（hex str）或 None。"""
        evm = self.env.instrumented_evm
        try:
            try:
                evm.storage_emulator.set_balance(
                    to_canonical_address(evm.accounts[0]), 100 * 10 ** 18
                )
            except Exception:
                pass
            try:
                from eth_abi import encode
            except ImportError:
                from eth_abi import encode_abi as encode
            constructor_args = encode(
                ["address"],
                [to_canonical_address(target_address)]
            ).hex()
            bytecode = self._agent_bytecode + constructor_args
            result = evm.deploy_contract(
                evm.accounts[0], bytecode, amount=10 ** 18
            )
            if result.is_error:
                self.logger.warning("Agent deployment failed: %s", result._error)
                return None
            agent_addr = encode_hex(result.msg.storage_address)
            self.logger.info("Agent deployed at %s", agent_addr)
            return agent_addr
        except Exception as e:
            import traceback
            self.logger.warning("Agent deploy exception: %s\n%s", e, traceback.format_exc())
            return None

    def _analyze_trace_for_reentrancy(self, exec_result, contract_address: str) -> bool:
        """
        判断攻击执行结果是否代表真实的重入漏洞。
        
        修复逻辑：
        1. 检查调用树结构（原有逻辑）
        2. 检查重入时是否真的修改了存储状态（新增）
        3. 检查 Agent 余额是否增加（新增）
        """
        if exec_result is None or exec_result.is_error:
            return False

        children = getattr(exec_result, "children", [])
        if not children:
            return False

        first_withdraw = children[0]
        grandchildren = getattr(first_withdraw, "children", [])
        if not grandchildren:
            return False

        fallback_result = grandchildren[0]
        great_grandchildren = getattr(fallback_result, "children", [])
        if not great_grandchildren:
            return False

        reentry_withdraw = great_grandchildren[0]
        reentry_trace = getattr(reentry_withdraw, "trace", None) or getattr(reentry_withdraw, "_trace", None)
        reentry_is_error = getattr(reentry_withdraw, "is_error", False)

        if reentry_is_error:
            self.logger.info(_yellow("Reentry withdraw REVERTED → blocked by reentrancy lock ✓"))
            return False

        if not reentry_trace:
            self.logger.info(_yellow("Reentry withdraw has no trace → blocked or did nothing"))
            return False

        reentry_ops = [instr.get("op", "") for instr in reentry_trace]
        has_sstore = "SSTORE" in reentry_ops
        has_revert = "REVERT" in reentry_ops

        if has_revert:
            self.logger.info(_yellow("Reentry withdraw REVERTED → blocked by reentrancy lock ✓"))
            return False

        if not has_sstore:
            self.logger.info(_yellow("Reentry withdraw has no SSTORE → did not modify state, not exploitable"))
            return False

        # ====== 新增修复 1：检查存储是否真的被修改 ======
        storage_modified = self._check_storage_diff(reentry_withdraw, contract_address)
        if not storage_modified:
            self.logger.info(_yellow(
                "Reentry withdraw has SSTORE but no actual state change "
                "→ not exploitable (e.g., writing 0 to already-0 slot)"
            ))
            return False

        # ====== 新增修复 2：检查 Agent 余额是否增加 ======
        balance_increased = self._check_balance_increase()
        if not balance_increased:
            self.logger.info(_yellow(
                "Agent balance did not increase → attack failed, no exploitable reentrancy"
            ))
            return False

        self.logger.info(_blue("Reentry withdraw executed SSTORE with actual state change AND Agent profited → NO reentrancy protection ✗"))
        return True

    def _check_storage_diff(self, exec_result, contract_address: str) -> bool:
        """
        检查执行前后目标合约的存储是否真的被修改。
        
        Returns:
            True: 存储确实被修改了（有意义的状态变化）
            False: 存储未变化或只是无意义的写入（如 0 → 0）
        """
        try:
            evm = self.env.instrumented_evm
            storage_emulator = evm.storage_emulator
            
            # 获取执行前后的存储快照
            # 注意：这需要 EVM 支持存储快照功能
            # 如果不支持，则降级为只检查 trace 中的 SSTORE
            
            # 简化版：检查 trace 中被 SSTORE 修改的 slot
            trace = getattr(exec_result, "trace", None) or getattr(exec_result, "_trace", None)
            if not trace:
                return True  # 无法判断，保守地认为有修改
            
            # 提取所有 SSTORE 操作及其 slot
            sstore_operations = []
            for i, instr in enumerate(trace):
                if instr.get("op") == "SSTORE":
                    # SSTORE 的 stack 结构：stack[-1] = slot, stack[-2] = value
                    stack = instr.get("stack", [])
                    if len(stack) >= 2:
                        slot = stack[-1]
                        value = stack[-2]
                        sstore_operations.append((slot, value))
            
            if not sstore_operations:
                return False
            
            # 检查是否有非零写入（简单启发式：如果写入的值不全是 0，则认为有修改）
            has_nonzero_write = any(
                int(value, 16) != 0 if isinstance(value, str) else value != 0
                for _, value in sstore_operations
            )
            
            if not has_nonzero_write:
                self.logger.debug("All SSTORE operations write zero values")
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug("Storage diff check failed: %s, assuming modified", e)
            return True  # 检查失败时保守处理

    def _check_balance_increase(self) -> bool:
        """
        检查 Agent 合约余额是否在攻击后增加。
        
        Returns:
            True: 余额增加（攻击获利）
            False: 余额未增加或减少（攻击失败）
        """
        if self._agent_address is None:
            self.logger.debug("Agent address not recorded, skipping balance check")
            return True  # 无法检查时保守处理
        
        try:
            evm = self.env.instrumented_evm
            balance_after = evm.storage_emulator.get_balance(
                to_canonical_address(self._agent_address)
            )
            
            balance_diff = balance_after - self._agent_balance_before
            
            if balance_diff > 0:
                self.logger.info(_blue(
                    f"Agent balance INCREASED by {balance_diff} wei → attack profitable ✗"
                ))
                return True
            else:
                self.logger.debug(
                    f"Agent balance change: {balance_diff} wei (not profitable)"
                )
                return False
                
        except Exception as e:
            self.logger.debug("Balance check failed: %s, assuming no profit", e)
            return False

    # ------------------------------------------------------------------
    # 方法 B：纯 trace 分析（无 Agent 合约编译时的降级方案）
    # ------------------------------------------------------------------

    def _simulate_via_trace(self, indv, trigger_hash, reentry_hash) -> bool:
        """
        不部署 Agent 合约，直接分析已有执行 trace。
        """
        data_deps = self.env.data_dependencies
        if trigger_hash not in data_deps:
            return False

        writes = data_deps[trigger_hash].get("write", set())
        reads = data_deps[trigger_hash].get("read", set())

        all_reads = set()
        for fh, deps in data_deps.items():
            if fh != trigger_hash:
                all_reads.update(deps.get("read", set()))

        overlapping = writes & all_reads
        if not overlapping:
            return False

        func_hashes = [
            tx["arguments"][0] for tx in indv.chromosome
            if tx.get("arguments")
        ]
        if trigger_hash in func_hashes:
            self.logger.debug(
                "Trace-based: potential reentrancy via %s -> %s (slots: %s)",
                trigger_hash, reentry_hash, overlapping
            )
            return False

        return False

    # ------------------------------------------------------------------
    # 辅助：找候选触发函数对 (trigger, reentry_target)
    # ------------------------------------------------------------------

    def _find_trigger_functions(self, indv):
        """
        找出重入攻击的候选函数对 (trigger_hash, reentry_hash)。
        
        修复：过滤掉只有单个 withdraw 类函数的情况（通常遵循 CEI 模式）。
        """
        data_deps = self.env.data_dependencies
        if not data_deps:
            return []

        func_hashes_in_indv = set(
            tx["arguments"][0]
            for tx in indv.chromosome
            if tx.get("arguments")
        )

        # ====== 新增修复：过滤单函数情况 ======
        if len(func_hashes_in_indv) == 1:
            only_func = list(func_hashes_in_indv)[0]
            self.logger.info(_yellow(
                f"Only one function in chromosome ({only_func}), "
                "likely isolated withdraw pattern following CEI → skipping"
            ))
            return []

        def _normalize_slots(slots):
            """把 mapping 的 keccak slot 归一化。"""
            result = set()
            for s in slots:
                try:
                    v = int(s) if not isinstance(s, int) else s
                except (ValueError, TypeError):
                    v = 999999
                if v < 256:
                    result.add(v)
                else:
                    result.add("_mapping")
            return result

        candidates_set = set()

        for trigger_hash in func_hashes_in_indv:
            if trigger_hash not in data_deps:
                continue

            written_slots = data_deps[trigger_hash].get("write", set())
            read_slots    = data_deps[trigger_hash].get("read",  set())

            if not written_slots or not read_slots:
                continue

            w_norm = _normalize_slots(written_slots)
            r_norm = _normalize_slots(read_slots)

            # 情形 A：自我重入
            if bool(w_norm & r_norm):
                candidates_set.add((trigger_hash, trigger_hash))
                self.logger.debug(
                    "Self-reentry candidate: trigger=%s (write=%s, read=%s)",
                    trigger_hash, written_slots, read_slots
                )

            # 情形 B：跨函数重入
            for other_hash, other_deps in data_deps.items():
                if other_hash == trigger_hash:
                    continue
                other_r_norm = _normalize_slots(other_deps.get("read", set()))
                if w_norm & other_r_norm:
                    candidates_set.add((trigger_hash, other_hash))
                    self.logger.debug(
                        "Cross-fn reentry candidate: trigger=%s -> reentry=%s",
                        trigger_hash, other_hash
                    )

        # 过滤：跨函数重入的 reentry 目标必须有写操作
        filtered = []
        for (trig, reentry) in candidates_set:
            if trig == reentry:
                filtered.append((trig, reentry))
            else:
                reentry_writes = data_deps.get(reentry, {}).get("write", set())
                if reentry_writes:
                    filtered.append((trig, reentry))
                else:
                    self.logger.debug(
                        "Filtered out cross-fn candidate (%s -> %s): reentry target is read-only",
                        trig, reentry
                    )

        return filtered

    # ------------------------------------------------------------------
    # ABI 编码辅助
    # ------------------------------------------------------------------

    @staticmethod
    def _get_function_selector(signature: str) -> bytes:
        """计算函数选择器（Keccak256 前 4 字节），返回 bytes。"""
        from eth_utils import keccak
        return keccak(text=signature)[:4]

    @staticmethod
    def _build_calldata(function_hash: str) -> bytes:
        """把函数 hash（0x + 8 hex chars）转为 bytes calldata。"""
        if function_hash.startswith("0x"):
            return bytes.fromhex(function_hash[2:])
        return bytes.fromhex(function_hash)

    @staticmethod
    def _abi_encode_two_bytes(data1: bytes, data2: bytes) -> bytes:
        """ABI 编码两个 bytes 参数。"""
        try:
            from eth_abi import encode
        except ImportError:
            from eth_abi import encode_abi as encode
        return encode(["bytes", "bytes"], [data1, data2])
