#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
invocation_sequence.py - 函数调用序列生成器（集成模块）

整合 path.py（关键函数提取）和 ast_analysis.py（读写分析）的结果，
基于 IR-Fuzz 论文中的 Rule 1 (Read & Write Dependency) 生成有序的交易序列。

使用方式：
    from static_analysis.invocation_sequence import InvocationSequenceGenerator
    
    generator = InvocationSequenceGenerator(bytecode, ast_json)
    sequences = generator.generate_sequences()
    chromosomes = generator.to_chromosomes(interface, contract, accounts)
"""

import json
from typing import Dict, Set, List, Tuple, Optional, Any
from collections import defaultdict

# 导入项目现有模块
try:
    from static_analysis.path import PathAnalyzer, extract_static_dependencies
    from static_analysis.ast_analysis import analyze_ast
except ImportError:
    # 如果直接运行此文件，使用相对导入
    pass


class InvocationSequenceGenerator:
    """
    函数调用序列生成器
    
    整合字节码级别的关键函数分析和 AST 级别的读写分析，
    生成满足数据依赖关系的有序函数调用序列。
    """
    
    def __init__(self, 
                 bytecode: str = None,
                 ast_json: dict = None,
                 critical_functions: Dict[str, Dict] = None,
                 ast_rw_info: Dict[str, Dict] = None):
        """
        初始化生成器
        
        可以通过两种方式初始化：
        1. 提供 bytecode 和 ast_json，自动分析
        2. 直接提供分析结果 critical_functions 和 ast_rw_info
        
        Args:
            bytecode: 合约运行时字节码
            ast_json: Solidity 编译输出的 AST JSON
            critical_functions: 预计算的关键函数信息
            ast_rw_info: 预计算的 AST 读写信息
        """
        self.bytecode = bytecode
        self.ast_json = ast_json
        
        # 分析结果
        self.critical_functions = critical_functions or {}
        self.ast_rw_info = ast_rw_info or {}
        
        # 计算缓存
        self._order_priorities = None
        self._dependency_graph = None
        self._sequences = None
        
        # 如果提供了原始数据，执行分析
        if bytecode and not critical_functions:
            self._analyze_bytecode()
        if ast_json and not ast_rw_info:
            self._analyze_ast()
            
    def _analyze_bytecode(self):
        """从字节码提取关键函数"""
        try:
            analyzer = PathAnalyzer(self.bytecode)
            self.critical_functions = analyzer.analyze()
        except Exception as e:
            print(f"字节码分析失败: {e}")
            self.critical_functions = {}
            
    def _analyze_ast(self):
        """从 AST 提取读写信息"""
        try:
            self.ast_rw_info = analyze_ast(self.ast_json)
        except Exception as e:
            print(f"AST 分析失败: {e}")
            self.ast_rw_info = {}
            
    def compute_order_priorities(self) -> Dict[str, int]:
        """
        计算所有函数的 Order Priority
        
        基于 IR-Fuzz 论文公式：
        OP_i = Σ_k Σ_p v_jp^op * (1 - v_ik^op) * cmp(v_ik, v_jp)
        
        简化理解：一个函数如果写入的变量被其他函数读取，则它的 OP 增加
        
        Returns:
            {函数签名: Order Priority}
        """
        if self._order_priorities is not None:
            return self._order_priorities
            
        all_functions = set(self.ast_rw_info.keys())
        priorities = {func: 0 for func in all_functions}
        
        for func_i in all_functions:
            info_i = self.ast_rw_info.get(func_i, {})
            writes_i = set(info_i.get("writes", []))
            
            for func_j in all_functions:
                if func_i == func_j:
                    continue
                    
                info_j = self.ast_rw_info.get(func_j, {})
                reads_j = set(info_j.get("reads", []))
                
                # func_i 写入的变量被 func_j 读取的数量
                common_vars = writes_i & reads_j
                priorities[func_i] += len(common_vars)
                
        self._order_priorities = priorities
        return priorities
    
    def build_dependency_graph(self) -> Dict[str, Set[str]]:
        """
        构建函数依赖图
        
        如果函数 A 读取的变量被函数 B 写入，则 A 依赖于 B（B 是 A 的前置函数）
        
        Returns:
            {函数签名: {前置函数签名集合}}
        """
        if self._dependency_graph is not None:
            return self._dependency_graph
            
        all_functions = set(self.ast_rw_info.keys())
        graph = defaultdict(set)
        
        for func in all_functions:
            info = self.ast_rw_info.get(func, {})
            reads = set(info.get("reads", []))
            
            if not reads:
                continue
                
            for other_func in all_functions:
                if other_func == func:
                    continue
                    
                other_info = self.ast_rw_info.get(other_func, {})
                writes = set(other_info.get("writes", []))
                
                # 如果 other_func 写入了当前函数读取的变量
                if writes & reads:
                    graph[func].add(other_func)
                    
        self._dependency_graph = dict(graph)
        return self._dependency_graph
    
    def get_prerequisite_chain(self, 
                               target_func: str, 
                               max_depth: int = 10) -> List[str]:
        """
        获取目标函数的完整前置函数链
        
        递归查找前置函数的前置函数，构建完整的调用链
        
        Args:
            target_func: 目标函数签名
            max_depth: 最大递归深度
            
        Returns:
            有序的函数调用列表（最先调用的在前）
        """
        dep_graph = self.build_dependency_graph()
        visited = set()
        chain = []
        
        def dfs(func: str, depth: int):
            if depth > max_depth or func in visited:
                return
            visited.add(func)
            
            # 先递归处理前置函数
            prerequisites = dep_graph.get(func, set())
            for prereq in prerequisites:
                if prereq in self.ast_rw_info:  # 确保函数存在
                    dfs(prereq, depth + 1)
                    
            # 添加当前函数
            if func not in chain:
                chain.append(func)
                
        dfs(target_func, 0)
        return chain
    
    def _topological_sort(self, functions: List[str]) -> List[str]:
        """
        对函数列表进行拓扑排序
        
        当有多个同优先级的函数时，按 Order Priority 排序
        
        Args:
            functions: 待排序的函数列表
            
        Returns:
            排序后的函数列表
        """
        if not functions:
            return []
            
        priorities = self.compute_order_priorities()
        dep_graph = self.build_dependency_graph()
        func_set = set(functions)
        
        # 计算在子图内的入度
        in_degree = {f: 0 for f in functions}
        for func in functions:
            prereqs = dep_graph.get(func, set())
            for prereq in prereqs:
                if prereq in func_set:
                    in_degree[func] += 1
                    
        result = []
        available = [f for f in functions if in_degree[f] == 0]
        
        while available:
            # 按 OP 降序选择（OP 高的优先）
            available.sort(key=lambda f: priorities.get(f, 0), reverse=True)
            current = available.pop(0)
            result.append(current)
            
            # 更新入度
            for func in functions:
                if current in dep_graph.get(func, set()) and func in func_set:
                    in_degree[func] -= 1
                    if in_degree[func] == 0 and func not in result:
                        available.append(func)
                        
        # 处理循环依赖
        remaining = [f for f in functions if f not in result]
        if remaining:
            remaining.sort(key=lambda f: priorities.get(f, 0), reverse=True)
            result.extend(remaining)
            
        return result
    
    def generate_sequence_for_function(self, target_func: str) -> List[str]:
        """
        为单个目标函数生成有序调用序列
        
        Args:
            target_func: 目标函数签名
            
        Returns:
            有序的函数调用序列（包含前置函数和目标函数）
        """
        # 获取前置函数链
        chain = self.get_prerequisite_chain(target_func)
        
        if not chain:
            return [target_func] if target_func in self.ast_rw_info else []
            
        # 拓扑排序
        sorted_chain = self._topological_sort(chain)
        
        # 确保目标函数在最后
        if target_func in sorted_chain:
            sorted_chain.remove(target_func)
        sorted_chain.append(target_func)
        
        return sorted_chain
    
    def generate_sequences(self) -> Dict[str, List[str]]:
        """
        为所有关键函数生成有序调用序列
        
        Returns:
            {关键函数签名: [有序调用序列]}
        """
        if self._sequences is not None:
            return self._sequences
            
        sequences = {}
        
        for critical_func in self.critical_functions:
            seq = self.generate_sequence_for_function(critical_func)
            if seq:
                sequences[critical_func] = seq
            else:
                # 如果无法生成序列，至少包含函数自身
                sequences[critical_func] = [critical_func]
                
        self._sequences = sequences
        return sequences
    
    def to_chromosome(self, 
                      sequence: List[str],
                      interface: Dict[str, List[str]],
                      contract: str,
                      accounts: List[str],
                      generator=None) -> List[Dict]:
        """
        将函数调用序列转换为 chromosome 格式
        
        Args:
            sequence: 函数调用序列
            interface: 函数接口 {函数签名: [参数类型]}
            contract: 合约地址
            accounts: 可用账户列表
            generator: Generator 实例（可选，用于生成随机参数）
            
        Returns:
            chromosome 格式的交易列表
        """
        chromosome = []
        default_account = accounts[0] if accounts else "0x" + "0" * 40
        
        for func_hash in sequence:
            arg_types = interface.get(func_hash, [])
            
            # 构建 arguments: [函数选择器, 参数1, 参数2, ...]
            arguments = [func_hash]
            
            if generator:
                for idx, arg_type in enumerate(arg_types):
                    arg = generator.get_random_argument(arg_type, func_hash, idx)
                    arguments.append(arg)
            else:
                for arg_type in arg_types:
                    arguments.append(self._get_default_value(arg_type))
                    
            gene = {
                "account": default_account,
                "contract": contract,
                "amount": 0,
                "arguments": arguments,
                "blocknumber": 1,
                "timestamp": 1,
                "gaslimit": 10000000,
                "call_return": {},
                "extcodesize": {},
                "returndatasize": {}
            }
            
            chromosome.append(gene)
            
        return chromosome
    
    def to_chromosomes(self,
                       interface: Dict[str, List[str]],
                       contract: str,
                       accounts: List[str],
                       generator=None) -> Dict[str, List[Dict]]:
        """
        为所有关键函数生成 chromosome 格式的交易序列
        
        Args:
            interface: 函数接口
            contract: 合约地址
            accounts: 可用账户列表
            generator: Generator 实例
            
        Returns:
            {关键函数签名: chromosome格式交易序列}
        """
        sequences = self.generate_sequences()
        chromosomes = {}
        
        for critical_func, seq in sequences.items():
            chromosomes[critical_func] = self.to_chromosome(
                seq, interface, contract, accounts, generator
            )
            
        return chromosomes
    
    def _get_default_value(self, arg_type: str) -> Any:
        """获取参数类型的默认值"""
        arg_type = arg_type.strip()
        
        if arg_type.startswith("uint") or arg_type.startswith("int"):
            return 0
        elif arg_type == "address":
            return "0x" + "0" * 40
        elif arg_type == "bool":
            return False
        elif arg_type.startswith("bytes"):
            if arg_type == "bytes":
                return bytearray()
            else:
                try:
                    size = int(arg_type[5:])
                    return bytearray(size)
                except:
                    return bytearray()
        elif arg_type == "string":
            return ""
        elif "[" in arg_type:
            return []
        else:
            return 0
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """
        获取分析摘要
        
        Returns:
            分析结果摘要
        """
        priorities = self.compute_order_priorities()
        dep_graph = self.build_dependency_graph()
        sequences = self.generate_sequences()
        
        return {
            "critical_functions_count": len(self.critical_functions),
            "analyzed_functions_count": len(self.ast_rw_info),
            "order_priorities": priorities,
            "dependency_graph": {k: list(v) for k, v in dep_graph.items()},
            "sequences": sequences
        }
    
    def print_report(self):
        """打印分析报告"""
        print("=" * 70)
        print("函数调用序列分析报告 (基于 IR-Fuzz Rule 1)")
        print("=" * 70)
        
        summary = self.get_analysis_summary()
        
        print(f"\n统计信息:")
        print(f"  - 关键函数数量: {summary['critical_functions_count']}")
        print(f"  - 分析函数数量: {summary['analyzed_functions_count']}")
        
        print(f"\n关键函数列表:")
        for func in self.critical_functions:
            static_deps = self.critical_functions[func]
            print(f"  {func}: 读取存储槽 {static_deps.get('read', set())}")
        
        print(f"\nOrder Priority 排名 (高 -> 低):")
        sorted_ops = sorted(summary['order_priorities'].items(), 
                           key=lambda x: x[1], reverse=True)
        for func, op in sorted_ops:
            marker = " *" if func in self.critical_functions else ""
            print(f"  {func}: OP = {op}{marker}")
            
        print(f"\n函数依赖关系 (函数 <- [前置函数]):")
        for func, prereqs in summary['dependency_graph'].items():
            if prereqs:
                print(f"  {func} <- {prereqs}")
                
        print(f"\n关键函数的有序调用序列:")
        for func, seq in summary['sequences'].items():
            print(f"\n  目标: {func}")
            print(f"  序列: {' -> '.join(seq)}")
            
        print("\n" + "=" * 70)


# 便捷函数
def generate_invocation_sequences(
    bytecode: str,
    ast_json: dict,
    interface: Dict[str, List[str]] = None,
    contract: str = None,
    accounts: List[str] = None
) -> Tuple[Dict[str, List[str]], Dict[str, List[Dict]]]:
    """
    一站式生成函数调用序列
    
    Args:
        bytecode: 合约运行时字节码
        ast_json: AST JSON
        interface: 函数接口（可选）
        contract: 合约地址（可选）
        accounts: 账户列表（可选）
        
    Returns:
        (sequences, chromosomes)
        - sequences: {关键函数: [调用序列]}
        - chromosomes: {关键函数: chromosome格式序列}（如果提供了 interface）
    """
    gen = InvocationSequenceGenerator(bytecode, ast_json)
    sequences = gen.generate_sequences()
    
    chromosomes = {}
    if interface and contract and accounts:
        chromosomes = gen.to_chromosomes(interface, contract, accounts)
        
    return sequences, chromosomes


# 测试
if __name__ == "__main__":
    print("=" * 70)
    print("函数调用序列生成器 - 读取 AST 文件 + 手动输入 Bytecode")
    print("=" * 70)

    # ======== 1. 固定 AST 文件路径 ========
    ast_file_path = "C:/Users/15028\Desktop\论文\论文配套智能合约remix\output/Depfuzz.sol_json.ast"   # 改成你的 AST 文件路径

    try:
        with open(ast_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"已成功读取 AST 文件: {ast_file_path}")
    except Exception as e:
        print(f"读取 AST 文件失败: {e}")
        exit(1)

    # ======== 2. 提取 AST（兼容多种 solc 输出格式） ========
    ast_json = None

    # 如果 JSON 本身就是 AST
    if "nodeType" in data:
        ast_json = data

    # 如果是 solc --combined-json
    elif "sources" in data:
        for file in data["sources"].values():
            if "AST" in file:
                ast_json = file["AST"]
                break

    if not ast_json:
        print("未找到 AST 数据，请检查 JSON 结构")
        exit(1)

    # ======== 3. 手动输入 Bytecode ========
    bytecode = "6080604052600436106100a4576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680631309f013146100a957806338af3eed146100d65780635a84eff21461012d5780637367c5eb1461015a5780639cb8a26a1461019b578063b06b0368146101b2578063bc408b131461021f578063c2bfccc01461024a578063c41bcb1b14610261578063d0e30db0146102a2575b600080fd5b3480156100b557600080fd5b506100d4600480360381019080803590602001909291905050506102cd565b005b3480156100e257600080fd5b506100eb610350565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561013957600080fd5b5061015860048036038101908080359060200190929190505050610376565b005b34801561016657600080fd5b5061018560048036038101908080359060200190929190505050610485565b6040518082815260200191505060405180910390f35b3480156101a757600080fd5b506101b061049f565b005b3480156101be57600080fd5b506101dd600480360381019080803590602001909291905050506104d3565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561022b57600080fd5b50610234610508565b6040518082815260200191505060405180910390f35b34801561025657600080fd5b5061025f61050e565b005b34801561026d57600080fd5b5061028c600480360381019080803590602001909291905050506105e9565b6040518082815260200191505060405180910390f35b3480156102ae57600080fd5b506102b7610603565b6040518082815260200191505060405180910390f35b6005816003811015156102dc57fe5b0160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561033757600080fd5b600160088260038110151561034857fe5b018190555050565b600460009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60016008600060038110151561038857fe5b015414151561039657600080fd5b6001600860016003811015156103a857fe5b01541415156103b657600080fd5b6001600860026003811015156103c857fe5b01541415156103d657600080fd5b6005816003811015156103e557fe5b0160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561044057600080fd5b6001600b8260038110151561045157fe5b01541415151561046057600080fd5b6001600354016003819055506001600b8260038110151561047d57fe5b018190555050565b60088160038110151561049457fe5b016000915090505481565b600160149054906101000a900460ff1615156104ba57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff16ff5b6005816003811015156104e257fe5b016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60035481565b60026003541015151561052057600080fd5b600160149054906101000a900460ff1615151561053c57600080fd5b600460009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc6002549081150290604051600060405180830381858888f193505050501580156105a6573d6000803e3d6000fd5b5060018060146101000a81548160ff0219169083151502179055506001600b60006003811015156105d357fe5b01541415156105e757600015156105e657fe5b5b565b600b816003811015156105f857fe5b016000915090505481565b600254815600a165627a7a723058207f756fe8bfead09a587ca90a4d8837b736326151054030dc0b9d0310c7c7dbf90029"

    if bytecode == "":
        bytecode = None
        print("未提供 Bytecode，仅基于 AST 分析")
    else:
        print("Bytecode 已输入")

    # ======== 4. 创建生成器 ========
    generator = InvocationSequenceGenerator(
        bytecode=bytecode,
        ast_json=ast_json
    )

    # ======== 5. 输出分析报告 ========
    generator.print_report()


    print("\n分析完成.")