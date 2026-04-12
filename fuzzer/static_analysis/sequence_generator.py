#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sequence_generator.py - 基于 IR-Fuzz 的交易序列生成模块

功能：
1. 从 path.py 获取关键函数（包含 CALL/TIMESTAMP/DELEGATECALL 等的函数）
2. 从 ast_analysis.py 获取所有函数的状态变量读写信息
3. 基于 IR-Fuzz Rule 1 (Read & Write Dependency) 计算 Order Priority
4. 找出关键函数的前置函数链（写入者优先于读取者）
5. 返回符合项目 chromosome 格式的交易序列

IR-Fuzz Rule 1: Read & Write Dependency
当一个全局变量出现在两个不同函数中时，执行写操作的函数应该在执行读操作的函数之前被调用。

Order Priority 计算公式（来自论文）：
OP_i = Σ_k Σ_p v_jp^op * (1 - v_ik^op) * cmp(v_ik, v_jp)
其中：
- v^op = 1 表示读操作，v^op = 0 表示写操作
- cmp(v_ik, v_jp) = 1 当变量名相同时，否则为 0
"""

from typing import Dict, Set, List, Tuple, Optional, Any
from collections import defaultdict
import json


class SequenceGenerator:
    """
    交易序列生成器：基于数据依赖分析生成有序的函数调用序列
    """

    def __init__(self, 
                 critical_functions: Dict[str, Dict[str, Set[int]]],
                 ast_rw_info: Dict[str, Dict[str, List[str]]],
                 interface: Dict[str, List[str]] = None):
        """
        初始化序列生成器

        Args:
            critical_functions: 来自 path.py 的关键函数信息
                格式: {"0x函数签名": {"read": {槽号集合}, "write": set()}}
            ast_rw_info: 来自 ast_analysis.py 的函数读写信息
                格式: {"0x函数签名": {"reads": [变量名], "writes": [变量名]}}
            interface: 函数接口信息（可选，用于生成 chromosome）
                格式: {"0x函数签名": [参数类型列表]}
        """
        self.critical_functions = critical_functions
        self.ast_rw_info = ast_rw_info
        self.interface = interface or {}
        
        # 存储计算结果
        self.order_priorities = {}
        self.dependency_graph = defaultdict(set)  # func -> set of prerequisite funcs
        
    def compute_order_priority(self) -> Dict[str, int]:
        """
        计算每个函数的 Order Priority (基于 IR-Fuzz Rule 1)
        
        Order Priority 越高，函数越应该被优先调用
        
        Returns:
            {函数签名: Order Priority}
        """
        all_functions = set(self.ast_rw_info.keys())
        priorities = {func: 0 for func in all_functions}
        
        for func_i in all_functions:
            info_i = self.ast_rw_info.get(func_i, {"reads": [], "writes": []})
            writes_i = set(info_i.get("writes", []))
            
            for func_j in all_functions:
                if func_i == func_j:
                    continue
                    
                info_j = self.ast_rw_info.get(func_j, {"reads": [], "writes": []})
                reads_j = set(info_j.get("reads", []))
                
                # Rule 1: 如果 func_i 写入的变量被 func_j 读取
                # 则 func_i 应该在 func_j 之前执行
                # func_i 的 OP 增加（共同变量的数量）
                common_vars = writes_i & reads_j
                priorities[func_i] += len(common_vars)
                
        self.order_priorities = priorities
        return priorities
    
    def build_dependency_graph(self) -> Dict[str, Set[str]]:
        """
        构建函数依赖图：对于每个函数，找出它的前置函数（必须在它之前执行的函数）
        
        Returns:
            {函数签名: {前置函数集合}}
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

                if writes & reads:
                    graph[func].add(other_func)
                    print(f"[DEP] {func} 依赖 {other_func}，交集变量: {writes & reads}")  # ← 加这里

        self._dependency_graph = dict(graph)
        print(f"[DEP] 完整依赖图: {dict(graph)}")  # ← 加这里
        return self._dependency_graph
    
    def get_prerequisite_chain(self, target_func: str, max_depth: int = 10) -> List[str]:
        """
        获取目标函数的完整前置函数链（递归查找前置函数的前置函数）
        
        Args:
            target_func: 目标函数签名
            max_depth: 最大递归深度，防止循环依赖
            
        Returns:
            有序的前置函数列表（按调用顺序排列，最先调用的在前）
        """
        if not self.dependency_graph:
            self.build_dependency_graph()
            
        visited = set()
        chain = []

        def dfs(func, depth):
            if depth > max_depth or func in visited:
                return
            visited.add(func)

            prerequisites = dep_graph.get(func, set())
            print(f"[DFS] func={func}, prerequisites={prerequisites}")  # ← 加这里
            for prereq in prerequisites:
                if prereq in self.ast_rw_info:
                    dfs(prereq, depth + 1)

            if func not in chain:
                chain.append(func)
    
    def sort_functions_by_priority(self, functions: List[str]) -> List[str]:
        """
        根据 Order Priority 对函数列表排序（没有依赖关系时使用）
        
        Args:
            functions: 函数签名列表
            
        Returns:
            按 OP 降序排列的函数列表
        """
        if not self.order_priorities:
            self.compute_order_priority()
            
        return sorted(functions, 
                     key=lambda f: self.order_priorities.get(f, 0), 
                     reverse=True)
    
    def generate_ordered_sequence(self, target_func: str) -> List[str]:
        """
        为目标关键函数生成有序的调用序列
        
        处理逻辑：
        1. 获取前置函数链
        2. 对于没有依赖关系的前置函数，按 Order Priority 排序
        3. 最后添加目标函数
        
        Args:
            target_func: 目标关键函数签名
            
        Returns:
            有序的函数调用序列
        """
        # 确保已计算 OP 和依赖图
        if not self.order_priorities:
            self.compute_order_priority()
        if not self.dependency_graph:
            self.build_dependency_graph()
            
        # 获取前置函数链
        chain = self.get_prerequisite_chain(target_func)
        
        if not chain:
            return [target_func] if target_func in self.ast_rw_info else []
            
        # 对链中的函数进行拓扑排序，考虑依赖关系
        result = self._topological_sort_with_priority(chain)
        
        # 确保目标函数在最后
        if target_func in result:
            result.remove(target_func)
        result.append(target_func)
        
        return result
    
    def _topological_sort_with_priority(self, functions: List[str]) -> List[str]:
        """
        对函数列表进行拓扑排序，当有多个可选时按 OP 排序
        
        Args:
            functions: 待排序的函数列表
            
        Returns:
            拓扑排序后的函数列表
        """
        func_set = set(functions)
        
        # 计算入度（在这个子图内）
        in_degree = {f: 0 for f in functions}
        for func in functions:
            prereqs = self.dependency_graph.get(func, set())
            for prereq in prereqs:
                if prereq in func_set:
                    in_degree[func] += 1
                    
        result = []
        available = []
        
        # 初始化可用函数（入度为 0）
        for func in functions:
            if in_degree[func] == 0:
                available.append(func)
                
        while available:
            # 按 OP 降序选择
            available.sort(key=lambda f: self.order_priorities.get(f, 0), reverse=True)
            current = available.pop(0)
            result.append(current)
            
            # 更新入度
            for func in functions:
                if current in self.dependency_graph.get(func, set()):
                    in_degree[func] -= 1
                    if in_degree[func] == 0 and func not in result:
                        available.append(func)
                        
        # 处理循环依赖（如果有剩余）
        remaining = [f for f in functions if f not in result]
        if remaining:
            remaining = self.sort_functions_by_priority(remaining)
            result.extend(remaining)
            
        return result
    
    def generate_all_critical_sequences(self) -> Dict[str, List[str]]:
        """
        为所有关键函数生成有序调用序列
        
        Returns:
            {关键函数签名: [有序调用序列]}
        """
        sequences = {}
        for critical_func in self.critical_functions:
            if critical_func in self.ast_rw_info:
                sequences[critical_func] = self.generate_ordered_sequence(critical_func)
            else:
                # 关键函数不在 AST 分析结果中，可能是 view 函数被过滤
                sequences[critical_func] = [critical_func]
        return sequences
    
    def sequence_to_chromosome(self, 
                               sequence: List[str],
                               generator=None,
                               contract: str = None,
                               accounts: List[str] = None) -> List[Dict]:
        """
        将函数调用序列转换为项目定义的 chromosome 格式
        
        Args:
            sequence: 函数调用序列
            generator: Generator 实例（可选，用于生成随机参数）
            contract: 合约地址
            accounts: 可用账户列表
            
        Returns:
            chromosome 格式的交易序列
        """
        chromosome = []
        
        default_account = accounts[0] if accounts else "0x" + "0" * 40
        default_contract = contract or "0x" + "0" * 40
        
        for func_hash in sequence:
            # 获取函数参数类型
            arg_types = self.interface.get(func_hash, [])
            
            # 构建 arguments 列表：[函数选择器, 参数1, 参数2, ...]
            arguments = [func_hash]
            
            if generator:
                # 使用 generator 生成随机参数
                for idx, arg_type in enumerate(arg_types):
                    arg = generator.get_random_argument(arg_type, func_hash, idx)
                    arguments.append(arg)
            else:
                # 使用默认值
                for arg_type in arg_types:
                    arguments.append(self._get_default_value(arg_type))
                    
            gene = {
                "account": default_account,
                "contract": default_contract,
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
    
    def _get_default_value(self, arg_type: str) -> Any:
        """
        获取参数类型的默认值
        
        Args:
            arg_type: 参数类型字符串
            
        Returns:
            默认值
        """
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
                size = int(arg_type[5:])
                return bytearray(size)
        elif arg_type == "string":
            return ""
        elif "[" in arg_type:
            return []
        else:
            return 0
    
    def analyze_and_generate(self) -> Dict[str, Any]:
        """
        完整分析并生成结果
        
        Returns:
            {
                "order_priorities": {函数: OP},
                "dependency_graph": {函数: [前置函数]},
                "critical_sequences": {关键函数: [调用序列]},
                "chromosomes": {关键函数: chromosome格式序列}
            }
        """
        # 计算 Order Priority
        self.compute_order_priority()
        
        # 构建依赖图
        self.build_dependency_graph()
        
        # 为所有关键函数生成序列
        sequences = self.generate_all_critical_sequences()
        
        # 转换为 chromosome 格式
        chromosomes = {}
        for critical_func, seq in sequences.items():
            chromosomes[critical_func] = self.sequence_to_chromosome(seq)
            
        return {
            "order_priorities": self.order_priorities,
            "dependency_graph": {k: list(v) for k, v in self.dependency_graph.items()},
            "critical_sequences": sequences,
            "chromosomes": chromosomes
        }
    
    def print_analysis_report(self):
        """打印分析报告"""
        print("=" * 70)
        print("交易序列生成分析报告 (基于 IR-Fuzz Rule 1)")
        print("=" * 70)
        
        # Order Priority
        print("\n【Order Priority 排名】")
        if not self.order_priorities:
            self.compute_order_priority()
        sorted_ops = sorted(self.order_priorities.items(), 
                           key=lambda x: x[1], reverse=True)
        for func, op in sorted_ops:
            print(f"  {func}: OP = {op}")
            
        # 依赖图
        print("\n【函数依赖关系】")
        if not self.dependency_graph:
            self.build_dependency_graph()
        for func, prereqs in self.dependency_graph.items():
            if prereqs:
                prereq_str = ", ".join(prereqs)
                print(f"  {func} <- [{prereq_str}]")
                
        # 关键函数序列
        print("\n【关键函数调用序列】")
        sequences = self.generate_all_critical_sequences()
        for critical_func, seq in sequences.items():
            print(f"\n  目标: {critical_func}")
            print(f"  序列: {' -> '.join(seq)}")
            
        print("\n" + "=" * 70)


def match_critical_functions_with_ast(
    static_deps: Dict[str, Dict[str, Set[int]]],
    ast_rw_info: Dict[str, Dict[str, List[str]]]
) -> Dict[str, Dict[str, List[str]]]:
    """
    将 path.py 的关键函数与 ast_analysis.py 的读写信息匹配
    
    Args:
        static_deps: 来自 path.py 的静态依赖
        ast_rw_info: 来自 ast_analysis.py 的读写信息
        
    Returns:
        匹配后的关键函数读写信息
    """
    matched = {}
    
    for func_sig in static_deps:
        if func_sig in ast_rw_info:
            matched[func_sig] = ast_rw_info[func_sig]
        else:
            # 尝试规范化签名后匹配
            normalized_sig = func_sig.lower()
            for ast_func in ast_rw_info:
                if ast_func.lower() == normalized_sig:
                    matched[func_sig] = ast_rw_info[ast_func]
                    break
                    
    return matched


# 测试代码
if __name__ == "__main__":
    # 模拟 path.py 的输出（关键函数）
    critical_functions = {
        "0x2e1a7d4d": {"read": {0, 1}, "write": set()},  # withdraw
        "0x3ccfd60b": {"read": {0}, "write": set()},     # getReward
    }
    
    # 模拟 ast_analysis.py 的输出（所有函数的读写信息）
    ast_rw_info = {
        "0x27e235e3": {"reads": ["prizePool", "userBalance"], "writes": ["prizePool", "userBalance"]},  # guess
        "0x2e1a7d4d": {"reads": ["userBalance", "prizePool"], "writes": ["userBalance", "prizePool"]},  # withdraw
        "0x3ccfd60b": {"reads": ["userBalance", "prizePool"], "writes": ["prizePool", "userBalance"]},  # getReward
        "0x12345678": {"reads": [], "writes": ["targetNumber"]},  # setTarget
    }
    
    # 模拟接口信息
    interface = {
        "0x27e235e3": ["uint256"],
        "0x2e1a7d4d": [],
        "0x3ccfd60b": [],
        "0x12345678": ["uint256"],
    }
    
    print("测试数据:")
    print(f"关键函数: {list(critical_functions.keys())}")
    print(f"AST 分析函数: {list(ast_rw_info.keys())}")
    print()
    
    # 创建生成器
    generator = SequenceGenerator(critical_functions, ast_rw_info, interface)
    
    # 打印分析报告
    generator.print_analysis_report()
    
    # 生成完整结果
    result = generator.analyze_and_generate()
    
    print("\n【Chromosome 格式示例】")
    for critical_func, chromosome in result["chromosomes"].items():
        print(f"\n目标函数: {critical_func}")
        print(json.dumps(chromosome, indent=2, default=str))
