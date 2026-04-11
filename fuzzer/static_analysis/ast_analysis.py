#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from web3 import Web3


def analyze_ast(ast):
    """
    分析 AST，提取每个函数的状态变量读写信息

    Args:
        ast: AST 字典

    Returns:
        {0x函数签名: {reads: [变量], writes: [变量]}}
    """
    result = {}

    # 找到合约定义
    for node in ast.get('nodes', []):
        if node.get('nodeType') == 'ContractDefinition':
            # 1. 收集所有状态变量
            state_variables = {}
            for item in node.get('nodes', []):
                if item.get('nodeType') == 'VariableDeclaration' and item.get('stateVariable'):
                    var_id = item.get('id')
                    var_name = item.get('name')
                    state_variables[var_id] = var_name

            # 2. 分析每个函数
            for item in node.get('nodes', []):
                if item.get('nodeType') == 'FunctionDefinition':
                    func_name = item.get('name')

                    # 跳过 constructor、fallback、receive
                    if not func_name or item.get('kind') in ['constructor', 'fallback', 'receive']:
                        continue

                    # 跳过 view 和 pure 函数
                    state_mutability = item.get('stateMutability')
                    if state_mutability in ['view', 'pure']:
                        continue

                    # 获取函数参数类型
                    params = item.get('parameters', {}).get('parameters', [])
                    param_types = []
                    for p in params:
                        param_type = get_canonical_type(p.get('typeName', {}))
                        param_types.append(param_type)

                    # 构建函数签名
                    signature = f"{func_name}({','.join(param_types)})"
                    selector = '0x' + Web3.sha3(text=signature)[:4].hex().replace('0x', '')

                    # 分析读写
                    reads = set()
                    writes = set()
                    analyze_function_body(item.get('body', {}), state_variables, reads, writes)

                    result[selector] = {
                        'reads': list(reads),
                        'writes': list(writes)
                    }

    return result


def get_canonical_type(type_node):
    """从 AST 类型节点获取规范类型字符串"""
    if not type_node:
        return ''

    node_type = type_node.get('nodeType')

    if node_type == 'ElementaryTypeName':
        name = type_node.get('name', '')
        # v0.4 兼容：uint -> uint256, int -> int256
        if name == 'uint':
            return 'uint256'
        if name == 'int':
            return 'int256'
        return name

    elif node_type == 'ArrayTypeName':
        base_type = get_canonical_type(type_node.get('baseType', {}))
        length = type_node.get('length')
        if length:
            # 固定长度数组
            length_value = length.get('value', '')
            return f"{base_type}[{length_value}]"
        else:
            # 动态数组
            return f"{base_type}[]"

    elif node_type == 'Mapping':
        key_type = get_canonical_type(type_node.get('keyType', {}))
        value_type = get_canonical_type(type_node.get('valueType', {}))
        return f"mapping({key_type} => {value_type})"

    elif node_type == 'UserDefinedTypeName':
        # 用户定义类型（如 struct、contract）
        # 对于函数签名，contract 类型等价于 address
        type_string = type_node.get('typeDescriptions', {}).get('typeString', '')
        if type_string.startswith('contract '):
            return 'address'
        return type_node.get('name', type_string)

    elif node_type == 'FunctionTypeName':
        return 'function'

    else:
        # 尝试从 typeDescriptions 获取
        type_desc = type_node.get('typeDescriptions', {})
        type_string = type_desc.get('typeString', '')
        return type_string


def analyze_function_body(node, state_variables, reads, writes):
    """递归分析函数体，找出状态变量的读写"""
    if not isinstance(node, dict):
        return

    node_type = node.get('nodeType')

    # 赋值操作
    if node_type == 'Assignment':
        # 左侧是写入
        analyze_lvalue(node.get('leftHandSide', {}), state_variables, writes, reads)
        # 右侧是读取
        analyze_expression(node.get('rightHandSide', {}), state_variables, reads)
        # 继续递归，不要 return

    # 一元操作 (++, --, delete)
    elif node_type == 'UnaryOperation':
        operator = node.get('operator', '')
        if operator in ['++', '--', 'delete']:
            # 这些操作符既读又写
            analyze_lvalue(node.get('subExpression', {}), state_variables, writes, reads)
            analyze_expression(node.get('subExpression', {}), state_variables, reads)
        else:
            analyze_expression(node.get('subExpression', {}), state_variables, reads)

    # 变量声明语句（可能有初始值）
    elif node_type == 'VariableDeclarationStatement':
        initial_value = node.get('initialValue')
        if initial_value:
            analyze_expression(initial_value, state_variables, reads)

    # 函数调用（作为语句）
    elif node_type == 'ExpressionStatement':
        expr = node.get('expression', {})
        if expr.get('nodeType') == 'FunctionCall':
            analyze_expression(expr, state_variables, reads)
        elif expr.get('nodeType') == 'Assignment':
            analyze_lvalue(expr.get('leftHandSide', {}), state_variables, writes, reads)
            analyze_expression(expr.get('rightHandSide', {}), state_variables, reads)
        else:
            analyze_expression(expr, state_variables, reads)

    # If 语句 - 条件中的读取
    elif node_type == 'IfStatement':
        analyze_expression(node.get('condition', {}), state_variables, reads)
        # 递归处理 then 和 else 分支
        analyze_function_body(node.get('trueBody', {}), state_variables, reads, writes)
        analyze_function_body(node.get('falseBody', {}), state_variables, reads, writes)
        return  # 已处理完，避免重复

    # While/For 循环 - 条件中的读取
    elif node_type == 'WhileStatement':
        analyze_expression(node.get('condition', {}), state_variables, reads)

    elif node_type == 'ForStatement':
        analyze_expression(node.get('condition', {}), state_variables, reads)

    # Return 语句
    elif node_type == 'Return':
        analyze_expression(node.get('expression', {}), state_variables, reads)

    # Require/Assert
    elif node_type == 'FunctionCall':
        analyze_expression(node, state_variables, reads)

    # 递归遍历所有子节点
    for key, value in node.items():
        if key in ['condition', 'expression', 'leftHandSide', 'rightHandSide', 'subExpression']:
            continue  # 已经处理过
        if isinstance(value, dict):
            analyze_function_body(value, state_variables, reads, writes)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    analyze_function_body(item, state_variables, reads, writes)


def analyze_lvalue(node, state_variables, writes, reads):
    """分析左值（写入目标）"""
    if not isinstance(node, dict):
        return

    node_type = node.get('nodeType')

    if node_type == 'Identifier':
        ref_id = node.get('referencedDeclaration')
        if ref_id in state_variables:
            writes.add(state_variables[ref_id])

    elif node_type == 'IndexAccess':
        # 如 balances[msg.sender]
        base = node.get('baseExpression', {})
        if base.get('nodeType') == 'Identifier':
            ref_id = base.get('referencedDeclaration')
            if ref_id in state_variables:
                writes.add(state_variables[ref_id])
        else:
            # 递归处理嵌套的 IndexAccess
            analyze_lvalue(base, state_variables, writes, reads)

        # index 表达式是读取
        analyze_expression(node.get('indexExpression', {}), state_variables, reads)

    elif node_type == 'MemberAccess':
        # 如 struct.field
        expr = node.get('expression', {})
        analyze_lvalue(expr, state_variables, writes, reads)

    elif node_type == 'TupleExpression':
        # 如 (a, b) = ...
        for component in node.get('components', []):
            if component:
                analyze_lvalue(component, state_variables, writes, reads)


def analyze_expression(node, state_variables, reads):
    """分析表达式（读取）"""
    if not isinstance(node, dict):
        return

    node_type = node.get('nodeType')

    if node_type == 'Identifier':
        ref_id = node.get('referencedDeclaration')
        if ref_id in state_variables:
            reads.add(state_variables[ref_id])

    elif node_type == 'IndexAccess':
        base = node.get('baseExpression', {})
        if base.get('nodeType') == 'Identifier':
            ref_id = base.get('referencedDeclaration')
            if ref_id in state_variables:
                reads.add(state_variables[ref_id])
        else:
            analyze_expression(base, state_variables, reads)

        analyze_expression(node.get('indexExpression', {}), state_variables, reads)

    elif node_type == 'MemberAccess':
        analyze_expression(node.get('expression', {}), state_variables, reads)

    elif node_type == 'FunctionCall':
        analyze_expression(node.get('expression', {}), state_variables, reads)
        for arg in node.get('arguments', []):
            analyze_expression(arg, state_variables, reads)

    elif node_type == 'BinaryOperation':
        analyze_expression(node.get('leftExpression', {}), state_variables, reads)
        analyze_expression(node.get('rightExpression', {}), state_variables, reads)

    elif node_type == 'UnaryOperation':
        analyze_expression(node.get('subExpression', {}), state_variables, reads)

    elif node_type == 'TupleExpression':
        for component in node.get('components', []):
            if component:
                analyze_expression(component, state_variables, reads)

    elif node_type == 'Conditional':
        analyze_expression(node.get('condition', {}), state_variables, reads)
        analyze_expression(node.get('trueExpression', {}), state_variables, reads)
        analyze_expression(node.get('falseExpression', {}), state_variables, reads)

    else:
        # 递归处理其他节点
        for key, value in node.items():
            if isinstance(value, dict):
                analyze_expression(value, state_variables, reads)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        analyze_expression(item, state_variables, reads)


if __name__ == '__main__':
    # 测试用：从文件读取 AST
    with open('C:/Users/15028/Desktop/论文/论文配套智能合约remix/output/Depfuzz.sol_json.ast', 'r') as f:
        ast = json.load(f)

    result = analyze_ast(ast)

    print("=" * 60)
    print("函数状态变量读写分析结果 (已过滤 view/pure)")
    print("=" * 60)
    print(json.dumps(result, indent=2, ensure_ascii=False))