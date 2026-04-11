#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.settings import FITNESS_ALPHA, FITNESS_BETA

def fitness_function(indv, env):
    block_coverage_fitness = compute_branch_coverage_fitness(
        env.individual_branches[indv.hash], env.code_coverage)
    if env.args.data_dependency:
        data_dependency_fitness = compute_data_dependency_fitness(
            indv, env.data_dependencies)
        seq_fitness = compute_sequence_fitness(indv, env.static_sequences) \
            if hasattr(env, 'static_sequences') and env.static_sequences else 0.0
        return block_coverage_fitness + FITNESS_ALPHA * data_dependency_fitness + FITNESS_BETA * seq_fitness
    return block_coverage_fitness

def compute_branch_coverage_fitness(branches, pcs):
    non_visited_branches = 0.0

    for jumpi in branches:
        for destination in branches[jumpi]:
            if not branches[jumpi][destination] and destination not in pcs:
                non_visited_branches += 1

    return non_visited_branches

def compute_data_dependency_fitness(indv, data_dependencies):
    data_dependency_fitness = 0.0
    all_reads = set()

    for d in data_dependencies:
        all_reads.update(data_dependencies[d]["read"])

    for i in indv.chromosome:
        _function_hash = i["arguments"][0]
        if _function_hash in data_dependencies:
            for i in data_dependencies[_function_hash]["write"]:
                if i in all_reads:
                    data_dependency_fitness += 1

    return data_dependency_fitness

def compute_sequence_fitness(indv, static_sequences):
    """
    f_seq：将染色体中实际的函数调用顺序与静态调用链对比，
    匹配的相邻有序对越多，分数越高。
    """
    if not static_sequences:
        return 0.0

    # 记录染色体中每个函数签名第一次出现的位置
    first_occurrence = {}
    for idx, gene in enumerate(indv.chromosome):
        func_hash = gene["arguments"][0]
        if func_hash not in first_occurrence:
            first_occurrence[func_hash] = idx

    score = 0.0
    for critical_func, seq in static_sequences.items():
        # seq 形如 ["0xdeposit", "0xsetState", "0xwithdraw"]
        for i in range(len(seq) - 1):
            pred_func = seq[i]
            succ_func = seq[i + 1]
            # 两个函数都出现在染色体中，且前置函数位置早于后继函数
            if pred_func in first_occurrence and succ_func in first_occurrence:
                if first_occurrence[pred_func] < first_occurrence[succ_func]:
                    score += 1.0

    return score
