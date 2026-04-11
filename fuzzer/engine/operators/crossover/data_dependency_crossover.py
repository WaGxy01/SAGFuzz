#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Crossover operator implementation. '''

import random

from utils import settings
from ...plugin_interfaces.operators.crossover import Crossover
from ...components.individual import Individual


class DataDependencyCrossover(Crossover):
    def __init__(self, pc, env):
        if pc <= 0.0 or pc > 1.0:
            raise ValueError('Invalid crossover probability')
        self.pc = pc
        self.env = env

    def cross(self, father, mother):
        do_cross = True if random.random() <= self.pc else False

        if mother is None:
            return father.clone(), father.clone()

        _father = father.clone()
        _mother = mother.clone()

        if not do_cross or len(father.chromosome) + len(mother.chromosome) > settings.MAX_INDIVIDUAL_LENGTH:
            return _father, _mother

        father_reads, father_writes = DataDependencyCrossover.extract_reads_and_writes(_father, self.env)
        mother_reads, mother_writes = DataDependencyCrossover.extract_reads_and_writes(_mother, self.env)

        f_funcs = set(g["arguments"][0] for g in _father.chromosome)
        m_funcs = set(g["arguments"][0] for g in _mother.chromosome)

        # 判断是否双向依赖
        f_reads_m_writes = not father_reads.isdisjoint(mother_writes)
        m_reads_f_writes = not mother_reads.isdisjoint(father_writes)
        bidirectional = f_reads_m_writes and m_reads_f_writes

        if bidirectional:
            # 用静态调用链判断正确拼接方向
            static_sequences = getattr(self.env, 'static_sequences', {})
            forced_order = DataDependencyCrossover.infer_order_from_sequences(
                f_funcs, m_funcs, static_sequences
            )
            # forced_order: 'father_first', 'mother_first', or None
            if forced_order == 'father_first':
                child1 = Individual(generator=_father.generator)
                child1.init(chromosome=_father.chromosome + _mother.chromosome)
                child2 = Individual(generator=_father.generator)
                child2.init(chromosome=_father.chromosome + _mother.chromosome)
            elif forced_order == 'mother_first':
                child1 = Individual(generator=_mother.generator)
                child1.init(chromosome=_mother.chromosome + _father.chromosome)
                child2 = Individual(generator=_mother.generator)
                child2.init(chromosome=_mother.chromosome + _father.chromosome)
            else:
                # 无法判断，回退到原始读写集合逻辑
                child1 = Individual(generator=_father.generator)
                child1.init(chromosome=_father.chromosome + _mother.chromosome)
                child2 = Individual(generator=_mother.generator)
                child2.init(chromosome=_mother.chromosome + _father.chromosome)
        else:
            # 单向依赖，原始逻辑
            if m_reads_f_writes:
                child1 = Individual(generator=_father.generator)
                child1.init(chromosome=_father.chromosome + _mother.chromosome)
            else:
                child1 = _father

            if f_reads_m_writes:
                child2 = Individual(generator=_mother.generator)
                child2.init(chromosome=_mother.chromosome + _father.chromosome)
            else:
                child2 = _mother

        return child1, child2

    @staticmethod
    def infer_order_from_sequences(f_funcs, m_funcs, static_sequences):
        """
        根据静态调用链判断父代和母代的拼接方向。

        返回：
          'father_first' - 父代应在前
          'mother_first' - 母代应在前
          None           - 无法判断，回退
        """
        for critical_func, seq in static_sequences.items():
            # 遍历调用链中所有相邻对
            for i in range(len(seq) - 1):
                pred = seq[i]  # 前置函数
                succ = seq[i + 1]  # 后继函数（关键函数方向）

                # 父代含前置函数，母代含关键函数/后继函数 → 父前母后
                if pred in f_funcs and succ in m_funcs:
                    return 'father_first'

                # 母代含前置函数，父代含关键函数/后继函数 → 母前父后
                if pred in m_funcs and succ in f_funcs:
                    return 'mother_first'

        return None  # 无法从静态链判断

    @staticmethod
    def extract_reads_and_writes(individual, env):
        reads, writes = set(), set()
        for t in individual.chromosome:
            _function_hash = t["arguments"][0]
            if _function_hash in env.data_dependencies:
                reads.update(env.data_dependencies[_function_hash]["read"])
                writes.update(env.data_dependencies[_function_hash]["write"])
        return reads, writes
