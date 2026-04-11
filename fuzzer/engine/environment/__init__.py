#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class FuzzingEnvironment:
    def __init__(self, **kwargs) -> None:
        # 初始化固定字段
        self.nr_of_transactions = 0
        self.unique_individuals = set()
        self.code_coverage = set()
        self.children_code_coverage = dict()
        self.previous_code_coverage_length = 0

        self.visited_branches = dict()

        self.memoized_fitness = dict()
        self.memoized_storage = dict()
        self.memoized_symbolic_execution = dict()

        self.individual_branches = dict()

        self.data_dependencies = dict()

        # 使用kwargs是为了接受额外参数而不用修改__init__.py，如果有相同的会覆盖
        self.__dict__.update(kwargs)
