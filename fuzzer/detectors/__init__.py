#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from utils.utils import print_individual_solution_as_transaction, initialize_logger


from .reentrancy import ReentrancyDetector


class DetectorExecutor:
    def __init__(self, source_map=None, function_signature_mapping={}):
        self.source_map = source_map
        self.function_signature_mapping = function_signature_mapping
        self.logger = initialize_logger("Detector")

        self.reentrancy_detector = ReentrancyDetector()


    def initialize_detectors(self):

        self.reentrancy_detector.init()


    @staticmethod
    def error_exists(errors, type):
        for error in errors:
            if error["type"] == type:
                return True
        return False

    @staticmethod
    def add_error(errors, pc, type, individual, mfe, detector, source_map):
        error = {
            "swc_id": detector.swc_id,
            "severity": detector.severity,
            "type": type,
            "individual": individual.solution,
            "time": time.time() - mfe.execution_begin,

        }
        if source_map and source_map.get_buggy_line(pc):
            error["line"] = source_map.get_location(pc)['begin']['line'] + 1
            error["column"] = source_map.get_location(pc)['begin']['column'] + 1
            error["source_code"] = source_map.get_buggy_line(pc)
        if not pc in errors:
            errors[pc] = [error]
            return True
        elif not DetectorExecutor.error_exists(errors[pc], type):
            errors[pc].append(error)
            return True
        return False

    def get_color_for_severity(severity):
        if severity == "High":
            return "\u001b[31m" # Red
        if severity == "Medium":
            return "\u001b[33m" # Yellow
        if severity == "Low":
            return "\u001b[32m" # Green
        return ""

    def run_detectors(self, previous_instruction, current_instruction, errors, tainted_record, individual, mfe, previous_branch, transaction_index):

        pc, index = self.reentrancy_detector.detect_reentrancy(tainted_record, current_instruction, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Reentrancy", individual, mfe, self.reentrancy_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.reentrancy_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"            !!! Reentrancy detected !!!              ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.reentrancy_detector.swc_id))
            self.logger.title(color+"Severity: "+self.reentrancy_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

