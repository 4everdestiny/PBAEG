"""
author : 4everdestiny
create_time : 2023.7.5
description : this is the code for global use in state analyse
input : state
output : the information we want to get
"""

from log.log import Log

log = Log()


class StateHelper:
    def __init__(self, state):
        self.state = state

    def GetString(self, address):
        """
        return the string from this address, according to the state
        :param address: the address of the string
        :return: the string
        """
        max_length = 0x100
        string = ""
        for i in range(max_length):
            char_sym = self.state.mem[address + i].uint8_t.resolved
            if char_sym.symbolic:
                log.Exception("the string's content is symbolic. please check it")
                return ""
            char = chr(self.state.solver.eval(char_sym))
            if char == "\x00":
                break
            string += char
        return string

    def GetSymbolicStringLength(self, address):
        """
        return the string's symbolic length from this address,
        according to the state
        :param state: the current state
        :param address: the address of the string
        :return: the string length for the symbolic length
        """
        max_length = 0x500
        length = 0
        for i in range(max_length):
            char_sym = self.state.mem[address + i].uint8_t.resolved
            if char_sym.symbolic:
                length += 1
            else:
                return length
        return length

    def JudgeParInStackAndReturnOffsetX86(self, par_sym, state=None):
        """
        give a parameter and judge whether this par is in the stack
        if this parameter is in stack, return the offset to ebp
        otherwise return False
        :param par_sym: the parameter symbol to judge
        :param state: the current state
        :return: True, offset when success, False, 0 when not in stack
        """
        argv_addr = state.solver.eval(state.posix.argv)
        esp = state.solver.eval(state.regs.esp)
        ebp = state.solver.eval(state.regs.ebp)
        high_range = argv_addr
        low_range = esp
        par_address = state.solver.eval(par_sym)
        if ebp >= par_address >= esp:
            return True, ebp - par_address + 4
        elif par_address >= high_range or par_address <= low_range:
            return False, 0
        else:
            for i in range(0x30):
                esp = ebp + 4
                ebp_sym = state.mem[ebp].uint32_t.resolved
                if ebp_sym.symbolic:
                    return False, 0
                ebp = state.solver.eval(ebp_sym)
                if high_range >= ebp >= low_range:
                    if ebp >= par_address >= esp:
                        return True, ebp - par_address + 4
                    else:
                        return False, 0
                else:
                    return False, 0
        return False, 0

    def JudgeParameterRange(self, parameter=0, step=4, max_range=0x2000):
        """
        judge the parameter's value range step by step
        for example, malloc(rdi), we need to find
        0x0 <= rdi <= 0x100
        :param parameter: the parameter's index
        :param step: the value judge step
        :param max_range: the max range to judge
        :return: None
        """
        if self.state.arch.name == "AMD64":
            parameters = [self.state.regs.rdi, self.state.regs.rsi, self.state.regs.rdx,
                          self.state.regs.rcx, self.state.regs.r8, self.state.regs.r9]
            if parameter <= 6:
                judge_parameter = parameters[parameter]
            else:
                judge_parameter = self.state.mem[self.state.regs.rsp + 8 * (parameter - 6)].uint64_t.resolved
            high_range = max_range
            low_range = -max_range
            for value in range(0, max_range, step):
                if not self.state.satisfiable(
                    extra_constraints=[judge_parameter == value]
                ):
                    high_range = value - step
                    break
            for value in range(0, -max_range, -step):
                if not self.state.satisfiable(
                    extra_constraints=[judge_parameter == value]
                ):
                    low_range = value + step
                    break
            return [low_range, high_range]
        elif self.state.arch.name == "X86":
            judge_parameter = self.state.mem[self.state.regs.rsp + 8 * (parameter - 6)].uint64_t.resolved
            high_range = max_range
            low_range = -max_range
            for value in range(0, max_range, step):
                if not self.state.satisfiable(
                        extra_constraints=[judge_parameter == value]
                ):
                    high_range = value
                    break
            for value in range(0, -max_range, -step):
                if not self.state.satisfiable(
                        extra_constraints=[judge_parameter == value]
                ):
                    low_range = value
                    break
            return [low_range, high_range]
        else:
            return [0, 0]