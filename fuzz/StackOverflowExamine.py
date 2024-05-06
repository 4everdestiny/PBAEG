"""
author : 4everdestiny
create_time : 2022.3.1
description : this is the code to find the stack overflow Vulnerability.
input : binary path
output : exploit of stack overflow
"""
import re

import angr
import claripy
from fuzz.Fuzzer import Fuzzer
from log import log
from state.StackOverFlowStateLog import StackOverFlowStateLog
from state.StackOverFlowStateLog import SingleStackOverFlowStateLog
from log.ScanfInfo import ScanfInfo

log = log.Log()


class StackOverflowExamine:
    def __init__(self, binarypath):
        self.binarypath = binarypath
        self.binary_static = False
        self.NewProject()
        self.fuzzer = Fuzzer(self.binarypath, self.project, self.state)
        self.stackoverflowlog = StackOverFlowStateLog()
        # the pre_statelog is used in format string state
        self.pre_statelog = None

    def NewProject(self):
        self.project = angr.Project(self.binarypath, auto_load_libs=True)
        if len(self.project.loader.requested_names) == 0:
            self.binary_static = True
        else:
            self.binary_static = False
        if not self.binary_static:

            #arg1 = claripy.BVS('arg1', 10240)
            self.state = self.project.factory.entry_state(
                remove_options={angr.options.LAZY_SOLVES}
                #, args=['-v', arg1]
            )
        else:
            main_address = self.GetFunctionAddress(function_name="main")
            if main_address is not None:
                self.state = self.project.factory.call_state(addr=main_address)
            else:
                self.state = self.project.factory.entry_state()

    def CheckHaveFunction(self, function_name="read"):
        """
        check whether this function_name's function is in this binary
        :param function_name: the function name to check
        :return: True when have, False when not have
        """
        obj = self.project.loader.main_object
        if function_name == "scanf":
            function_name = "__isoc99_scanf"
        if self.binary_static:
            symbol = obj.get_symbol(function_name)
            if symbol is not None:
                # this line need debug, don't test much
                return True
            else:
                return False
        else:
            if function_name in obj.plt.keys():
                return True
            else:
                return False

    def GetFunctionAddress(self, function_name):
        """
        due to static binary and dynamic binary differences,
        this function is used to get the function's address
        :param function_name: the function's name
        :return: the functions address , None if not found
        """
        obj = self.project.loader.main_object
        if function_name == "scanf":
            function_name = "__isoc99_scanf"
        if self.binary_static:
            symbol = obj.get_symbol(function_name)
            if symbol is not None:
                # this line need debug, don't test much
                function_address = symbol.linked_addr
            else:
                log.Exception(f"no {function_name} in this binary, no meaning for this action")
                return None
        else:
            if function_name in obj.plt.keys():
                function_address = obj.plt[function_name]
            else:
                log.Exception(f"no {function_name} in this binary, no meaning for this action")
                return None
        return function_address

    def GetString(self, state, address):
        """
        return the string from this address, according to the state
        :param state: the current state
        :param address: the address of the string
        :return: the string
        """
        max_length = 0x100
        string = ""
        for i in range(max_length):
            char_sym = state.mem[address + i].uint8_t.resolved
            if char_sym.symbolic:
                log.Exception("the string's content is symbolic. please check it")
                return ""
            char = chr(state.solver.eval(char_sym))
            if char == "\x00":
                break
            string += char
        return string

    def ParseFormatString(self, formatstring=""):
        """
        return the formats of the formatstring
        :param formatstring: the format string, such as %s
        :return: the formats
        """
        return re.findall(r"%\d*[dscuoxX]", formatstring)

    def PrintfCond(self, state):
        """
        finish the printf function's condition, if it is a printf function call
        call check of read, and then check the stack overflow vulnerability.
        :param state: the current state to check
        :return: return True when it is a printf call, False when not
        """
        printf_address = self.GetFunctionAddress("printf")
        if printf_address is None:
            # log.Exception("no printf in this binary, no meaning for this function")
            return False
        if state.arch.name == "X86":
            eip = state.solver.eval(state.regs.eip)
            if eip == printf_address:
                return True
            else:
                return False
        elif state.arch.name == "AMD64":
            rip = state.solver.eval(state.regs.rip)
            if rip == printf_address:
                return True
            else:
                return False
        return False

    def AvoidFormatStringVuln(self, state):
        """
        if there is a format string Vulnerability in this binary,
        it may end this fuzz, so we need to give a concrete value to avoid this error
        remember in stack overflow we just check stack overflow vulnerability
        :param state: the angr state
        :return: None
        """
        call_address = state.solver.eval(state.mem[state.regs.rsp].int.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        log.info("fmt_rdi_symbolic:" + str(state.regs.rdi.symbolic))
        if state.regs.rdi.symbolic == True:
            log.info("printf function rdi is symbolic")
            log.Exception("format string rdi is symbolic")
            return None
        else:
            rdi = state.solver.eval(state.regs.rdi)
            # print(type(state.mem[rdi]))
            format_string = state.memory.load(rdi, 4)
            # print(dir(format_string))
            if format_string.symbolic:
                log.success("find a symbolic format string")
                log.success("call_addr:" + hex(state.solver.eval(state.mem[state.regs.rsp].int.resolved) - 5))
                log.info("try to avoid this error")
                copystate = state.copy()
                rdi = copystate.solver.eval(copystate.regs.rdi)
                payload = "aaa\x00"
                constrained_parameter_address = rdi
                constrained_parameter_size_bytes = len(payload)
                constrained_parameter_bitvector = state.memory.load(
                    constrained_parameter_address,
                    constrained_parameter_size_bytes
                )
                constrained_parameter_desired_value = payload
                constraint_expression = constrained_parameter_bitvector == constrained_parameter_desired_value
                copystate.add_constraints(constraint_expression)
                if copystate.satisfiable():
                    state.add_constraints(constraint_expression)
                    log.success(
                        "have avoided a format string Vulnerability in {address}".format(address=hex(call_address)))
                    return True
            else:
                log.info("this printf function's format string is stable")
                log.info("not useful for format string Vulnerability")
                return False

    def ReadCond(self, state):
        """
        finish the read function's condition, if it is a read function call
        call check of read, and then check the stack overflow vulnerability.
        :param state: the current state to check
        :return: return True when it is a read call, False when not
        """
        read_address = self.GetFunctionAddress("read")
        if read_address is None:
            log.Exception("no read in this binary, no meaning for this function")
            return False
        if state.arch.name == "X86":
            eip = state.solver.eval(state.regs.eip)
            if eip == read_address:
                return True
            else:
                return False
        elif state.arch.name == "AMD64":
            rip = state.solver.eval(state.regs.rip)
            if rip == read_address:
                return True
            else:
                return False
        return False

    def ReadStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this read function
        :param state: the current state to check
        :return: False when no stack overflow, True when this function
        has stack overflow inside it, and generate the payload
        """
        if state.arch.name == "AMD64":
            log.info("#" * 0x10 + "read function call" + "#" * 0x10)
            call_address = state.solver.eval(state.mem[state.regs.rsp].int64_t.resolved) - 5
            log.info("call_addr:" + hex(call_address))
            rdi = state.solver.eval(state.regs.rdi)
            log.info("rdi:" + hex(rdi))
            if state.regs.rdx.symbolic == True:
                log.info("read funtion's length is symbolic")
            else:
                log.info("read funtion's length is not symbolic")
                log.info("check whether there is a overflow here")
                if state.regs.rsi.symbolic == True:
                    log.info("read function's address is symbolic")
                else:
                    log.info("read function's address is not symbolic")
                    rbp = state.solver.eval(state.regs.rbp)
                    rsi = state.solver.eval(state.regs.rsi)
                    rdx = state.solver.eval(state.regs.rdx)
                    # print(hex(rbp - rsi))
                    # 8 for the rsp
                    overflow_needlength = rbp - rsi + 8
                    input_length = rdx
                    # print(self.fuzzer.simgr)
                    if input_length > overflow_needlength:
                        log.success(
                            "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                        statelog = SingleStackOverFlowStateLog(
                            state=state, prefixlength=overflow_needlength,
                            needline=False, avoidchars="", needlength=input_length,
                            functionname="read", pre_statelog=self.pre_statelog
                        )
                        self.stackoverflowlog.insert(statelog=statelog)
                        log.success("have logged to the stackoverflow log")
                    else:
                        log.info(
                            "there isn't a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
        elif state.arch.name == "X86":
            log.info("#" * 0x10 + "read function call" + "#" * 0x10)
            call_address = state.solver.eval(state.mem[state.regs.esp].int.resolved) - 5
            log.info("call_addr:" + hex(call_address))
            par1 = state.solver.eval(state.mem[state.regs.esp + 4].int.resolved)
            log.info("par1:" + hex(par1))
            par3 = state.mem[state.regs.esp + 12].int.resolved
            if par3.symbolic == True:
                log.info("read funtion's length is symbolic")
            else:
                log.info("read funtion's length is not symbolic")
                log.info("check whether there is a overflow here")
                par2 = state.mem[state.regs.esp + 8].int.resolved
                if par2.symbolic == True:
                    log.info("read function's address is symbolic")
                else:
                    log.info("read function's address is not symbolic")
                    ebp = state.solver.eval(state.regs.ebp)
                    buf = state.solver.eval(par2)
                    length = state.solver.eval(par3)
                    # print(hex(rbp - rsi))
                    # 8 for the rsp
                    overflow_needlength = ebp - buf + 4
                    input_length = length
                    # print(self.fuzzer.simgr)
                    if input_length > overflow_needlength:
                        log.success(
                            "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                        statelog = SingleStackOverFlowStateLog(
                            state=state, prefixlength=overflow_needlength,
                            needline=False, avoidchars="", needlength=input_length,
                            functionname="read", pre_statelog=self.pre_statelog
                        )
                        self.stackoverflowlog.insert(statelog=statelog)
                        log.success("have logged to the stackoverflow log")
                    else:
                        log.info(
                            "there isn't a stack overflow Vulnerability in {address}".format(address=hex(call_address)))

    def GetsCond(self, state):
        """
        finish the read function's condition, if it is a gets function call
        ruturn true, else return False
        :param state: the current state to check
        :return: return True when it is a gets call, False when not
        """
        gets_address = self.GetFunctionAddress("gets")
        if gets_address is None:
            log.Exception("no gets in this binary, no meaning for this function")
            return False
        if state.arch.name == "X86":
            eip = state.solver.eval(state.regs.eip)
            if eip == gets_address:
                return True
            else:
                return False
        elif state.arch.name == "AMD64":
            rip = state.solver.eval(state.regs.rip)
            if rip == gets_address:
                return True
            else:
                return False
        return False

    def GetsStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this gets function
        :param state: the current state to check
        :return: False when no stack overflow, True when this function
        has stack overflow inside it, and generate the payload
        """
        if state.arch.name == "AMD64":
            log.info("#" * 0x10 + "gets function call" + "#" * 0x10)
            call_address = state.solver.eval(state.mem[state.regs.rsp].uint64_t.resolved) - 5
            log.info("call_addr:" + hex(call_address))
            rdi = state.solver.eval(state.regs.rdi)
            rsp = state.solver.eval(state.regs.rsp)
            rbp = state.solver.eval(state.regs.rbp)
            if rbp >= rdi >= rsp:
                log.success("there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
            else:
                log.info("parameter is not in this function's variable, maybe in global segement")
            buf = rdi
            overflow_needlength = rbp - buf + 8
            statelog = SingleStackOverFlowStateLog(
                state=state, prefixlength=overflow_needlength,
                needline=True, avoidchars="\n", needlength=0,
                functionname="gets", pre_statelog=self.pre_statelog
            )
            self.stackoverflowlog.insert(statelog=statelog)
            log.success("have logged to the stackoverflow log")
        elif state.arch.name == "X86":
            log.info("#" * 0x10 + "gets function call" + "#" * 0x10)
            call_address = state.solver.eval(state.mem[state.regs.esp].int.resolved) - 5
            log.info("call_addr:" + hex(call_address))
            par1 = state.solver.eval(state.mem[state.regs.esp + 4].int.resolved)
            log.info("par1:" + hex(par1))
            esp = state.solver.eval(state.regs.esp)
            ebp = state.solver.eval(state.regs.ebp)
            if ebp >= par1 >= esp:
                log.success("there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
            else:
                log.info("parameter is not in this function's variable, maybe in global segement")
            buf = par1
            overflow_needlength = ebp - buf + 4
            statelog = SingleStackOverFlowStateLog(
                state=state, prefixlength=overflow_needlength,
                needline=True, avoidchars="\n", needlength=0,
                functionname="gets", pre_statelog=self.pre_statelog
            )
            self.stackoverflowlog.insert(statelog=statelog)
            log.success("have logged to the stackoverflow log")

    def ScanfCond(self, state):
        """
        finish the scanf function's condition, if it is a scanf function call
        :param state: the current state to check
        :return: return True when it is a gets call, False when not
        """
        scanf_address = self.GetFunctionAddress("scanf")
        if scanf_address is None:
            log.Exception("no scanf in this binary, no meaning for this function")
            return False
        if state.arch.name == "X86":
            eip = state.solver.eval(state.regs.eip)
            if eip == scanf_address:
                return True
            else:
                return False
        elif state.arch.name == "AMD64":
            rip = state.solver.eval(state.regs.rip)
            if rip == scanf_address:
                return True
            else:
                return False
        return False

    def ScanfStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this scanf function
        especially for the %s format
        :param state: the current state to check
        :return: False when no stack overflow, True when this function
        has stack overflow inside it, and generate the payload
        """
        if state.arch.name == "AMD64":
            log.info("#" * 0x10 + "scanf function call" + "#" * 0x10)
            call_address = state.solver.eval(state.mem[state.regs.rsp].uint64_t.resolved) - 5
            log.info("call_addr:" + hex(call_address))
            par1_sym = state.regs.rdi
            if par1_sym.symbolic:
                log.Exception("scanf has an symbolic format string, please check it")
                return False
            par1 = state.solver.eval(par1_sym)
            log.info("par1:" + hex(par1))
            formatstring = self.GetString(state=state, address=par1)
            formats = self.ParseFormatString(formatstring=formatstring)
            par_offset = 8
            have_stack_overflow = False
            overflow_needlength = 0
            overflow_index = -1
            maps = [state.regs.rdi, state.regs.rsi, state.regs.rdx,
                    state.regs.rcx, state.regs.r8, state.regs.r9]
            for i in range(len(formats)):
                format = formats[i]
                if format[-1] == "s":
                    # means here we have a %s format string
                    if format[1:-1] == "":
                        length = "max"
                    else:
                        length = int(format[1:-1])
                    if par_offset < 6 * 8:
                        # 6 for rdi rsi rdx rcx r8 r9
                        # temp = state.solver.eval(maps[par_offset // 8])
                        parn_sym = maps[par_offset // 8]
                    else:
                        # + 8 for the return address in stack
                        temp = par_offset - 6 * 8 + 8
                        parn_sym = state.mem[state.regs.rsp + temp].uint64_t.resolved
                    if parn_sym.symbolic:
                        log.Exception("scanf has an symbolic format string, please check it")
                        return False
                    parn_address = state.solver.eval(parn_sym)
                    rsp = state.solver.eval(state.regs.rsp)
                    rbp = state.solver.eval(state.regs.rbp)
                    need_length = rbp - parn_address
                    if length == "max" and rbp >= parn_address >= rsp:
                        log.success(
                            "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                        have_stack_overflow = True
                        overflow_needlength = rbp - parn_address + 8
                        overflow_index = i
                    elif length != "max" and length > need_length:
                        log.success(
                            "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                        have_stack_overflow = True
                        overflow_needlength = rbp - parn_address + 8
                        overflow_index = i
                    else:
                        log.info("parameter is not in this function's variable, maybe in global segement")
                        overflow_needlength = 0
                par_offset += 8
            if have_stack_overflow:
                scanfinfo = ScanfInfo(
                    formatstring=formatstring, overflow_index=overflow_index,
                    formats=formats
                )
                statelog = SingleStackOverFlowStateLog(
                    state=state, prefixlength=overflow_needlength,
                    needline=True, avoidchars="\n\x20", needlength=0,
                    functionname="scanf", pre_statelog=self.pre_statelog,
                    scanfinfo=scanfinfo
                )
                self.stackoverflowlog.insert(statelog=statelog)
                log.success("have logged to the stackoverflow log")
        elif state.arch.name == "X86":
            log.info("#" * 0x10 + "scanf function call" + "#" * 0x10)
            call_address = state.solver.eval(state.mem[state.regs.esp].int.resolved) - 5
            log.info("call_addr:" + hex(call_address))
            par1_sym = state.mem[state.regs.esp + 4].uint32_t.resolved
            if par1_sym.symbolic:
                log.Exception("scanf has an symbolic format string, please check it")
                return False
            par1 = state.solver.eval(par1_sym)
            log.info("par1:" + hex(par1))
            formatstring = self.GetString(state=state, address=par1)
            formats = self.ParseFormatString(formatstring=formatstring)
            par_offset = 8
            have_stack_overflow = False
            overflow_needlength = 0
            overflow_index = -1
            for i in range(len(formats)):
                format = formats[i]
                if format[-1] == "s":
                    # means here we have a %s format string
                    if format[1:-1] == "":
                        length = "max"
                    else:
                        length = int(format[1:-1])
                    parn_sym = state.mem[state.regs.esp + par_offset].uint32_t.resolved
                    if parn_sym.symbolic:
                        log.Exception("scanf has an symbolic format string, please check it")
                        return False
                    parn_address = state.solver.eval(parn_sym)
                    esp = state.solver.eval(state.regs.esp)
                    ebp = state.solver.eval(state.regs.ebp)
                    need_length = ebp - parn_address
                    if length == "max" and ebp >= parn_address >= esp:
                        log.success("there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                        have_stack_overflow = True
                        overflow_needlength = ebp - parn_address + 4
                        overflow_index = i
                    elif length != "max" and length > need_length and ebp >= parn_address >= esp:
                        log.success("there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                        have_stack_overflow = True
                        overflow_needlength = ebp - parn_address + 4
                        overflow_index = i
                    else:
                        log.info("parameter is not in this function's variable, maybe in global segement")
                        overflow_needlength = 0
                par_offset += 4
            if have_stack_overflow:
                scanfinfo = ScanfInfo(
                    formatstring=formatstring, overflow_index=overflow_index,
                    formats=formats
                )
                statelog = SingleStackOverFlowStateLog(
                    state=state, prefixlength=overflow_needlength,
                    needline=True, avoidchars="\n\x20", needlength=0,
                    functionname="scanf", pre_statelog=self.pre_statelog,
                    scanfinfo=scanfinfo
                )
                self.stackoverflowlog.insert(statelog=statelog)
                log.success("have logged to the stackoverflow log")

    def InitReadBreakpoint(self, state=None):
        """
        init breakpoint used in read, for check read function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.CheckHaveFunction(function_name="read"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.ReadCond, action=self.ReadStackOverflowCheck)
        else:
            return None

    def InitGetsBreakpoint(self, state=None):
        """
        init breakpoint used in gets, for check gets function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.CheckHaveFunction(function_name="gets"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.GetsCond, action=self.GetsStackOverflowCheck)
        else:
            return None

    def InitScanfBreakpoint(self, state=None):
        """
        init breakpoint used in gets, for check gets function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.CheckHaveFunction(function_name="scanf"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.ScanfCond, action=self.ScanfStackOverflowCheck)
        else:
            return None

    def InitCheckStackOverflowBreakpoints(self, fmtstatelog=None):
        """
        init the breakpoints used in stackoverflow check
        if fmtstatelog is set, use this state to run the fuzz
        if fmtstatelog not set, use the entry state to run the fuzz, because
        it means we have to check the vulnerability from the beginning of a binary
        :param fmtstatelog: the state log of format string vulnerablity
        :return: no return
        """
        if fmtstatelog is None:
            state = self.state
        else:
            state = fmtstatelog.state
        # init all the function's check breakpoint,
        # for the stack overflow vulnerablt functions
        self.InitReadBreakpoint(state=state)
        self.InitGetsBreakpoint(state=state)
        self.InitScanfBreakpoint(state=state)
        # state.inspect.b("call", when=angr.BP_BEFORE, condition=self.PrintfCond, action=self.AvoidFormatStringVuln)

    def StackOverflowMain(self, stepcount=0x1000, fmtstatelog=None):
        self.InitCheckStackOverflowBreakpoints(fmtstatelog=fmtstatelog)
        if fmtstatelog is None:
            fuzzer = Fuzzer(
                binarypath=self.binarypath, project=self.project,
                state=self.state)
        else:
            self.pre_statelog = fmtstatelog
            project = fmtstatelog.project
            state = fmtstatelog.state
            fuzzer = Fuzzer(
                binarypath=self.binarypath,
                project=project, state=state)
        fuzzer.run(stepcount=stepcount)

    def StackOverflowFMTStateMain(self, stepcount=0x1000):
        self.InitCheckStackOverflowBreakpoints()
        fuzzer = Fuzzer(self.binarypath, self.project, self.state)
        fuzzer.run(stepcount=stepcount)


if __name__ == '__main__':
    binarypath = "../binaries/stack_overflow/leak_canary/leak_canary"
    StackOverflowExamine = StackOverflowExamine(binarypath)
    StackOverflowExamine.StackOverflowMain()
