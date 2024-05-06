"""
author : 4everdestiny
create_time : 2022.3.1
description : this is the code to find the stack overflow Vulnerability.
input : binary path
output : exploit of stack overflow
"""
import re

import angr
from fuzz.Fuzzer import Fuzzer
from log import log
from state.StackOverFlowStateLog import StackOverFlowStateLog
from state.StackOverFlowStateLog import SingleStackOverFlowStateLog
from log.ScanfInfo import ScanfInfo
from log.StrcpyInfo import StrcpyInfo
from global_func.StateHelper import StateHelper
from global_func.FuzzerHelper import FuzzerHelper
import configparser

log = log.Log()


class StackOverflowExamineX64:
    def __init__(self, binarypath, function_helper=None, protection=None):
        self.binarypath = binarypath
        self.binary_static = False
        self.function_helper = function_helper
        self.protection = protection
        self.project = False
        self.NewProject()
        # self.fuzzer = Fuzzer(self.binarypath, self.project, self.state)
        self.fuzzer = None
        self.stackoverflowlog = StackOverFlowStateLog()
        # the pre_statelog is used in format string state
        self.pre_statelog = None
        self.onevulnforhook = False
        self.onevulnforgeneral = False
        self.havefindvulnforhook = False
        self.havefindvulnforgeneral = False

    def readconf(self):
        """
        this is the function to read the config file
        :return: None
        """
        conf = configparser.ConfigParser()
        conf.read("../config.ini")
        if conf.has_section("Fuzzer"):
            self.onevulnforhook = conf.get("Fuzzer", "onevulnforhook") == "True"
            self.onevulnforgeneral = conf.get("Fuzzer", "onevulnforgeneral") == "True"
        else:
            log.Exception("Fuzzer config missing")

    def NewProject(self):
        self.project = angr.Project(self.binarypath, auto_load_libs=True)
        if not self.protection["static"]:
            self.state = self.project.factory.entry_state(
                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
                remove_options={angr.options.ALL_FILES_EXIST,
                                angr.options.LAZY_SOLVES},
                args=[self.project.filename]
            )
            # self.state.fs.insert(filename, symfile)
        else:
            fuzzerhelper = FuzzerHelper(binary_path=self.binarypath, function_helper=self.function_helper)
            fuzzerhelper.HookForStaticBinary(project=self.project, protection=self.protection)
            # self.HookForStripperStaticBinary()
            """
            if self.function_helper.CheckHaveFunction(func_name="main"):
                main_addr = self.function_helper.GetFunctionAddress(func_name="main")
                self.state = self.project.factory.call_state(
                    addr=main_addr,
                    add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                 angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
                    remove_options={angr.options.ALL_FILES_EXIST,
                                    angr.options.LAZY_SOLVES}
                )
            """
            self.state = self.project.factory.entry_state(
                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
                remove_options={angr.options.ALL_FILES_EXIST,
                                angr.options.LAZY_SOLVES},
                args=[self.project.filename]
            )

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
        printf_address = self.function_helper.GetFunctionAddress(func_name="printf")
        if printf_address is None:
            # log.Exception("no printf in this binary, no meaning for this function")
            return False
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        rip = state.solver.eval(state.regs.rip)
        if rip == printf_address:
            return True
        else:
            return False

    def AvoidFormatStringVuln(self, state):
        """
        if there is a format string Vulnerability in this binary,
        it may end this fuzz, so we need to give a concrete value to avoid this error
        remember in stack overflow we just check stack overflow vulnerability
        :param state: the angr state
        :return: None
        """
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
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

    def ParseInputInArgv(self, state=None, test_input=b""):
        """
        parse the input for strcpy and find this in argv
        :param state: the current state
        :param state: the test_input
        :return: True when find, False when not, prefix_payload_index,
        suffix_payload_index, output_index
        """
        # state.mem[state.solver.eval(state.mem[state.solver.eval(state.posix.argv) + 0].uint32_t.resolved)].uint32_t.resolved = <BV32 0x6d6f682f>
        argc = state.solver.eval(state.posix.argc)
        argv_addr = state.solver.eval(state.posix.argv)
        for i in range(argc):
            argvi_addr = state.mem[argv_addr + i * 8].uint64_t.resolved
            state_helper = StateHelper(state=state)
            symbolic_length = state_helper.GetSymbolicStringLength(address=argvi_addr)
            if symbolic_length == 0:
                argvi_sym = state.mem[argvi_addr].string.resolved
                argv_bytes = state.solver.eval(argvi_sym, cast_to=bytes)
            else:
                argvi_sym = state.memory.load(argvi_addr, symbolic_length)
                argv_bytes = state.solver.eval(argvi_sym, cast_to=bytes)
            if test_input in argv_bytes:
                strcpyinfo = StrcpyInfo(inargv=True, argv_index=i)
                return strcpyinfo
        return None

    def ParseInput(self, state=None):
        """
        parse the input for strcpy
        for example:
        read(0, buf, 0x100)
        strcpy(s, buf)
        buf must be a symbolic string
        we need to find the buf part in the input
        if we cannot find, means we have some encryption for the input
        :param state: the current state
        :return: True when find, False when not, prefix_payload_index,
        suffix_payload_index, output_index
        """
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return None
        copy_state = state.copy()
        par2_sym = copy_state.regs.rsi
        par2 = copy_state.solver.eval(par2_sym)
        state_helper = StateHelper(state=state)
        par2_length = state_helper.GetSymbolicStringLength(address=par2)
        test_input = b"1" * par2_length
        par2 = copy_state.solver.eval(par2_sym)
        payload = test_input
        constrained_parameter_address = par2
        constrained_parameter_size_bytes = len(payload)
        constrained_parameter_bitvector = state.memory.load(
            constrained_parameter_address,
            constrained_parameter_size_bytes
        )
        constrained_parameter_desired_value = payload
        constraint_expression = constrained_parameter_bitvector == constrained_parameter_desired_value
        copy_state.add_constraints(constraint_expression)
        if copy_state.satisfiable():
            # we can insert our input in par2, and this input can be
            # dumped to strcpy's par1, thus we have a stack overflow
            all_input = copy_state.posix.dumps(0)
            all_output = copy_state.posix.dumps(1)
            if test_input not in all_input:
                # here maybe the symbolic length is longer
                # for sometime the ebp is symbolic
                # change the init state to full_init_state
                # log.Exception("cannot find the payload in input, maybe have encryption")
                return self.ParseInputInArgv(state=copy_state, test_input=test_input)
            prefix_index = [0, all_input.index(test_input)]
            suffix_index = [all_input.index(test_input) + len(test_input), len(all_input)]
            output_index = [0, len(all_output)]
            strcpyinfo = StrcpyInfo(prefix_payload_index=prefix_index,
                                    suffix_payload_index=suffix_index,
                                    output_index=output_index)
            return strcpyinfo
        else:
            log.Exception("cannot find the payload in input, maybe have encryption")
            return None

    def ReadCond(self, state):
        """
        finish the read function's condition, if it is a read function call
        call check of read, and then check the stack overflow vulnerability.
        :param state: the current state to check
        :return: return True when it is a read call, False when not
        """
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        read_address = self.function_helper.GetFunctionAddress(func_name="read")
        if read_address is None:
            log.Exception("no read in this binary, no meaning for this function")
            return False
        rip = state.solver.eval(state.regs.rip)
        if rip == read_address:
            return True
        else:
            return False

    def ReadStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this read function
        :param state: the current state to check
        :return: False when no stack overflow, True when this function
        has stack overflow inside it, and generate the payload
        """
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "read function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.rsp].int64_t.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        rdi = state.solver.eval(state.regs.rdi)
        log.info("rdi:" + hex(rdi))
        if state.regs.rdx.symbolic == True:
            log.info("read function's length is symbolic")
        else:
            log.info("read function's length is not symbolic")
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
                if input_length > overflow_needlength and overflow_needlength > 0:
                    log.success(
                        "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                    statelog = SingleStackOverFlowStateLog(
                        state=state, prefixlength=overflow_needlength,
                        needline=False, avoidchars=b"", needlength=input_length,
                        functionname="read", pre_statelog=self.pre_statelog,
                        project=self.project
                    )
                    self.stackoverflowlog.insert(statelog=statelog)
                    self.havefindvulnforhook = True
                    self.JudgeEndFuzz()
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
        gets_address = self.function_helper.GetFunctionAddress(func_name="gets")
        if gets_address is None:
            log.Exception("no gets in this binary, no meaning for this function")
            return False
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        if state.arch.name == "AMD64":
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
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
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
            return False
        buf = rdi
        overflow_needlength = rbp - buf + 8
        statelog = SingleStackOverFlowStateLog(
            state=state, prefixlength=overflow_needlength,
            needline=True, avoidchars=b"\n", needlength=0,
            functionname="gets", pre_statelog=self.pre_statelog,
            project=self.project
        )
        self.stackoverflowlog.insert(statelog=statelog)
        self.havefindvulnforhook = True
        self.JudgeEndFuzz()
        log.success("have logged to the stackoverflow log")

    def ScanfCond(self, state):
        """
        finish the scanf function's condition, if it is a scanf function call
        :param state: the current state to check
        :return: return True when it is a gets call, False when not
        """
        scanf_address = self.function_helper.GetFunctionAddress(func_name="scanf")
        if scanf_address is None:
            log.Exception("no scanf in this binary, no meaning for this function")
            return False
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        rip = state.solver.eval(state.regs.rip)
        if rip == scanf_address:
            return True
        else:
            return False

    def ScanfStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this scanf function
        especially for the %s format
        :param state: the current state to check
        :return: False when no stack overflow, True when this function
        has stack overflow inside it, and generate the payload
        """
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "scanf function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.rsp].uint64_t.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1_sym = state.regs.rdi
        if par1_sym.symbolic:
            log.Exception("scanf has an symbolic format string, please check it")
            return False
        par1 = state.solver.eval(par1_sym)
        log.info("par1:" + hex(par1))
        state_helper = StateHelper(state=state)
        formatstring = state_helper.GetString(address=par1)
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
                needline=True, avoidchars=b"\n\x20", needlength=0,
                functionname="scanf", pre_statelog=self.pre_statelog,
                scanfinfo=scanfinfo, project=self.project
            )
            self.stackoverflowlog.insert(statelog=statelog)
            # self.havefindvuln = True
            self.havefindvulnforhook = True
            self.JudgeEndFuzz()
            log.success("have logged to the stackoverflow log")

    def StrcpyCond(self, state):
        """
        finish the strcpy function's condition, if it is a strcpy function call
        ruturn true, else return False
        :param state: the current state to check
        :return: return True when it is a gets call, False when not
        """
        strcpy_address = self.function_helper.GetFunctionAddress(func_name="strcpy")
        if strcpy_address is None:
            log.Exception("no gets in this binary, no meaning for this function")
            return False
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        rip = state.solver.eval(state.regs.rip)
        if rip == strcpy_address:
            return True
        else:
            return False

    def StrcpyStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this strcpy function
        :param state: the state to check
        :return: True when have, False when not
        """
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "strcpy function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.rsp].uint64_t.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1_sym = state.regs.rdi
        par2_sym = state.regs.rsi
        if par1_sym.symbolic:
            log.info("strcpy has an symbolic target address, please check it")
            return False
        par1 = state.solver.eval(par1_sym)
        log.info("par1:" + hex(par1))
        if par2_sym.symbolic:
            log.info("strcpy has a symbolic source address, maybe we cannot use this function to ROP")
            return False
        par2 = state.solver.eval(par2_sym)
        log.info("par2:" + hex(par2))
        statehelper = StateHelper(state=state)
        par2_length = statehelper.GetSymbolicStringLength(address=par2)
        rsp = state.solver.eval(state.regs.rsp)
        rbp = state.solver.eval(state.regs.rbp)
        need_length = rbp - par1 + 8
        if par2_length >= need_length and rbp >= par1 >= rsp:
            log.info("there is a stack overflow in this strcpy")
            strcpyinfo = self.ParseInput(state)
            if strcpyinfo is None:
                log.Exception("cannot find original payload in standard input, maybe there is a encryption")
                return False
            statelog = SingleStackOverFlowStateLog(
                state=state, prefixlength=need_length,
                needline=False, avoidchars=b"\x00\n", needlength=par2_length,
                functionname="strcpy", pre_statelog=self.pre_statelog,
                strcpyinfo=strcpyinfo, project=self.project
            )
            self.stackoverflowlog.insert(statelog=statelog)
            self.havefindvulnforhook = True
            self.JudgeEndFuzz()
            log.success("have logged to the stackoverflow log")

    def StrncpyCond(self, state):
        """
        finish the strcpy function's condition, if it is a strcpy function call
        ruturn true, else return False
        :param state: the current state to check
        :return: return True when it is a gets call, False when not
        """
        strncpy_address = self.function_helper.GetFunctionAddress(func_name="strncpy")
        if strncpy_address is None:
            log.Exception("no gets in this binary, no meaning for this function")
            return False
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        rip = state.solver.eval(state.regs.rip)
        if rip == strncpy_address:
            return True
        else:
            return False

    def StrncpyStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this strncpy function
        :param state: the state to check
        :return: True when have, False when not
        """
        if state.arch.name != "AMD64":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "strncpy function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.rsp].uint64_t.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1_sym = state.regs.rdi
        par2_sym = state.regs.rsi
        par3_sym = state.regs.rdx
        if par1_sym.symbolic:
            log.info("strncpy has an symbolic target address, please check it")
            return False
        par1 = state.solver.eval(par1_sym)
        log.info("par1:" + hex(par1))
        if par2_sym.symbolic:
            log.info("strncpy has a symbolic source address, maybe we cannot use this function to ROP")
            return False
        par2 = state.solver.eval(par2_sym)
        log.info("par2:" + hex(par2))
        if par3_sym.symbolic:
            log.info("strncpy has a symbolic length, maybe we cannot use this function to ROP")
            return False
        par3 = state.solver.eval(par3_sym)
        log.info("par3:" + hex(par3))
        state_helper = StateHelper(state=state)
        par2_length = state_helper.GetSymbolicStringLength(address=par2)
        rsp = state.solver.eval(state.regs.rsp)
        rbp = state.solver.eval(state.regs.rbp)
        need_length = rbp - par1 + 8
        if par2_length > par3:
            input_length = par3
        else:
            input_length = par2_length
        if input_length >= need_length and rbp >= par1 >= rsp:
            log.info("there is a stack overflow in this strcpy")
            strcpyinfo = self.ParseInput(state)
            if strcpyinfo is None:
                log.Exception("cannot find original payload in standard input, maybe there is a encryption")
                return False
            statelog = SingleStackOverFlowStateLog(
                state=state, prefixlength=need_length,
                needline=False, avoidchars=b"\x00\n", needlength=input_length,
                functionname="strncpy", pre_statelog=self.pre_statelog,
                strcpyinfo=strcpyinfo, project = self.project
            )
            self.stackoverflowlog.insert(statelog=statelog)
            self.havefindvulnforhook = True
            self.JudgeEndFuzz()
            log.success("have logged to the stackoverflow log")

    def VariableReturnAddressCond(self, state):
        """
        for general check, when the return address is a symbolic value
        means there is a chance we can control the return address
        thus probably there is a stack overflow vulnerability
        :param state: the current state
        :return: True when return address is symbolic value, false when not
        """
        # return_address_sym = state.mem[state.regs.esp].uint32_t.resolved
        # ebp_sym = state.mem[state.regs.esp - 4].uint32_t.resolved
        rip = state.regs.rip
        # rip_value = state.solver.eval(rip)
        # log.info("ret from " + hex(rip_value))
        # text_section = self.project.loader.main_object.sections_map[".text"]
        # is_text = text_section.max_addr >= eip >= text_section.min_addr
        if rip.symbolic:
            log.info("find a function's return address is symbolic, means there is a stack overflow vunlnerability maybe")
            return True
        else:
            return False

    def VariableReturnAddressHandler(self, state):
        """
        when general stack overflow hit, return address == symbolic, come to this function
        :param state: the current state
        :return: None
        """
        statelog = SingleStackOverFlowStateLog(
            state=state, prefixlength=0,
            needline=False, avoidchars=b"", needlength=0,
            functionname="general_check", pre_statelog=self.pre_statelog,
            project=self.project
        )
        self.stackoverflowlog.insert(statelog=statelog)
        self.havefindvulnforgeneral = True
        self.JudgeEndFuzz()
        log.success("have logged to the stackoverflow log")

    def InitReadBreakpoint(self, state=None):
        """
        init breakpoint used in read, for check read function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.function_helper.CheckHaveFunction(func_name="read"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.ReadCond, action=self.ReadStackOverflowCheck)
        else:
            return None

    def InitGetsBreakpoint(self, state=None):
        """
        init breakpoint used in gets, for check gets function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.function_helper.CheckHaveFunction(func_name="gets"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.GetsCond, action=self.GetsStackOverflowCheck)
        else:
            return None

    def InitScanfBreakpoint(self, state=None):
        """
        init breakpoint used in gets, for check gets function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.function_helper.CheckHaveFunction(func_name="scanf"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.ScanfCond, action=self.ScanfStackOverflowCheck)
        else:
            return None

    def InitStrcpyBreakpoint(self, state=None):
        """
        init breakpoint used in strcpy, for check strcpy function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.function_helper.CheckHaveFunction(func_name="strcpy"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.StrcpyCond, action=self.StrcpyStackOverflowCheck)
        else:
            return None

    def InitStrncpyBreakpoint(self, state=None):
        """
        init breakpoint used in strncpy, for check strncpy function's overflow
        :param state: the state which to check
        :return: None
        """
        if self.function_helper.CheckHaveFunction(func_name="strncpy"):
            state.inspect.b("call", when=angr.BP_BEFORE, condition=self.StrncpyCond, action=self.StrncpyStackOverflowCheck)
        else:
            return None

    def InitGeneralCheckBreakpoint(self, state=None):
        """
        init breakpoints used in general check
        what is general check, just for we don't know or functions not added in check
        :param state: the state which to check
        :return: None
        """
        state.inspect.b("return", when=angr.BP_BEFORE, condition=self.VariableReturnAddressCond, action=self.VariableReturnAddressHandler)

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
        self.InitStrcpyBreakpoint(state=state)
        self.InitStrncpyBreakpoint(state=state)
        self.InitGeneralCheckBreakpoint(state=state)
        # state.inspect.b("call", when=angr.BP_BEFORE, condition=self.PrintfCond, action=self.AvoidFormatStringVuln)

    def JudgeEndFuzz(self):
        """
        we need to end fuzz when we finish the vulnerability finding
        :return: True when end, False when not
        """
        if self.onevulnforhook and self.onevulnforgeneral:
            if self.havefindvulnforhook and self.havefindvulnforgeneral:
                self.fuzzer.havefindvulnandstop = True

    def StackOverflowMain(self, stepcount=0x10000, fmtstatelog=None):
        self.readconf()
        self.InitCheckStackOverflowBreakpoints(fmtstatelog=fmtstatelog)
        if fmtstatelog is None:
            self.fuzzer = Fuzzer(
                binarypath=self.binarypath, project=self.project,
                state=self.state)
        else:
            self.pre_statelog = fmtstatelog
            project = fmtstatelog.project
            state = fmtstatelog.state
            self.fuzzer = Fuzzer(
                binarypath=self.binarypath,
                project=project, state=state)
        self.fuzzer.run(stepcount=stepcount)

    def StackOverflowFMTStateMain(self, stepcount=0x10000):
        self.InitCheckStackOverflowBreakpoints()
        fuzzer = Fuzzer(self.binarypath, self.project, self.state)
        fuzzer.run(stepcount=stepcount)


if __name__ == '__main__':
    binarypath = "../binaries/stack_overflow/leak_canary/leak_canary"
    StackOverflowExamine = StackOverflowExamineX64(binarypath)
    StackOverflowExamine.StackOverflowMain()
