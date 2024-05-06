"""
author : 4everdestiny
create_time : 2022.3.1
description : this is the code to find the stack overflow Vulnerability.
input : binary path
output : exploit of stack overflow
"""
import re
import sys

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


class StackOverflowExamineX86:
    def __init__(self, binarypath, function_helper=None, protection=None):
        self.binarypath = binarypath
        self.binary_static = False
        # self.sigfilepath = "../binaries/2023_wangding/sigfile/libc6_2.23-0ubuntu11_i386.sig"
        self.function_helper = function_helper
        self.protection = protection
        self.project = None
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
        self.exploit_method = ""

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

    def JudgeEndFuzz(self):
        """
        we need to end fuzz when we finish the vulnerability finding
        :return: True when end, False when not
        """
        if self.onevulnforhook and self.onevulnforgeneral:
            if self.havefindvulnforhook and self.havefindvulnforgeneral:
                self.fuzzer.havefindvulnandstop = True

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
            # self.HookForStripperStaticBinary()
            fuzzerhelper = FuzzerHelper(
                binary_path=self.binarypath, function_helper=self.function_helper
            )
            fuzzerhelper.HookForStaticBinary(
                project=self.project, protection=self.protection
            )
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
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        eip = state.solver.eval(state.regs.eip)
        if eip == printf_address:
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
            argvi_addr = state.mem[argv_addr + i * 4].uint32_t.resolved
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

    def ParseInputInFile(self, state=None, test_input=b""):
        """
        parse the input for strcpy and find this in file
        :param state: the current state
        :param state: the test_input
        :return: True when find, False when not, prefix_payload_index,
        suffix_payload_index, output_index
        """
        # state.mem[state.solver.eval(state.mem[state.solver.eval(state.posix.argv) + 0].uint32_t.resolved)].uint32_t.resolved = <BV32 0x6d6f682f>
        for fd in state.posix.fd.keys():
            if fd in [0, 1, 2]:
                continue
            all_input = state.posix.dumps(fd)
            if test_input in all_input:
                log.success("find test_input in file fd:{fd}".format(fd=fd))
                all_output = state.posix.dumps(sys.stdout.fileno())
                index = all_input.index(test_input) - 1
                prefix_index = [0, index]
                suffix_index = [index + len(test_input) + 1, len(all_input) + 1]
                output_index = [0, len(all_output)]
                strcpyinfo = StrcpyInfo(
                    prefix_payload_index=prefix_index,
                    suffix_payload_index=suffix_index,
                    output_index=output_index,
                    infile=True, file_fd=fd
                )
                log.success("successfully ")
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
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return None
        copy_state = state.copy()
        par2_sym = copy_state.mem[copy_state.regs.esp + 8].uint32_t.resolved
        par2 = copy_state.solver.eval(par2_sym)
        state_helper = StateHelper(state=state)
        par2_length = state_helper.GetSymbolicStringLength(address=par2)
        test_input = b"1" * (par2_length - 1)
        par2 = copy_state.solver.eval(par2_sym)
        payload = test_input
        constrained_parameter_address = par2
        constrained_parameter_size_bytes = len(payload)
        constrained_parameter_bitvector = state.memory.load(
            constrained_parameter_address + 1,
            constrained_parameter_size_bytes
        )
        constrained_parameter_desired_value = payload
        constraint_expression = constrained_parameter_bitvector == constrained_parameter_desired_value
        # copy_state.add_constraints(constraint_expression)
        # print(state.solver.constraints)
        if copy_state.satisfiable(extra_constraints=[constraint_expression]):
            # we can insert our input in par2, and this input can be
            # dumped to strcpy's par1, thus we have a stack overflow
            copy_state.add_constraints(constraint_expression)
            all_input = copy_state.posix.dumps(0)
            all_output = copy_state.posix.dumps(1)
            if test_input not in all_input:
                # here maybe the symbolic length is longer
                # for sometime the ebp is symbolic
                # change the init state to full_init_state
                strcpyinfo = self.ParseInputInArgv(state=copy_state, test_input=test_input)
                if strcpyinfo is not None:
                    return strcpyinfo
                strcpyinfo = self.ParseInputInFile(state=copy_state, test_input=test_input)
                if strcpyinfo is not None:
                    return strcpyinfo
                log.Exception("cannot find the payload in input, maybe have encryption")
                return None
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
        read_address = self.function_helper.GetFunctionAddress(func_name="read")
        if read_address is None:
            log.Exception("no read in this binary, no meaning for this function")
            return False
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        eip = state.solver.eval(state.regs.eip)
        if eip == read_address:
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
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "read function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.esp].uint32_t.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1 = state.solver.eval(state.mem[state.regs.esp + 4].uint32_t.resolved)
        log.info("par1:" + hex(par1))
        par3 = state.mem[state.regs.esp + 12].int.resolved
        if par3.symbolic == True:
            log.info("read function's length is symbolic")
        else:
            log.info("read function's length is not symbolic")
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
                esp = state.solver.eval(state.regs.esp)
                if input_length > overflow_needlength and ebp > buf > esp:
                    log.success(
                        "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                    statelog = SingleStackOverFlowStateLog(
                        state=state, prefixlength=overflow_needlength,
                        needline=False, avoidchars=b"", needlength=input_length,
                        functionname="read", pre_statelog=self.pre_statelog,
                        project=self.project
                    )
                    self.stackoverflowlog.insert(statelog=statelog)
                    log.success("have logged to the stackoverflow log")
                    self.havefindvulnforhook = True
                    self.JudgeEndFuzz()
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
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        eip = state.solver.eval(state.regs.eip)
        if eip == gets_address:
            return True
        else:
            return False

    def GetsStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this gets function
        :param state: the current state to check
        :return: False when no stack overflow, True when this function
        has stack overflow inside it, and generate the payload
        """
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "gets function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.esp].uint32_t.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1 = state.solver.eval(state.mem[state.regs.esp + 4].uint32_t.resolved)
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
        scanf_address = self.function_helper.GetFunctionAddress("scanf")
        if scanf_address is None:
            log.Exception("no scanf in this binary, no meaning for this function")
            return False
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        eip = state.solver.eval(state.regs.eip)
        if eip == scanf_address:
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
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "scanf function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.esp].int.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1_sym = state.mem[state.regs.esp + 4].uint32_t.resolved
        if par1_sym.symbolic:
            log.Exception("scanf has an symbolic format string, please check it")
            return False
        par1 = state.solver.eval(par1_sym)
        log.info("par1:" + hex(par1))
        formatstring = StateHelper(state=state).GetString(address=par1)
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
                    log.success(
                        "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
                    have_stack_overflow = True
                    overflow_needlength = ebp - parn_address + 4
                    overflow_index = i
                elif length != "max" and length > need_length and ebp >= parn_address >= esp:
                    log.success(
                        "there is a stack overflow Vulnerability in {address}".format(address=hex(call_address)))
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
                needline=True, avoidchars=b"\n\x20", needlength=0,
                functionname="scanf", pre_statelog=self.pre_statelog,
                scanfinfo=scanfinfo, project=self.project
            )
            self.stackoverflowlog.insert(statelog=statelog)
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
        gets_address = self.function_helper.GetFunctionAddress("strcpy")
        if gets_address is None:
            log.Exception("no gets in this binary, no meaning for this function")
            return False
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        eip = state.solver.eval(state.regs.eip)
        if eip == gets_address:
            return True
        else:
            return False

    def StrcpyStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this strcpy function
        :param state: the state to check
        :return: True when have, False when not
        """
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "strcpy function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.esp].int.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1_sym = state.mem[state.regs.esp + 4].uint32_t.resolved
        par2_sym = state.mem[state.regs.esp + 8].uint32_t.resolved
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
        par2_length = StateHelper(state=state).GetSymbolicStringLength(address=par2)
        state_helper = StateHelper(state=state)
        is_in_stack, need_length = state_helper.JudgeParInStackAndReturnOffsetX86(par1_sym, state)
        if is_in_stack and need_length < par2_length:
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
        gets_address = self.function_helper.GetFunctionAddress("strncpy")
        if gets_address is None:
            log.Exception("no gets in this binary, no meaning for this function")
            return False
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        eip = state.solver.eval(state.regs.eip)
        if eip == gets_address:
            return True
        else:
            return False

    def StrncpyStackOverflowCheck(self, state):
        """
        check whether there is a stack overflow Vulnerability in this strncpy function
        :param state: the state to check
        :return: True when have, False when not
        """
        if state.arch.name != "X86":
            log.Exception("architecture error, please check it")
            return False
        log.info("#" * 0x10 + "strncpy function call" + "#" * 0x10)
        call_address = state.solver.eval(state.mem[state.regs.esp].uint32_t.resolved) - 5
        log.info("call_addr:" + hex(call_address))
        par1_sym = state.mem[state.regs.esp + 4].uint32_t.resolved
        par2_sym = state.mem[state.regs.esp + 8].uint32_t.resolved
        par3_sym = state.mem[state.regs.esp + 12].uint32_t.resolved
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
        par2_length = StateHelper(state=state).GetSymbolicStringLength(address=par2)
        esp = state.solver.eval(state.regs.esp)
        ebp = state.solver.eval(state.regs.ebp)
        need_length = ebp - par1 + 4
        if par2_length > par3:
            input_length = par3
        else:
            input_length = par2_length
        if input_length >= need_length and ebp >= par1 >= esp:
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
        eip = state.regs.eip
        # eip_value = state.solver.eval(eip)
        # log.info("ret from " + hex(eip_value))
        # text_section = self.project.loader.main_object.sections_map[".text"]
        # is_text = text_section.max_addr >= eip >= text_section.min_addr
        if eip.symbolic:
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
        init breakpoint used in scanf, for check gets function's overflow
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

    def StackOverflowMain(self, stepcount=0x1000, fmtstatelog=None):
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

    def StackOverflowFMTStateMain(self, stepcount=0x1000):
        self.InitCheckStackOverflowBreakpoints()
        fuzzer = Fuzzer(self.binarypath, self.project, self.state)
        fuzzer.run(stepcount=stepcount)


if __name__ == '__main__':
    binarypath = "../binaries/stack_overflow/leak_canary/leak_canary"
    StackOverflowExamine = StackOverflowExamineX86(binarypath)
    StackOverflowExamine.StackOverflowMain()
