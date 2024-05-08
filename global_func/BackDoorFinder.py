"""
author : 4everdestiny
create_time : 2023.7.3
description : this is the code to analyse the backdoor in a binary file
input : binary path
output : the backdoor inside this binary
"""

import angr
from log.log import Log
from global_func.FunctionHelper import Functionhelper
from global_func.StateHelper import StateHelper
import pwn

log = Log()


class BackDoorFinder:
    def __init__(self, binary_path="", function_helper=None):
        self.binary_path = binary_path
        self.project = angr.Project(self.binary_path)
        self.elf = pwn.ELF(self.binary_path, checksec=False)
        self.functionhelper = function_helper
        self.backdoorcmd = ["/bin/sh", "cat flag", "cat flag.txt"]
        self.findbackdoor = False
        self.backdoors = []

    def CallInstructionAnalyseAMD64(self, state=None):
        """
        the function to check the call instruction inside the function
        :param state: the current state
        :return: if it's a backdoor, log to backdoor, otherwise finish this function
        """
        rdi = state.solver.eval(state.regs.rdi)
        statehelper = StateHelper(state)
        rdi_string = statehelper.GetString(address=rdi)
        # print(rdi_string)
        system_addr = self.functionhelper.GetFunctionAddress(func_name="system")
        rip = state.solver.eval(state.regs.rip)
        if rip == system_addr and rdi_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=rdi_string))
            self.findbackdoor = True
        else:
            ret_addr = state.mem[state.regs.rsp].uint64_t.resolved
            state.regs.rip = ret_addr
            state.regs.rsp += 8

    def CheckCmdAMD64(self, state=None):
        """
        check the cmd status of current state
        :param state: the current state
        :return: None
        """
        rdi = state.solver.eval(state.regs.rdi)
        statehelper = StateHelper(state)
        rdi_string = statehelper.GetString(address=rdi)
        # print(rdi_string)
        if rdi_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=rdi_string))
            self.findbackdoor = True

    def InitBackDoorFinderBreakpointsAMD64(self, state=None):
        """
        init the breakpoint for the backdoor
        :param state: the current state
        :return: set the breakpoint for the binary
        """
        state.inspect.b("call", when=angr.BP_BEFORE,
                        action=self.CallInstructionAnalyseAMD64)

    def FindBackDoorFromFuncHeader(self):
        """
        in x86 arch, we need to find the backdoor from the function header
        :return: the backdoor addresses
        """
        system_references = self.functionhelper.GetFuncReferenceByName(
            "system", use_deep_find=True)
        if len(system_references) == 0:
            log.info("cannot find the reference for system")
            return None
            # print(system_references)
        for system_reference in system_references:
            calls = system_reference["calls"]
            for xref in system_reference["xrefs"]:
                if xref == calls:
                    # if we come to here, it means we found a junk reference
                    # we need to find the head of function manually
                    find, address = self.functionhelper.FindFuncionHeaderByAddress(address=xref)
                    if not find:
                        return self.backdoors
                    else:
                        calls = address
                # 1. find the block contain reference
                temp_calls = calls
                if self.elf.pie:
                    if self.elf.arch == "amd64":
                        temp_calls += 0x400000
                        xref += 0x400000
                        # default rebase address
                    elif self.elf.arch == "i386":
                        temp_calls += 0x08048000
                        xref += 0x08048000
                # self.project.factory.block(temp_calls).pp()
                state = self.project.factory.full_init_state(
                    addr=temp_calls, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
                arch = self.project.arch.name
                if arch == "AMD64":
                    self.InitBackDoorFinderBreakpointsAMD64(state=state)
                elif arch == "X86":
                    self.InitBackDoorFinderBreakpointsX86(state=state)
                elif arch == "MIPS32":
                    self.InitBackDoorFinderBreakpointsMIPS32(state=state)
                elif arch == "ARMEL" or arch == "ARMHF":
                    self.InitBackDoorFinderBreakpointsARM(state=state)
                else:
                    log.Exception("unsupported architecture in AnalyseBackdoorMain")
                    return None
                simgr = self.project.factory.simgr(state, veritesting=True)
                self.findbackdoor = False
                try:
                    """
                    for _ in range(0x100):
                        simgr.step(num_inst=1)
                        state = simgr.stashes["active"][0]
                        print(simgr.stashes)
                    """
                    simgr.explore(find=xref)
                except:
                    log.Exception("simgr running error in AnalyseBackdoorMain")
                    # last we just return to the func header
                    if self.project.arch.name == "X86":
                        self.backdoors.append(
                            {"backdoorentry": temp_calls,
                             "backdoortarget": xref}
                        )
                        self.findbackdoor = True
                    return self.backdoors
                if self.findbackdoor:
                    self.backdoors.append(
                        {"backdoorentry": temp_calls,
                         "backdoortarget": xref}
                    )
                    continue
                found_states = simgr.found
                if len(found_states) > 0:
                    for state in found_states:
                        arch = self.project.arch.name
                        if arch == "AMD64":
                            self.CheckCmdAMD64(state=state)
                        elif arch == "X86":
                            self.CheckCmdX86(state=state)
                        elif arch == "MIPS32":
                            self.CheckCmdMIPS32(state=state)
                        elif arch == "ARMEL" or arch == "ARMHF":
                            self.CheckCmdARM(state=state)
                        else:
                            log.Exception("unsupported architecture in AnalyseBackdoorMain")
                            return self.backdoors
                        if self.findbackdoor:
                            self.backdoors.append(
                                {"backdoorentry": temp_calls,
                                 "backdoortarget": xref}
                            )
        return self.backdoors

    def AnalyseBackdoorMain(self):
        """
        find the backdoor inside an binary
        system("/bin/sh")
        system("cat flag")
        system("cat flag.txt")
        :return: the backdoor and backdoor entry
        """
        system_references = self.functionhelper.GetFuncReferenceByName(
            "system", use_deep_find=True)
        if len(system_references) == 0:
            log.info("cannot find the reference for system")
            return None
            # print(system_references)
        for system_reference in system_references:
            calls = system_reference["calls"]
            for xref in system_reference["xrefs"]:
                if xref == calls:
                    # if we come to here, it means we found a junk reference
                    # we need to find the head of function manually
                    find, address = self.functionhelper.FindFuncionHeaderByAddress(address=xref)
                    if not find:
                        return self.backdoors
                    else:
                        calls = address
                # 1. find the block contain reference
                temp_calls = calls
                if self.elf.pie:
                    if self.elf.arch == "amd64":
                        temp_calls += 0x400000
                        xref += 0x400000
                        # default rebase address
                    elif self.elf.arch == "i386":
                        temp_calls += 0x08048000
                        xref += 0x08048000
                block = self.project.factory.block(temp_calls)
                while xref not in block.instruction_addrs:
                    temp_calls += block.size
                    block = self.project.factory.block(temp_calls)
                # self.project.factory.block(temp_calls).pp()
                state = self.project.factory.call_state(temp_calls)
                arch = self.project.arch.name
                if arch == "AMD64":
                    self.InitBackDoorFinderBreakpointsAMD64(state=state)
                elif arch == "X86":
                    self.InitBackDoorFinderBreakpointsX86(state=state)
                elif arch == "MIPS32":
                    self.InitBackDoorFinderBreakpointsMIPS32(state=state)
                elif arch == "ARMEL" or arch == "ARMHF":
                    self.InitBackDoorFinderBreakpointsARM(state=state)
                else:
                    log.Exception("unsupported architecture in AnalyseBackdoorMain")
                    return self.backdoors
                simgr = self.project.factory.simgr(state, veritesting=True)
                self.findbackdoor = False
                try:
                    simgr.explore(find=xref)
                except:
                    log.Exception("simgr running error in AnalyseBackdoorMain")
                if self.findbackdoor:
                    self.backdoors.append(
                        {"backdoorentry": temp_calls,
                         "backdoortarget": xref}
                    )
                    continue
                found_states = simgr.found
                if len(found_states) > 0:
                    for state in found_states:
                        arch = self.project.arch.name
                        if arch == "AMD64":
                            self.CheckCmdAMD64(state=state)
                        elif arch == "X86":
                            self.CheckCmdX86(state=state)
                        elif arch == "MIPS32":
                            self.CheckCmdMIPS32(state=state)
                        elif arch == "ARMEL" or arch == "ARMHF":
                            self.CheckCmdARM(state=state)
                        else:
                            log.Exception("unsupported architecture in AnalyseBackdoorMain")
                            return self.backdoors
                        if self.findbackdoor:
                            self.backdoors.append(
                                {"backdoorentry": temp_calls,
                                 "backdoortarget": xref}
                            )
                            return self.backdoors
                if arch == "X86" and len(self.backdoors) == 0:
                    self.FindBackDoorFromFuncHeader()
        return self.backdoors

    def AnalyseBackdoorAMD64(self):
        """
        find the backdoor inside an amd64 binary
        system("/bin/sh")
        system("cat flag")
        system("cat flag.txt")
        :return: the backdoor and backdoor entry
        """
        system_references = self.functionhelper.GetFuncReferenceByName(
            "system", use_deep_find=True)
        if len(system_references) == 0:
            log.info("cannot find the reference for system")
            return None
        self.backdoors = []
        # print(system_references)
        for system_reference in system_references:
            calls = system_reference["calls"]
            for xref in system_reference["xrefs"]:
                # 1. find the block contain reference
                if xref == calls:
                    pass
                temp_calls = calls
                block = self.project.factory.block(temp_calls)
                while xref not in block.instruction_addrs:
                    temp_calls += block.size
                    block = self.project.factory.block(temp_calls)
                # self.project.factory.block(temp_calls).pp()
                state = self.project.factory.call_state(temp_calls)
                self.InitBackDoorFinderBreakpointsAMD64(state=state)
                simgr = self.project.factory.simgr(state, veritesting=True)
                self.findbackdoor = False
                try:
                    simgr.explore(find=xref)
                except:
                    log.Exception("simgr running error in AnalyseBackdoorAMD64")
                if self.findbackdoor:
                    self.backdoors.append(
                        {"backdoorentry": temp_calls,
                         "backdoortarget": xref}
                    )
                    continue
                found_states = simgr.found
                if len(found_states) > 0:
                    for state in found_states:
                        self.CheckCmdAMD64(state=state)
                        if self.findbackdoor:
                            self.backdoors.append(
                                {"backdoorentry": temp_calls,
                                 "backdoortarget": xref}
                            )
        return self.backdoors

    def CallInstructionAnalyseX86(self, state=None):
        """
        the function to check the call instruction inside the function
        x86 arch
        :param state: the current state
        :return: if it's a backdoor, log to backdoor, otherwise finish this function
        """
        par1 = state.solver.eval(state.mem[state.regs.esp + 4].uint32_t.resolved)
        statehelper = StateHelper(state)
        par1_string = statehelper.GetString(address=par1)
        # print(rdi_string)
        system_addr = self.functionhelper.GetFunctionAddress(func_name="system")
        eip = state.solver.eval(state.regs.eip)
        if eip == system_addr and par1_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=par1_string))
            self.findbackdoor = True
        else:
            ret_addr = state.mem[state.regs.esp].uint32_t.resolved
            state.regs.eip = ret_addr
            state.regs.esp += 4

    def CheckCmdX86(self, state=None):
        """
        check the cmd status of current state
        :param state: the current state
        :return: None
        """
        # this is a call instruction
        par1 = state.solver.eval(state.mem[state.regs.esp].uint32_t.resolved)
        statehelper = StateHelper(state)
        par1_string = statehelper.GetString(address=par1)
        if par1_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=par1_string))
            self.findbackdoor = True

    def InitBackDoorFinderBreakpointsX86(self, state=None):
        """
        init the breakpoint for the backdoor
        :param state: the current state
        :return: set the breakpoint for the binary
        """
        state.inspect.b("call", when=angr.BP_BEFORE,
                        action=self.CallInstructionAnalyseX86)

    def AnalyseBackdoorX86(self):
        """
        find the backdoor inside an amd64 binary
        system("/bin/sh")
        system("cat flag")
        system("cat flag.txt")
        :return: the backdoor and backdoor entry
        """
        system_references = self.functionhelper.GetFuncReferenceByName(
            "system", use_deep_find=True)
        if len(system_references) == 0:
            log.info("cannot find the reference for system")
            return None
        self.backdoors = []
        # print(system_references)
        for system_reference in system_references:
            calls = system_reference["calls"]
            for xref in system_reference["xrefs"]:
                # 1. find the block contain reference
                temp_calls = calls
                block = self.project.factory.block(temp_calls)
                while xref not in block.instruction_addrs:
                    temp_calls += block.size
                    block = self.project.factory.block(temp_calls)
                # self.project.factory.block(temp_calls).pp()
                state = self.project.factory.call_state(temp_calls)
                self.InitBackDoorFinderBreakpointsX86(state=state)
                simgr = self.project.factory.simgr(state, veritesting=True)
                self.findbackdoor = False
                simgr.explore(find=xref)
                if self.findbackdoor:
                    self.backdoors.append(
                        {"backdoorentry": temp_calls,
                         "backdoortarget": xref}
                    )
                    continue
                found_states = simgr.found
                if len(found_states) > 0:
                    for state in found_states:
                        self.CheckCmdX86(state=state)
                        if self.findbackdoor:
                            self.backdoors.append(
                                {"backdoorentry": temp_calls,
                                 "backdoortarget": xref}
                            )
        return self.backdoors

    def CallInstructionAnalyseMIPS32(self, state=None):
        """
        the function to check the call instruction inside the function
        x86 arch
        :param state: the current state
        :return: if it's a backdoor, log to backdoor, otherwise finish this function
        """
        par1 = state.solver.eval(state.regs.a0)
        statehelper = StateHelper(state)
        par1_string = statehelper.GetString(address=par1)
        # print(rdi_string)
        system_addr = self.functionhelper.GetFunctionAddress(func_name="system")
        eip = state.solver.eval(state.regs.pc)
        if eip == system_addr and par1_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=par1_string))
            self.findbackdoor = True
        else:
            ret_addr = state.regs.ra
            state.regs.eip = ret_addr
            # state.regs.esp += 4

    def CheckCmdMIPS32(self, state=None):
        """
        check the cmd status of current state
        :param state: the current state
        :return: None
        """
        # this is a call instruction
        par1 = state.solver.eval(state.regs.a0)
        statehelper = StateHelper(state)
        par1_string = statehelper.GetString(address=par1)
        if par1_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=par1_string))
            self.findbackdoor = True

    def InitBackDoorFinderBreakpointsMIPS32(self, state=None):
        """
        init the breakpoint for the backdoor
        :param state: the current state
        :return: set the breakpoint for the binary
        """
        state.inspect.b("call", when=angr.BP_BEFORE,
                        action=self.CallInstructionAnalyseMIPS32)

    def AnalyseBackdoorMIPS32(self):
        """
        find the backdoor inside an amd64 binary
        system("/bin/sh")
        system("cat flag")
        system("cat flag.txt")
        :return: the backdoor and backdoor entry
        """
        system_references = self.functionhelper.GetFuncReferenceByName(
            "system", use_deep_find=True)
        if len(system_references) == 0:
            log.info("cannot find the reference for system")
            return None
        self.backdoors = []
        # print(system_references)
        for system_reference in system_references:
            calls = system_reference["calls"]
            for xref in system_reference["xrefs"]:
                # 1. find the block contain reference
                temp_calls = calls
                block = self.project.factory.block(temp_calls)
                while xref not in block.instruction_addrs:
                    temp_calls += block.size
                    block = self.project.factory.block(temp_calls)
                    if block.size == 0:
                        # maybe we find a junk block
                        break
                    if temp_calls > xref:
                        break
                # self.project.factory.block(temp_calls).pp()
                state = self.project.factory.call_state(temp_calls)
                self.InitBackDoorFinderBreakpointsMIPS32(state=state)
                simgr = self.project.factory.simgr(state, veritesting=True)
                self.findbackdoor = False
                simgr.explore(find=xref)
                if self.findbackdoor:
                    self.backdoors.append(
                        {"backdoorentry": temp_calls,
                         "backdoortarget": xref}
                    )
                    continue
                found_states = simgr.found
                if len(found_states) > 0:
                    for state in found_states:
                        self.CheckCmdMIPS32(state=state)
                        if self.findbackdoor:
                            self.backdoors.append(
                                {"backdoorentry": temp_calls,
                                 "backdoortarget": xref}
                            )
        return self.backdoors

    def CallInstructionAnalyseARM(self, state=None):
        """
        the function to check the call instruction inside the function
        arm arch
        :param state: the current state
        :return: if it's a backdoor, log to backdoor, otherwise finish this function
        """
        par1 = state.solver.eval(state.regs.r0)
        statehelper = StateHelper(state)
        par1_string = statehelper.GetString(address=par1)
        # print(rdi_string)
        system_addr = self.functionhelper.GetFunctionAddress(func_name="system")
        eip = state.solver.eval(state.regs.ip)
        if eip == system_addr and par1_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=par1_string))
            self.findbackdoor = True
        else:
            ret_addr = state.regs.ra
            state.regs.eip = ret_addr
            # state.regs.esp += 4

    def CheckCmdARM(self, state=None):
        """
        check the cmd status of current state
        :param state: the current state
        :return: None
        """
        # this is a call instruction
        par1 = state.solver.eval(state.regs.r0)
        statehelper = StateHelper(state)
        par1_string = statehelper.GetString(address=par1)
        if par1_string in self.backdoorcmd:
            log.success("find a backdoor system(\"{cmd}\")".format(cmd=par1_string))
            self.findbackdoor = True

    def InitBackDoorFinderBreakpointsARM(self, state=None):
        """
        init the breakpoint for the backdoor
        :param state: the current state
        :return: set the breakpoint for the binary
        """
        state.inspect.b("call", when=angr.BP_BEFORE,
                        action=self.CallInstructionAnalyseARM)

    def AnalyseBackdoorARM(self):
        """
        find the backdoor inside an amd64 binary
        system("/bin/sh")
        system("cat flag")
        system("cat flag.txt")
        :return: the backdoor and backdoor entry
        """
        system_references = self.functionhelper.GetFuncReferenceByName(
            "system", use_deep_find=True)
        if len(system_references) == 0:
            log.info("cannot find the reference for system")
            return None
        self.backdoors = []
        # print(system_references)
        for system_reference in system_references:
            calls = system_reference["calls"]
            for xref in system_reference["xrefs"]:
                # 1. find the block contain reference
                temp_calls = calls
                block = self.project.factory.block(temp_calls)
                while xref not in block.instruction_addrs:
                    temp_calls += block.size
                    block = self.project.factory.block(temp_calls)
                # self.project.factory.block(temp_calls).pp()
                state = self.project.factory.call_state(temp_calls)
                self.InitBackDoorFinderBreakpointsARM(state=state)
                simgr = self.project.factory.simgr(state, veritesting=True)
                self.findbackdoor = False
                simgr.explore(find=xref)
                if self.findbackdoor:
                    self.backdoors.append(
                        {"backdoorentry": temp_calls,
                         "backdoortarget": xref}
                    )
                    continue
                found_states = simgr.found
                if len(found_states) > 0:
                    for state in found_states:
                        self.CheckCmdARM(state=state)
                        if self.findbackdoor:
                            self.backdoors.append(
                                {"backdoorentry": temp_calls,
                                 "backdoortarget": xref}
                            )
        return self.backdoors

    def AnalyseBackdoor(self):
        """dynamic_test1
        get the backdoor address inside a binary
        :return: the backdoor target and the backdoor entry
        """
        arch = self.project.arch.name
        if arch == "AMD64" or arch == "X86":
            return self.AnalyseBackdoorMain()
        if arch == "MIPS32":
            return self.AnalyseBackdoorMIPS32()
        elif arch == "ARMEL" or arch == "ARMHF":
            return self.AnalyseBackdoorARM()
        else:
            log.Exception("cannot support arch " + arch + " in AnalyseBackdoor")
            return None


if __name__ == '__main__':
    testbackdoorfinder = BackDoorFinder(
        binary_path="../binaries/2023_longjian_final/1/pwn1"
    )
    print(testbackdoorfinder.AnalyseBackdoor())

    """
    testbackdoorfinder = BackDoorFinder(
        binary_path="../binaries/libcs/libc-2.27.so"
    )
    testbackdoorfinder.AnalyseBackdoor()
    """

    testbackdoorfinder = BackDoorFinder(
        binary_path="../binaries/64bit/stack_overflow/dynamic/test1/dynamic_test1"
    )
    print(testbackdoorfinder.AnalyseBackdoor())


    testbackdoorfinder = BackDoorFinder(
        binary_path="../binaries/mips32/stack_overflow/dynamic/test1/dynamic_test1"
    )
    print(testbackdoorfinder.AnalyseBackdoor())
