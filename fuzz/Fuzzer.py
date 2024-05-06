"""
author : 4everdestiny
create_time : 2022.3.1
description : this is the code to fuzz the binary
input : state(ProgramState),project #sigmr(Simulation Managers)
output : nearly no output, please init the breakpoint or the functions before
"""
import traceback

import angr
import configparser
from fuzz.SimStateLog import SimStateLog
from fuzz.FunctionStackLog import FunctionStackLog
from log import log

log = log.Log()


class Fuzzer:
    def __init__(self, binarypath, project, state):
        self.binarypath = binarypath
        self.project = project
        # self.state = self.project.factory.entry_state()
        self.state = state
        self.simgr = self.project.factory.simgr(self.state)#, veritesting=True)
        self.simstatelog = SimStateLog()
        self.functionstacklog = FunctionStackLog()
        self.readconf()
        self.pathstepcount = 0
        self.needremovestate = []
        self.global_parameter = 0
        self.global_state = 0
        self.havefindvulnandstop = False

    def readconf(self):
        conf = configparser.ConfigParser()
        conf.read("../config.ini")
        if conf.has_section("Fuzzer"):
            self.depthlimit = int(conf.get("Fuzzer", "depthlimit"))
            self.stepcountlimit = int(conf.get("Fuzzer", "stepcountlimit"))
            self.pathsearchlimit = int(conf.get("Fuzzer", "pathsearchlimit"))
            # print(self.depthlimit)
        else:
            log.Exception("Fuzzer config missing")
            exit(0)

    def stashothers(self, state):
        self.judge_index += 1
        if self.judge_index != 0:
            return True
        else:
            return False

    def stashfirst(self, state):
        self.judge_index += 1
        if self.judge_index == 0:
            return True
        else:
            return False

    def unstashone(self, state):
        self.judge_index += 1
        if self.judge_index == 0:
            return True
        else:
            return False

    def prunepathjudge(self, state):
        """
        judge which patch to prune
        :param state: default parameter for judge, having regs' state
        :return: whether the path is needed to prune or not
        """
        self.judge_index += 1
        if state.arch.name == "X86":
            eip1 = state.solver.eval(state.regs.eip)
            esp1 = state.solver.eval(state.regs.esp)
            eip2 = self.global_state.solver.eval(self.global_state.regs.eip)
            esp2 = self.global_state.solver.eval(self.global_state.regs.esp)
            if eip1 == eip2 and esp1 == esp2 and self.original_index < self.judge_index:
                return True
        elif state.arch.name == "AMD64":
            rip1 = state.solver.eval(state.regs.rip)
            rsp1 = state.solver.eval(state.regs.rsp)
            rip2 = self.global_state.solver.eval(self.global_state.regs.rip)
            rsp2 = self.global_state.solver.eval(self.global_state.regs.rsp)
            if rip1 == rip2 and rsp1 == rsp2 and self.original_index < self.judge_index:
                return True
        elif state.arch.name == "MIPS32":
            pc1 = state.solver.eval(state.regs.pc)
            esp1 = state.solver.eval(state.regs.sp)
            pc2 = self.global_state.solver.eval(self.global_state.regs.pc)
            esp2 = self.global_state.solver.eval(self.global_state.regs.sp)
            if pc1 == pc2 and esp1 == esp2 and self.original_index < self.judge_index:
                return True
        else:
            log.Exception("not supported architecture, please check it")
        return False

    def prunepathjudgepruned(self, state):
        """
        judge which patch to prune
        :param state: default parameter for judge, having regs' state
        :return: whether the path is needed to prune or not
        """
        """
        rip1 = state.solver.eval(state.regs.rip)
        rsp1 = state.solver.eval(state.regs.rsp)
        rip2 = self.global_state.solver.eval(self.global_state.regs.rip)
        rsp2 = self.global_state.solver.eval(self.global_state.regs.rsp)
        # print(rip1,rip2,rsp1,rsp2)
        if rip1 == rip2 and rsp1 == rsp2:
            return True
        """
        if state.arch.name == "X86":
            eip1 = state.solver.eval(state.regs.eip)
            esp1 = state.solver.eval(state.regs.esp)
            eip2 = self.global_state.solver.eval(self.global_state.regs.eip)
            esp2 = self.global_state.solver.eval(self.global_state.regs.esp)
            if eip1 == eip2 and esp1 == esp2:
                return True
        elif state.arch.name == "AMD64":
            rip1 = state.solver.eval(state.regs.rip)
            rsp1 = state.solver.eval(state.regs.rsp)
            rip2 = self.global_state.solver.eval(self.global_state.regs.rip)
            rsp2 = self.global_state.solver.eval(self.global_state.regs.rsp)
            if rip1 == rip2 and rsp1 == rsp2:
                return True
        elif state.arch.name == "MIPS32":
            pc1 = state.solver.eval(state.regs.pc)
            esp1 = state.solver.eval(state.regs.esp)
            pc2 = self.global_state.solver.eval(self.global_state.regs.pc)
            esp2 = self.global_state.solver.eval(self.global_state.regs.esp)
            if pc1 == pc2 and esp1 == esp2:
                return True
        else:
            log.Exception("not supported architecture, please check it")
        return False

    def pathsearchcountjudge(self, state):
        findable, index = self.simstatelog.find(state)
        if findable:
            times = self.simstatelog.SimStates[index].times
            if times >= self.pathsearchlimit:
                log.info("path search limit judge prune")
                # log.info(self.simstatelog)
                log.info(state)
                return True
        else:
            return False

    def prunepath(self):
        """
        1. prune the paths, for the loop statements
        2. if have same state,(rip equal && rsp equal), prune them, only one abandon
        3. if any path run serveral times(> path search limit), prune them
        :return: None
        """
        """
        statelist = self.simgr.stashes["pruned"]
        for i in range(len(statelist)):
            self.global_state = self.simgr.stashes["pruned"][i]
            self.simgr.move(filter_func=self.prunepathjudge, from_stash="stashed", to_stash="pruned")
        """
        statelist = self.simgr.stashes["searchqueue"]
        for i in range(len(statelist)):
            if i >= len(self.simgr.stashes["searchqueue"]):
                break
            self.global_state = self.simgr.stashes["searchqueue"][i]
            self.original_index = i
            self.judge_index = -1
            self.simgr.move(filter_func=self.prunepathjudge, from_stash="searchqueue", to_stash="pruned")
        self.simgr.move(filter_func=self.pathsearchcountjudge, from_stash="active", to_stash="pathsearchlimit")
        self.simgr.move(filter_func=self.pathsearchcountjudge, from_stash="searchqueue", to_stash="pathsearchlimit")

    def step(self):
        """
        1. step once(finished)
        2. only one "active", DFS search(finished)
        3. if none "active", active one(finished)
        4. if all "deadended",end(finished)
        5. depth limit == conf.depthlimit(finished)
        6. if after one step, there are two paths, log the paths' count
        to avoid Persistent search(finished)
        7. because we need to log the function use status, so we need
        to log the function stack while search(and log the input/path)
        :return:
        """
        #print(self.simgr.stashes)
        if self.pathstepcount >= self.depthlimit:
            self.judge_index = -1
            self.simgr.move(filter_func=self.stashfirst, from_stash="active", to_stash="depthlimit")
            # self.simgr.stash(filter_func=self.stashfirst)
        if len(self.simgr.stashes["active"]) > 1:
            # print(self.simgr.stashes)
            for i in range(len(self.simgr.stashes["active"])):
                self.simgr.stashes["active"][i].kargs = self.functionstacklog.copy()
            self.judge_index = -1
            self.simgr.move(filter_func=self.stashothers,from_stash="active",to_stash="searchqueue")
            self.prunepath()
            if len(self.simgr.stashes["active"]) != 0:
                self.simstatelog.insert(self.simgr.stashes["active"][0])
        if len(self.simgr.stashes["active"]) == 0:
            if len(self.simgr.stashes["searchqueue"]) == 0:
                return False
            self.judge_index = -1
            self.simgr.move(filter_func=self.unstashone, from_stash="searchqueue", to_stash="active")
            self.simstatelog.insert(self.simgr.stashes["active"][0])
            # print("copy function stack log")
            # print(self.simgr.stashes["active"])
            self.functionstacklog = self.simgr.stashes["active"][0].kargs
            self.pathstepcount = 0
        # num_inst for the instruction number step
        result_simgr = self.simgr.step(stash="active")
        # result_simgr = self.simgr.step(stash="active", num_inst=1)
        # result_simgr = self.simgr.step(stash="active")
        if len(result_simgr.errored) != 0:
            log.Exception(result_simgr.errored)
            state = result_simgr.errored[0].state
            eip = state.solver.eval(state.regs.pc)
            log.Exception(hex(eip))
            return False
        self.pathstepcount += 1
        #print(self.simgr.stashes)
        return True

    def run(self, stepcount=0x10000):
        self.simgr.stashes["searchqueue"] = []
        self.simgr.stashes["depthlimit"] = []
        self.simgr.stashes["pathsearchlimit"] = []
        for i in range(stepcount):
            try:
                if self.havefindvulnandstop:
                    break
                canstep = self.step()
                if not canstep:
                    break
            except:
                # print(e)
                import traceback
                traceback.print_exc()
                log.info("maybe find a format string vulnerability")
                canstep = False
                break
        log.info("run for {stepcount} steps".format(stepcount=i))
        log.info("your wish step count:{stepcount}".format(stepcount=stepcount))


if __name__ == '__main__':
    binarypath = "../binaries/stack_overflow/leak_canary/leak_canary"
    project = angr.Project(binarypath, auto_load_libs=True)
    state = project.factory.entry_state()
    testpj = Fuzzer(binarypath, project, state)
    testpj.run(stepcount=2000)