"""
author : 4everdestiny
create_time : 2022.3.30
description : this is the code to log the state
1. the stack overflow state
2. the format string state
also need to deduplication about the same state
same state:
rsp equal and rip equal
input : state
output : return the state list
"""

import angr


class SingleSimStateLog:
    def __init__(self, state=None):
        self.simstate = state.copy()
        self.times = 1

    def __str__(self):
        return "[{state},{times}]".format(state=self.simstate.__str__(), times=self.times)
        #return self.simstate.__str__() + "," + str(self.times)


class SimStateLog:
    def __init__(self):
        self.SimStates = []

    def insert(self, state):
        findable, index = self.find(state)
        if not findable:
            self.SimStates.insert(index, SingleSimStateLog(state))
        else:
            self.SimStates[index].times += 1
        return self.SimStates[index].times

    def find(self, state):
        low = 0
        high = len(self.SimStates) - 1
        mid = int((low + high) / 2)
        #print(low, mid, high)
        while low <= high:
            if self.compare(self.SimStates[mid].simstate, state) == 0:
                #print("equal")
                return True, mid
            elif self.compare(self.SimStates[mid].simstate, state) > 0:
                # mid.rip > state.rip
                #print("big")
                high = mid - 1
            else:
                # mid.rip < state.rip
                #print("small")
                low = mid + 1
            mid = int((low + high) / 2)
            #print(low,mid,high)
        return False, low

    def compare(self, state1, state2):
        """
        compare two state according to the eip/rip
        :param state1: state1
        :param state2: state2
        :return: if equal, return 0
        if state1.rip > state2.rip, return 1
        else return -1
        """
        if state1.arch.name == "AMD64":
            if state2.arch.name != "AMD64":
                print("two state arch are not the same")
                return -1
            rip1 = state1.solver.eval(state1.regs.rip)
            rsp1 = state1.solver.eval(state1.regs.rsp)
            rip2 = state2.solver.eval(state2.regs.rip)
            rsp2 = state2.solver.eval(state2.regs.rsp)
            # print(rip1,rip2,rsp1,rsp2)
            if rip1 == rip2 and rsp1 == rsp2:
                return 0
            elif rip1 >= rip2:
                return 1
            else:
                return -1
        elif state1.arch.name == "MIPS32":
                if state2.arch.name != "MIPS32":
                    print("two state arch are not the same")
                    return -1
                eip1 = state1.solver.eval(state1.regs.ip)
                esp1 = state1.solver.eval(state1.regs.sp)
                eip2 = state2.solver.eval(state2.regs.ip)
                esp2 = state2.solver.eval(state2.regs.sp)
                # print(rip1,rip2,rsp1,rsp2)
                if eip1 == eip2 and esp1 == esp2:
                    return 0
                elif eip1 >= eip2:
                    return 1
                else:
                    return -1

    def __str__(self):
        string = ""
        length = len(self.SimStates)
        string += str(length) + "\n"
        for i in range(length):
            string += self.SimStates[i].__str__() + "\n"
        return string

if __name__ == '__main__':
    testpj = angr.Project("../binarys/heap_overflow/pesp")
    state = testpj.factory.entry_state()
    simgr = testpj.factory.simgr(state)
    teststate = []
    for i in range(50):
        teststate.append(simgr.stashes["active"][0])
        simgr.step()
    testSSL = SimStateLog()
    for i in range(50):
        testSSL.insert(teststate[i])
        print(testSSL)
    for i in range(50):
        testSSL.insert(teststate[i])
        print(testSSL)
