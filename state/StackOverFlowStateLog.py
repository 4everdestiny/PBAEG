"""
author : 4everdestiny
create_time : 2022.3.31
description : this is the code to log the stackoverflow state
input : state
output : the state's information and the input information
"""

from exploit_generation.PayloadList import PayloadList


class SingleStackOverFlowStateLog:
    def __init__(self, state=None, needline=False, prefixlength=0,
                 avoidchars="0a", needlength=0xdeadbeef, functionname="read",
                 pre_statelog=None, scanfinfo=None, strcpyinfo=None, project=None):
        """
        some information needed in stack overflow
        :param state: the state when check a stack overflow
        :param needline: some functions like gets, need \n to indicate a line
        :param prefixlength: the prefix length for stack overflow(input_address to rbp)
        :param avoidchars: the avoid chars, for example gets:\n, scanf:\n etc
        :param needlength: the length needed in total
        :param functionname: the stackoverflow function's name, read, strcpy etc.
        :param pre_statelog: the statelog used in pre, generally used in format string
        """
        if state is not None:
            self.state = state.copy()
        else:
            self.state = state
        self.times = 1
        self.needline = needline
        self.prefixlength = prefixlength
        self.avoidchars = avoidchars
        self.needlength = needlength
        self.functionname = functionname
        self.payloadlist = PayloadList()
        self.pre_statelog = pre_statelog
        self.scanfinfo = scanfinfo
        self.strcpyinfo = strcpyinfo
        self.project = project
        self.needrecvlibc = False
        self.need_send = False
        self.need_send_payload = None

    def Changeneedrecvlibc(self):
        """
        for general payload usage, we need to add recv info for sometime
        :return: None
        """
        self.needrecvlibc = True

    def __str__(self):
        string = "({state},{times})\n".format(state=self.state.__str__(), times=self.times)
        string += r"needline:{needline} prefixlength:{prefixlength} avoidchars:{avoidchars}".format(
            needline=self.needline, prefixlength=hex(self.prefixlength), avoidchars=self.avoidchars
        )
        return string
        #return self.simstate.__str__() + "," + str(self.times)


class StackOverFlowStateLog:
    def __init__(self):
        self.SimStates = []

    def insert(self, statelog):
        findable, index = self.find(statelog)
        if not findable:
            self.SimStates.insert(index, statelog)
        else:
            self.SimStates[index].times += 1
        return self.SimStates[index].times

    def find(self, statelog):
        low = 0
        high = len(self.SimStates) - 1
        mid = int((low + high) / 2)
        state = statelog.state
        #print(low, mid, high)
        while low <= high:
            if self.compare(self.SimStates[mid].state, state) == 0:
                #print("equal")
                return True, mid
            elif self.compare(self.SimStates[mid].state, state) > 0:
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
        elif state1.arch.name == "X86":
            if state2.arch.name != "X86":
                print("two state arch are not the same")
                return -1
            eip1 = state1.solver.eval(state1.regs.eip)
            esp1 = state1.solver.eval(state1.regs.esp)
            eip2 = state2.solver.eval(state2.regs.eip)
            esp2 = state2.solver.eval(state2.regs.esp)
            # print(rip1,rip2,rsp1,rsp2)
            if eip1 == eip2 and esp1 == esp2:
                return 0
            elif eip1 >= eip2:
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

    def GetSimStates(self):
        return self.SimStates

    def MergePayloadList(self, payloadlist=None):
        """
        In the state log, we need to add the payload in the log
        :param payloadlist: the final payload list for the state
        :return: None
        """
        if payloadlist == None:
            return None
        self.payloadlist.MergePayloadList(payloadlist=payloadlist)

    def ClearPayloadlist(self):
        """
        clear the payload list in the stackoverflow log
        :return: None
        """
        for i in range(len(self.SimStates)):
            self.SimStates[i].payloadlist = PayloadList()