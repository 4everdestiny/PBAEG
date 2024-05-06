"""
author : 4everdestiny
create_time : 2022.3.29
description : this is the code to schedule the fuzzer and the exploit generation
input : binary path
output : run the fuzzer to test the binaries and run the exploit generation
also, we need to run the exploit checker to check the payload's correctness
"""

from fuzz.StackOverflowExamineX86 import StackOverflowExamineX86
from fuzz.StackOverflowExamineX64 import StackOverflowExamineX64
from fuzz.StackOverflowExamineMips32 import StackOverflowExamineMips32
from fuzz.StackOverflowExamineArm import StackOverflowExamineArm
from exploit_generation.ProtectionInformation import ProtectionInformation
from exploit_generation.ROPGeneration import ROPGeneration
from exploit_check.ExploitCheckLocal import ExploitCheckLocal
from exploit_check.ExploitCheckState import ExploitCheckState
from exploit_check.ExploitCheckRemote import ExploitCheckRemote
from fuzz.FormatStringExamine import FormatStringExamine
from exploit_generation.FMTGeneration import FMTGeneration
from exploit_generation.PayloadList import PayloadList
from exploit_generation.BackdoorPathExamine import BackdoorPathExamine
from AFL_fuzz.FuzzStackOverflowExamineMipsel import FuzzStackOverflowExamineMipsel
from global_func.FunctionHelper import Functionhelper
from web_interface.Challenge import Challenge
import pwn
import configparser
from log.log import Log

log = Log()


class MainSchedule:
    def __init__(self, binarypath=""):
        self.binarypath = binarypath
        self.elf = pwn.ELF(self.binarypath, checksec=False)
        self.protection = ProtectionInformation(self.binarypath).GetProtection()
        self.stackoverflowstates = []
        self.formatstringstates = []
        self.backdoorpathstates = []
        self.fmtexamine = None
        self.stepcount = 0x10000
        self.needfmtvuln = False
        self.payloadlist = []
        self.vulnerability_type = ""
        self.exploitgeneratelocal = False
        self.exploitgenerateremote = False
        self.exploitchecklocal = False
        self.exploitcheckremote = False
        self.useangr = False
        self.useafl = False
        self.usebackdoor = False
        self.exploit_method = ""
        self.technique_used = ""
        self.libc_path = ""
        self.libc_path_remote = ""
        self.libc_x64_path = ""
        self.libc_x64_path_remote = ""
        self.sig_path = ""
        self.sdb_path = ""
        self.sig_x64_path = ""
        self.sdb_x64_path = ""
        self.function_helper = None

    def readconf(self):
        """
        this is the function to read the config file
        :return: None
        """
        conf = configparser.ConfigParser()
        conf.read("../config.ini")
        if conf.has_section("ExploitGenerate"):
            self.exploitgeneratelocal = (conf.get("ExploitGenerate", "Local") == "True")
            self.exploitgenerateremote = (conf.get("ExploitGenerate", "Remote") == "True")
        else:
            log.Exception("ExploitGenerate config missing")
        if conf.has_section("ExploitCheck"):
            self.exploitchecklocal = (conf.get("ExploitCheck", "Local") == "True")
            self.exploitcheckremote = (conf.get("ExploitCheck", "Remote") == "True")
        else:
            log.Exception("ExploitCheck config missing")
        if conf.has_section("ToolsUse"):
            self.useangr = (conf.get("ToolsUse", "UseAngr") == "True")
            self.useafl = (conf.get("ToolsUse", "UseAFL") == "True")
            self.usebackdoor = (conf.get("ToolsUse", "UseBackdoor") == "True")
        else:
            log.Exception("ToolsUse config missing")
        if conf.has_section("FilePath"):
            self.libc_path = conf.get("FilePath", "libc_path")
            self.libc_x64_path = conf.get("FilePath", "libc_x64_path")
            self.libc_path_remote = conf.get("FilePath", "libc_path_remote")
            self.libc_x64_path_remote = conf.get("FilePath", "libc_x64_path_remote")
            if self.protection["static"] \
                    and self.protection["stripped"]:
                self.sig_path = conf.get("FilePath", "sig_path")
                self.sdb_path = conf.get("FilePath", "sdb_path")
                self.sig_x64_path = conf.get("FilePath", "sig_x64_path")
                self.sdb_x64_path = conf.get("FilePath", "sdb_x64_path")

    def ClearStatesLog(self):
        """
        after a examine finished, and payload generated
        we need to clear the states.
        especially used in GET....
        :return: None
        """
        self.stackoverflowstates = []
        self.formatstringstates = []
        self.backdoorpathstates = []

    def GetVulnerabilityType(self):
        """
        get the vulnerability type for this binary
        :return: the vulnerability type of this binary
        """
        if len(self.formatstringstates) != 0:
            self.vulnerability_type += "fmt "
        if len(self.stackoverflowstates) != 0:
            self.vulnerability_type += "stackoverflow"
        if len(self.backdoorpathstates) != 0:
            self.vulnerability_type += "backdoorpath"
        return self.vulnerability_type

    def StackOverFlowNoPIECanary(self):
        """
        this is the function to run the fuzzer to check the stack overflow
        :return: the information stack overflow needed
        """
        self.ClearStatesLog()
        if self.protection["arch"] == "i386":
            stackoverflowexamine = StackOverflowExamineX86(
                binarypath=self.binarypath, function_helper=self.function_helper,
                protection=self.protection
            )
        elif self.protection["arch"] == "amd64":
            stackoverflowexamine = StackOverflowExamineX64(
                binarypath=self.binarypath,  function_helper=self.function_helper,
                protection=self.protection
            )
        elif self.protection["arch"] == "mips":
            stackoverflowexamine = StackOverflowExamineMips32(
                binarypath=self.binarypath#, function_helper=self.function_helper
            )
        elif self.protection["arch"] == "arm":
            stackoverflowexamine = StackOverflowExamineArm(
                binarypath=self.binarypath#, function_helper=self.function_helper
            )
        else:
            log.Exception("not supported architecture in MainSchedule")
            return False
        if self.useangr:
            self.technique_used += "DSE "
            stackoverflowexamine.StackOverflowMain(stepcount=self.stepcount)
            self.stackoverflowstates.extend(stackoverflowexamine.stackoverflowlog.GetSimStates())
        if self.useafl:
            self.technique_used += "fuzzing "
            if self.protection["arch"] == "mips":
                fuzzstackoverflowexaminemipsel = FuzzStackOverflowExamineMipsel(binary_path=self.binarypath)
                fuzzstackoverflowexaminemipsel.Main()
            elif self.protection["arch"] == "arm":
                fuzzstackoverflowexaminemipsel = FuzzStackOverflowExamineMipsel(binary_path=self.binarypath)
                fuzzstackoverflowexaminemipsel.Main()
            else:
                log.Exception("not supported architecture in MainSchedule")
                return False
            self.stackoverflowstates.extend(fuzzstackoverflowexaminemipsel.stackoverflowlog.GetSimStates())

    def StackOverFlowHavePIECanary(self):
        """
        this is the function to run the fuzzer to check the stack overflow
        but this time we need to bypass PIE and Canary using format string vulnerability
        use the statelog to generate the final payload
        1. remember to set the format string to a specific value
        2. use the state to generate a stack overflow payload
        3. check the status for the path
        :return: the information stack overflow needed
        """
        # self.ClearStatesLog()
        if self.protection["arch"] == "i386":
            stackoverflowexamine = StackOverflowExamineX86(
                binarypath=self.binarypath, function_helper=self.function_helper,
                protection=self.protection
            )
        elif self.protection["arch"] == "amd64":
            stackoverflowexamine = StackOverflowExamineX64(
                binarypath=self.binarypath, function_helper=self.function_helper,
                protection=self.protection
            )
        else:
            log.Exception("not supported architecture in MainSchedule")
            return False
        for statelog in self.formatstringstates:
            stackoverflowexamine.StackOverflowMain(
                stepcount=self.stepcount, fmtstatelog=statelog
            )
            self.stackoverflowstates = stackoverflowexamine.stackoverflowlog.GetSimStates()

    def GetFormatStringStates(self):
        """
        for a single bianry, use same strategy
        if PIE or Canary or libc_base needed,
        use format string exploit generation to find the correct payload
        :return: None, but log the format string states into self.formatstringstates
        also set self.needformatstring = True
        """
        self.ClearStatesLog()
        if self.protection["PIE"] or self.protection["Canary"]:
            log.info("PIE or canary enabled, need format string Vulnerability")
            self.fmtexamine = FormatStringExamine(
                binarypath=self.binarypath, function_helper=self.function_helper
            )
            self.fmtexamine.FormatStringMain(stepcount=self.stepcount)
            self.formatstringstates = self.fmtexamine.formatstringstatelog.GetSimStates()

    def GetStackOverFlowStates(self):
        """
        for a single binary, use different strategies
        No PIE No Canary: only stack overflow
        PIE enabled or Canary enabled: format string and stack overflow
        :return: None, give the stack overflow states to stackoverflowstates
        """
        if self.protection["PIE"] or self.protection["Canary"]:
            log.info("PIE or canary enabled, need format string Vulnerability")
            if self.needfmtvuln and len(self.formatstringstates) != 0:
                self.StackOverFlowHavePIECanary()
            else:
                log.Exception("need format string for bypassing PIE and canary,but no state log, please check it")
        else:
            self.StackOverFlowNoPIECanary()

    def GenerateROPPayload(self, remote=False):
        """
        from the stack overflow state log to generate payload
        use the prefix length, state.posix.dump(0) info like to generate payload
        :return: True when successfully generated, False when failed
        """
        if not remote:
            if self.protection["bits"] == 32:
                libc_path = self.libc_path
            else:
                libc_path = self.libc_x64_path
        else:
            if self.protection["bits"] == 32:
                libc_path = self.libc_path_remote
            else:
                libc_path = self.libc_x64_path_remote
        for statelog in self.stackoverflowstates:
            # print(dir(statelog))
            statelog.payloadlist = PayloadList()
            needlength = statelog.needlength
            avoidchars = statelog.avoidchars
            needline = statelog.needline
            prefixlength = statelog.prefixlength
            ropgeneration = ROPGeneration(
                binarypath=self.binarypath, needlength=needlength,
                avoidchars=avoidchars, prefixlength=prefixlength,
                needline=needline, statelog=statelog,
                libcpath=libc_path, function_helper=self.function_helper
            )
            can_generate = ropgeneration.GeneratePayload()
            if not can_generate:
                log.Exception("cannot successfully generate in this statelog")
                continue
            self.exploit_method += ropgeneration.exploit_method + " "
            statelog.payloadlist.MergePayloadList(ropgeneration.GetPayloadList())
        # payload = ROPGeneration(binarypath=self.binarypath,needlength=)

    def GenerateFMTPayload(self):
        """
        according to the protection mechanism, generate specific payloads
        :return: True when success, False when fail
        """
        needinfo = []
        if self.protection["Canary"]:
            needinfo.append("canary")
        if self.protection["PIE"]:
            needinfo.append("elf_base")
        needinfo.append("libc_base")
        if len(needinfo) == 1:
            self.needfmtvuln = False
            return None
        else:
            self.needfmtvuln = True
        for statelog in self.formatstringstates:
            fmtgeneration = FMTGeneration(
                binarypath=self.binarypath
            )
            fmtgeneration.LeakPayloadGeneration(
                fmtstatelog=statelog, leakinfo=needinfo
            )
            statelog.payloadlist.MergePayloadList(fmtgeneration.GetPayloadList())

    def StateCheckExploit(self):
        """
        this is used to check state, but hard to finish, abandon
        :return:
        """
        for i in range(len(self.stackoverflowstates)):
            statelog = self.stackoverflowstates[i]
            state = statelog.state
            functionname = statelog.functionname
            exploitcheckstate = ExploitCheckState(
                state=state, functionname=functionname, payloadlist=statelog.payloadlist
            )
            exploitcheckstate.CheckPayload()

    def LocalCheckExploit(self, full_test=True, isbackdoorpath=False):
        """
        local process exploit check
        :param full_test: for the full test, every payload need to check,
        if not full test, any of the payload susccess is ok
        :return: True when success, False when fail
        """
        if full_test:
            final_result = True
        else:
            final_result = False
        exploitchecklocal = ExploitCheckLocal(binarypath=self.binarypath)
        for i in range(len(self.payloadlist)):
            temppayloadlist = self.payloadlist[i]
            if temppayloadlist.CheckEmpty():
                if full_test:
                    final_result &= False
                else:
                    final_result |= False
                continue
            if isbackdoorpath:
                result = exploitchecklocal.CheckPayload(
                    payloadlist=temppayloadlist, write_payload=self.exploitgeneratelocal,
                    change_file_path=True, index=i, state=self.backdoorpathstates[i]
                )
            else:
                result = exploitchecklocal.CheckPayload(
                    payloadlist=temppayloadlist, write_payload=self.exploitgeneratelocal,
                    change_file_path=True, index=i, state=self.stackoverflowstates[i].state
                )
            if result:
                log.success("[Local]: payload[{index}] check successfully".format(index=i))
            else:
                log.Exception("[Local]: payload[{index}] check failed".format(index=i))
            if full_test:
                final_result &= result
            else:
                final_result |= result
        return final_result

    def RemoteCheckExploit(self, full_test=True, isbackdoorpath=False, challenge=Challenge()):
        """
        docker remote check exploit
        :param isbackdoorpath: if find the vuln by backdoor path, set it True
        :param full_test: for the full test, every payload need to check,
        :param isbackdoorpath: is a backdoorpath finder
        :param challenge: the challenge class
        if not full test, any of the payload susccess is ok
        :return: True when success, False when fail
        """
        if full_test:
            final_result = True
        else:
            final_result = False
        exploitcheckremote = ExploitCheckRemote(binarypath=self.binarypath, challenge=challenge)
        for i in range(len(self.payloadlist)):
            temppayloadlist = self.payloadlist[i]
            if temppayloadlist.CheckEmpty():
                if full_test:
                    final_result &= False
                else:
                    final_result |= False
                continue
            if isbackdoorpath:
                result = exploitcheckremote.CheckPayload(
                    payloadlist=temppayloadlist, write_payload=self.exploitgeneratelocal,
                    change_file_path=True, index=i, state=self.backdoorpathstates[i]
                )
            else:
                result = exploitcheckremote.CheckPayload(
                    payloadlist=temppayloadlist, write_payload=self.exploitgenerateremote,
                    change_file_path=True, index=i
                )
            if result:
                log.success("[Remote]: payload[{index}] check successfully".format(index=i))
            else:
                log.Exception("[Remote]: payload[{index}] check failed".format(index=i))
            if full_test:
                final_result &= result
            else:
                final_result |= result
        return final_result

    def InitMainSchedule(self):
        self.readconf()
        self.stackoverflowstates = []
        self.formatstringstates = []
        self.fmtexamine = None
        self.needfmtvuln = False
        self.payloadlist = []
        if self.elf.bits == 32:
            self.function_helper = Functionhelper(
                binary_path=self.binarypath, sdb_path=self.sdb_path,
                sig_path=self.sig_path, libc_path=self.libc_path
            )
        else:
            self.function_helper = Functionhelper(
                binary_path=self.binarypath, sdb_path=self.sdb_x64_path,
                sig_path=self.sig_x64_path, libc_path=self.libc_x64_path
            )

    def MainScheduleForFormatString(self):
        """
        the Main function of testing format string
        1. get the states
        2. based on protection mechanism, use different leak payload first
        3. use FMT generation to generate the payload
        4. use state check first
        5. use the exploit check to check the exploit
        :return: None
        """
        self.GetFormatStringStates()
        self.GenerateFMTPayload()
        # no need for this step, because we use state check in exploit generate
        # self.StateCheckExploit()
        """
        if self.exploitchecklocal:
            self.LocalCheckExploit()
        if self.exploitcheckremote:
            self.RemoteCheckExploit()
        """

    def MainScheduleForStackOverflow(self, remote=False):
        """
        1. get the states
        2. based on protection mechanism, use different algorithm
        3. use ROP generation to generate the payload
        4. use state check first
        5. use the exploit check to check the exploit
        :param remote: if remote payload, True, otherwise False
        :return:
        """
        self.GetStackOverFlowStates()
        self.GenerateROPPayload(remote=remote)
        # self.StateCheckExploit()

    def MainScheduleForBackdoor(self):
        """
        judge whether there is backdoor inside a binary, and use
        dynamic symbolic execution to find the path
        :return: None
        """
        backdoorpathexamine = BackdoorPathExamine(
            binary_path=self.binarypath, function_helper=self.function_helper,
            protection=self.protection
        )
        result = backdoorpathexamine.BackdoorMain(stepcount=self.stepcount)
        if result:
            #temppayloadlist = PayloadList()
            #temppayloadlist.MergePayloadList(backdoorpathexamine.payloadlist)
            self.payloadlist.extend(backdoorpathexamine.payloadlist)
            self.backdoorpathstates.extend(backdoorpathexamine.statelog)
            self.exploit_method = "path to backdoor"
            self.technique_used = "dynamic symbolic execution"
            return True
        else:
            return False

    def HandleExploitMerge(self):
        """
        we have two exploit set, one for format string, another for stack overflow
        we need to connect two set, and generate final exploit
        :return: True when success, False when fail
        """
        if self.needfmtvuln and len(self.formatstringstates) == 0:
            log.Exception("need format string vulnerability but don't find")
            return False
        if len(self.stackoverflowstates) == 0:
            log.Exception("cannot find stack overflow vulnerability in this binary")
            return False
        self.payloadlist = []
        if not self.needfmtvuln:
            for ROPstatelog in self.stackoverflowstates:
                temppayloadlist = PayloadList()
                temppayloadlist.MergePayloadList(ROPstatelog.payloadlist)
                self.payloadlist.append(temppayloadlist)
        else:
            for fmtstatelog in self.formatstringstates:
                for stackstatelog in self.stackoverflowstates:
                    temppayloadlist = PayloadList()
                    temppayloadlist.MergePayloadList(fmtstatelog.payloadlist)
                    temppayloadlist.MergePayloadList(stackstatelog.payloadlist)
                    self.payloadlist.append(temppayloadlist)
        return True

    def MainScheduleForFuzz(self, challenge=Challenge()):
        """
        1. get the states
        2. based on protection mechanism, use different algorithm
        3. use ROP generation to generate the payload
        4. use state check first
        5. use the exploit check to check the exploit
        :return: None
        """
        localcheckpass = False
        remotecheckpass = False
        self.InitMainSchedule()
        if self.usebackdoor:
            find_backdoor_path = self.MainScheduleForBackdoor()
            if find_backdoor_path:
                if self.exploitchecklocal:
                    localcheckpass = self.LocalCheckExploit(full_test=False, isbackdoorpath=True)
                if self.exploitcheckremote:
                    remotecheckpass = self.RemoteCheckExploit(full_test=False, isbackdoorpath=True, challenge=challenge)
                return localcheckpass, remotecheckpass
        self.MainScheduleForFormatString()
        if self.exploitchecklocal:
            self.MainScheduleForStackOverflow(remote=False)
            if self.HandleExploitMerge():
                log.info("success merge all exploit")
            else:
                log.Exception("error when handle merge exploit")
                return False, False
            localcheckpass = self.LocalCheckExploit(full_test=False)
        if self.exploitcheckremote:
            self.MainScheduleForStackOverflow(remote=True)
            if self.HandleExploitMerge():
                log.info("success merge all exploit")
            else:
                log.Exception("error when handle merge exploit")
                return False, False
            remotecheckpass = self.RemoteCheckExploit(full_test=False, challenge=challenge)
        return localcheckpass, remotecheckpass


if __name__ == '__main__':
    """
    test the Schedule
    """
    # have tested:
    # ../binaries/stack_overflow/static/test1/static_test1
    # ../binaries/stack_overflow/static/test2/static_test2
    # ../binaries/stack_overflow/static/test3/static_test3
    # ../binaries/stack_overflow/static/test4/static_test4
    # ../binaries/stack_overflow/dynamic/test1/dynamic_test1
    # ../binaries/stack_overflow/dynamic/test2/dynamic_test2
    # ../binaries/stack_overflow/dynamic/test3/dynamic_test3
    # ../binaries/stack_overflow/dynamic/test4/dynamic_test4
    # not tested:
    # binarypath = "../binaries/formatstring_stackoverflow/fmt_stack_canary/fmt_stack_canary"
    # binarypath = "../binaries/formatstring_stackoverflow/fmt_stack_canary_PIE/fmt_stack_canary_PIE"
    binarypath = "/home/yuge/Documents/ACBEG/binaries/mips32/stack_overflow/dynamic/test1"
    # StackOverflowExamine = StackOverflowExamine(binarypath=binarypath)
    # StackOverflowExamine.StackOverflowMain(stepcount=0x1000)
    # print(StackOverflowExamine.stackoverflowlog)
    mainschedule = MainSchedule(binarypath=binarypath)
    mainschedule.MainScheduleForFuzz()