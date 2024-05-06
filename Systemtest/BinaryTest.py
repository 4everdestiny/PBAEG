"""
author : 4everdestiny
create_time : 2022.7.12
description : this is the code to test the final project
"""

import sys
sys.path.append("..")

import os
from Schedule.MainSchedule import MainSchedule
from log.log import Log
from Systemtest.ConnectDatabase import Database
from exploit_generation.ProtectionInformation import ProtectionInformation
from web_interface.Challenge import Challenge
import time
import configparser
import traceback
log = Log()


class BinaryTest:
    def __init__(self, is_IOT=False):
        self.directorys = ["../binaries/32bit", "../binaries/64bit",
                           "../binaries/gets_vuln",
                           "../binaries/easy_stack_overflow"]
        #self.directorys = ["../binaries/easy_stack_overflow/plainR2B"]
        self.database = Database()
        self.dbinfo = ["time", "binary_name", "binary_path",
                        "finish_detect", "time_consuming",
                        "vulnerability_type", "payload_path",
                       "architecture", "NX", "Canary",
                       "PIE", "RELRO", "exploit_method", "technique_used"]
        self.exploitchecklocal = False
        self.exploitcheckremote = False
        self.is_IOT = is_IOT

    def readconf(self):
        """
        this is the function to read the config file
        :return: None
        """
        conf = configparser.ConfigParser()
        conf.read("../config.ini")
        if conf.has_section("ExploitCheck"):
            self.exploitchecklocal = conf.get("ExploitCheck", "Local") == "True"
            self.exploitcheckremote = conf.get("ExploitCheck", "Remote") == "True"
            # print(self.depthlimit)
        else:
            log.Exception("ExploitCheck config missing")

    def ScanFile(self, directory=""):
        """
        just a scan directory function
        :return:
        """
        file = os.listdir(directory)
        directorys = []
        for f in file:
            if f == "Makefile" or f == "fuzz_in" or f == "fuzz_out":
                continue
            if f.startswith("."):
                continue
            if f.endswith(".c") or f.endswith(".py") or f.endswith(".idb")\
                    or f.endswith(".txt") or f.endswith(".so") or f.endswith(".md")\
                    or f.endswith(".conf"):
                continue
            real_url = os.path.join(directory, f)
            if os.path.isfile(real_url):
                directorys.append(os.path.abspath(real_url))
            elif os.path.isdir(real_url):
                directorys.extend(self.ScanFile(directory=real_url))
            else:
                pass
        return directorys

    def GetNeedTestPath(self, one_directory=False, directorys=[]):
        """
        get the need test path
        1. scan the directorys to the get the bianry path
        2. use the path to generate a payload according to path
        3. test the payload generation in local and remote mode
        4. if occur an error, exist and find which bianry cause
        :return: the needed test pathes
        """
        if one_directory and len(directorys) == 1:
            directory = directorys[0]
            return self.ScanFile(directory=directory)
        else:
            paths = []
            for directory in directorys:
                paths.extend(self.ScanFile(directory=directory))
            return paths

    def SystemTestMain(self, force_update=False, paths=[], challenge=Challenge()):
        """
        the main of system test
        :return: None
        """
        self.readconf()
        if len(paths) == 0:
            paths = self.GetNeedTestPath(directorys=self.directorys)
        else:
            paths = paths
        for path in paths:
            #print(path)
            need_detect = self.database.CheckNeedDetect(
                binarypath=path, is_IOT=self.is_IOT
            )
            if not force_update and not need_detect:
            # if not need_detect:
                log.info("{binary_path} not need to detect".format(binary_path=path))
                continue
            temp_time = time.time()
            protection_info = ProtectionInformation(binarypath=path)
            test_demo = MainSchedule(binarypath=path)
            try:
                local_pass, remote_pass = test_demo.MainScheduleForFuzz(challenge=challenge)
                if (not self.exploitchecklocal or local_pass) and (not self.exploitcheckremote or remote_pass):
                    log.success("{binarypath}: check succeed".format(binarypath=path))
                    finish = True
                else:
                    log.Exception("error occur in {binarypath}".format(binarypath=path))
                    finish = False
            except Exception as e:
                log.Exception(traceback.print_exc())
                log.Exception(e)
                log.Exception("error occur in {binarypath}".format(binarypath=path))
                finish = False
            temp_info = dict.fromkeys(self.dbinfo)
            temp_info["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            temp_info["binary_name"] = path.split("/")[-1]
            temp_info["binary_path"] = path
            temp_info["finish_detect"] = finish
            temp_info["time_consuming"] = time.time() - temp_time
            temp_info["vulnerability_type"] = test_demo.GetVulnerabilityType()
            temp_info["exploit_method"] = test_demo.exploit_method
            temp_info["technique_used"] = test_demo.technique_used
            temp_info["payload_path"] = path + ".py"
            temp_info["architecture"] = protection_info.protection["arch"]
            temp_info["NX"] = protection_info.protection["NX"]
            temp_info["Canary"] = protection_info.protection["Canary"]
            temp_info["PIE"] = protection_info.protection["PIE"]
            temp_info["RELRO"] = protection_info.protection["RELRO"]
            have_insert_database = self.database.InsertSingleDetectResult(info=temp_info, is_IOT=self.is_IOT)
            if have_insert_database:
                log.success("{binarypath} result have insert the result to database".format(binarypath=path))
            else:
                log.Exception("{binarypath} result not insert the result to database".format(binarypath=path))
        # finally close the database
        # self.database.connection.close()

    def FinishDetect(self):
        """
        just close database and return
        :return: None
        """
        self.database.connection.close()


if __name__ == '__main__':
    binarytest = BinaryTest(is_IOT=True)
    paths = binarytest.GetNeedTestPath(
        one_directory=True,
        directorys=["/home/yuge/Documents/PBAEG/binaries/64bit/path_search_test/path_search_stack/path_search_stack_test1"]
    )
    #paths = binarytest.GetNeedTestPath(directorys=["../binaries/mips32/stack_overflow/dynamic/test1"])
    binarytest.SystemTestMain(paths=paths, force_update=True)
