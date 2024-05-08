"""
author : 4everdestiny
create_time : 2023.6.27
description : this is the code to use redare2 to help fuzzer
input : binary path and the sig file path
output : the function's addr map
"""

import r2pipe
import os
import json
import pwn
import angr
import re


class Radare2Helper:
    def __init__(self, binarypath="", libc_path="", sigfilepath="", sdbfilepath=""):
        self.binarypath = os.path.abspath(binarypath)
        self.sigfilepath = os.path.abspath(sigfilepath)
        self.sdbfilepath = os.path.abspath(sdbfilepath)
        # use the libc to find the alternative name
        if libc_path != "":
            self.libc = pwn.ELF(libc_path, checksec=False)
        else:
            self.libc = None
        self.funcmap = {}
        self.haveparsesig = False
        self.angr_libc_hook_address_map = {}
        self.angr_glibc_hook_address_map = {}
        self.angr_posix_hook_address_map = {}
        self.sdb_process = None
        self.have_init_sdb_process = False

    def GetFuncMap(self):
        """
        get the func map of binary
        :return: the funcmap of current binary
        """
        self.ParseSig()
        return self.funcmap

    def GetFuncAddressBySimilarity(self, func_name=""):
        """
        get the function address by the similarity judge
        :param func_name: the function name to judge
        :return: (True, address) when success, (False, 0) when fail
        """
        res = self.sdb_process.cmd(f"zbrj sym.{func_name} 1")
        # r2.quit()
        if res == "":
            return False, 0
        # print(res)
        func_match = json.loads(res)[0]
        if func_match["similarity"] < 0.6:
            return False, 0
        if func_match["byte similarity"] < 0.6:
            return False, 0
        if func_match["graph similarity"] < 0.6:
            return False, 0
        return True, int(func_match["name"].replace("fcn.", ""), 16)

    def GetFuncAddress(self, func_name=""):
        """
        this is only used for stripped statically-linked binary
        :param func_name: the func name to search
        :return: find and the func address
        """
        if not self.have_init_sdb_process:
            r2 = r2pipe.open(self.binarypath, flags=["-2"])  # , flags=["-d"])
            #r2.process.stdout = subprocess.DEVNULL
            r2.cmd("aaa")
            r2.cmd("zo {sdbfilepath}".format(sdbfilepath=self.sdbfilepath))
            self.have_init_sdb_process = True
            self.sdb_process = r2
            # this two line to init function search
            # self.sdb_process.cmd("aaa")
            # self.sdb_process.cmd("afl")
            # too slow, ignore it
        funclist = [func_name]
        func_name_list = self.ParseAlternativeFuncname(funclist=funclist)
        if len(func_name_list) == 0:
            return False, 0
        for func_name_temp in func_name_list[func_name]:
            # func_name_temp = func_name_list[func_name][i]
            find, address = self.GetFuncAddressBySimilarity(func_name=func_name_temp)
            if find:
                return find, address
        return False, 0
        # print(func_match)

    def GetFuncReference(self, func_addr=0):
        """
        get the func reference inside this binary
        :param func_addr: the function's address
        :return: the func reference of this function
        """
        r2 = r2pipe.open(self.binarypath, flags=["-2"])  # , flags=["-d"])
        # r2.process.
        #r2.process.stdout = subprocess.DEVNULL
        r2.cmd("aaa")
        r2.cmd(hex(func_addr))
        res = r2.cmd("aflx")
        r2.quit()
        info = res
        references = []
        for line in info.split("\n"):
            # print(line)
            if line == "":
                continue
            addrs = list(map(lambda x: int(x, 16), re.findall("0x[0-9a-f]+", line)))
            calls = addrs[0]
            xrefs = addrs[1:]
            references.append({"calls": calls, "xrefs": xrefs})
        return references

    def ParseSig(self):
        """
        parse the sig file and find the functions' address by using the sig file
        :return: the functions' address map
        """
        # print(self.binarypath)
        if self.haveparsesig:
            return None
        self.funcmap = {}
        r2 = r2pipe.open(self.binarypath, flags=["-2"]) #, flags=["-d"])
        #r2.process.stderr = subprocess.DEVNULL
        r2.cmd("aaa")
        r2.cmd("zfs {sigfilepath}".format(sigfilepath=self.sigfilepath))
        funcs = json.loads(r2.cmd("aflj"))
        r2.quit()
        for func in funcs:
            #print(func)
            func_name = func["name"]
            if "fcn." in func_name:
                # fcn. means cannot analyse this function's name
                continue
            else:
                # flirt means analyse, after . is the name
                func_name = func_name.replace("flirt.", "")
            func_addr = func["offset"]
            self.funcmap[func_name] = func_addr
        #print(self.funcmap)
        self.haveparsesig = True
        return None

    def ParseAlternativeFuncname(self, funclist=None):
        """
        get the alternative func names from a libc file
        :param funclist: the funcname map
        :return:
        """
        if funclist is None:
            funclist = list()
        funcname_alternativename_map = {}
        funcname_address_map = {}
        # 1. get the funcname -> address map
        for funcname in funclist:
            if funcname in self.libc.symbols.keys():
                address = self.libc.symbols[funcname]
                funcname_address_map[funcname] = address
            else:
                # log.Exception("cannot find name for {funcname} in ParseAlternativeFuncname".format(funcname=funcname))
                continue
        # 2. get the name -> alternative map
        for symbol in self.libc.symbols.keys():
            address = self.libc.symbols[symbol]
            for funcname in funcname_address_map.keys():
                if address == funcname_address_map[funcname]:
                    if funcname not in funcname_alternativename_map.keys():
                        funcname_alternativename_map[funcname] = [symbol]
                    else:
                        funcname_alternativename_map[funcname].append(symbol)
        # print(funcname_alternativename_map)
        return funcname_alternativename_map

    def SearchFunction(self, func_name="", alternative_funcs={}):
        """
        search the function in a list, if found, return the address
        :param alternative_funcs: alternative name of funcs
        :return: return (True, func_address) if found
        return (False, 0) if not found
        """
        if func_name == "":
            return False, 0
        if alternative_funcs is None:
            return False, 0
        alternative_func_names = alternative_funcs[func_name]
        for alternative_func_name in alternative_func_names:
            if alternative_func_name in self.funcmap.keys():
                func_address = self.funcmap[alternative_func_name]
                return True, func_address
            if "_" + alternative_func_name in self.funcmap.keys():
                func_address = self.funcmap["_" + alternative_func_name]
                return True, func_address
            if "__" + alternative_func_name in self.funcmap.keys():
                func_address = self.funcmap["__" + alternative_func_name]
                return True, func_address
        return False, 0

    def GetSymbolAddrMap(self):
        """
        here we want to get the map[symbol: addr] from a stripped file
        :return: the map[symbol: addr]
        """
        self.ParseSig()
        self.angr_libc_hook_address_map = {}
        self.angr_glibc_hook_address_map = {}
        self.angr_posix_hook_address_map = {}
        libc_funcs = list(angr.procedures.SIM_PROCEDURES['libc'].keys())
        glibc_funcs = list(angr.procedures.SIM_PROCEDURES['glibc'].keys())
        posix_funcs = list(angr.procedures.SIM_PROCEDURES['posix'].keys())
        alternative_libc_funcs = self.ParseAlternativeFuncname(funclist=libc_funcs)
        alternative_glibc_funcs = self.ParseAlternativeFuncname(funclist=glibc_funcs)
        alternative_posix_funcs = self.ParseAlternativeFuncname(funclist=posix_funcs)
        alternative_posix_funcs["read"].append("__libc_read")
        alternative_posix_funcs["write"].append("__libc_write")
        # print(alternative_libc_funcs)
        # print(alternative_glibc_funcs)
        for func_name in alternative_libc_funcs.keys():
            find, func_address = self.SearchFunction(
                func_name=func_name, alternative_funcs=alternative_libc_funcs)
            if find:
                self.angr_libc_hook_address_map[func_name] = func_address
        for func_name in alternative_glibc_funcs.keys():
            find, func_address = self.SearchFunction(
                func_name=func_name, alternative_funcs=alternative_glibc_funcs)
            if find:
                self.angr_glibc_hook_address_map[func_name] = func_address
        for func_name in alternative_posix_funcs.keys():
            find, func_address = self.SearchFunction(
                func_name=func_name, alternative_funcs=alternative_posix_funcs)
            if find:
                self.angr_posix_hook_address_map[func_name] = func_address
        # print(self.angr_libc_hook_address_map)
        # print(self.angr_glibc_hook_address_map)


if __name__ == '__main__':
    parsesig = Radare2Helper(
        binarypath="../binaries/2023_wangding/1/bin01",
        sigfilepath="../binaries/2023_wangding/sigfile/libc6_2.23-0ubuntu11_i386.sig"
    )
    # print(parsesig.getsymbolname(address=0x080511E0))
    print(parsesig.GetSymbolAddrMap())