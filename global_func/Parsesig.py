"""
author : 4everdestiny
create_time : 2023.6.11
description : this is the code to parse the sig file
input : binary path and sig file path
output :the information needed
"""

import nampa
import pwn
import angr
from log.log import Log

log = Log()


class MyFlirtLog:
    def __init__(self, FlirtModule=None, pattern=None, variant_mask=None):
        self.FlirtModule = FlirtModule
        self.pattern = pattern
        self.variant_mask = variant_mask


class ParseSig:
    def __init__(self, binarypath="", sigfilepath=""):
        self.binarypath = binarypath
        self.sigfilepath = sigfilepath
        self.sig = None
        self.elf = pwn.ELF(self.binarypath, checksec=False)
        self.parsesigfile()
        self.libc = pwn.ELF("../binaries_for_wangding/libcs/libc-2.23.so", checksec=False)
        self.funcnameflirtmap = {}

    def parsesigfile(self):
        """
        get the function addresses from the sig file
        :return: the
        """
        print(open(self.sigfilepath, 'rb'))
        self.sig = nampa.parse_flirt_file(open(self.sigfilepath, 'rb'))

    def getsymbolname(self, address=0x0):
        """
        get the symbol name from the sig file
        :param address: the function's address
        :return: the symbol of the function's name
        """
        offset = self.elf.vaddr_to_offset(address=address)
        code = b""
        for index in range(0x300):
            code_byte = self.elf.data[offset + index].to_bytes(
                length=1, byteorder="little")
            if code_byte != b"\xc3":
                code += code_byte
            else:
                code += code_byte
                break
        print(code)
        self.findbycode(code=code)

    def Recurse(self, node=None, funcnamemap=None):
        """
        recurse the tree of sig
        :param node: the node of the tree of sig
        :param funcnamemap: the function name map, and then change to
        :return:
        """
        if node.is_leaf:
            for m in node.modules:
                print(m)
        else:
            for child in node.children:
                self.Recurse(node=child, funcnamemap=funcnamemap)

    def GetCodeByName(self, funcnamemap=dict()):
        """
        find the code judge from a .sig file
        :param funcnamemap: the alternative name map
        :return: the name -> code map
        """
        self.funcnameflirtmap = {}
        for child in self.sig.root.children:
            self.Recurse(node=child, funcnamemap=funcnamemap)

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

    def GetSymbolAddrMap(self):
        """
        here we want to get the map[symbol: addr] from a stripped file
        :return: the map[symbol: addr]
        """
        libc_funcs = list(angr.procedures.SIM_PROCEDURES['libc'].keys())
        # print(libc_funcs)
        glibc_funcs = list(angr.procedures.SIM_PROCEDURES['glibc'].keys())
        alternative_libc_funcs = self.ParseAlternativeFuncname(funclist=libc_funcs)
        alternative_glibc_funcs = self.ParseAlternativeFuncname(funclist=glibc_funcs)
        print(alternative_libc_funcs)
        print(alternative_glibc_funcs)

if __name__ == '__main__':
    parsesig = ParseSig(
        binarypath="../binaries_p10/1/bin01", sigfilepath="../binaries_p10/sig/libc6_2.23-0ubuntu9_i386.sig"
    )
    # print(parsesig.getsymbolname(address=0x080511E0))
    print(parsesig.GetSymbolAddrMap())