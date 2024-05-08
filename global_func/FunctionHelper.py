"""
author : 4everdestiny
create_time : 2023.7.4
description : this is the code to analyse the functions in a binary file
input : binary path
output : the function and addr inside this binary
"""
import angr
import pwn
from log.log import Log
from global_func.Radare2Helper import Radare2Helper
import os

log = Log()


class Functionhelper:
    def __init__(self, binary_path="", libc_path="", sig_path="", sdb_path=""):
        """
        the init function of Functionhelper
        :param binary_path: the binary path
        :param libc_path: the libc path
        """
        self.binary_path = binary_path
        if self.binary_path != "":
            self.project = angr.Project(self.binary_path)
            self.elf = pwn.ELF(self.binary_path, checksec=False)
        else:
            self.project = None
            self.elf = None
        self.funcname_alternativename_map = {}
        self.havesig = False
        self.havesdb = False
        self.sig_path = sig_path
        self.sdb_path = sdb_path
        self.binary_static = False
        self.stripped = False
        self.libc_path = libc_path
        self.ParseBinaryInfo()
        if self.libc_path != "":
            self.libc = pwn.ELF(self.libc_path, checksec=False)
        else:
            self.libc = None
        self.funcname_alternativename_map = self.ParseLibcAlternativeFuncname()
        self.radare2helper = Radare2Helper(
            binarypath=self.binary_path,
            libc_path=self.libc_path,
            sigfilepath=self.sig_path,
            sdbfilepath=self.sdb_path
        )

    def ParseBinaryInfo(self):
        """
        parse the binary info first
        :return: None
        """
        if self.project is None:
            return False
        if len(self.project.loader.requested_names) == 0:
            self.binary_static = True
        else:
            self.binary_static = False
        if self.sig_path == "":
            self.havesig = False
        else:
            self.havesig = True
        if self.sdb_path == "":
            self.havesdb = False
        else:
            self.havesdb = True
        if self.binary_static:
            # stripped binary only for dynamic binary
            if self.CheckHaveFunction(func_name="__libc_start_main"):
                self.stripped = False
            else:
                self.stripped = True
        if self.libc_path == "":
            if self.project.arch.name == "MIPS32":
                self.libc_path = "../binaries/libcs/mips32/libc-mipsel-2.27.s0"
            elif self.project.arch.name == "AMD64":
                self.libc_path = "../binaries/libcs/libc-2.27.so"
            elif self.project.arch.name == "X86":
                self.libc_path = "../binaries/libcs/libc-2.27_x86.so"
            elif self.project.arch.name == "ARMEL":
                self.libc_path = "../binaries/libcs/arm/libc_arm_2.27.so"
            elif self.project.arch.name == "ARMHF":
                self.libc_path = "../binaries/libcs/arm/libc_armhf_2.27.so"
            else:
                log.Exception("cannot support arch {arch_name} in Functionhelper".format(arch_name=self.project.arch.name))

    def ParseLibcAlternativeFuncname(self):
        """
        get the alternative func names from a libc file
        :return:
        """
        if self.libc is None:
            return False
        funclist = self.libc.symbols.keys()
        funcname_alternativename_map = {}
        funcname_address_map = {}
        # 1. get the funcname -> address map
        for funcname in funclist:
            if funcname == "":
                continue
            address = self.libc.symbols[funcname]
            funcname_address_map[funcname] = address
        # 2. get the name -> alternative map
        for symbol in self.libc.symbols.keys():
            if symbol == "":
                continue
            address = self.libc.symbols[symbol]
            for funcname in funcname_address_map.keys():
                if address == funcname_address_map[funcname]:
                    if funcname not in funcname_alternativename_map.keys():
                        funcname_alternativename_map[funcname] = [symbol]
                    else:
                        funcname_alternativename_map[funcname].append(symbol)
        """
        for funcname in funcname_address_map.keys():
            if len(funcname_alternativename_map[funcname]) > 1:
                print(funcname)
        """
        # mannually add the scanf for c99 format
        funcname_alternativename_map["scanf"].append("__isoc99_scanf")
        funcname_alternativename_map["__isoc99_scanf"].append("scanf")
        # for read/write function, the alternative name
        funcname_alternativename_map["read"].append("__libc_read")
        funcname_alternativename_map["write"].append("__libc_write")
        # print(funcname_alternativename_map)
        return funcname_alternativename_map

    def CheckHaveFunction(self, func_name="", use_deep_find=False):
        """
        check the function is in or not in the binary(symbol)
        :param func_name: the function's name
        :return: True when have, False when not
        """
        if self.binary_static and self.stripped:
            return self.CheckHaveFunctionDeep(func_name=func_name, use_deep_find=use_deep_find)
        obj = self.project.loader.main_object
        if func_name in self.funcname_alternativename_map.keys():
            func_altname_list = self.funcname_alternativename_map[func_name]
        else:
            func_altname_list = [func_name]
        for func_name in func_altname_list:
            symbol = obj.get_symbol(func_name)
            if symbol is not None:
                # this line need debug, don't test much
                return True
        return False

    def CheckHaveFunctionDeep(self, func_name="", use_deep_find=False):
        """
        check the function is in or not in the binary(symbol)
        sometimes, in stripped statically linked binary,
        we need to use radare2 to load a sig file, and then check the function
        :param func_name: the function's name
        :param use_deep_find: if this is set to True,
        we use sdb file to search for the function
        :return: True when have, False when not
        """
        if self.stripped and self.binary_static:
            if not (self.havesig and self.havesdb):
                log.Exception("cannot find a function inside a stripped statically-linked binary in CheckHaveFunctionDeep")
                return False
        if self.binary_static and self.stripped:
            funcmap = self.radare2helper.GetFuncMap()
            if func_name in self.funcname_alternativename_map.keys():
                func_altname_list = self.funcname_alternativename_map[func_name]
            else:
                func_altname_list = [func_name]
            for func_name in func_altname_list:
                func_name_ = "_" + func_name
                if func_name in funcmap.keys() or func_name_ in funcmap.keys():
                    return True
                if use_deep_find:
                    have_func, func_addr = self.radare2helper.GetFuncAddress(
                        func_name=func_name)
                    if have_func:
                        # print(hex(func_addr))
                        return True
            return False
        else:
            obj = self.project.loader.main_object
            if func_name in self.funcname_alternativename_map.keys():
                func_altname_list = self.funcname_alternativename_map[func_name]
            else:
                func_altname_list = [func_name]
            for func_name in func_altname_list:
                symbol = obj.get_symbol(func_name)
                if symbol is not None:
                    # this line need debug, don't test much
                    return True
            return False

    def GetLibcStartMainAddr(self):
        """
        return the __libc_start_main function address
        :return: the __libc_start_main function address
        """
        # print("here")
        if self.elf.arch == "i386":
            entry_point = self.project.loader.main_object.entry
            block = self.project.factory.block(entry_point)
            temp_calls = entry_point
            #while block.size != 1:
            for _ in range(10):
                if block.size == 1:
                    break
                temp_calls += block.size
                block = self.project.factory.block(temp_calls)
            """
            call    sub_8048D20
            hlt
            """
            if block.size != 1:
                log.Exception("cannot find __libc_start_main inside this binary in GetLibcStartMainAddr")
                return 0
            call_ins_addr = temp_calls - 5
            block_pp = self.project.factory.block(call_ins_addr)
            if block_pp.disassembly.insns[0].mnemonic != "call":
                log.Exception("cannot find __libc_start_main inside this binary in GetLibcStartMainAddr(not call)")
                return 0
            address = int(block_pp.disassembly.insns[0].op_str, 16)
            return address
        elif self.elf.arch == "amd64":
            entry_point = self.project.loader.main_object.entry
            block = self.project.factory.block(entry_point)
            temp_calls = entry_point
            # while block.size != 1:
            for _ in range(10):
                if block.size == 1:
                    break
                temp_calls += block.size
                block = self.project.factory.block(temp_calls)
            """
            call    sub_400F90
            hlt
            """
            if block.size != 1:
                log.Exception("cannot find __libc_start_main inside this binary in GetLibcStartMainAddr")
                return 0
            call_ins_addr = temp_calls - 5
            block_pp = self.project.factory.block(call_ins_addr)
            if block_pp.disassembly.insns[0].mnemonic != "call":
                log.Exception("cannot find __libc_start_main inside this binary in GetLibcStartMainAddr(not call)")
                return 0
            address = int(block_pp.disassembly.insns[0].op_str, 16)
            return address
        else:
            log.Exception("unsupported architecture in GetLibcStartMainAddr")
            return 0

    def GetFunctionAddress(self, func_name="", use_deep_find=False, rebase_addr=False):
        """
        get the function address, if in stripped statically-linked binary
        need to use Radare2helper
        :param func_name: the func_name
        :param use_deep_find: only used in stripped-statically linked binary
        :param rebase_addr: if True, minus the binary's base, if False, just return
        if set to True, use .sdb file to search for the funciton
        :return: the func's address, remember to deal with the ASLR in user's code
        """
        if self.binary_static and self.stripped:
            return self.GetFunctionAddressDeep(func_name=func_name, use_deep_find=use_deep_find)
        obj = self.project.loader.main_object
        if func_name in self.funcname_alternativename_map.keys():
            func_altname_list = self.funcname_alternativename_map[func_name]
        else:
            func_altname_list = [func_name]
        for func_name in func_altname_list:
            symbol = obj.get_symbol(func_name)
            if symbol is not None:
                # this line need debug, don't test much
                if symbol.linked_addr == 0:
                    # in x86/amd64, this is 0
                    if obj.arch.name == "MIPS32":
                        return self.elf.plt[func_name]
                    if self.elf.pie and rebase_addr:
                        return obj.plt[func_name] - self.project.loader.main_object.min_addr
                    return obj.plt[func_name]
                return symbol.linked_addr
        return 0

    def GetFunctionAddressDeep(self, func_name="", use_deep_find=False):
        """
        get the function address in the binary(symbol)
        sometimes, in stripped statically linked binary,
        we need to use radare2 to load a sig file, and then check the function
        :param func_name: the func name to search
        :param use_deep_find: if this is set to True,
        we use sdb file to search for the function
        :return: the func's addr
        """
        if self.stripped and self.binary_static:
            if not (self.havesig and self.havesdb):
                log.Exception("cannot get a function inside a stripped statically-linked binary in GetFunctionAddressDeep")
                return 0
        if self.binary_static and self.stripped:
            funcmap = self.radare2helper.GetFuncMap()
            if func_name in self.funcname_alternativename_map.keys():
                func_altname_list = self.funcname_alternativename_map[func_name]
            else:
                func_altname_list = [func_name]
            for func_name in func_altname_list:
                if func_name in funcmap.keys():
                    return funcmap[func_name]
                func_name_ = "_" + func_name
                if func_name_ in funcmap.keys():
                    return funcmap[func_name_]
                func_name__ = "__" + func_name
                if func_name__ in funcmap.keys():
                    return funcmap[func_name__]
                if use_deep_find:
                    have_func, func_addr = self.radare2helper.GetFuncAddress(func_name=func_name)
                    if have_func:
                        # print(hex(func_addr))
                        return func_addr
            if func_name == "__libc_start_main":
                return self.GetLibcStartMainAddr()
            return 0
        else:
            obj = self.project.loader.main_object
            if func_name in self.funcname_alternativename_map.keys():
                func_altname_list = self.funcname_alternativename_map[func_name]
            else:
                func_altname_list = [func_name]
            for func_name in func_altname_list:
                symbol = obj.get_symbol(func_name)
                if symbol is not None:
                    # this line need debug, don't test much
                    if symbol.linked_addr == 0:
                        # in x86/amd64, this is 0
                        return obj.plt[func_name]
                    return symbol.linked_addr
            return 0

    def GetFuncReferenceByName(self, func_name="", use_deep_find=False):
        """
        get the func reference by func name
        :param func_name: the function's name
        :param use_deep_find: if use_deep_find is set to True,
        use .sdb file to find the functions
        :return: the references
        """
        func_addr = self.GetFunctionAddress(
            func_name=func_name, use_deep_find=use_deep_find)
        if func_addr == 0:
            log.Exception("cannot find function inside this binary")
            return []
        if self.elf.pie:
            func_addr -= self.project.loader.main_object.min_addr
        return self.radare2helper.GetFuncReference(func_addr=func_addr)

    def GetFuncReferenceByAddress(self, func_addr=0):
        """
        get the func reference by func addr
        :param func_addr: the function's address
        :return: the references
        """
        if func_addr == 0:
            log.Exception("cannot find function inside this binary")
            return None
        return self.radare2helper.GetFuncReference(func_addr=func_addr)

    def FindFuncionHeaderByAddress(self, address=0):
        """
        find the function header from an address
        :return: the function header address
        """
        offset = self.elf.vaddr_to_offset(address=address)
        search_range = min(0x500, offset)
        data = self.elf.data[offset - search_range: offset]
        if self.elf.arch == "amd64":
            pwn.context.arch = "amd64"
            pwn.context.bits = 64
            judge_bytes = pwn.asm("push rbp; mov rbp, rsp")
            index = data.find(judge_bytes)
            if index == -1:
                log.Exception("cannot find the function header in FindFuncionHeaderByAddress")
                return False, 0
            temp_data = data
            for _ in range(0x100):
                # find the last judge_bytes
                temp_data = temp_data[index + len(judge_bytes): offset]
                index = temp_data.find(judge_bytes)
                if index == -1:
                    break
            return True, self.elf.offset_to_vaddr(offset - len(temp_data) - len(judge_bytes))
        elif self.elf.arch == "i386":
            pwn.context.arch = "i386"
            pwn.context.bits = 32
            judge_bytes = pwn.asm("push ebp; mov ebp, esp")
            index = data.find(judge_bytes)
            if index == -1:
                log.Exception("cannot find the function header in FindFuncionHeaderByAddress")
                return False, 0
            temp_data = data
            for _ in range(0x100):
                # find the last judge_bytes
                temp_data = temp_data[index + len(judge_bytes): offset]
                index = temp_data.find(judge_bytes)
                if index == -1:
                    break
            return True, self.elf.offset_to_vaddr(offset - len(temp_data) - len(judge_bytes))

    def GetFuncEndByAddress(self, address=0, address_in_angr=True):
        """
        find the function ret instruction from an address
        :return: the function's ret address
        """
        if address_in_angr and self.elf.pie:
            load_address = self.project.loader.main_object.min_addr
            address += load_address
        block = self.project.factory.block(address)
        temp_calls = address
        # while block.size != 1:
        for _ in range(1000):
            if block.size == 1:
                break
            if b"\xc3" in block.bytes:
                # maybe we find a ret instruction
                if block.disassembly.insns[-1].mnemonic == "ret":
                    end_address = block.disassembly.insns[-1].address
                    if address_in_angr and self.elf.pie:
                        end_address -= load_address
                    return end_address
            temp_calls += block.size
            block = self.project.factory.block(temp_calls)
        return 0

    def GetCallFunctionsInside(self, address=0, address_in_angr=True):
        """
        get the function calls inside a function
        the call target must in plt
        :param address: the funtion address you want to analyze
        :param address_in_angr: if address_in_angr is set to True, we need to
        check the pie is enable or disable, if pie, plus load_address
        and when return, minus load_address
        :return: [{address: call_address}]
        """
        if self.elf.pie:
            load_address = self.project.loader.main_object.min_addr
        else:
            load_address = 0
        if address_in_angr and self.elf.pie:
            load_address = self.project.loader.main_object.min_addr
            address += load_address
        block = self.project.factory.block(address)
        temp_calls = address
        loader = self.project.loader.main_object
        calls = {}
        # while block.size != 1:
        for _ in range(1000):
            if block.size == 1:
                break
            if b"\xe8" in block.bytes:
                # maybe we find a call instruction
                for ins in block.disassembly.insns:
                    if ins.mnemonic == "call":
                        ins_target = int(ins.op_str, 16)
                        if ins_target in loader.reverse_plt.keys():
                            symbol = loader.reverse_plt[ins_target]
                            ins_addr = ins.address - load_address
                            # ins_real_target = ins_target - load_address
                            calls[ins_addr] = symbol
            if b"\xc3" in block.bytes:
                # maybe we find a ret instruction
                if block.disassembly.insns[-1].mnemonic == "ret":
                    break
            temp_calls += block.size
            block = self.project.factory.block(temp_calls)
        # print(calls)
        return calls


if __name__ == '__main__':
    """
    testfunctionhelper = Functionhelper(
        binary_path="../binaries/2023_wangding/5/bin05",
        libc_path="../binaries/2023_wangding/libc/libc-2.23.so",
        sig_path="../binaries/2023_wangding/sigfile/libc6_2.23-0ubuntu11_i386.sig",
        sdb_path="../binaries/2023_wangding/sigfile/libc_2.23_0ubuntu11.3_i386.sdb"
    )
    # print(hex(testfunctionhelper.GetFunctionAddress("system")))
    print(testfunctionhelper.GetFuncReferenceByName("system"))
    testfunctionhelper = Functionhelper(
        binary_path="../binaries/64bit/stack_overflow/dynamic/test1/dynamic_test1"
    )
    # print(hex(testfunctionhelper.GetFunctionAddress("system")))
    #print(testfunctionhelper.GetFuncReferenceByName("system"))

    # print(testfunctionhelper.CheckHaveFunction("system"))
    # print(hex(testfunctionhelper.GetFunctionAddress("system")))
    #print(testfunctionhelper.GetFuncReferenceByName("system"))

    # testfunctionhelper.ParseLibcAlternativeFuncname()
    """
    testfunctionhelper = Functionhelper(
        binary_path="../binaries/heap_binaries/heap_overflow/heap_overflow"
    )
    testfunctionhelper.GetCallFunctionsInside(address=0x400b9f)