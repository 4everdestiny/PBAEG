"""
author : 4everdestiny
create_time : 2023.9.7
description : this is the code to help fuzzer to run stably and quickly
input : binary path, functionhelper, project
output : the hooked project
"""

import angr
from log import log

log = log.Log()


class FuzzerHelper:
    def __init__(self, binary_path="", function_helper=None):
        self.binary_path = binary_path
        self.function_helper = function_helper

    def HookForStaticBinary(self, project=None, protection=None):
        """
        sometimes we need to hook for the static binary
        :param project: the angr project
        :param protection: the protection information
        :return: None
        """
        libc_black_list = ["puts"]
        glibc_white_list = ["__libc_start_main"]
        if project.arch.name == "X86":
            use_deep_find = True
        else:
            use_deep_find = False
        if not (protection["static"] and protection["stripped"]):
            # if have, means we have no-stripped statically-linked binary
            libc_funcs = list(angr.procedures.SIM_PROCEDURES['libc'].keys())
            glibc_funcs = list(angr.procedures.SIM_PROCEDURES['glibc'].keys())
            posix_funcs = list(angr.procedures.SIM_PROCEDURES['posix'].keys())
            for libc_func in libc_funcs:
                if libc_func in libc_black_list:
                    continue
                if self.function_helper.CheckHaveFunction(func_name=libc_func, use_deep_find=use_deep_find):
                    address = self.function_helper.GetFunctionAddress(func_name=libc_func, use_deep_find=use_deep_find)
                    if not project.is_hooked(address):
                        project.hook(address, angr.SIM_PROCEDURES['libc'][libc_func]())
                        log.success("hook for {name}:{address}".format(name=libc_func, address=hex(address)))
            for glibc_func in glibc_funcs:
                if self.function_helper.CheckHaveFunction(func_name=glibc_func):
                    address = self.function_helper.GetFunctionAddress(func_name=glibc_func)
                    if not project.is_hooked(address):
                        project.hook(address, angr.SIM_PROCEDURES['glibc'][glibc_func]())
                        log.success("hook for {name}:{address}".format(name=glibc_func, address=hex(address)))
            for posix_func in posix_funcs:
                if self.function_helper.CheckHaveFunction(func_name=posix_func):
                    address = self.function_helper.GetFunctionAddress(func_name=posix_func)
                    if not project.is_hooked(address):
                        project.hook(address, angr.SIM_PROCEDURES['posix'][posix_func]())
                        log.success("hook for {name}:{address}".format(name=posix_func, address=hex(address)))
        else:
            # here, means we have a stripped statically-linked binary
            r2helper = self.function_helper.radare2helper
            r2helper.GetSymbolAddrMap()
            angr_libc_hook_address_map = r2helper.angr_libc_hook_address_map
            angr_glibc_hook_address_map = r2helper.angr_glibc_hook_address_map
            angr_posix_hook_address_map = r2helper.angr_posix_hook_address_map
            libc_funcs = list(angr.procedures.SIM_PROCEDURES['libc'].keys())
            glibc_funcs = list(angr.procedures.SIM_PROCEDURES['glibc'].keys())
            posix_funcs = list(angr.procedures.SIM_PROCEDURES['posix'].keys())
            for libc_func in libc_funcs:
                if libc_func in libc_black_list:
                    continue
                if libc_func in angr_libc_hook_address_map.keys():
                    address = angr_libc_hook_address_map[libc_func]
                    if not project.is_hooked(address):
                        if not project.is_hooked(address):
                            project.hook(address, angr.SIM_PROCEDURES['libc'][libc_func]())
                            log.success("hook for {name}:{address}".format(name=libc_func, address=hex(address)))
                else:
                    if use_deep_find:
                        address = self.function_helper.GetFunctionAddress(
                            func_name=libc_func, use_deep_find=use_deep_find)
                        if address == 0:
                            continue
                        if not project.is_hooked(address):
                            project.hook(address, angr.SIM_PROCEDURES['libc'][libc_func]())
                            log.success("hook for {name}:{address}".format(name=libc_func, address=hex(address)))
                            continue
            for glibc_func in glibc_funcs:
                if glibc_func in angr_glibc_hook_address_map:
                    address = angr_glibc_hook_address_map[glibc_func]
                    if not project.is_hooked(address):
                        project.hook(address, angr.SIM_PROCEDURES['glibc'][glibc_func]())
                        log.success("hook for {name}:{address}".format(name=glibc_func, address=hex(address)))
                else:
                    if glibc_func in glibc_white_list:
                        address = self.function_helper.GetFunctionAddress(
                            func_name=glibc_func, use_deep_find=True)
                        if address == 0:
                            continue
                        if not project.is_hooked(address):
                            project.hook(address, angr.SIM_PROCEDURES['glibc'][glibc_func]())
                            log.success("hook for {name}:{address}".format(name=glibc_func, address=hex(address)))
                            continue
                    if use_deep_find:
                        address = self.function_helper.GetFunctionAddress(
                            func_name=glibc_func, use_deep_find=True)
                        if address == 0:
                            continue
                        if not project.is_hooked(address):
                            project.hook(address, angr.SIM_PROCEDURES['glibc'][glibc_func]())
                            log.success("hook for {name}:{address}".format(name=glibc_func, address=hex(address)))
                            continue
            for posix_func in posix_funcs:
                if posix_func in angr_posix_hook_address_map:
                    address = angr_posix_hook_address_map[posix_func]
                    if not project.is_hooked(address):
                        project.hook(address, angr.SIM_PROCEDURES['posix'][posix_func]())
                        log.success("hook for {name}:{address}".format(name=posix_func, address=hex(address)))
                        continue
                if use_deep_find:
                    address = self.function_helper.GetFunctionAddress(
                        func_name=posix_func, use_deep_find=True)
                    if address == 0:
                        continue
                    if not project.is_hooked(address):
                        project.hook(address, angr.SIM_PROCEDURES['posix'][posix_func]())
                        log.success("hook for {name}:{address}".format(name=posix_func, address=hex(address)))
                        continue


