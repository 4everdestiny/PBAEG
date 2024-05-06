#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import time

"""
author : 王宇
id : 4everdestiny
last_date : 2019-12-18
info : log
"""


class Log:
    def __init__(self):
        self.console = sys.stdout

    def ensure_bytes(self, content, encoding='utf-8'):
        if isinstance(content, str):
            return bytes(content, encoding=encoding)
        return content

    def _simpleprint(self, word):
        try:
            self.console.write(word)
        except Exception as e:
            self.console.write(self.ensure_bytes(word))

    def _print(self, word):
        try:
            self.console.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + '\n')
            self.console.write(word)
        except Exception as e:
            self.console.write(
                self.ensure_bytes(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + '\n'))
            self.console.write(self.ensure_bytes(word))

    def _printout(self, word):
        try:
            sys.stdout.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + '\n')
            sys.stdout.write(word)
        except Exception as e:
            sys.stdout.write(self.ensure_bytes(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + '\n'))
            sys.stdout.write(self.ensure_bytes(word))

    def beauty(self, word):
        res = ''
        beauty_length = 75
        loop = len(word) / beauty_length
        for i in range(loop):
            res += word[i * beauty_length:i * beauty_length + beauty_length] + "\n    "
        res += word[loop * beauty_length:]
        return res

    def Exception(self, word):
        self._simpleprint("[-] exception %s\n" % repr(word))

    def info(self, word):
        self._simpleprint("[*] %s\n" % repr(word))

    def success(self, word):
        self._simpleprint("[+] %s\n" % repr(word))

    def close(self):
        self.console.close()