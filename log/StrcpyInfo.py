"""
author : 4everdestiny
create_time : 2022.12.8
description : this is the code to log the strcpy function's information
"""

import re
import sys


class StrcpyInfo:
    def __init__(self, prefix_payload_index=[0, 0], suffix_payload_index=[0, 0],
                 output_index=[0, 0], inargv=False, argv_index=0,
                 infile=False, file_fd=sys.stdin.fileno()):
        self.prefix_payload_begin_index = prefix_payload_index[0]
        self.prefix_payload_end_index = prefix_payload_index[1]
        self.suffix_payload_begin_index = suffix_payload_index[0]
        self.suffix_payload_end_index = suffix_payload_index[1]
        self.output_begin_index = output_index[0]
        self.output_end_index = output_index[1]
        self.inargv = inargv
        self.argv_index = argv_index
        self.infile = infile
        self.file_fd = file_fd