"""
author : 4everdestiny
create_time : 2022.12.8
description : this is the code to log the scanf function's information
"""

import re


class ScanfInfo:
    def __init__(self, formatstring="", overflow_index=0, formats=None):
        self.formatstring = formatstring
        if formats == None:
            self.formats = self.ParseFormatString(self.formatstring)
        else:
            self.formats = formats
        self.overflow_index = overflow_index

    def ParseFormatString(self, formatstring=""):
        """
        return the formats of the formatstring
        :param formatstring: the format string, such as %s
        :return: the formats
        """
        return re.findall(r"%\d*[dscuoxX]", formatstring)