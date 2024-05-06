"""
author : 4everdestiny
create_time : 2022.3.30
description : this is the code to log the state
1. the stack overflow state
2. the format string state
also need to deduplication about the same state
same state:
rsp equal and rip equal
input : state
output : return the state list
"""

class StateList:
    def __init__(self):
        self.statelist = []

    def insert(self, state):
        """
        insert a state into the state list
        if there are other states, need to do deduplication
        :param state: the state want to insert
        :return: True if insert successfully, False if repeat
        """
        for i in range(len(self.statelist)):
            pass