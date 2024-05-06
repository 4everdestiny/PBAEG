"""
author : 4everdestiny
create_time : 2022.7.12
description : this is the code to connect to the database, and pass data
"""

import pymysql


class Database:
    def __init__(self):
        self.connection = self.ConnectDatabase()

    def ConnectDatabase(self):
        """
        connect to the database
        :return: None
        """
        connection = pymysql.connect(
            host="localhost", user="root",
            password="root", db='ACBEG'
        )
        return connection

    def DeleteNotFinishResult(self, binary_path="", is_IOT=False):
        """
        delete the log in the database which has finish_detect=False
        :param binary_path: the binary path
        :param is_IOT: if the binary is in IOT struct, set it True
        :return: True when success, False when failed
        """
        if is_IOT:
            return self.DeleteNotFinishResultIOT(binary_path=binary_path)
        sql = """delete from 
                vulnerability_detection where vulnerability_detection.binary_path="{binary_path}";
                """.format(binary_path=binary_path)
        # sql = """delete from
        # vulnerability_detection where vulnerability_detection.binary_path="{binary_path}"
        # AND vulnerability_detection.finish_detect=FALSE;
        # """.format(binary_path=binary_path)
        cur = self.connection.cursor()
        try:
            #print(sql)
            cur.execute(sql)
            self.connection.commit()
            return True
        except:
            self.connection.rollback()
            return False

    def DeleteNotFinishResultIOT(self, binary_path=""):
        """
        delete the log in the database which has finish_detect=False
        :param binary_path: the binary path
        :param is_IOT: if the binary is in IOT struct, set it True
        :return: True when success, False when failed
        """
        sql = """delete from 
        vulnerability_detection_IOT where vulnerability_detection_IOT.binary_path="{binary_path}"
        AND vulnerability_detection_IOT.finish_detect=FALSE;
        """.format(binary_path=binary_path)
        cur = self.connection.cursor()
        try:
            #print(sql)
            cur.execute(sql)
            self.connection.commit()
            return True
        except:
            self.connection.rollback()
            return False

    def InsertSingleDetectResult(self, info, is_IOT=False):
        """
        insert a detect result to the database
        :param info: the info needed when insert
        :param is_IOT: if the binary is in IOT struct, set it True
        :return: return True when successfully insert, False when error occured
        """
        if is_IOT:
            return self.InsertSingleDetectResultIOT(info)
        self.DeleteNotFinishResult(binary_path=info["binary_path"])
        sql = r"""insert into vulnerability_detection (time, binary_name,
        binary_path, finish_detect, time_consuming, vulnerability_type,
        payload_path, architecture, NX, Canary, PIE, RELRO) values ("{time}",
        "{binary_name}","{binary_path}",{finish_detect},{time_consuming},
        "{vulnerability_type}","{payload_path}","{architecture}",{NX},
        {Canary},{PIE},"{RELRO}")""".format(
            time=info["time"], binary_name=info["binary_name"],
            binary_path=info["binary_path"], finish_detect=info["finish_detect"],
            time_consuming=info["time_consuming"], vulnerability_type=info["vulnerability_type"],
            payload_path=info["payload_path"], architecture=info["architecture"],
            NX=info["NX"], Canary=info["Canary"], PIE=info["PIE"], RELRO=info["RELRO"]

        )
        cur = self.connection.cursor()
        try:
            #print(sql)
            cur.execute(sql)
            self.connection.commit()
            return True
        except:
            self.connection.rollback()
            return False

    def InsertSingleDetectResultIOT(self, info):
        """
        insert a detect result to the database
        :param info: the info needed when insert
        :return: return True when successfully insert, False when error occured
        """
        self.DeleteNotFinishResult(binary_path=info["binary_path"], is_IOT=True)
        sql = r"""insert into vulnerability_detection_IOT (time, binary_name,
        binary_path, finish_detect, time_consuming, vulnerability_type,
        payload_path, architecture, NX, Canary, PIE, RELRO, exploit_method, technique_used) values ("{time}",
        "{binary_name}","{binary_path}",{finish_detect},{time_consuming},
        "{vulnerability_type}","{payload_path}","{architecture}",{NX},
        {Canary},{PIE},"{RELRO}","{exploit_method}","technique_used")""".format(
            time=info["time"], binary_name=info["binary_name"],
            binary_path=info["binary_path"], finish_detect=info["finish_detect"],
            time_consuming=info["time_consuming"], vulnerability_type=info["vulnerability_type"],
            payload_path=info["payload_path"], architecture=info["architecture"],
            NX=info["NX"], Canary=info["Canary"], PIE=info["PIE"], RELRO=info["RELRO"],
            exploit_method=info["exploit_method"], technique_used=info["technique_used"]

        )
        cur = self.connection.cursor()
        try:
            #print(sql)
            cur.execute(sql)
            self.connection.commit()
            return True
        except:
            self.connection.rollback()
            return False

    def CheckNeedDetect(self, binarypath="", force_update=False, is_IOT=False):
        """
        check in database
        :param binarypath: the bianrypath to detect
        :param force_update: if True, return True, if False, according to the database
        value to choose whether update
        :param is_IOT: if the binary is in IOT struct, set it True
        the bianry of binarypath has finished, return False, otherwise True
        :return: True when need detect, False when not need
        """
        if force_update:
            return True
        if is_IOT:
            return self.CheckNeedDetectIOT(binarypath=binarypath)
        sql = """select count(*) from 
        vulnerability_detection where vulnerability_detection.binary_path="{binarypath}"
        AND vulnerability_detection.finish_detect=TRUE;
        """.format(binarypath=binarypath)
        cur = self.connection.cursor()
        try:
            #print(sql)
            cur.execute(sql)
            sql_result = cur.fetchall()
            number = sql_result[0][0]
            if number == 0:
                # means have not finished detect
                return True
            else:
                # means have finished detect
                return False
        except:
            return True

    def CheckNeedDetectIOT(self, binarypath=""):
        """
        check in database for this binary need to be detect or not
        :return: True when need, False when not
        """
        sql = """select count(*) from 
                vulnerability_detection_IOT where vulnerability_detection_IOT.binary_path="{binarypath}"
                AND vulnerability_detection_IOT.finish_detect=TRUE;
                """.format(binarypath=binarypath)
        cur = self.connection.cursor()
        try:
            # print(sql)
            cur.execute(sql)
            sql_result = cur.fetchall()
            number = sql_result[0][0]
            if number == 0:
                # means have not finished detect
                return True
            else:
                # means have finished detect
                return False
        except:
            return True
