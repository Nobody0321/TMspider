#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from six import itervalues
import pymysql

class SQL():
    #数据库初始化
    def __init__(self):
        #数据库连接相关信息
        hosts    = '127.0.0.1'  
        username = 'root'
        password = '1234'
        database = 'Threat_Miner'
        charsets = 'utf8'

        self.connection = False
        try:
            self.conn = pymysql.connect(host = hosts,user = username,passwd = password,db = database,charset = charsets)
            self.cursor = self.conn.cursor()
            self.cursor.execute("set names "+charsets)
            self.connection = True
        except Exception as e:
            print ("无法连接到MySQL数据库!/n",e)

    def escape(self,string):
        return ('%s' % string)
    #插入数据到数据库   
    def insert(self,tablename=None,**values):

        if self.connection: 
            tablename = self.escape(tablename)  
            if values:
                _keys = ",".join(self.escape(k) for k in values)
                _values = ",".join(['%s',]*len(values))
                sql_query = "insert into %s (%s) values (%s)" % (tablename,_keys,_values)
            else:
                sql_query = "replace into %s default values" % tablename
            try:
                if values:
                    self.cursor.execute(sql_query,list(itervalues(values)))
                else:       
                    self.cursor.execute(sql_query)
                self.conn.commit()
                return True
            except Exception as e:
                print ("遇到了错误: ",e)
                return False
