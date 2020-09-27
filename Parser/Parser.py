import re
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter

Regrex = [r'(?P<host>\S+)', r'\S+', r'(?P<user>\S+)', r'\[(?P<time>.+)\]', r'"(?P<request>.*)"', r'(?P<status>[0-9]+)', r'(?P<size>\S+)', r'"(?P<referrer>.*)"', r'"(?P<agent>.*)"']
pattern = re.compile(r'\s+'.join(Regrex)+r'\s*\Z')

def write(FileName, LogData):
    with open(FileName, "w") as f:
        for line in LogData:
            f.write(line['host'] +" "+ line['user'] + " " + line['time']+ " " + '"'+line['request']+ '"' + " " + line['status']+ " " + line['size']+ " " + '"' + line['referrer'] +'"'+ " " + '"'+ line['agent'] +'"'+ '\n')

def Parse(FileName):
    LogData = []
    NonFormat = []
    with open(FileName, "r") as f:
         for line in f:
            try:
                LogData.append(pattern.match(line).groupdict())
            except:
                NonFormat.append(line)
    return LogData

def GetErr(LogData, ErrCode):
    LogErr = []
    for line in LogData:
        if line['status'] == ErrCode:
            LogErr.append(line)
    return LogErr

def GetSQL(LogData):
    LogSQL = []
    for line in LogData:
        if (re.search(r'select.*from', line['request'])!= None):
            LogSQL.append(line)
    return LogSQL


def CheckDOS(LogData):
    LogDos = []
    dict = Counter(x['host'] for x in LogData)
    df = np.zeros((0,5));
    for j in range (len(LogData)):
        line = LogData[j]
        if (dict[line['host']] < 11):
            continue
        CurTime = datetime.strptime(line['time'][:-6], "%d/%b/%Y:%H:%M:%S")
        count = True
        size = df.shape[0]
        for i in range(size):
            if(i >= size):
                break
            Time = datetime.strptime(df[i,3][:-6], "%d/%b/%Y:%H:%M:%S")
            if (df[i,0] == line['host'] and df[i,1] == line['request'] and (CurTime - Time).seconds < 4):
                df[i,2] = int(df[i,2]) + 1
                df[i,4] = df[i,4] + " " + str(j)
                count = False
            if(j == len(LogData) - 1):
                if(int(df[i,2]) >= 10):
                    temp = df[i,4].split(' ')
                    for k in temp:
                        LogDos.append(LogData[int(k)])
            if (df[i,0] != line['host'] and (CurTime - Time).seconds > 4):
               if(int(df[i,2]) >= 10):
                    temp = df[i,4].split(' ')
                    for k in temp:
                        LogDos.append(LogData[int(k)])
               df = np.delete(df, i, 0)
               i-=1
               size -=1
        if(count):
            df = np.append(df,[[line['host'], line['request'], 1, line['time'], str(j)]], axis = 0)
    return LogDos
       
LogData = Parse("access.log")
write("dos.log", CheckDOS(LogData))
write("sql.log", GetSQL(LogData))
write("401.log", GetErr(LogData, "401"))
write("403.log", GetErr(LogData, "403"))