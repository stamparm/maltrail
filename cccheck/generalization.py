#!/usr/bin python3
#coding=utf-8

import re
import os
import sys
import pandas as pd


'''
功能：最新版的请求泛化，待完善
注：
读取csv，必须设置sep='\a' 。例如：df = pd.read_csv(readFile,sep='\a')
同时，写入新csv文件时，也必须设置(一些情况可不必)sep='\a' 。例如：df.to_csv(wirteFile,sep='\a',index=False)   
'''

emptySet=['nan','','0','/']

def isFloat(string):
    return re.compile(r'^[-+]?[0-9]+\.[0-9]+$').match(string)

def isHex(string):
    return re.compile(r'^[0-9a-fA-F]+$').match(string)

def replace(string,split2_char):
    #由split2_char是否为空，决定是否有第二次截取字符串
    #类似 /ss/sss/ssss   只截/
    if split2_char=='':
        str1=''
        str2=string    
    #类似 /ss=2/ss=3  先截/，再截=
    else:
        str_list=string.split(split2_char)
        if len(str_list)==1:
            return string               #无法二次截取，直接return

        str1=str_list[0]+split2_char    #截取的前部分
        str2=str_list[1]                #截取的后部分

    if str2.isdigit():                              #纯数字
        return str1+'int;'+str(len(str2))
    elif str2.isalpha():                            #纯字母
        return str1+'str;'+str(len(str2))
    elif isFloat(str2):                             #浮点型  如：2.1254
        return str1+"float;"+str(len(str2))
    elif isHex(str2):                               #16进制  如：46ed4ac85e
        return str1+"hex;"+str(len(str2))
    elif str2.isalnum():                            #所有都是数字或字母
        return str1+"alnum;"+str(len(str2))
    else:                                           #其他
        return str1+"other;"+str(len(str2))


def replace_2(string,split2_char):
    #由split2_char是否为空，决定是否有第二次截取字符串
    #类似 /ss/sss/ssss   只截/
    if split2_char=='':
        str1=''
        str2=string    
    #类似 /ss=2/ss=3  先截/，再截=
    else:
        str_list=string.split(split2_char)
        if len(str_list)==1:
            return string               #无法二次截取，直接return

        str1=str_list[0]+split2_char    #截取的前部分
        str2=str_list[1]                #截取的后部分

    if str2.isdigit():                              #纯数字
        return '$'*(len(str2))
    elif str2.isalpha():                            #纯字母
        return '*'*(len(str2))
    # elif isFloat(str2):                             #浮点型  如：2.1254
    #     return str1+"float;"+str(len(str2))
    elif isHex(str2):                               #16进制  如：46ed4ac85e
        return '@'*(len(str2))
    # elif str2.isalnum():                            #所有都是数字或字母
    #     return str1+"alnum;"+str(len(str2))
    return string                                   #其他

def handle(list,type,split_char='',split2_char=''):
    # print(list)
    for index in range(len(list)):
    # print(str(index),value)
        if str(list[index]) in emptySet:                 #假如为空，修改为0或''，并结束
            # print(str(index))
            if type=='path':
                list[index]=''                      #假如为path，修改为''
            else:
                list[index]='0'                       #假如为其他类型，修改为0
        else:
            if split_char=='':
                list[index]=replace(list[index],split2_char)        #假如split_char为空，不需要截取，直接replace处理
                continue
            new_values=''
            values=list[index].split(split_char)                        #假如split_char不为空，第一次截取。如'/ss/586/dsa'，split_char='/'
            for value in values:
                if value!='':
                    if type=='path':
                        new_values=new_values+replace_2(value,split2_char)      #path是另一种处理方式
                    else:
                        new_values=new_values+replace(value,split2_char)    #逐个replace处理，传入split2_char，可能有二次处理
                new_values+=split_char
            list[index]=new_values[0:-1]                                #因为多次拼接，去除最后一个多余的字符
    # print(list)
    
def handle_2(list,type):
    total_num=0
    total_length=0
    for index,value in enumerate(list):
        if str(value) not in emptySet:
            list[index]=type+';'+str(len(str(value)))
            total_num+=1
            total_length+=len(str(value))
    
    average=total_length//total_num
    print(type+';'+str(average))

    for index,value in enumerate(list):
        if str(value) in emptySet:
            list[index]=type+';'+str(average)

    return list


def generalization(readFile,wirteFile):
    df = pd.read_csv(readFile,sep='\a')                         #读取csv

    pd.options.mode.chained_assignment = None                   # default='warn',允许直接在df改动

    # 保存泛化前的host+其他头部的数据
    df['original_accept_language']=df['accept_language']
    df['original_accept_encoding']=df['accept_encoding']
    df['original_host']=df['host']

    handle(df['path'],'path','/','')                            #处理中间路径
    handle(df['query'],'query','&','=')      #处理请求参数
    # handle(df['user_agent'],'user_agent')                     #处理user-agent
    # handle(df['accept_language'],'accept_language')           #处理accept_language
    # handle(df['host'])                                        #处理其他的？？
    handle_2(df['accept_language'],'accept_language')
    handle_2(df['accept_encoding'],'accept_encoding')
    handle_2(df['host'],'host')   

    df.to_csv(wirteFile,sep='\a',index=False)                   #写入csv
    print("Succeed to generalize !")


def delete_same(inFile,outFile):
    lines_seen = set()

    infile= open(inFile,"r")
    outfile=open(outFile,"w")

    for line in infile:
        if line not in lines_seen:
            outfile.write(line)
            lines_seen.add(line)

    infile.close()
    outfile.close()
    print ("Succeed to deletesame !")


def main(filename):
    # path=os.path.abspath(os.path.join(os.getcwd(), ".."))               #获取目录路径
    path=filename.split('.')[0];
    #文件选择1
    # readFile=path+'/data/lastest_deletesame.csv'                         #请求泛化：输入的文件名
    # wirteFile=path+'/data/lastest_deletesame_Generalization.csv'         #请求泛化：输出的文件名
    # inFile=path+'/data/lastest_deletesame_Generalization.csv'            #去重：输入的文件名
    # outFile=path+'/data/lastest_deletesame_Generalization_deletesame.csv'#去重：输出的文件名
    #文件选择2
    # readFile=path+'/data/totalcsv_deletesame.csv'                         #请求泛化：输入的文件名
    # wirteFile=path+'/data/totalcsv_deletesame_Generalization.csv'         #请求泛化：输出的文件名
    # inFile=path+'/data/totalcsv_deletesame_Generalization.csv'            #去重：输入的文件名
    # outFile=path+'/data/totalcsv_deletesame_Generalization_deletesame.csv'#去重：输出的文件名
    #文件选择3
    readFile=path+'.csv'                            #请求泛化：输入的文件名
    wirteFile=path+'_Generalization.csv'            #请求泛化：输出的文件名
    inFile=path+'_Generalization.csv'               #去重：输入的文件名
    outFile=path+'_Generalization_deletesame.csv'   #去重：输出的文件名

    generalization(readFile,wirteFile)                                  #请求泛化

    delete_same(inFile,outFile)                                         #去重


# if __name__ == "__main__":
#     filename = sys.argv[1]
#     main(filename)

def generalize(df):

    pd.options.mode.chained_assignment = None  # default='warn',允许直接在df改动

    # 保存泛化前的host+其他头部的数据
    df['original_accept_language'] = df['accept_language']
    df['original_accept_encoding'] = df['accept_encoding']
    df['original_host'] = df['host']

    handle(df['path'], 'path', '/', '')  # 处理中间路径
    handle(df['query_parameter'], 'query_parameter', '&', '=')  # 处理请求参数
    # handle(df['user_agent'],'user_agent')                     #处理user-agent
    # handle(df['accept_language'],'accept_language')           #处理accept_language
    # handle(df['host'])                                        #处理其他的？？
    handle_2(df['accept_language'], 'accept_language')
    handle_2(df['accept_encoding'], 'accept_encoding')
    handle_2(df['host'], 'host')

    # df.to_csv(wirteFile, sep='\a', index=False)  # 写入csv
    # print("Succeed to generalize !")
    return df









