#! coding=utf-8
import warnings
import numpy as np

import random
import re
import Levenshtein
import autopep8
import lightgbm as lgb
import read_data
import cal_smilar
import first_clustering
import Sentiment_RNN_Solution

warnings.filterwarnings('ignore')

"""
用于后续流量匹配模板
"""

def Edit_distance_str_match(str1, str2):
    """
    计算中值URL的编辑距离
    :param str1: 后续检测到的http请求的URLpath
    :param str2: CPT模板中的URLpath
    :return:
    """
    if (len(str1) == 0)&(len(str2) == 0):
        return 1
    str2_array =np.array(str2.split('&'))
    # print(str2_array)
    edit_distance_distance = 0
    for s in str2_array:
        edit_distance_distance += (Levenshtein.distance(str1, s)/max(len(str1), len(s)))
    similarity = 1-(edit_distance_distance/len(str2_array))
    return similarity


def get_smilar(df, CPT):
    """
    计算http请求的各项字段与CPT模板的相似度
    :param df:
    :param CPT:
    :return: s1, s2a, s2b, s3, s4, s5
    """
    # S1
    s1 = np.zeros((len(df), len(CPT)))
    CPT_path = np.array(CPT['path'])
    df_path = np.array(df['path'])
    i = 0
    for tmp in df_path:
        j = 0
        for cpt in CPT_path:
            s1[i][j] = Edit_distance_str_match(tmp, cpt)
            j += 1
        i += 0
    # S2a，S2b
    s2a = np.zeros((len(df), len(CPT)))
    s2b = np.zeros((len(df), len(CPT)))
    CPT_query = np.array(CPT['query_parameter'])
    data_tmp_query = np.array(df['query_parameter'])
    i = 0
    for tmp in data_tmp_query:
        j = 0
        for cpt in CPT_query:
            s2a[i][j], s2b[i][j] = cal_smilar.Jaccrad(tmp, cpt)
            j += 1
        i += 0
    #S3
    s3 = np.zeros((len(df), len(CPT)))
    sm = []
    CPT_user = np.array(CPT['user_agent'])
    data_tmp_user = np.array(df['user_agent'])
    i = 0
    for tmp in data_tmp_user:
        j = 0
        for cpt in CPT_user:
            s3[i][j], m = cal_smilar.get_S3(tmp, cpt)
            sm.append(m)
            j += 1
        i += 0
    #S4
    s4 = np.zeros((len(df), len(CPT)))
    CPT_query = np.array(CPT[['host', 'accept_language', 'accept_encoding']])
    data_tmp_query = np.array(df[['host', 'accept_language', 'accept_encoding']])
    i = 0

    for tmp in data_tmp_query:
        j = 0
        for cpt in CPT_query:
            # print(tmp, cpt)
            s4[i][j] = cal_smilar.get_S4(tmp, cpt)
            j += 1
        i += 0
    # S5
    s5 = np.zeros((len(df), len(CPT)))
    CPT_query = np.array(CPT['ip_dst'])
    data_tmp_query = np.array(df['ip_dst'])
    i = 0

    for tmp in data_tmp_query:
        j = 0
        for cpt in CPT_query:
            #         print(tmp,cpt)
            s5[i][j] = cal_smilar.get_S5(tmp, cpt)
            j += 1
        i += 0

    return s1, s2a, s2b, s3, s4, s5


def get_dis(df, CPT, gs):
    """
    用于计算http请求与CPT模板之间的距离，计算获取 np.array 为http请求与所有CPT模板之间的距离，
    最终返回距离最短的模板
    :param df:
    :param CPT:
    :param gs:
    :return:
    """
    w1, w2_a, w2_b, w3, w4, w5 = 0.15, 0.2, 0.2, 0.25, 0.1, 0.1
    tmp_s1, tmp_s2a, tmp_s2b, tmp3, tmp4, tmp5 = get_smilar(df, CPT)
    # ip_24 = list(set(np.array(CPT['ip_24'])))[0]
    # data_tmp = data[data['ip_24'] == ip_24]
    # gs = first_clustering.get_gs(data_tmp)
    sig1, sig3, sig4, sig5, sigd = cal_smilar.get_sig(df, gs)
    # print(sig1, sig3, sig4, sig5, sigd)

    w1_k = (1 + 1 / (2 - (sig1.reshape(len(sig1), 1) * tmp_s1))) * w1
    w2a_k = (1 + 1 / (2 - (sig1.reshape(len(sig1), 1) * tmp_s2a))) * w2_a
    w2b_k = (1 + 1 / (2 - (sig1.reshape(len(sig1), 1) * tmp_s2b))) * w2_b
    w3_k = (1 + 1 / (2 - (sig3.reshape(len(sig3), 1) * tmp3))) * w3
    w4_k = (1 + 1 / (2 - (sig4.reshape(len(sig4), 1) * tmp4))) * w4
    w5_k = (1 + 1 / (2 - (sig5.reshape(len(sig5), 1) * tmp5))) * w5

    dis = sigd * (tmp_s1 * w1_k + tmp_s2a * w2a_k + tmp_s2b * w2b_k + tmp3 * w3_k + tmp4 * w4_k + tmp5 * w5_k) / (
                w1_k + w2a_k + w2b_k + w3_k + w4_k + w5_k)
    return CPT.iloc[dis.argmin(), :], dis.min()

