#! coding=utf8

import warnings
import pandas as pd
import numpy as np

import first_clustering
import Levenshtein
import autopep8
import lightgbm as lgb
import read_data

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans, AgglomerativeClustering
warnings.filterwarnings('ignore')


def Edit_distance_str(str1, str2):
    """
    计算s1，编辑距离
    :param str1:
    :param str2:
    :return:
    """
    if (len(str1) == 0) & (len(str2) == 0):
        return 0
    edit_distance_distance = Levenshtein.distance(str1, str2)
    similarity = 1 - (edit_distance_distance/max(len(str1), len(str2)))
#     return {'Distance': edit_distance_distance, 'Similarity': similarity}
    return similarity


def query(str):
    str_list = str.split('&')

    str_list_name = []
    str_list_type_dic = ({})
    str_list_type_num = ({})
    str_list_dic = dict({})
    for i in str_list:
        tmp = i.split('=')
        if len(tmp) <= 1:
            continue
        if tmp[1].find("%") != -1:
            continue
        if len(tmp) != 2:
            continue

        str_list_dic[tmp[0]] = tmp[1]
        tmp1 = tmp[1].split(';')
        if len(tmp1) <= 1:
            continue
        str_list_name.append(tmp[0])

        if tmp1[0] in str_list_type_dic.keys():
            str_list_type_dic[tmp1[0]] = float(
                (str_list_type_dic[tmp1[0]] * str_list_type_num[tmp1[0]] + int(tmp1[1])) / (
                            str_list_type_num[tmp1[0]] + 1))
            str_list_type_num[tmp1[0]] = str_list_type_num[tmp1[0]] + 1
        else:
            str_list_type_dic[tmp1[0]] = int(tmp1[1])
            str_list_type_num[tmp1[0]] = 1

    return str_list_name, str_list_type_dic


# URL 参数 S2a S2b
def Jaccrad(str1, str2):
    """
    S2a，S2b计算
    :param str1:
    :param str2:
    :return:
    """
    if (len(str1.split('=')) == 1)|(len(str2.split('=')) == 1):
        return 0, 0
    # elif (str1 == 'None=str;1') | (str2 == 'None=str;1'):
    #     return 0, 0
    elif (len(str1.split(';')) == 1)|(len(str2.split(';')) == 1):
        return 0, 0

    # 获取str1 str2 中的所有请求项，以及长度
    # str1
    str1_list_name, str1_list_type_dic = query(str1)
    # str2
    str2_list_name, str2_list_type_dic = query(str2)
    if (len(str1_list_name) == 0)&(len(str2_list_name) == 0):
        return 0,0
    # temp = 0
    # for i in str1_list_name:
    #     if i in str2_list_name:
    #         temp = temp + 1

    s2b = 0
    num = 0
    keys = str2_list_type_dic.keys()
    for i in str1_list_type_dic.keys():
        if i in keys:
            s2b = s2b + float(str1_list_type_dic[i] / str2_list_type_dic[i])
            num = num + 1

    # fenmu = len(str1_list_name) + len(str2_list_name) - temp
    # # s2a 杰卡德相似系数
    # jaccard_score = float(temp/fenmu)
    jaccard_score = len(set(str1_list_name) & set(str2_list_name)) / len(set(str1_list_name) | set(str2_list_name))
    len_ = len(str1_list_type_dic)
    if len_ == 0:
        len_ += 1
    s2b = float((s2b + num) / (2 * len_))
    return jaccard_score, s2b


# user-agent S3
def get_S3(str1, str2):
    """
    S3 的计算，使用编辑距离
    :param str1:
    :param str2:
    :return:
    """
    str2_list = str2.split('&')
    dm = Levenshtein.distance(
        str1, str2_list[0]) / max(len(str1), len(str2_list[0]))
    m = str2_list[0]
    # 对于str1来说，一个http请求只有一个user-agent，而str2可能为CPT模板，因此需要遍历找到满足条件的m
    for i in range(1, len(str2_list)):
        d = Levenshtein.distance(
            str1, str2_list[i]) / max(len(str1), len(str2_list[i]))
        if d < dm:
            dm = d
            m = str2_list[i]
    return 1 - dm, m


def head_query(str1):
    head_list = str1
    # print(str1)
    head_list_name = []
    head_list_dic = dict({})
    # mid_len = 0
    for i in head_list:
        # print(i)
        tmp = i.split(';')
        head_list_dic[tmp[0]] = float(tmp[1])
        # mid_len = mid_len + float(tmp[1])
        head_list_name.append(tmp[0])
    # mid_len = float(mid_len / len(head_list))
    return head_list_name, head_list_dic


def get_S4(str1, str2):
    """
    计算S4
    :param str1:
    :param str2:
    :return:
    """
    # 与 S2 相似 考虑到存在多个请求头，全部取出，然后计算
    str1_head_name, str1_head_dic = head_query(str1)
    str2_head_name, str2_head_dic = head_query(str2)
    temp = 0
    # for i in str1_head_name:
    #     if i in str2_head_name:
    #         temp = temp + 1
    # fenmu = len(str1_head_name) + len(str2_head_name) - temp
    # j = float(temp/fenmu)

    j = len(set(str1_head_name) & set(str2_head_name)) / len(set(str1_head_name) | set(str2_head_name))

    tmp = 0
    ans = 0
    o = 0
    for i in str2_head_name:
        ans += (str1_head_dic[i] / str2_head_dic[i])
        if i == str1_head_name[tmp]:
            tmp += 1
        if tmp == len(str1_head_name):
            o = 1
            break
    # tmp = str1_mid_len / str2_mid_len

    return (j + o + ans) / (2 + len(str2_head_name))


def get_S5(str1, str2):
    """
    计算S5 如果𝑟中的目的ip属于𝜏_5中的某个C类网络𝑛_𝑖,则𝑠_5为1，否则为0 这里C类网络为ip_24
    :param str1:
    :param str2:
    :return:
    """
    tmp = str2.split(',')
    if str1 in tmp:
        return 1
    else:
        return 0


def get_smilar(df):
    """
    调用前面所有函数，计算各项相似度
    :param df:
    :return:
    """
    tmp_s1 = np.zeros((len(df), len(df)))
    s1_data = np.array(df['path'])
    i = 0
    j = 0
    for str1 in s1_data:
        for str2 in s1_data:
            tmp_s1[i, j] = Edit_distance_str(str1, str2)
            j += 1
        i += 1
        j = 0

    s2_data = np.array(df['query_parameter'])
    tmp_s2a = np.zeros((len(df), len(df)))
    tmp_s2b = np.zeros((len(df), len(df)))
    i = 0
    j = 0
    for str1 in s2_data:
        for str2 in s2_data:
            #         print(j)
            tmp_s2a[i, j], tmp_s2b[i, j] = Jaccrad(str1, str2)
            j += 1
        i += 1
        j = 0

    tmp3 = np.zeros((len(df), len(df)))
    s3_data = np.array(df['user_agent'])
    i = 0
    j = 0
    for str1 in s3_data:
        for str2 in s3_data:
            tmp3[i, j], _ = get_S3(str1, str2)
            j += 1
        i += 1
        j = 0

    tmp4 = np.zeros((len(df), len(df)))
    s4_data = np.array(df[['host', 'accept_language', 'accept_encoding']])
    i = 0
    j = 0
    for str1 in s4_data:
        for str2 in s4_data:
            tmp4[i, j] = get_S4(str1, str2)
            j += 1
        i += 1
        j = 0

    tmp5 = np.zeros((len(df), len(df)))
    s5_data = np.array(df['ip_24'])
    i = 0
    j = 0
    for str1 in s5_data:
        for str2 in s5_data:
            tmp5[i, j] = get_S5(str1, str2)
            j += 1
        i += 1
        j = 0

    return tmp_s1, tmp_s2a, tmp_s2b, tmp3, tmp4, tmp5


def group_feature(df,fea):
    """
    为方便计算user-agent 与其他头部的特异度，先计算需要的值，基于请求聚合计算主机count和目的域名count
    :param df:
    :param fea:
    :return:
    """
    group = df.groupby(fea)['path'].count().reset_index().rename(columns = {'path':fea + '_count'})
    df = pd.merge(df, group,on=fea,how='left')
    if fea!= 'host':
        group = df.groupby(fea)['host'].nunique().reset_index().rename(columns = {'host':fea + '_host_count'})
        df = pd.merge(df, group,on=fea,how='left')
    else:
        df[fea+'_host_count'] = 1
    df[fea+'_count_max'] = df[fea+'_count'].max()
    df[fea+'_host_count_max'] = df[fea+'_host_count'].max()
    return df


def get_p(df, gs):
    """
    计算 sigma1
    :param df:
    :param gs:
    :return:
    """
    return 1 - gs.predict_proba(df)[:, 1]


def get_sig3(df):
    """
    计算sigma3
    :param df:
    :return:
    """
    arr1 = np.array(df['user_agent_count']/df['user_agent_count_max'])
    arr2 = np.array(df['user_agent_host_count']/df['user_agent_host_count_max'])
    sig3 = np.vstack([arr1,arr2]).min(axis=0)
    sig3 = 1 - sig3*0.95
    return sig3


def get_sig4(df):
    """
    计算sigma4
    :param df:
    :return:
    """
    arr1 = np.array(df['accept_language_count'] / df['accept_language_count_max'])
    arr2 = np.array(df['accept_language_host_count'] / df['accept_language_host_count_max'])
    sig4 = np.vstack([arr1, arr2]).min(axis=0)

    arr1 = np.array(df['accept_encoding_count'] / df['accept_encoding_count_max'])
    arr2 = np.array(df['accept_encoding_host_count'] / df['accept_encoding_host_count_max'])
    sig4 = np.vstack([sig4, arr1, arr2]).min(axis=0)

    arr1 = np.array(df['host_count'] / df['host_count_max'])
    sig4 = np.vstack([sig4, arr1]).min(axis=0)
    sig4 = 1 - sig4*0.95
    return sig4


def get_sig5(df):
    """
    计算sigma5
    :param df:
    :return:
    """
    arr1 = np.array(df['ip_dst_count']/df['ip_dst_count_max'])
    sig5 = 1 - arr1*0.95
    return sig5


def get_sigd(df):
    """
    论文中计算距离的最后一项，部署网络中向域名𝑑发起HTTP请求的主机数除以〖𝑚𝑎𝑥〗_𝑖 {𝑚_(𝑑_𝑖 )}
    :param df:
    :return:
    """
    arr1 = np.array(df['host_count']/df['host_count_max'])
    sigd = 1 - arr1
    return sigd


def get_sig(df, gs):
    sig1 = np.array(get_p(df['full_uri'], gs))
    sig3 = get_sig3(df)
    sig4 = get_sig4(df)
    sig5 = get_sig5(df)
    sigd = get_sigd(df)
    return sig1, sig3, sig4, sig5, sigd


def get_dis(df, gs):
    """
    计算粗聚类后的簇中任意两个http请求之间的距离
    :param df:
    :param gs:
    :return:
    """
    w1, w2_a, w2_b, w3, w4, w5 = 0.15, 0.2, 0.2, 0.25, 0.1, 0.1
    tmp_s1, tmp_s2a, tmp_s2b, tmp3, tmp4, tmp5 = get_smilar(df)
    sig1, sig3, sig4, sig5, sigd = get_sig(df, gs)

    w1_k = (1 + 1 / (2 - (sig1.reshape(len(sig1), 1) * tmp_s1))) * w1
    w2a_k = (1 + 1 / (2 - (sig1.reshape(len(sig1), 1) * tmp_s2a))) * w2_a
    w2b_k = (1 + 1 / (2 - (sig1.reshape(len(sig1), 1) * tmp_s2b))) * w2_b
    w3_k = (1 + 1 / (2 - (sig3.reshape(len(sig3), 1) * tmp3))) * w3
    w4_k = (1 + 1 / (2 - (sig4.reshape(len(sig4), 1) * tmp4))) * w4
    w5_k = (1 + 1 / (2 - (sig5.reshape(len(sig5), 1) * tmp5))) * w5
    # w1_k = (1 + 1 / (2 - tmp_s1)) * w1
    # w1_k[np.isnan(w1_k)] = w1
    # w2a_k = (1 + 1 / (2 - tmp_s2a)) * w2_a
    # w2a_k[np.isnan(w2a_k)] = w2_a
    # w2b_k = (1 + 1 / (2 - tmp_s2b)) * w2_b
    # w2b_k[np.isnan(w2b_k)] = w2_b
    # w3_k = (1 + 1 / (2 - tmp3)) * w3
    # w3_k[np.isnan(w3_k)] = w3
    # w4_k = (1 + 1 / (2 - tmp4)) * w4
    # w4_k[np.isnan(w4_k)] = w4
    # w5_k = (1 + 1 / (2 - tmp5)) * w5
    # w5_k[np.isnan(w5_k)] = w5
    print(w5_k.shape)
    print(tmp_s1.shape)
    print(sig1.shape)

    # print(w1_k, w2a_k, w2b_k, w3_k, w4_k, w5_k)

    dis = sigd * (tmp_s1 * w1_k + tmp_s2a * w2a_k + tmp_s2b * w2b_k + tmp3 * w3_k + tmp4 * w4_k +
                  tmp5 * w5_k) / (w1_k + w2a_k + w2b_k + w3_k + w4_k + w5_k)
    print(dis.shape)
    # dis[np.isnan(dis)] = np.mean(dis[~np.nan(dis)])

    return dis


def getCPT(i, df):
    """
    根据凝聚型层次聚类算法得到的类别建立CPT模板
    :param i:
    :param df:
    :return:
    """
    tmp = df[df['class'] == i]

    path_tmp = list(set(np.array(tmp['path'])))
    path = path_tmp[0]
    for i in range(1, len(path_tmp)):
        path = path+'&'+path_tmp[i]

    query_tmp = np.array(tmp['query_parameter'])
    query = query_tmp[0]
    for i in range(1, len(query_tmp)):
        query = query + '&' + query_tmp[i]

    ip_dst_tmp = list(set(np.array(tmp['ip_dst'])))
    ip_dst = ip_dst_tmp[0]
    for i in range(1, len(ip_dst_tmp)):
        ip_dst = ip_dst + '&' + ip_dst_tmp[i]

    user_agent_tmp = list(set(np.array(tmp['user_agent'])))
    user_agent = user_agent_tmp[0]
    for i in range(1, len(user_agent_tmp)):
        user_agent = user_agent + '&' + user_agent_tmp[i]

    accept_language_tmp = np.array(tmp['accept_language'])
    accept_language = float(accept_language_tmp[0].split(';')[1])
    for i in range(1, len(accept_language_tmp)):
        accept_language = accept_language + float(accept_language_tmp[i].split(';')[1])
    accept_language = accept_language / len(accept_language_tmp)
    accept_language = 'accept_language;' + str(accept_language)

    accept_encoding_tmp = np.array(tmp['accept_encoding'])
    accept_encoding = float(accept_encoding_tmp[0].split(';')[1])
    for i in range(1, len(accept_encoding_tmp)):
        accept_encoding = accept_encoding + float(accept_encoding_tmp[i].split(';')[1])
    accept_encoding = accept_encoding / len(accept_encoding_tmp)
    accept_encoding = 'accept_encoding;' + str(accept_encoding)

    host_tmp = list(set(np.array(tmp['host'])))
    host = float(host_tmp[0].split(';')[1])
    for i in range(1, len(host_tmp)):
        host = host + float(host_tmp[i].split(';')[1])
    host = host / len(host_tmp)
    host = 'host;' + str(host)

    dic = {
        'path': path,
        'query_parameter': query,
        'class': list(set(np.array(tmp['class'])))[0],
        'ip_dst': ip_dst,
        'ip_24': list(set(np.array(tmp['ip_24'])))[0],
        'user_agent': user_agent,
        'accept_language': accept_language,
        'accept_encoding': accept_encoding,
        'host': host,
        'p': len(tmp[tmp['label'] == 1]) / len(tmp)
    }

    CPT_tmp = pd.DataFrame(dic, index=[0])

    return CPT_tmp


def get_clustering(df, gs):
    """
    精准聚类，方法为凝聚型层次聚类
    :param df:
    :param gs:
    :return:
    """
    dis = get_dis(df, gs)
    # clustering = AgglomerativeClustering(n_clusters=None, affinity='precomputed', distance_threshold=0.2,
    #                                      linkage='average')
    clustering = AgglomerativeClustering()
    clustering.fit(dis)

    df['class'] = clustering.labels_
    CPT = getCPT(0, df)
    for i in set(clustering.labels_):
        if i == 0:
            continue
        CPT_tmp = getCPT(i, df)
        CPT = pd.concat([CPT, CPT_tmp], axis=0, ignore_index=True)

    return CPT, df


def get_all_CPT(df, gs):
    # j = 0
    # ip_24 = list(set(np.array(df['ip_24'])))
    # data_tmp = df[df['ip_24'] == ip_24[j]]
    # print(ip_24[j])
    CPT, _ = get_clustering(df, gs)

    # for i in range(1, len(ip_24)):
    #     print(ip_24[i])
    #     data_tmp = df[df['ip_24'] == ip_24[i]]
    #     CPT_tmp, _ = get_clustering(data_tmp, gs)
    #     CPT = pd.concat([CPT, CPT_tmp], axis=0, ignore_index=True)
        # tmp_df = pd.concat([tmp_df, df_ans], axis=0)
    # tmp_df.to_csv('data.csv', index=False)
    # df['class'] = tmp_df['class']
    # df.to_csv('data1.csv',index=False)
    return CPT
