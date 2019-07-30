#! coding=utf-8
import os

import torch
import pandas as pd
import read_data
import warnings
import time
import cal_smilar
from sklearn.externals import joblib
import match
import tldextract
import tqdm
import Sentiment_RNN_Solution


def get_host(x):
    val = tldextract.extract(x)
    return val.domain + '.' + val.suffix


def in_ip(x):
    if x < 0:
        return 1
    return 0


def not_in_ip(x, y):
    if x <= 0.12:
        return 1
    elif (x > 0.12) & (y == 1):
        return 1
    else:
        return 0


def predict(df=None):
    """

    :param df: 一条或多条http请求，DataFrame格式
    :return: result 其中pre为预测结果
    """

    # 读取模型
    net = torch.load('model/LSTM_model.pkl')
    gs = joblib.load('model/gs.m')

    result = read_data.read('data/data.csv')
    if df is None:
        result['tmp'] = 0
    else:
        df = read_data.get_data(df)
        result['tmp'] = 1
        df['tmp'] = 0
        result = pd.concat([result, df], axis=0)
    result = cal_smilar.group_feature(result, 'user_agent')
    result = cal_smilar.group_feature(result, 'host')
    result = cal_smilar.group_feature(result, 'accept_language')
    result = cal_smilar.group_feature(result, 'accept_encoding')
    result = cal_smilar.group_feature(result, 'ip_dst')
    result = result[result['tmp'] == 0]
    del result['tmp']

    CPT = pd.read_csv('model/CPT.csv', sep='\a')
    train = pd.read_csv('data/test.csv')
    safe_host = pd.read_csv('data/host.csv', names=['host'])

    result['original_host'] = result['original_host'].apply(lambda x: get_host(x))

    # 规则筛选
    ans_host = result['original_host'].unique()
    safe_host = list(safe_host['host'].values)
    same_host = list(set(safe_host) & set(ans_host))
    result_safe = result[result['original_host'].isin(same_host)]
    result = result[~result['original_host'].isin(same_host)]
    print(len(result[result['y'] == 'malicious']))

    test_ip_1 = train['ip_24'].unique()
    test_ip_2 = [ip for ip in result['ip_24'].unique() if ip not in test_ip_1]
    # result = result[(result['y'] == 'safe') | (result['y'] == 'malicious')]

    dis = []
    lens = len(result)
    with tqdm.tqdm(range(lens), 'calculate dis') as t:
        for i in t:
            #     print(test_df.iloc[i,:])
            cpt, tmp = match.get_dis(pd.DataFrame(result.iloc[i, :]).T, CPT, gs)
            dis.append(tmp)
    result['dis'] = dis

    result_in_ip = result[result['ip_24'].isin(test_ip_1)]
    result = result[result['ip_24'].isin(test_ip_2)]
    # result = result[(result['y'] == 'safe') | (result['y'] == 'malicious')]

    # LSTM预测不在模板中的
    now_time = time.time()
    seq_length = 200
    pre = []
    for s in result['original_host']:
        val = tldextract.extract(s)
        strs = val.domain
        pre.append(net.predict(strs, seq_length))
    result['label'] = pre
    print("LSTM spent time {} s".format(time.time() - now_time))

    result_in_ip['pre'] = result_in_ip['dis'].apply(lambda x: in_ip(x))
    result_safe['pre'] = 0
    if len(result) != 0:
        result['pre'] = result.apply(lambda x: not_in_ip(x['dis'], x['label']), axis=1)
    result = pd.concat([result, result_in_ip, result_safe])

    # x = 0.12
    # print(len(result[(result['y'] == 'safe') | (result['y'] == 'malicious')]))
    # print("safe dis > " + str(x) + " :" + str(len(result[(result['y'] == 'safe') & (result['dis'] > x)])))
    # print("safe dis > " + str(x) + " label=1:" + str(
    #     len(result[(result['y'] == 'safe') & (result['dis'] > x) & (result['label'] == 1)])))
    # print("safe dis <= " + str(x) + " :" + str(len(result[(result['y'] == 'safe') & (result['dis'] <= x)])))
    # print("safe dis <= " + str(x) + " label=1:" + str(
    #     len(result[(result['y'] == 'safe') & (result['dis'] <= x) & (result['label'] == 1)])))
    # print("malicious dis > " + str(x) + " :" + str(len(result[(result['y'] == 'malicious') & (result['dis'] > x)])))
    # print("malicious dis > " + str(x) + " label=1:" + str(
    #     len(result[(result['y'] == 'malicious') & (result['dis'] > x) & (result['label'] == 1)])))
    # print("malicious dis <= " + str(x) + " :" + str(len(result[(result['y'] == 'malicious') & (result['dis'] <= x)])))
    # print("malicious dis <= " + str(x) + " label=1:" + str(
    #     len(result[(result['y'] == 'malicious') & (result['dis'] <= x) & (result['label'] == 1)])))
    #
    # # 计算得分
    # TP = len(result[(result['pre'] == 1) & (result['y'] == 'malicious')])
    # FN = len(result[(result['pre'] == 0) & (result['y'] == 'malicious')])
    # FP = len(result[(result['pre'] == 1) & (result['y'] == 'safe')])
    # TN = len(result[(result['pre'] == 0) & (result['y'] == 'safe')])
    # P = TP / (TP + FP)
    # R = TP / (TP + FN)
    # F1 = 2 * TP / (2 * TP + FP + FN)
    # auc = (TP + TN) / (TP + FN + FP + TN)
    # print("精确率 = {} 召回率 = {} F1_Score = {} 准确率 = {}".format(P, R, F1, auc))
    # print(TP, FN, FP, TN)

    return result


def test():
    # 读取模型
    net = torch.load('model/LSTM_model.pkl')
    gs = joblib.load('model/gs.m')

    result = read_data.read('data/data.csv')
    result = cal_smilar.group_feature(result, 'user_agent')
    result = cal_smilar.group_feature(result, 'host')
    result = cal_smilar.group_feature(result, 'accept_language')
    result = cal_smilar.group_feature(result, 'accept_encoding')
    result = cal_smilar.group_feature(result, 'ip_dst')
    CPT = pd.read_csv('model/CPT.csv', sep='\a')
    valid = pd.read_csv('data/valid.csv')
    train = pd.read_csv('data/test.csv')
    safe_host = pd.read_csv('data/host.csv', names=['host'])

    result['original_host'] = result['original_host'].apply(lambda x: get_host(x))

    test_ip_1 = valid['ip_24'].unique()
    test_ip_2 = [ip for ip in result['ip_24'].unique() if ip not in test_ip_1]

    result = result[result['ip_24'].isin(test_ip_2)]
    result = result[(result['y'] == 'safe') | (result['y'] == 'malicious')]

    ans_host = result['original_host'].unique()
    safe_host = list(safe_host['host'].values)
    same_host = list(set(safe_host) & set(ans_host))
    result = result[~result['original_host'].isin(same_host)]
    print(len(result[result['y'] == 'malicious']))

    dis = []
    lens = len(result)
    with tqdm.tqdm(range(lens), 'calculate dis') as t:
        for i in t:
            #     print(test_df.iloc[i,:])
            cpt, tmp = match.get_dis(pd.DataFrame(result.iloc[i, :]).T, CPT, gs)
            dis.append(tmp)
    result['dis'] = dis

    # LSTM预测不在模板中的
    now_time = time.time()
    seq_length = 200
    pre = []
    for s in result['original_host']:
        val = tldextract.extract(s)
        strs = val.domain
        pre.append(net.predict(strs, seq_length))
    result['label'] = pre
    print("LSTM spent time {} s".format(time.time() - now_time))

    result['pre'] = result.apply(lambda x: not_in_ip(x['dis'], x['label']), axis=1)

    x = 0.12
    print(len(result[(result['y'] == 'safe') | (result['y'] == 'malicious')]))
    print("safe dis > " + str(x) + " :" + str(len(result[(result['y'] == 'safe') & (result['dis'] > x)])))
    print("safe dis > " + str(x) + " label=1:" + str(
        len(result[(result['y'] == 'safe') & (result['dis'] > x) & (result['label'] == 1)])))
    print("safe dis <= " + str(x) + " :" + str(len(result[(result['y'] == 'safe') & (result['dis'] <= x)])))
    print("safe dis <= " + str(x) + " label=1:" + str(
        len(result[(result['y'] == 'safe') & (result['dis'] <= x) & (result['label'] == 1)])))
    print("malicious dis > " + str(x) + " :" + str(len(result[(result['y'] == 'malicious') & (result['dis'] > x)])))
    print("malicious dis > " + str(x) + " label=1:" + str(
        len(result[(result['y'] == 'malicious') & (result['dis'] > x) & (result['label'] == 1)])))
    print("malicious dis <= " + str(x) + " :" + str(len(result[(result['y'] == 'malicious') & (result['dis'] <= x)])))
    print("malicious dis <= " + str(x) + " label=1:" + str(
        len(result[(result['y'] == 'malicious') & (result['dis'] <= x) & (result['label'] == 1)])))

    # 计算得分
    TP = len(result[(result['pre'] == 1) & (result['y'] == 'malicious')])
    FN = len(result[(result['pre'] == 0) & (result['y'] == 'malicious')])
    FP = len(result[(result['pre'] == 1) & (result['y'] == 'safe')])
    TN = len(result[(result['pre'] == 0) & (result['y'] == 'safe')])
    P = TP / (TP + FP)
    R = TP / (TP + FN)
    F1 = 2 * TP / (2 * TP + FP + FN)
    auc = (TP + TN) / (TP + FN + FP + TN)
    print("精确率 = {} 召回率 = {} F1_Score = {} 准确率 = {}".format(P, R, F1, auc))
    print(TP, FN, FP, TN)


if __name__ == "__main__":
    df=pd.read_csv("sss.csv")
    predict(df)
