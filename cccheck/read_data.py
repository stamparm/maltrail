#! coding=utf8
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')


def get_ip_24(ip):
    """
    取数据集中的ip地址前24位
    :param ip:
    :return:
    """
    tmp = ip.split('.')
    if(len(tmp)<4):
        return np.nan
    else:
        ip_24 = tmp[0] + '.'+tmp[1]+'.'+tmp[2]
    return ip_24


def read(path):
    data = pd.read_csv(path)
    data.query_parameter[data['query_parameter'] == "0"] = "None=str;1"
    data = data.fillna(" ")
    data['ip_24'] = data['ip_dst'].apply(lambda x: get_ip_24(x))
    data.dropna(inplace=True)
    return data


def get_data(data):
    data.query_parameter[data['query_parameter'] == "0"] = "None=str;1"
    data = data.fillna(" ")
    data['ip_24'] = data['ip_dst'].apply(lambda x: get_ip_24(x))
    data.dropna(inplace=True)
    return data
