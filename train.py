#! coding=utf8
import torch
import cccheck.read_data
import warnings
import cccheck.first_clustering
import cccheck.cal_smilar
from sklearn.externals import joblib
import cccheck.match
import Sentiment_RNN_Solution


if __name__ == "__main__":
    output_size = 1
    # embedding_dim = 400
    embedding_dim = 100
    # hidden_dim = 256
    hidden_dim = 64
    n_layers = 2
    net = Sentiment_RNN_Solution.SentimentRNN(output_size, embedding_dim, hidden_dim, n_layers)
    net.fit()

    # 保存模型
    torch.save(net, '/media/mrl/FAD0E3C934BABEE4/security-competition/code_together/maltrail/model/LSTM_model.pkl')
    data = cccheck.read_data.read('/media/mrl/FAD0E3C934BABEE4/security-competition/code_together/maltrail/data/test.csv')
    data1 = cccheck.read_data.read('/media/mrl/FAD0E3C934BABEE4/security-competition/code_together/maltrail/data/data.csv')
    # print(data.columns)
    # del data['ip_24_count']
    # data = data[data['ip_24'] == '23.62.6']
    data = cccheck.cal_smilar.group_feature(data, 'user_agent')
    data = cccheck.cal_smilar.group_feature(data, 'host')
    data = cccheck.cal_smilar.group_feature(data, 'accept_language')
    data = cccheck.cal_smilar.group_feature(data, 'accept_encoding')
    data = cccheck.cal_smilar.group_feature(data, 'ip_dst')
    # data = data.head(10000)
    gs = cccheck.first_clustering.get_gs(data1[['path', 'original_host', 'ip_dst']])
    CPT = cccheck.cal_smilar.get_all_CPT(data, gs)
    print("模板生成成功")
    CPT.to_csv("/media/mrl/FAD0E3C934BABEE4/security-competition/code_together/maltrail/model/CPT.csv", sep='\a', index=False)
    # # 保存模型
    # joblib.dump(gs, 'model/gs.m')        ,protocol=2
    joblib.dump(gs, '/media/mrl/FAD0E3C934BABEE4/security-competition/code_together/maltrail/model/gs.m')
