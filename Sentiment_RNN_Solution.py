#! coding=utf8
# 读入数据
import codecs
import numpy as np
from collections import Counter
import torch
from torch.utils.data import TensorDataset, DataLoader
import torch.nn as nn


# 元素展平与填充
def pad_features(reviews_ints, seq_length):
    features = np.zeros((len(reviews_ints), seq_length), dtype=int)

    # 填充或展平
    for i, row in enumerate(reviews_ints):
        features[i, -len(row):] = np.array(row)[:seq_length]

    return features


def read_data():
    # read data from text files
    with codecs.open('/media/mrl/FAD0E3C934BABEE4/security-competition/code_together/maltrail/data/reviews.txt', 'r', encoding='UTF-8') as f:
        reviews = f.read()
    with codecs.open('/media/mrl/FAD0E3C934BABEE4/security-competition/code_together/maltrail/data/labels.txt', 'r', encoding='UTF-8') as f:
        labels = f.read()

    # 数据预处理
    reviews = reviews.lower()  # 转化为小写
    words = []
    reviews_split = []

    # 按行分割
    reviews_split = reviews.split('\n')

    # 建立字母表
    for i in range(0, 26):
        words.append(chr(ord('a') + i))
    for i in range(0, 10):
        words.append(str(i))
    words.append('-')
    words.append('_')

    # 字符映射
    ## 建立字典映射
    counts = Counter(words)
    vocab = sorted(counts, key=counts.get, reverse=True)
    vocab_to_int = {word: ii for ii, word in enumerate(vocab, 1)}

    ## 存储标准化结果
    reviews_ints = []
    for review in reviews_split:
        renow = list(str(review))
        reviews_ints.append([vocab_to_int[word] for word in renow])

    # 标签编码
    # 1=恶意, 0=良性
    labels_split = labels.split('\n')
    encoded_labels = np.array([1 if label == '1' else 0 for label in labels_split])

    # 除去异常值 除去0长度的元素
    # outlier review stats
    review_lens = Counter([len(x) for x in reviews_ints])

    non_zero_idx = [ii for ii, review in enumerate(reviews_ints) if len(review) != 0]

    reviews_ints = [reviews_ints[ii] for ii in non_zero_idx]
    encoded_labels = np.array([encoded_labels[ii] for ii in non_zero_idx])

    seq_length = 50

    features = pad_features(reviews_ints, seq_length=seq_length)

    # test statements - do not change - ##
    assert len(features) == len(reviews_ints), "Your features should have as many rows as reviews."
    assert len(features[0]) == seq_length, "Each feature row should contain seq_length values."

    # 训练、验证、测试
    split_frac = 0.8

    # 分割数据为训练集、验证集、测试集

    split_idx = int(len(features) * split_frac)
    train_x, remaining_x = features[:split_idx], features[split_idx:]
    train_y, remaining_y = encoded_labels[:split_idx], encoded_labels[split_idx:]

    test_idx = int(len(remaining_x) * 0.5)
    val_x, test_x = remaining_x[:test_idx], remaining_x[test_idx:]
    val_y, test_y = remaining_y[:test_idx], remaining_y[test_idx:]

    # 打印各数据集维度
    print("\t\t\tFeature Shapes:")
    print("Train set: \t\t{}".format(train_x.shape),
          "\nValidation set: \t{}".format(val_x.shape),
          "\nTest set: \t\t{}".format(test_x.shape))

    # 数据加载和分块
    # 创建数据集
    train_data = TensorDataset(torch.from_numpy(train_x), torch.from_numpy(train_y))
    valid_data = TensorDataset(torch.from_numpy(val_x), torch.from_numpy(val_y))
    test_data = TensorDataset(torch.from_numpy(test_x), torch.from_numpy(test_y))

    # 数据加载
    batch_size = 50

    # 注意是否保证能被batch_size整除
    train_loader = DataLoader(train_data, shuffle=True, batch_size=batch_size)
    valid_loader = DataLoader(valid_data, shuffle=True, batch_size=batch_size)
    test_loader = DataLoader(test_data, shuffle=True, batch_size=batch_size)

    return vocab_to_int, train_loader, valid_loader, test_loader


# # 获取一个数据块
# dataiter = iter(train_loader)
# sample_x, sample_y = dataiter.next()
#
# print('Sample input size: ', sample_x.size())
# print('Sample input: \n', sample_x)
# print()
# print('Sample label size: ', sample_y.size())
# print('Sample label: \n', sample_y)


# LSTM模型部分
class SentimentRNN(nn.Module):

    def __init__(self, output_size, embedding_dim, hidden_dim, n_layers, drop_prob=0.5):
        """
        Initialize the model by setting up the layers.
        """
        super(SentimentRNN, self).__init__()
        self.vocab_to_int, self.train_loader, self.valid_loader, self.test_loader = read_data()

        self.output_size = output_size
        self.vocab_size = len(self.vocab_to_int) + 1
        self.n_layers = n_layers
        self.hidden_dim = hidden_dim

        # LSTM层embeddign
        self.embedding = nn.Embedding(self.vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, n_layers,
                            dropout=drop_prob, batch_first=True)

        # 随机丢弃层
        self.dropout = nn.Dropout(0.3)

        # Linear和Sigmod
        self.fc = nn.Linear(hidden_dim, output_size)
        self.sig = nn.Sigmoid()

        self.train_on_gpu = torch.cuda.is_available()

    def forward(self, x, hidden):
        """
        Perform a forward pass of our model on some input and hidden state.
        """
        batch_size = x.size(0)

        x = x.long()
        embeds = self.embedding(x)
        lstm_out, hidden = self.lstm(embeds, hidden)

        lstm_out = lstm_out.contiguous().view(-1, self.hidden_dim)

        out = self.dropout(lstm_out)
        out = self.fc(out)

        sig_out = self.sig(out)

        sig_out = sig_out.view(batch_size, -1)
        sig_out = sig_out[:, -1]

        return sig_out, hidden

    def init_hidden(self, batch_size):
        ''' Initializes hidden state '''

        weight = next(self.parameters()).data

        if self.train_on_gpu:
            hidden = (weight.new(self.n_layers, batch_size, self.hidden_dim).zero_().cuda(),
                      weight.new(self.n_layers, batch_size, self.hidden_dim).zero_().cuda())
        else:
            hidden = (weight.new(self.n_layers, batch_size, self.hidden_dim).zero_(),
                      weight.new(self.n_layers, batch_size, self.hidden_dim).zero_())

        return hidden

    def fit(self):
        batch_size = 50

        if self.train_on_gpu:
            print('Training on GPU.')
        else:
            print('No GPU available, training on CPU.')
        # # 初始化网络
        # # 调整网络参数
        # vocab_size = len(self.vocab_to_int) + 1  # +1 for the 0 padding + our word tokens
        # output_size = 1
        # embedding_dim = 400
        # hidden_dim = 256
        # n_layers = 2
        #
        # net = SentimentRNN(vocab_size, output_size, embedding_dim, hidden_dim, n_layers)
        #
        # print(net)

        # 训练
        # loss和优化函数
        lr = 0.001

        criterion = nn.BCELoss()
        optimizer = torch.optim.Adam(self.parameters(), lr=lr)

        # 训练参数

        epochs = 4  # 训练周期

        counter = 0
        print_every = 100
        clip = 5

        # GPU训练
        if self.train_on_gpu:
            self.cuda()

        self.train()

        for e in range(epochs):

            h = self.init_hidden(batch_size)
            # 循环
            for inputs, labels in self.train_loader:
                counter += 1

                if self.train_on_gpu:
                    inputs, labels = inputs.cuda(), labels.cuda()

                h = tuple([each.data for each in h])

                self.zero_grad()

                output, h = self(inputs, h)

                loss = criterion(output.squeeze(), labels.float())
                loss.backward()

                nn.utils.clip_grad_norm_(self.parameters(), clip)
                optimizer.step()

                # loss状态
                if counter % print_every == 0:
                    # 验证损失
                    val_h = self.init_hidden(batch_size)
                    val_losses = []
                    self.eval()
                    for inputs, labels in self.valid_loader:

                        val_h = tuple([each.data for each in val_h])

                        if self.train_on_gpu:
                            inputs, labels = inputs.cuda(), labels.cuda()

                        output, val_h = self(inputs, val_h)
                        val_loss = criterion(output.squeeze(), labels.float())

                        val_losses.append(val_loss.item())

                    self.train()
                    print("Epoch: {}/{}...".format(e + 1, epochs),
                          "Step: {}...".format(counter),
                          "Loss: {:.6f}...".format(loss.item()),
                          "Val Loss: {:.6f}".format(np.mean(val_losses)))

        # 验证
        test_losses = []
        num_correct = 0

        h = self.init_hidden(batch_size)

        self.eval()

        for inputs, labels in self.test_loader:

            h = tuple([each.data for each in h])

            if self.train_on_gpu:
                inputs, labels = inputs.cuda(), labels.cuda()

            output, h = self(inputs, h)

            test_loss = criterion(output.squeeze(), labels.float())
            test_losses.append(test_loss.item())

            pred = torch.round(output.squeeze())

            correct_tensor = pred.eq(labels.float().view_as(pred))
            correct = np.squeeze(correct_tensor.numpy()) if not self.train_on_gpu else np.squeeze(
                correct_tensor.cpu().numpy())
            num_correct += np.sum(correct)

        print("Test loss: {:.3f}".format(np.mean(test_losses)))

        test_acc = num_correct / len(self.test_loader.dataset)
        print("Test accuracy: {:.3f}".format(test_acc))

    @staticmethod
    def tokenize_review(test_review, vocab_to_int):
        test_review = test_review.lower()

        test_words = test_review.split()
        if len(test_words) == 0:
            test_words = [' ']
        #     print(test_words,len(test_words),test_words==[])
        test_words = list(test_words[0])

        # tokens
        test_ints = []
        test_ints.append([vocab_to_int[word] for word in test_words])

        return test_ints

    def predict(self, test_review, sequence_length=200):
        self.eval()

        test_ints = self.tokenize_review(test_review, self.vocab_to_int)

        seq_length = sequence_length
        features = pad_features(test_ints, seq_length)

        feature_tensor = torch.from_numpy(features)

        batch_size = feature_tensor.size(0)

        h = self.init_hidden(batch_size)

        if self.train_on_gpu:
            feature_tensor = feature_tensor.cuda()

        output, h = self(feature_tensor, h)

        if output.squeeze().item() >= 0.2:
            pred = 1.0
        else:
            pred = 0.0

        return pred
