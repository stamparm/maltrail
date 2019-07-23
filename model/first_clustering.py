import pandas as pd
import numpy as np
import warnings
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression

warnings.filterwarnings('ignore')


def makeURLTokens(f):
    """
    用于TF-IDF提取URL各字段数据
    :param f:
    :return:
    """
    tkns_BySlash = str(f.encode('utf-8')).split('/')
    total_Tokens = []
    for i in tkns_BySlash:
        tokens = str(i).split('-')
        tkns_ByDot = []
        for j in range(0, len(tokens)):
            temp_Tokens = str(tokens[j]).split('.')
            tkns_ByDot = tkns_ByDot + temp_Tokens
        total_Tokens = total_Tokens + tokens + tkns_ByDot
    total_Tokens = list(set(total_Tokens))
    if 'com' in total_Tokens:
        total_Tokens.remove('com')
    return total_Tokens


def host_count(df):
    """
    统计访问
    :param df:
    :return:
    """
    grouped = df.groupby('original_host')

    aggs = {
        'ip_dst': ['nunique']
    }

    intermediate_group = grouped.agg(aggs)
    intermediate_group.columns = [
        '_'.join(col).strip() for col in intermediate_group.columns.values]
    intermediate_group.reset_index(inplace=True)

    return intermediate_group


def get_gs(urldata):
    """
    训练二分类器，用于后期特异度判断
    :param urldata:
    :return:
    """
    tmp = host_count(urldata)
    urldata = pd.merge(urldata, tmp, on='original_host')
    low = urldata['ip_dst_nunique'].describe()[4]
    mid = urldata['ip_dst_nunique'].describe()[5]
    high = urldata['ip_dst_nunique'].describe()[6]
    url_class = urldata[(urldata['ip_dst_nunique'] <= (low + mid)/2) | (urldata['ip_dst_nunique'] >= (high + mid) / 2 )]
    url_class['pos'] = np.nan
    url_class.pos[url_class['ip_dst_nunique'] <= (low + mid) / 2] = 0
    url_class.pos[urldata['ip_dst_nunique'] >= (high + mid) / 2] = 1
    del url_class['ip_dst_nunique']
    del url_class['original_host']
    X_train_list = url_class['path']
    y_train = url_class['pos']
    print(url_class.nunique())

    skf = StratifiedKFold(n_splits=2, shuffle=True, random_state=2019)
    pipeline = Pipeline(
        [('tfidf', TfidfVectorizer(analyzer='word', tokenizer=makeURLTokens)), ('lg', LogisticRegression())])
    parameters = {
        'lg__C': (2.25, 2.5, 2.75),
    }
    gs = GridSearchCV(estimator=pipeline, param_grid=parameters, n_jobs=1, scoring='roc_auc', cv=skf, verbose=3)
    gs.fit(X_train_list, y_train)
    return gs
