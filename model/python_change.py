

#!/usr/bin/env python3

import pickle
import joblib

gs = joblib.load('gs_py3.m')
joblib.dump(gs,"gs2.m",protocol=2,compress=2)

