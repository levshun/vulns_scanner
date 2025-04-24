import json
from collections import Counter
import logging
import pandas as pd
logger = logging.getLogger('make dataset')
logger.setLevel('INFO')
fmtter = logging.Formatter('{name} - {asctime} - {levelname} - {message}',
                           style='{',
                           datefmt="%Y-%m-%d %H:%M:%S")
handler = logging.StreamHandler()
handler.setFormatter(fmtter)
logger.addHandler(handler)

with open('/home/mikhail/Documents/pandan_study/vkr/vulns_scanner/mikhail_code/data/full_corpus.json') as j:
    corpus = json.loads(j.read())

# print(corpus['NVD']['CVE-2013-3538'])

df_length = len(corpus['NVD'])

cve_ids, words, labels = [], [], []
c = Counter()
json_data = []
for enum_i, (cve_id, cve_data) in enumerate(corpus['NVD'].items()):
    logger.info(cve_id)
    wrds, lbls = list(zip(*cve_data))
    assert len(wrds) == len(lbls), f'Length of list for words and BIO-labels is different for CVE {cve_id}'
    cve_ids.extend([cve_id] + ['0' for _ in range(len(wrds)-1)])
    words.extend(wrds)
    labels.extend(lbls)
    if enum_i == df_length:
        break

# print(cve_ids, words, labels, sep='\n\n\n')
df = pd.DataFrame(data={'cve_id': cve_ids,
                   'words': words,
                   'bio': labels})
print(df.head())
print(df.describe())
df.to_csv(f'./cve_dataset_bio_{df_length}_texts_v2.tsv', index=False, sep='\t')
