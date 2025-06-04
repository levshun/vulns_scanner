import json
from collections import Counter
import logging
logger = logging.getLogger('make dataset')
logger.setLevel('INFO')
fmtter = logging.Formatter('{name} - {asctime} - {levelname} - {message}',
                           style='{',
                           datefmt="%Y-%m-%d %H:%M:%S")
handler = logging.StreamHandler()
handler.setFormatter(fmtter)
logger.addHandler(handler)

# with open('/home/mikhail/Documents/pandan_study/vkr/vulns_scanner/mikhail_code/data/cve/nvdcve-1.1-2024/nvdcve-1.1-2024.json') as j:
#     corpus = json.loads(j.read())

# print(json.dumps(corpus['CVE_Items'][0], indent=4))
with open('/home/mikhail/Documents/pandan_study/vkr/vulns_scanner/mikhail_code/data/full_corpus.json') as j:
    corpus = json.loads(j.read())

words, labels = [], []
c = Counter()
json_data = []
for enum_i, (cve_id, cve_data) in enumerate(corpus['NVD'].items()):
    logger.info(cve_id)
    output = {}
    word_ner_pairs = list(filter(lambda x: x[1] not in ('O', 'B-relevant_term', 'I-relevant_term'), cve_data))
    logger.debug(word_ner_pairs)
    for i in range(len(word_ner_pairs)):
        logger.debug(f'i -- {i}')
        if word_ner_pairs[i][1][0] == 'B':
            ner_text = word_ner_pairs[i][0]
            word_ner_pairs_subset = word_ner_pairs[i+1:]
            logger.debug(word_ner_pairs_subset)
            for ii in range(len(word_ner_pairs_subset)):
                next_ner_pair = word_ner_pairs_subset[ii][1].split('-')
                logger.debug(f'ii -- {ii}, {word_ner_pairs_subset[ii][0]}')
                if next_ner_pair[0] == 'I' and next_ner_pair[1] == word_ner_pairs_subset[ii][1][2:]:
                    ner_text += ' '
                    ner_text += word_ner_pairs_subset[ii][0]
                else:
                    break
        output[word_ner_pairs[i][1][2:]] = ner_text
    wrds = list(zip(*cve_data))[0]
    lbls = list(zip(*word_ner_pairs))[1]
    c.update(lbls)
    data = {'text': ' '.join(wrds), 'output': output}
    logger.info(data)
    json_data.append(data)
    logger.info('*'*50)
    if enum_i > 100:
        break
logger.info(c.keys())

with open('nuner_data.jsonl', 'w') as f:
    for l in json_data:
        f.write(json.dumps(l) + '\n')
        
    