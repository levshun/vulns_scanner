import json
from collections import Counter

# with open('/home/mikhail/Documents/pandan_study/vkr/vulns_scanner/mikhail_code/data/cve/nvdcve-1.1-2024/nvdcve-1.1-2024.json') as j:
#     corpus = json.loads(j.read())

# print(json.dumps(corpus['CVE_Items'][0], indent=4))
with open('/home/mikhail/Documents/pandan_study/vkr/vulns_scanner/mikhail_code/data/full_corpus.json') as j:
    corpus = json.loads(j.read())
cve_list = corpus['NVD']['CVE-2013-3269']
labels = list(zip(*cve_list))[1]
print(Counter(labels))