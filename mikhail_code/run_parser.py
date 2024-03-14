import json
from tqdm import tqdm
import string
import itertools
# import pandas as pd
import time
import csv
import os
import psycopg2 as p2
from psycopg2 import sql
import pickle

from parse_nisd_feeds import get_non_empty_cpe_from_right, check_versions_cpe, \
                                search_in_cpe_feed, parse_feed


# memory-heavy operation
with open("./nvdcpematch-1.0.json") as f:
    file = f.read()
    cpe_json = json.loads(file)


minimal_non_empty_from_right_cpe = []
cpe_names = []
for match_cpe in tqdm(cpe_json['matches']):
    minimal_non_empty_from_right_cpe.append(get_non_empty_cpe_from_right(match_cpe['cpe23Uri']))
    if match_cpe['cpe_name']:
        store_cpe_names = []
        for cpe_name in match_cpe['cpe_name']:
            store_cpe_names.append(cpe_name['cpe23Uri'])
        cpe_names.append(store_cpe_names)
    else:
        cpe_names.append([match_cpe['cpe23Uri']])


# Creates a dictionary with right side trimmed CPE and corresponding cpe_names
dict_from_cpe_feed = dict(zip(minimal_non_empty_from_right_cpe, cpe_names))


root_path = "./cve"


# iterating over folders with cve feed json fiels
for dir_path, _, _ in os.walk(root_path):
    # print(dir_path)
    if dir_path not in (root_path, './cve/downloaded'):
        cve_feed_name = os.listdir(dir_path)[0]
        print(cve_feed_name)
        cve_feed_path = os.path.join(dir_path, cve_feed_name)

        with open(f"{cve_feed_path}", "r") as f:
            file = f.read()
            json_file = json.loads(file)

        cve_cpe_config = []
        counter = 0
        with open('cve_cpe_config_dir/logs.txt', 'a') as log_file:
            print(f'Starting iteration for {cve_feed_name}', file=log_file)
            for i in tqdm(range(len(json_file['CVE_Items']))): 
                # getting list of list with all cve_cpe_config pairs
                try:
                    i_cve_cpe_config, new_counter = parse_feed(json_file['CVE_Items'][i], counter, dict_from_cpe_feed)
                except ValueError:
                    print(i)
                    i_cve_cpe_config, new_counter = parse_feed(json_file['CVE_Items'][i], counter, dict_from_cpe_feed)
                    break
                # print(counter, new_counter)
                cve_cpe_config.extend(i_cve_cpe_config)
                counter = new_counter
            
            for i in range(len(cve_cpe_config)):
                if cve_cpe_config[i] == [[], [], []]:
                    cve_cpe_config.pop(i)

            # writing list of lists to csv
            with open(f'cve_cpe_config_dir/{cve_feed_name.rstrip(".json")}.csv', 'a') as csv_file:
                print(f'Writing to csv file for {cve_feed_name}')
                writer = csv.writer(csv_file)
                writer.writerow(['cve', 'cpe', 'config_id'])
                writer.writerows(cve_cpe_config)
                print(f'Done  with csv file for {cve_feed_name}')
                print('*'*50)

# # save resulted list to pickle
# with open('pickled_cve_cpe_config', 'wb') as fp:
#     pickle.dump(cve_cpe_config, fp)
#     print('Successfully dumped to pickle')