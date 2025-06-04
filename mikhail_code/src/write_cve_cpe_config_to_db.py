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
from typing import List

import sys
sys.path.insert(0, os.getcwd().rstrip('src'))
#print(sys.path)
import logging
from src.utils.logger import main_logger
logger = main_logger()


def split_cpe(cpe:str) -> List[str]:
    initial_cpe = cpe
    cpe = ''.join([x for x in cpe.lstrip("cpe:") if x != '*'])
    cpe_version, part, vendor, product, version, update, edition, sw_edition,\
         target_sw, target_hw, language, other = cpe.split(":")
    return cpe_version, part, vendor, product, version, update, edition, sw_edition,\
         target_sw, target_hw, language, other, initial_cpe


# Чтобы зайти через bash:
# psql -d vulns_scanner -U postgres -h localhost

dbname = "vulns_scanner"
user = 'postgres'
password = 'postgres'
host = 'localhost'
port = '5432'


# table_name = 'cves'

conn = p2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
cur = conn.cursor()

track_cve = {}
track_cpe = {}

path = 'data/cve_cpe_config_dir'
for filename in os.listdir(path):
    fullpath = os.path.join(path, filename)
    if os.path.isfile(fullpath):
        with open(fullpath, 'r') as csv_f:
            print(f'Starting to write rows from file {filename}')
            reader_csv = csv.reader(csv_f)
            for i, row in enumerate(reader_csv):
                if i != 0:        
                    if i % 100_000 == 0:
                        print(f'{i} iteration passed\n******************************\n')
                    # cves
                    try:
                        if track_cve.get(row[0], -1) == -1:
                            cur.execute('''insert into cves (cve_id) 
                                        values (%s)
                                        returning cve_id_pk;''', (row[0],))
                            cve_id_pk = cur.fetchone()[0]
                            track_cve[row[0]] = 1
                        else:
                            cur.execute('''select cve_id_pk from cves
                                            where cve_id = %s''', (row[0],))
                            cve_id_pk = cur.fetchone()[0]
                        
                        # cpes
                        splitted_cpe = split_cpe(row[1])
                        if track_cpe.get(row[1], -1) == -1:
                            cur.execute('''
                                insert into cpes (cpe_version, part, vendor, product, version, update, edition, sw_edition,
                                    target_sw, target_hw, language, other, initial_cpe)
                                values (%s, %s,%s, %s,%s, %s,%s, %s,%s, %s,%s, %s, %s)
                                returning cpe_id_pk
                            ''', splitted_cpe)
                            cpe_id_pk = cur.fetchone()[0]
                            track_cpe[row[1]] = 1
                        else:
                            cur.execute('''select cpe_id_pk from cpes
                                            where initial_cpe = %s''', row[1])

                        # print(type(cve_id_pk), type(cpe_id_pk), type(cve_cpe_config[0][2]))

                        cur.execute('''insert into cve_cpe_config (cve_id_fk, cpe_id_fk, config_id)
                                    values (%s, %s, %s)''', (cve_id_pk, cpe_id_pk, row[2]))


                        conn.commit()
                    except:
                        continue
            logger.debug('\n\n' + '*'*50 + '\n\n')
conn.close()
