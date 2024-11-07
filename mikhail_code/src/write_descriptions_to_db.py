import psycopg2 as p2
from psycopg2 import sql
import json
import os
import sys
sys.path.insert(0, os.getcwd().rstrip('src'))

dbname = "vulns_scanner"
user = 'postgres'
password = 'postgres'
host = 'localhost'
port = '5432'
table_name = 'descriptions'
conn = p2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
cur = conn.cursor()

import logging
from src.utils.logger import main_logger
logger = main_logger()

# track_cve = {}
# track_cpe = {}

root_path = "data/cve"
for _, dir_folds, _ in os.walk(root_path):
    if dir_folds:
        for folder in dir_folds:
            cve_feed_path_to_json = os.path.join(root_path, folder, folder+".json")
            logger.info(f'Start processing {cve_feed_path_to_json}')

            with open(cve_feed_path_to_json) as json_f:
                json_feed_file = json.load(json_f)

                for i in range(len(json_feed_file['CVE_Items'])):
                    cve_id = json_feed_file['CVE_Items'][i]['cve']['CVE_data_meta']['ID'] 
                    cve_descr = json_feed_file['CVE_Items'][i]['cve']['description']['description_data'][0]['value']

                    # for i in range(len(cve_cpe_config)):
                    if i % 10_000 == 0:
                        logger.info(f'{i} iteration passed\n******************************\n')
                    # cves
                    try:  
                        # logger.info(cve_id)
                        cur.execute('''select cve_id_pk from cves
                                    where cve_id = (%s)''', (cve_id,))
                        cve_id_pk = cur.fetchone()[0]
                        if not cve_id_pk:
                            continue
                        # print(cve_id_pk, cve_descr)
                        cur.execute('''insert into descriptions (cve_id_fk, descr)
                                        values (%s, %s)''', (cve_id_pk, cve_descr,))
                        conn.commit()
                    except:
                        logger.debug(f'Error for CVE-ID -- {cve_id}')
                        continue
                print("Everything is written")

conn.close()