from transformers import (AutoTokenizer, AutoModelForTokenClassification,
                         pipeline)
import pandas as pd
import re
from itertools import product
import numpy as np
import pylcs
import psycopg2 as p2
from tqdm import tqdm
from Levenshtein import ratio
from itertools import product
from utils import (get_df_from_bd, extract_ners, deduplicate_using_probs,
                   extract_version, classify_version_string, parse_version,
                   generate_versions, get_lcs, lcs_mini)

pd.set_option('display.width', 20000)
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', 100)
pd.set_option('display.max_colwidth', 200)




def create_suggestions():
    return {'suggestions': ['vendor:product1', 'vendor:product2'],
            'versions': [0.1, 0.2, 0.3]}

def pipeline(text):
    path_to_model = "/home/mikhail/Documents/pandan_study/vkr/vulns_scanner/mikhail_code/models/nuner_180525_full_dataset"
    final_tokenizer = AutoTokenizer.from_pretrained(path_to_model, use_fast=True, add_prefix_space=True, local_files_only=True)
    final_model = AutoModelForTokenClassification.from_pretrained(path_to_model, local_files_only=True)
    extracted = extract_ners(text, 
                             tokenizer=final_tokenizer,
                             model=final_model)
    vendors = extracted['ners'][0]
    vendors_scores = extracted['scores'][0]
    products = extracted['ners'][1]
    products_scores = extracted['scores'][1]
    versions = extracted['ners'][2]
    versions_score = extracted['scores'][2]
    
    # print(vendors, products, versions)

    dedup_vendor, dedup_vendor_scores = deduplicate_using_probs(vendors, vendors_scores)
    dedup_product, dedup_product_scores = deduplicate_using_probs(products, products_scores)
    
    # print(dedup_vendor, dedup_product, dedup_product_scores)

    possible_versions = []

    for version_ner in versions:
        preprocessed_ner = classify_version_string(version_ner)
        if preprocessed_ner[0][0] is None:
            continue
        generated_versions = generate_versions(*preprocessed_ner)
        possible_versions.extend(generated_versions)
    
    df_all = get_df_from_bd('select * from cpes limit 10000000;')
    unique_products = df_all['product'].unique()
    unique_vendors = df_all['vendor'].unique()

    if dedup_product:
        # print(f'Product NER: {pr}')
        prod, _ = get_lcs(dedup_product[0], unique_products)
        # print(f'Found product in DB: {prod}')
        df_all = get_df_from_bd(f"""
                                select distinct vendor, product 
                                from cpes 
                                where vendor in 
                                    (select vendor 
                                    from cpes 
                                    where product = '{prod}'
                                    )
                                """)
        found_candidates = [x for x in set(lcs_mini(prod, df_all['product'].tolist(), top_k=3))]
        found_vendor = df_all['vendor'].values[0]
        
    else:
        found_candidates = [dedup_product]
        found_vendor = dedup_vendor

    if found_candidates == [[]] or found_candidates == []:
        return {'suggestions': None,
            'versions': None}
    
    if found_vendor:
        generated_cpes = [f'{found_vendor}\t{cand}' for cand in found_candidates]
    else:
        generated_cpes = [f'\t{cand}' for cand in found_candidates]


    
    return {'suggestions': generated_cpes,
            'versions': possible_versions}

    

# s = '''HDF5 Library through 1.14.3 has a SEGV in H5T_close_real in H5T.c, resulting in a corrupted instruction pointer.'''
# pipeline(s)