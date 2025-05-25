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

def get_df_from_bd(q):
    dbname = "vulns_scanner"
    user = 'postgres'
    password = 'postgres'
    host = 'localhost'
    port = '5432'
    conn = p2.connect(dbname=dbname, 
                      user=user, 
                      password=password, 
                      host=host, port=port)
    cur = conn.cursor()
    cur.execute(q)
    colnames = [desc[0] for desc in cur.description]
    tuples = cur.fetchall()
    cur.close()
    df = pd.DataFrame(tuples, columns=colnames)
    return df

def extract_ners(cve, 
                 tokenizer, 
                 model):
    token_classifier = pipeline(
        "token-classification", 
        model=model, 
        aggregation_strategy="first", 
        tokenizer=tokenizer
    )
    result = token_classifier(cve)
    vendor = []
    product = []
    version = []
    vendor_probs = []
    product_probs = []
    version_probs = []

    for ner_item in result:
        if ner_item['entity_group'] == 'vendor':
            vendor.append(str.lower(ner_item['word'].strip()))
            vendor_probs.append(str.lower(str(ner_item['score'])))
        elif ner_item['entity_group'] == 'product':
            product.append(str.lower(str(ner_item['word'].strip())))
            product_probs.append(str.lower(str(ner_item['score'])))
        elif ner_item['entity_group'] == 'version':
            version.append(str.lower(str(ner_item['word'].strip())))
            version_probs.append(str.lower(str(ner_item['score'])))
    return {'ners': [vendor, product, version], 'scores': [vendor_probs, product_probs, version_probs]}

def deduplicate_using_probs(entities, scores):
    if not entities or len(entities) == 1:
        return entities, scores
        
    max_idx = scores.index(max(scores))
    return [entities[max_idx]], [scores[max_idx]]

def extract_version(matched):
        if matched:
            version = matched.group('version')
            # Normalize separators (replace '-' with '.' if needed)
            version = version.replace('-', '.')
            return version
        return None

def classify_version_string(version_str):
    """
    Generate all versions for expressions containing 'before'.
    Handles two cases:
    1) "before X.Y.Z" - generates all versions up to X.Y.Z
    2) "A.B.x before A.B.C" - generates all patch versions A.B.0 to A.B.(C-1)
    """
    version_str = str.lower(version_str)

    # through, including
    group_name = 'through'
    group_words = ['through', 'earlier', '<=', 'prior', 'up to', 'up to, and including', 'up to and including', 'older']
    for group_wrd in group_words:
        if group_wrd in version_str:
            # More complicated multi version logic
            # '2.1 through 3.17'
            multi_version_pattern = r'(?P<version1>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)\s*' \
                        r'(?:through|earlier|prior|\<\=|up to)\s*' \
                        r'(?P<version2>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)'
            multi_match = re.search(multi_version_pattern, version_str, re.IGNORECASE)
            if multi_match:
                version1 = multi_match.group('version1')
                version2 = multi_match.group('version2')
                return [version1, version2], f'{group_name} multi-match'

            pattern = (
                r'(?P<version>[\dxX]+(?:[.-]\s*[\dxX]+)*)'  # Version with digits/x and separators
            )
            matched = re.search(pattern, version_str, re.IGNORECASE)
            return [extract_version(matched)], f'{group_name} group'

    # before, not including
    group_name = 'before'
    group_words = ['before', '<']
    for group_wrd in group_words:
        if group_wrd in version_str:
            # More complicated multi version logic
            # '4.2.x before 4.2.8'
            multi_version_pattern = r'(?P<version1>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)\s*' \
                        r'(?:before)\s*' \
                        r'(?P<version2>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)'
            multi_match = re.search(multi_version_pattern, version_str, re.IGNORECASE)
            if multi_match:
                version1 = multi_match.group('version1')
                version2 = multi_match.group('version2')
                return [version1, version2], f'{group_name} multi-match'

            # if simple logic
            pattern = (
                r'(?P<version>[\dxX]+(?:[.-]\s*[\dxX]+)*)'  # Version with digits/x and separators
            )
            matched = re.search(pattern, version_str, re.IGNORECASE)
            return [extract_version(matched)], f'{group_name} group'

    # after, including
    group_name = 'after'
    group_words = ['after', '>=']
    for group_wrd in group_words:
        if group_wrd in version_str:
            # More complicated multi version logic
            # '4.2.x before 4.2.8'
            multi_version_pattern = r'(?P<version1>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)\s*' \
                        r'(?:older|after|\>\=)\s*' \
                        r'(?P<version2>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)'
            multi_match = re.search(multi_version_pattern, version_str, re.IGNORECASE)
            if multi_match:
                version1 = multi_match.group('version1')
                version2 = multi_match.group('version2')
                return [version1, version2], f'{group_name} multi-match'

            # if simple logic
            pattern = (
                r'(?P<version>[\dxX]+(?:[.-]\s*[\dxX]+)*)'  # Version with digits/x and separators
            )
            matched = re.search(pattern, version_str, re.IGNORECASE)
            return [extract_version(matched)], f'{group_name} group'

    # between
    group_name = 'between'
    group_words = ['between', 'to', ' - ']
    for group_wrd in group_words:
        if group_wrd in version_str:
            # More complicated multi version logic
            # '4.2.x before 4.2.8'
            multi_version_pattern = r'(?P<version1>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)\s*' \
                        r'(?:between|to)\s*' \
                        r'(?P<version2>[\dxX]+(?:\s*[.-]\s*[\dxX]+)*)'
            multi_match = re.search(multi_version_pattern, version_str, re.IGNORECASE)
            if multi_match:
                version1 = multi_match.group('version1')
                version2 = multi_match.group('version2')
                return [version1, version2], f'{group_name} multi-match'

            # # if simple logic
            # pattern = (
            #     r'(?P<version>[\dxX]+(?:[.-]\s*[\dxX]+)\s*)'  # Version with digits/x and separators
            # )
            # matched = re.search(pattern, version_str, re.IGNORECASE)
            # return extract_version(matched), f'{group_name} group'



    pattern = (
        r'(?:v|version)?\s*'  # Optional 'v' or 'version'
        r'(?P<version>[\dxX]+(?:[.-]\s*[\dxX]+)*)'  # Version with digits/x and separators
    )
    matched = re.search(pattern, version_str, re.IGNORECASE)
    return [extract_version(matched)], 'other'

def parse_version(version_str):
    components = re.findall(r'\d+|x', version_str, re.IGNORECASE)
    parsed = []
    for c in components:
        if c.lower() == 'x':
            parsed.append('x')
        else:
            parsed.append(int(c))
    return parsed

def generate_versions(versions, group_name, debug=False):
    if group_name == 'other':
        result = [versions[0]]
        version_other = parse_version(versions[0])
        while len(version_other) != 3:
            if len(version_other) > 3:
                result.append('.'.join([str(x) for x in version_other]))
                version_other.pop()
            elif len(version_other) < 3:
                result.append('.'.join([str(x) for x in version_other]))
                version_other.append(0)
        else:
            result.append('.'.join([str(x) for x in version_other]))
        # print(f'result: {result}')
        # print(f'other versions: {other_versions}')
        # result_merged = result + other_versions
        # print(f'joined: {result_merged}')
        return result
        # return versions
    group_type = group_name.split()[0].lower()

    if len(versions) == 1:
        if group_type == 'before':
            return generate_versions(['0.0.0', versions[0]], 'before multi-match', debug=debug)
        elif group_type == 'through':
            return generate_versions(['0.0.0', versions[0]], 'through multi-match', debug=debug)
        # here access DB and query max version?
        elif group_type == 'after':
            return generate_versions([versions[0], '20.0.0'], 'after multi-match', debug=debug)
        else:
            return []
    elif len(versions) >= 1:
        # for ['3.x', '3.1.1']
        # 3.x
        start = parse_version(versions[0])
        len_original_start = len(start)
        # 3.1.1
        end = parse_version(versions[1])
        len_original_end = len(end)
        # normalize versions
        while len(start) != 3:
            if len(start) > 3:
                start.pop()
            elif len(start) < 3:
                start.append(0)

        while len(end) != 3:
            if len(end) > 3:
                end.pop()
            elif len(end) < 3:
                end.append(0)

        possible_values = []
        if debug:
            print(f'start version: {start}, end version: {end}')
            print(f'len_original_end: {len_original_end}')
        for i in range(3):
            # print(f'possible values: {possible_values}')
            # 3
            start_comp = start[i]
            # 3
            end_comp = end[i]
            if debug:
                print(f'Start component: {start_comp}, End component: {end_comp}')

            if start_comp == 'x':
                # Надо как-то проверять, нужно ли генерировать такик большие числа версий
                if 'before' in group_type:
                    max_val = end_comp - 1 if isinstance(end_comp, int) else 99
                else:
                    max_val = end_comp if isinstance(end_comp, int) else 99
                possible_values.append(list(range(0, max_val + 1)))

                continue
            if isinstance(start_comp, int):
                if isinstance(end_comp, str) and end_comp.lower() == 'x':
                    end_comp = 99  # High maximum for 'x' in end
                if start_comp > end_comp:
                    return []
                if start_comp < end_comp:
                    if 'before' in group_type:
                        current_max = end_comp - 1
                    else:
                        current_max = end_comp
                    # possible_values.append(list(range(start_comp, current_max + 1)))
                    possible_values.append(list(range(start_comp, 10)))

                    # Allow any values for remaining components
                    for j in range(i + 1, 3):
                        possible_values.append(list(range(0, 100)))  # Arbitrary high limit
                    break
                else:
                    possible_values.append([start_comp])
            else:
                # print(f'possible values: {possible_values}')
                possible_values.append([0])


        if debug:
            print(f'possible values: {possible_values}')
        if 'x' not in end and 'x' not in start:
            generated_components = list(product(*possible_values))
            if debug:
                print(f'generated components: {generated_components[:10]}')
            generated_components_to_use = []
            for val in generated_components:
                if not (((val[0] == end[0]
                        and val[1] > end[1]) or
                        (val[0] == end[0]
                        and val[1] == end[1]
                        and val[2] > end[2]) or
                        val[0] > end[0])
                    or ((val[0] == start[0]
                         and val[1] < start[1]) or
                        (val[0] == start[0]
                         and val[1] == start[1]
                         and val[2] < start[2])) or
                        val[0] < start[0]):
                    generated_components_to_use.append(val)
            if debug:
                print(f'generated components to use: {generated_components_to_use[:10], generated_components_to_use[-10:]}')
            versions_list = ['.'.join(map(str, v)) for v in generated_components_to_use]

            # return versions_list
        else:
            generated_components = list(product(*possible_values))
            versions_list = ['.'.join(map(str, v)) for v in generated_components]
        if len_original_end == 2 or len_original_start == 2:
            versions_set = []
            for x in versions_list:
                versions_set.append(x.split('.')[:2])
            versions_set = set(['.'.join(y) for y in versions_set])
            # for x in versions_list:
            versions_list.extend(list(versions_set))
        if debug:
            print(versions_list[:10])
        return versions_list
    else:
        # print('last else')
        return []
    
def get_lcs(ner_name, unique_entities, debug=False):
    if ner_name in unique_entities:
        return ner_name, 1
    lcs_scores = np.array(pylcs.lcs_of_list(ner_name, unique_entities))
    if len(np.argwhere(lcs_scores == np.max(lcs_scores))) <= 1:
        return unique_entities[np.argmax(lcs_scores)], np.max(lcs_scores)
    else:
        candidates = unique_entities[np.argwhere(lcs_scores == np.max(lcs_scores))]
        len_of_query = len(ner_name)
        d = -1
        fit_cand = ''
        for cand in candidates:
            cand = cand[0]
            diff = abs(len_of_query - len(cand))
            # print(cand, d, diff)
            if d == -1:
                d = diff
                fit_cand = cand
            elif d > diff:
                d = diff
                fit_cand = cand
            else:
                continue
        return fit_cand, np.max(lcs_scores)

def lcs_mini(ner_name, unique_entities, top_k=5):
    # print(unique_entities)
    lcs_scores = np.array(pylcs.lcs_of_list(ner_name, unique_entities))
    l = [(name, round(score/len(name), 4)) for name, score in zip(unique_entities, lcs_scores)]
    ll = sorted(l, key=lambda x: x[1], reverse=True)[:top_k]

    return list(zip(*ll))[0]