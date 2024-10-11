import json
import string
import itertools
# import pandas as pd
import time
import csv
import os
import pickle

import logging
from src.utils.logger import main_logger
logger = main_logger()


def get_non_empty_cpe_from_right(cpe23uri_to_search):
    '''
    Trims all '*' (empty attributes) from right side of CPE
    cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:* -> cpe:2.3:h:eq-3:homematic_ccu2
    '''
    splitted_cpe = cpe23uri_to_search.lstrip("cpe:2.3:").split(":")
    for i in range(len(splitted_cpe)-1, 0, -1):
        if splitted_cpe[i] != "*":
            minimal_non_empty_from_right_cpe = ":".join(["cpe:2.3"] + splitted_cpe[:i+1])
            break
    return minimal_non_empty_from_right_cpe




def check_versions_cpe(cpe, 
                       versionStartIncluding=False, versionEndIncluding=False,
                       versionStartExcluding=False, versionEndExcluding=False,
                       ):
    '''
    Compares CPEs from CPE JSON feed with CPEs from CVE JSON feed 
    '''
    # Если нет условий для сравнения по версиям и минимально совпадает начало CPE до версии    
    # (а оно совпадает, если дошло до этой функции), то все CPE подходят
    
    if versionStartIncluding == False and versionEndIncluding == False and \
                         versionStartExcluding == False and versionEndExcluding == False:
        return True   

    if versionStartIncluding and versionStartExcluding:
        logger.info("Both versionStarted are present. Weird!")
    if versionEndIncluding and versionEndExcluding:
        logger.info("Both versionEnd are present. Weird!")
    
    # Removes letters from version like in https://nvd.nist.gov/vuln/detail/CVE-2022-24844#match-9944199. 
    # Probably should not be done???
    # ...2.5.0b:*:*:*:*:*:*:*
    letters_and_chars = string.ascii_letters + "-,(){}[]"
    cpe_version = cpe.lstrip("cpe:2.3").split(":")[3]
    # If CPE contains "-"  in version, meaning it matches all versions...
    # Example - cpe:2.3:a:postgresql:postgresql:-:*:*:*:*:*:*:*
    # ...or '*'. Example, cpe:2.3:a:amazon:log4jhotpatch:*:*:*:*:*:*:*:* (CVE-2022-0070)
    if cpe_version == "-" or cpe_version == "*":
        return True
    # print(cpe_version)
    
    # Unusual versions to delete manually
    for chars in ['\(aala.3\)c0', '\(aalb.3\)c0', '\(aaly.3\)c0', '\(aaky.3\)c0', '\(aakz.3\)c0'
                  , '_\(929\)', '_\(1360\)', 'udraw']:
        if chars in cpe_version:
            cpe_version = cpe_version.replace(chars, '')
    # print(cpe_version)
    for char in cpe_version:
        if char in letters_and_chars:
            cpe_version = cpe_version.replace(char, '')

    if versionStartIncluding:
        for chars in ['-h', 'a', 'b', '\(aala.3\)c', '-']:
            # print(chars, vers)
            if chars in versionStartIncluding:
                versionStartIncluding = versionStartIncluding.replace(chars, ".")
    if versionStartExcluding:
        for chars in ['-h', 'a', 'b', '\(aala.3\)c', '-']:
            if chars in versionStartExcluding:
                versionStartExcluding = versionStartExcluding.replace(chars, ".")
    if versionEndIncluding:
        for chars in ['-h', 'a', 'b', '\(aala.3\)c', '-']:
            if chars in versionEndIncluding:
                versionEndIncluding = versionEndIncluding.replace(chars, ".")
    if versionEndExcluding:
        for chars in ['-h', 'a', 'b', '\(aala.3\)c', '-']:
            if chars in versionEndExcluding:
                versionEndExcluding = versionEndExcluding.replace(chars, ".")

    # add trailing zeros to cpe version
    cpe_version = cpe_version.rstrip(".").lstrip(".")
    while len(cpe_version.split(".")) < 7:
        cpe_version = cpe_version + ".0"
    # Split version to list of ints to compare 2 CPEs number by number
    # cpe1 = [1, 0, 3]
    # cpe2 = [1, 0, 4]
    # Compare 1 == 1 -> 0 == 0 -> 3 < 4 ----> cpe1 < cpe2
    try:
        cpe_version = list(map(int, cpe_version.split(".")))
    except:
        logger.error(f'Error while converting version to list of ints for CPE {cpe}')
        return False

    #  Do above-mentioned operations for all version operatots (start, end, including, excluding)
    if versionStartIncluding:
        versionStartIncluding = versionStartIncluding.rstrip(".")
        while len(versionStartIncluding.split(".")) < 7:
            versionStartIncluding = versionStartIncluding + ".0"
        try:
            versionStartIncluding = list(map(int, versionStartIncluding.split(".")))
        except:
            versionStartIncluding = False
            logger.error(f'Error while converting versionStartIncluding {versionStartIncluding} value\
                  from CPE {cpe}. So versionStartIncluding was set to False')    
    if versionEndIncluding:
        versionEndIncluding = versionEndIncluding.rstrip(".")
        while len(versionEndIncluding.split(".")) < 7:
            versionEndIncluding = versionEndIncluding + ".0"
        try:
            versionEndIncluding = list(map(int, versionEndIncluding.split(".")))
        except:
            versionEndIncluding = False
            logger.error(f'Error while converting versionEndIncluding {versionEndIncluding} value\
                  from CPE {cpe}. So versionEndIncluding was set to False')
    if versionStartExcluding:
        versionStartExcluding = versionStartExcluding.rstrip(".")
        while len(versionStartExcluding.split(".")) < 7:
            versionStartExcluding = versionStartExcluding + ".0"
        try:
            versionStartExcluding = list(map(int, versionStartExcluding.split(".")))
        except:
            versionStartExcluding = False
            logger.error(f'Error while converting versionStartExcluding {versionStartExcluding} value\
                  from CPE {cpe}. So versionStartExcluding was set to False')
    if versionEndExcluding:
        versionEndExcluding = versionEndExcluding.rstrip(".")
        while len(versionEndExcluding.split(".")) < 7:
            versionEndExcluding = versionEndExcluding + ".0"
    # print(versionEndExcluding)
        try:
            versionEndExcluding = list(map(int, versionEndExcluding.split(".")))
        except:
            versionEndExcluding = False
            logger.error(f'Error while converting versionEndExcluding {versionEndExcluding} value\
                  from CPE {cpe}. So versionEndExcluding was set to False')

    start_flag = 0
    end_flag = 0

    # Add zeros to right side to be able to compare up to 7-digit versions
    # Example - compare 1.2.2.2.2.1`.0`(added 0) with 1.2.2.2.2.1.`2``
    # strictly higher
    if versionStartExcluding:
        if (cpe_version[0] > versionStartExcluding[0]):
            start_flag = 1
        elif (cpe_version[0] == versionStartExcluding[0]):
            if (cpe_version[1] > versionStartExcluding[1]):
                start_flag = 1
            elif (cpe_version[1] == versionStartExcluding[1]):
                if (cpe_version[2] > versionStartExcluding[2]):
                    start_flag = 1
                elif (cpe_version[2] == versionStartExcluding[2]):
                    if (cpe_version[3] > versionStartExcluding[3]):
                        start_flag = 1
                    elif (cpe_version[3] == versionStartExcluding[3]):
                        if (cpe_version[4] > versionStartExcluding[4]):
                            start_flag = 1
                        elif (cpe_version[4] == versionStartExcluding[4]):
                            if (cpe_version[5] > versionStartExcluding[5]):
                                start_flag = 1
                            elif (cpe_version[5] == versionStartExcluding[5]):
                                if (cpe_version[6] > versionStartExcluding[6]):
                                    start_flag = 1
    if versionEndIncluding == False and versionEndExcluding == False:
        end_flag = 1
    # equal or higher
    if versionStartIncluding:
        if (cpe_version[0] > versionStartIncluding[0]):
            start_flag = 1
        elif (cpe_version[0] == versionStartIncluding[0]):
            if (cpe_version[1] > versionStartIncluding[1]):
                start_flag = 1
            elif (cpe_version[1] == versionStartIncluding[1]):
                if (cpe_version[2] > versionStartIncluding[2]):
                    start_flag = 1
                elif (cpe_version[2] == versionStartIncluding[2]):
                    if (cpe_version[3] > versionStartIncluding[3]):
                        start_flag = 1
                    elif (cpe_version[3] == versionStartIncluding[3]):
                        if (cpe_version[4] > versionStartIncluding[4]):
                            start_flag = 1
                        elif (cpe_version[4] == versionStartIncluding[4]):
                            if (cpe_version[5] > versionStartIncluding[5]):
                                start_flag = 1
                            elif (cpe_version[5] == versionStartIncluding[5]):
                                if (cpe_version[6] >= versionStartIncluding[6]):
                                    start_flag = 1
    if versionEndIncluding == False and versionEndExcluding == False:
        end_flag = 1

    if versionEndExcluding:
    # strictly lower
        if (cpe_version[0] < versionEndExcluding[0]):
            end_flag = 1
        elif (cpe_version[0] == versionEndExcluding[0]):
            if (cpe_version[1] < versionEndExcluding[1]):
                end_flag = 1
            elif (cpe_version[1] == versionEndExcluding[1]):
                if (cpe_version[2] < versionEndExcluding[2]):
                    end_flag = 1
                elif (cpe_version[2] == versionEndExcluding[2]):
                    if (cpe_version[3] < versionEndExcluding[3]):
                        end_flag = 1
                    elif (cpe_version[3] == versionEndExcluding[3]):
                        if (cpe_version[4] < versionEndExcluding[4]):
                            end_flag = 1
                        elif (cpe_version[4] == versionEndExcluding[4]):
                            if (cpe_version[5] < versionEndExcluding[5]):
                                end_flag = 1
                            elif (cpe_version[5] == versionEndExcluding[5]):
                                if (cpe_version[6] < versionEndExcluding[6]):
                                    end_flag = 1
                    # print(versionStartExcluding, versionStartIncluding)
        if versionStartIncluding == False and versionStartExcluding == False:
            start_flag = 1
    # equal or higher
    elif versionEndIncluding:
        if (cpe_version[0] < versionEndIncluding[0]):
            end_flag = 1
        elif (cpe_version[0] == versionEndIncluding[0]):
            if (cpe_version[1] < versionEndIncluding[1]):
                end_flag = 1
            elif (cpe_version[1] == versionEndIncluding[1]):
                if (cpe_version[2] <= versionEndIncluding[2]):
                    end_flag = 1
                elif (cpe_version[2] == versionEndIncluding[2]):
                    if (cpe_version[3] < versionEndIncluding[3]):
                        end_flag = 1
                    elif (cpe_version[3] == versionEndIncluding[3]):
                        if (cpe_version[4] < versionEndIncluding[4]):
                            end_flag = 1
                        elif (cpe_version[4] == versionEndIncluding[4]):
                            if (cpe_version[5] < versionEndIncluding[5]):
                                end_flag = 1
                            elif (cpe_version[5] == versionEndIncluding[5]):
                                if (cpe_version[6] <= versionEndIncluding[6]):
                                    end_flag = 1
                    # print(versionStartExcluding, versionStartIncluding)
        if versionStartIncluding == False and versionStartExcluding == False:
            start_flag = 1

    return start_flag==1 and end_flag==1




def search_in_cpe_feed(dict_from_cpe_feed, cpe23uri_to_search: str,
                       versionStartIncluding=False, versionEndIncluding=False,
                        versionStartExcluding=False, versionEndExcluding=False):
    '''
    Receives CPE23Uri, trims to the first non-empty category from the right side 
    and looks for it in CPE JSON feed
    '''
    try:
        splitted_cpe = cpe23uri_to_search.lstrip("cpe:2.3:").split(":") 
    except AttributeError as e:
        # logger.debug(f'Error for cpe23uri_to_search -- {cpe23uri_to_search}. Error -- {e}')
        return None
    
    for i in range(len(splitted_cpe)-1, 0, -1):
        if splitted_cpe[i] != "*":
            minimal_non_empty_from_right_cpe = ":".join(["cpe:2.3"] + splitted_cpe[:i+1])
            break
    try:
        available_cpes = dict_from_cpe_feed[minimal_non_empty_from_right_cpe]  
    except:
        # logger.debug(f'UnboundLocalError for cpe23uri_to_search -- {cpe23uri_to_search}. Error -- {e}')
        return None
    found_cpes = []
    # # !!!!!!!!!!!!!!!!!! slow approach!!!!!!!!cpe23uri_to_search!!!!!!!!!!
    # for cpe in cpe_json['matches']:
    #     if minimal_non_empty_from_right_cpe in 
    # cpe['cpe23Uri']:
    # # !!!!!!!!!!!!!!!!!! slow approach !!!!!!!!!!!!!!!!!!
    # available_cpes = df_from_cpe_feed[df_from_cpe_feed.minimal_cpe == minimal_non_empty_from_right_cpe].cpe_names.tolist()[0]

    for cpe in available_cpes:
        # print(cpe)
        if cpe not in found_cpes \
            and check_versions_cpe(cpe, versionStartIncluding, 
                                    versionEndIncluding, versionStartExcluding, versionEndExcluding):
            found_cpes.append(cpe)            
        else:
            logger.debug(f"No CPES found in CPE json feed for cpe23uri {cpe23uri_to_search}. Weird!") 
    # print(f"Elapsed inside search_in_cpe: {time.time() - t1}")
    return found_cpes




def parse_feed(config: json, old_counter: int, dict_from_cpe_feed):
    '''
    Parses JSON feed.
    Returns (['cve', 'cpe', 'config_id'], counter_id)
    '''
    cve_name = config['cve']['CVE_data_meta']['ID']
    config_nodes = config['configurations']['nodes']
    len_nodes = len(config_nodes)

    counter = old_counter
    cve_cpe_match = []
    for i in range(len_nodes):
        # Basic Configuration
        if config_nodes[i]['operator'] == "OR":
            for cpe_match_i in config_nodes[i]['cpe_match']:
                # t1 = time.time()
                # print(cpe_match_i)
                # print(type(cpe_match_i))
                cpe23Uri = cpe_match_i['cpe23Uri']
                # check for conditions in versions
                # cpe_match_keys = config_nodes[i]['cpe_match'].keys()
                versionStartIncluding = cpe_match_i.get('versionStartIncluding', 0)
                versionEndIncluding = cpe_match_i.get('versionEndIncluding', 0)
                versionStartExcluding = cpe_match_i.get('versionStartExcluding', 0)
                versionEndExcluding = cpe_match_i.get('versionEndExcluding', 0)
                # if 'versionStartIncluding' in cpe_match_keys or 'versionEndIncluding' in cpe_match_keys:
                    # versionStartIncluding = config_nodes[i]['cpe_match']
                # t2 = time.time()
                matched_cpes_from_feed = search_in_cpe_feed(dict_from_cpe_feed, cpe23Uri, versionStartIncluding, 
                                               versionEndIncluding, versionStartExcluding, versionEndExcluding)
                # t3 = time.time()
                if matched_cpes_from_feed:
                    for _, cpe_i in enumerate(matched_cpes_from_feed):
                        cve_cpe_match.append([cve_name, cpe_i, counter])
                        counter += 1
                
                # print(f"Elapsed inside search_in_cpe t4-t3: {time.time() - t3}")
                # print(f"Elapsed inside search_in_cpe t3-t2: {t3 - t2}")
                # print(f"Elapsed inside search_in_cpe t2-t1: {t2 - t1}")
                # print("*"*50)

        elif config_nodes[i]['operator'] == "AND":
            len_children_and_operator = len(config_nodes[i]['children'])
            # Advanced configuration
            if len_children_and_operator == 0:
                # print("That is advanced configuration")
                len_cpe_match = len(config_nodes[i]['cpe_match'])
                cpe_uri23_list = [[] for _ in range(len_cpe_match)]
                for cpe_match_i, cpe_match in enumerate(config_nodes[i]['cpe_match']):
                    versionStartIncluding = cpe_match.get('versionStartIncluding', 0)
                    versionEndIncluding = cpe_match.get('versionEndIncluding', 0)
                    versionStartExcluding = cpe_match.get('versionStartExcluding', 0)
                    versionEndExcluding = cpe_match.get('versionEndExcluding', 0)
                    cpe23Uri = cpe_match['cpe23Uri']
                    matched_cpes_from_feed = search_in_cpe_feed(cpe23Uri, versionStartIncluding, 
                                versionEndIncluding, versionStartExcluding, versionEndExcluding)
                    if matched_cpes_from_feed:
                        cpe_uri23_list[cpe_match_i].extend(matched_cpes_from_feed)
                # [[1, 2], [3, 4], [5, 6]] -> [(1, 3, 5), (1, 3, 6),...]
                all_combinations_cpe_uri23_list = itertools.product(*cpe_uri23_list)
                for combination in all_combinations_cpe_uri23_list:
                    for cpe_inside_combination in combination:
                        cve_cpe_match.append([cve_name, cpe_inside_combination, counter])
                    counter += 1
                

            #  Running On\With Configuration
            else:
                if len_children_and_operator > 2:
                    print("Length of Running On\With more than 2   ", config_nodes)
                
                # CPE c On\With vulnerable: True частью
                cpe_vuln_true_list = []
                # CPE c On\With vulnerable: False частью
                cpe_vuln_false_list = []

                for node_child_i, nodes_child in enumerate(config_nodes[i]['children']):
                    # Непоследний потомок внутри Running On\With конфига
                    if nodes_child['operator'] == "OR" and (node_child_i+1) != len_children_and_operator:
                        for cpe_match_i in nodes_child['cpe_match']:
                            versionStartIncluding = cpe_match_i.get('versionStartIncluding', 0)
                            versionEndIncluding = cpe_match_i.get('versionEndIncluding', 0)
                            versionStartExcluding = cpe_match_i.get('versionStartExcluding', 0)
                            versionEndExcluding = cpe_match_i.get('versionEndExcluding', 0)
                            cpe23Uri = cpe_match_i['cpe23Uri']
                            # if 'versionStartIncluding' in cpe_match_keys or 'versionEndIncluding' in cpe_match_keys:
                                # versionStartIncluding = config_nodes[i]['cpe_match']
                            matched_cpes_from_feed = search_in_cpe_feed(cpe23Uri, versionStartIncluding, 
                                                        versionEndIncluding, versionStartExcluding, versionEndExcluding)
                            if matched_cpes_from_feed:
                                cpe_vuln_true_list.extend(matched_cpes_from_feed)

                    # Последний потомок внутри Running On\With конфига зарезервирован
                    # за On\With vulnerable: False частью
                    elif nodes_child['operator'] == "OR" and (node_child_i+1) == len_children_and_operator:
                        for cpe_match_i in nodes_child['cpe_match']:
                            versionStartIncluding = cpe_match_i.get('versionStartIncluding', 0)
                            versionEndIncluding = cpe_match_i.get('versionEndIncluding', 0)
                            versionStartExcluding = cpe_match_i.get('versionStartExcluding', 0)
                            versionEndExcluding = cpe_match_i.get('versionEndExcluding', 0)
                            cpe23Uri = cpe_match_i['cpe23Uri']
                            matched_cpes_from_feed = search_in_cpe_feed(cpe23Uri, versionStartIncluding, 
                                                        versionEndIncluding, versionStartExcluding, versionEndExcluding)
                            if matched_cpes_from_feed:
                                cpe_vuln_false_list.extend(matched_cpes_from_feed)
                
                # print(f"True list: {cpe_vuln_true_list}\nFalse list:{cpe_vuln_false_list}")
                for true_elem in cpe_vuln_true_list:
                    for false_elem in cpe_vuln_false_list:
                        cve_cpe_match.append([cve_name, true_elem, counter])
                        cve_cpe_match.append([cve_name, false_elem, counter])
                        counter += 1

    # return config
    return cve_cpe_match, counter



