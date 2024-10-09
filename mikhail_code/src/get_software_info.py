import subprocess
import re
import csv
import psycopg2 as p2
from psycopg2 import sql 
from typing import List

import logging
from src.utils.logger import main_logger
logger = main_logger()


class InfoGetter:
    def __init__(self) -> None:
        self.dbname = "vulns_scanner"
        self.user = 'postgres'
        self.password = 'postgres'
        self.host = 'localhost'
        self.port = '5432'

    def terminal_command(self, command:str, splitter=True) -> List:
        '''Pass command to get string with packages'''
        do = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        bstring_result = do.communicate()[0]
        if splitter:
            splitted_results = str(bstring_result).strip('b').strip("'").split("\\n")
            return splitted_results
        elif splitter == False:
            return str(bstring_result)

    def write_to_csv(self, processed_packages: list, schema, csv_file_name='csv_file.csv'):
        with open(csv_file_name, 'w+') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(schema)
            for package in processed_packages:
                writer.writerow(package)
        logger.info(f'Done writing to {csv_file_name}')
        return
    
    def execute_sql(self, sql_query):
        conn = p2.connect(dbname=self.dbname, user=self.user, 
                          password=self.password, host=self.host, port=self.port)
        cur = conn.cursor()
        cur.execute(sql_query)
        conn.commit()
        conn.close()
        logger.info('Done with executing sql query')
        return
    
    def write_to_db(self, packages_list, table_name, schema, args_number=3):

        conn = p2.connect(dbname=self.dbname, user=self.user, 
                          password=self.password, host=self.host, port=self.port)
        cur = conn.cursor()
        for package in packages_list:
            insert_mask = "%s,"*args_number
            cur.execute(f'''insert into {table_name}({schema})
                            values (''' + insert_mask.rstrip(",") + ")", package)
            conn.commit()
        conn.close()
        return
    
    def process_dpkg(self, list_with_packages, verbose=False):
        '''Iterate over string, get packages, versions and architectures'''
        pluses = []
        processed_list_with_packages = []
        for app in list_with_packages:
            # print(app)
            try:
                package, version, architecture = app.split("---")
            except ValueError:
                continue
            # How versioning works: https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
            if ':' in version:
                epoch = version.split(':')[0]
                version =  version.split(':')[1]
            if '-' in version:
                debian_revision = version.split('-')[1]
                version = version.split('-')[0]
                # Будем ли как-то бороться с этим?
            if '+' in version:
                # print(version)
                if verbose:
                    logger.debug('Plus is here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                matched_plus_thing = re.findall('(\+.*)', version)
                if matched_plus_thing:
                    if matched_plus_thing[0] not in pluses:
                        pluses.append(matched_plus_thing[0])
                version = re.findall('(.*)\+.*', version)[0]
            if verbose:
                logger.info(package, version, architecture)
                logger.info('*'*30)
            processed_list_with_packages.append((package, version, architecture))
        return processed_list_with_packages
    
    #### Добавить доп инф-ю через apt show
    def process_apt(self, list_with_packages, verbose=False):
        pluses = []
        processed_list_with_packages = []
        for app in list_with_packages:
            try:
                splitted_app = app.split(" ")
            except ValueError:
                continue
            if len(splitted_app) >= 3:
                package, version, architecture = splitted_app[0], splitted_app[1], splitted_app[2]
            else:
                continue
            if '/' in package:
                splitted_package = package.split("/")
                # print(splitted_package)
                package = ''.join(splitted_package[:-1])
            if ':' in version:
                epoch = version.split(':')[0]
                version =  version.split(':')[1]
            if '-' in version:
                debian_revision = version.split('-')[1]
                version = version.split('-')[0]
                # Будем ли как-то бороться с этим?
            if '+' in version:
                # print(version)
                if verbose:
                    logger.debug('Plus is here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                matched_plus_thing = re.findall('(\+.*)', version)
                if matched_plus_thing:
                    if matched_plus_thing[0] not in pluses:
                        pluses.append(matched_plus_thing[0])
                version = re.findall('(.*)\+.*', version)[0]
            if verbose:
                logger.info(package, version, architecture)
                logger.info('*'*30)
            processed_list_with_packages.append((package, version, architecture))
            # print('*'*30)
        return processed_list_with_packages
    
    def process_snap(self, list_with_packages, verbose=False):
        '''
        Example:
            python3 get_software_info.py
            acestreamplayer            3.1.74-snap2                15     latest/stable    vasilisc            -

        '''
        # -> ['acestreamplayer', '3.1.74-snap2', '15', 'latest/stable', 'vasilisc', '-']
        # первая строчка -- названия столбцов
        list_with_packages = [[x for x in pack.split(' ') if x != ''] for pack in list_with_packages[1:]]
        pluses = []
        processed_list_with_packages = []
        for app in list_with_packages:
            try:
                package, version, publisher = app[0], app[1], app[4]
            except IndexError:
                continue
            if ':' in version:
                epoch = version.split(':')[0]
                version =  version.split(':')[1]
            if '-' in version:
                debian_revision = version.split('-')[1]
                version = version.split('-')[0]
                # Будем ли как-то бороться с этим?
            if '+' or '~' in version:
                # print(version)
                if verbose:
                    logger.debug('Plus is here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                matched_plus_thing = re.findall('([\+|\~].*)', version)
                if matched_plus_thing:
                    if matched_plus_thing[0] not in pluses:
                        pluses.append(matched_plus_thing[0])
                version = re.findall('(.*)[\+|\~].*', version)[0]
            publisher = publisher.strip('**').strip('*')
            if verbose:
                logger.info(package, version, publisher)
                logger.info('*'*30)
            processed_list_with_packages.append((package, version, publisher))       
        return processed_list_with_packages
    
    def process_hardware(self, string_with_info:str, verbose=False):
        if verbose: 
            logger.debug(string_with_info)
        hardware_product = re.findall(r'\*-cpu\\n\s+product:\s(.*?)\\n', string_with_info)[0]
        # if 'amd' in hardware_product.lower():
        #     amd_flag = 1
        # vendor_product = re.findall(r'\*-cpu.*?vendor:\s(.*?)\\n', string_with_info)[0]
        hardware_product = [x.lower() for x in hardware_product.split(' ') if x]
        vendor, product = hardware_product[0], '_'.join(hardware_product[1:4])
        return vendor, product
                    # , vendor_product
    
    def process_os_version(self, string_with_info:str, verbose=False):
        if verbose: 
            print(string_with_info)  
        name = re.findall(r'\\nNAME=(.*?)\\n', string_with_info)[0].lower()   
        version_id = re.findall(r'\\nVERSION_ID=(.*?)\\n', string_with_info)[0]
        full_version = re.findall(r'\\nVERSION=(.*?)\\n', string_with_info)[0].lower()
        if 'lts' in full_version:
            lts_flag = 1
        else:
            lts_flag = 0
        return name.strip("'").strip('"'), version_id.strip("'").strip('"'), lts_flag

info_getter = InfoGetter()

# dpkg
# dpkg = "dpkg-query -W -f='${Package}---${Version}---${Architecture}\n'"
# l = info_getter.terminal_command(dpkg)
# packs = info_getter.process_dpkg(l, verbose=True)
# info_getter.write_to_csv(packs, ['package', 'version', 'architecture'])
# info_getter.execute_sql('''
                # create table if not exists
                #         dpkg_packages(
                #             dpkg_package_id serial not null primary key,
                #             package text,
                #             version text, 
                #             architecture text
                #         )
#             ''')
# info_getter.write_to_db('dpkg_packages', "package, version, architecture", packs)

# # apt
# apt = "apt list"
# l = info_getter.terminal_command(apt)
# # print(l)
# packs = info_getter.process_apt(l, verbose=False)
# info_getter.write_to_csv(packs, ['package', 'version', 'architecture'])
# info_getter.execute_sql('''
#                 create table if not exists
#                         apt_packages(
#                             apt_package_id serial not null primary key,
#                             package text,
#                             version text, 
#                             architecture text
#                         )
#             ''')
# info_getter.write_to_db('apt_packages', "package, version, architecture", packs)

# snap
# snap = "snap list"
# l = info_getter.terminal_command(snap)
# packs = info_getter.process_snap(l)
# info_getter.execute_sql('''
#     create table if not exists
#             snap_packages(
#                 snap_package_id serial not null primary key,
#                 package text,
#                 version text, 
#                 publisher text
#             )
# ''')
# info_getter.write_to_db('snap_packages', "package, version, publisher", packs)

# # hardware
hardw = 'lshw'
s = info_getter.terminal_command(hardw,splitter=False)
hw_version = info_getter.process_hardware(s)
info_getter.execute_sql('''
                create table if not exists
                        hw_info (
                            hw_info_id serial not null primary key,
                            vendor text,
                            product text
                        )
            ''')
# print(os_product, os_version)
info_getter.write_to_db([hw_version], 'hw_info', "vendor, product", args_number=2)

# # os version
# os_v = 'cat /etc/os-release'
# s = info_getter.terminal_command(os_v, splitter=False)
# version_info = info_getter.process_os_version(s)
# info_getter.execute_sql('''
                # create table if not exists
                #         os_info (
                #             os_info_id serial not null primary key,
                #             product text,
                #             version text
                #         )
#             ''')
# os_product = version_info[0]
# if version_info[2] == 1:
#     os_product += '_linux'
# os_version = version_info[1]
# # print(os_product, os_version)
# info_getter.write_to_db([[os_product, os_version]], 'os_info', "product, version", args_number=2)