import subprocess
import re
import csv
import psycopg2 as p2
from psycopg2 import sql 

class InfoGetter:
    def __init__(self) -> None:
        self.dbname = "vulns_scanner"
        self.user = 'postgres'
        self.password = 'postgres'
        self.host = 'localhost'
        self.port = '5432'
        self.terminal_command_used = None
        # colors for terminal output printing
        self.OKBLUE = '\033[94m'
        self.OKGREEN = '\033[92m'
        self.FAIL = '\033[91m'
        self.ENDC = '\033[0m'
        self.HEADER = '\033[95m'

    def terminal_command(self, command:str, splitter=True) -> list:
        '''Pass command to get string with packages'''
        # warnings are supressed!
        self.terminal_command_used = command
        do = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        bstring_result = do.communicate()[0]
        if splitter:
            splitted_results = str(bstring_result).strip('b').strip("'").split("\\n")
            return splitted_results
        elif splitter == False:
            return str(bstring_result)
    
    def print_command_execution(self):
        if self.terminal_command_used:
            print(f'Terminal command {self.OKBLUE}{self.terminal_command_used}{self.ENDC} is executed', end='\n'+'*'*50+'\n')
        else:
            print('No terminal command was provided', end='\n'+'*'*50+'\n')

    def write_to_csv(self, processed_packages: list, schema, csv_file_name='csv_file.csv'):
        with open(csv_file_name, 'w+') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(schema)
            for package in processed_packages:
                writer.writerow(package)
        print(f'Done writing to {csv_file_name}')
        return
    
    def execute_sql(self, sql_query):
        conn = p2.connect(dbname=self.dbname, user=self.user, 
                          password=self.password, host=self.host, port=self.port)
        cur = conn.cursor()
        cur.execute(sql_query)
        conn.commit()
        conn.close()
        print('Done with executing sql query')
        return
    
    def write_to_db(self, packages_list, table_name, schema, args_number=3):

        conn = p2.connect(dbname=self.dbname, user=self.user, 
                          password=self.password, host=self.host, port=self.port)
        cur = conn.cursor()
        for package in packages_list:
            # print(package)
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
                    print('Plus is here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                matched_plus_thing = re.findall('(\+.*)', version)
                if matched_plus_thing:
                    if matched_plus_thing[0] not in pluses:
                        pluses.append(matched_plus_thing[0])
            version = re.findall('(.*?)(?=\+|[A-z]+|\~|$)', version)[0]
            if verbose:
                print(package, version, architecture)
                print('*'*30)
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
                    print('Plus is here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                matched_plus_thing = re.findall('(\+.*)', version)
                if matched_plus_thing:
                    if matched_plus_thing[0] not in pluses:
                        pluses.append(matched_plus_thing[0])
                version = re.findall('(.*?)(?=\+|[A-z]+|\~|$)', version)[0]
            if verbose:
                print(package, version, architecture)
                print('*'*30)
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
                    print('Plus is here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                matched_plus_thing = re.findall('([\+|\~].*)', version)
                if matched_plus_thing:
                    if matched_plus_thing[0] not in pluses:
                        pluses.append(matched_plus_thing[0])
                # print(version)
                if '~' in version or '+' in version:
                    version = re.findall('(.*)[\+|\~].*', version)[0]
            publisher = publisher.strip('**').strip('*')
            if verbose:
                print(package, version, publisher)
                print('*'*30)
            processed_list_with_packages.append((package, version, publisher))       
        return processed_list_with_packages
    
    def process_hardware(self, string_with_info:str, verbose=False):
        if verbose: 
            print(string_with_info)
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

