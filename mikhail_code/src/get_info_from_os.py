from src.infogetter import InfoGetter

import logging
from src.utils.logger import main_logger
logger = main_logger()


# initialize
info_getter = InfoGetter()

# dpkg
dpkg = "dpkg-query -W -f='${Package}---${Version}---${Architecture}\n'"
l = info_getter.terminal_command(dpkg)
packs = info_getter.process_dpkg(l, verbose=False)
# print(packs[:30])
info_getter.write_to_csv(packs, ['package', 'version', 'architecture'])
info_getter.execute_sql('''
                create table if not exists
                        dpkg_packages(
                            dpkg_package_id serial not null primary key,
                            package text,
                            version text, 
                            architecture text
                        )
            ''')
info_getter.write_to_db(packs, 'dpkg_packages', "package, version, architecture")
info_getter.print_command_execution()

# apt
apt = "apt list"
l = info_getter.terminal_command(apt)
# print(l)
packs = info_getter.process_apt(l, verbose=False)
info_getter.write_to_csv(packs, ['package', 'version', 'architecture'])
info_getter.execute_sql('''
                create table if not exists
                        apt_packages(
                            apt_package_id serial not null primary key,
                            package text,
                            version text, 
                            architecture text
                        )
            ''')
info_getter.write_to_db(packs, 'apt_packages', "package, version, architecture")
info_getter.print_command_execution()

# snap
snap = "snap list"
l = info_getter.terminal_command(snap)
packs = info_getter.process_snap(l)
info_getter.execute_sql('''
    create table if not exists
            snap_packages(
                snap_package_id serial not null primary key,
                package text,
                version text, 
                publisher text
            )
''')
info_getter.write_to_db(packs, 'snap_packages', "package, version, publisher")
info_getter.print_command_execution()


# hardware
hardw = 'lshw'
s = info_getter.terminal_command(hardw, splitter=False)
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
info_getter.print_command_execution()

# os version
os_v = 'cat /etc/os-release'
s = info_getter.terminal_command(os_v, splitter=False)
version_info = info_getter.process_os_version(s)
info_getter.execute_sql('''
                create table if not exists
                        os_info (
                            os_info_id serial not null primary key,
                            product text,
                            version text
                        )
            ''')
os_product = version_info[0]
if version_info[2] == 1:
    os_product += '_linux'
os_version = version_info[1]
# print(os_product, os_version)
info_getter.write_to_db([[os_product, os_version]], 'os_info', "product, version", args_number=2)
info_getter.print_command_execution()
