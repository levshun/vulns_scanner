import subprocess

import logging
from src.utils.logger import main_logger
logger = main_logger()

command = '''apt list'''
do = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
logger.info(do.communicate()[0][:30])

