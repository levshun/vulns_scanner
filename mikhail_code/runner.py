import sys
import os

import logging
from src.utils.logger import main_logger
logger = main_logger()

from src.run_parser import run_parser

print(os.getcwd())

def run():
    run_parser()

if __name__ == '__main__':
    run()