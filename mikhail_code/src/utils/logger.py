import logging

def main_logger():
    logger = logging.getLogger("main_logger")
    logger.setLevel("DEBUG")
    formatter = logging.Formatter("{name} - {asctime} - {levelname} - {message}", 
                                style = "{", 
                                datefmt = "%Y-%m-%d %H:%M:%S")

    console_handler = logging.StreamHandler()
    console_handler.setLevel('INFO')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(f"logs/main_logger.log", mode='a', encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger