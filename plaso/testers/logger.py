import logging

def log_decorator(func):
    logger = logging.getLogger(func.__name__)

    logger.info("Starting parsing")
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return result

    return wrapper

