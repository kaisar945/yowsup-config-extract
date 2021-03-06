import logging

__version__ = "1.0.2"
__author__ = "Kaisar Zu"

logger = logging.getLogger(__name__)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(levelname).1s %(asctime)s %(name)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)
