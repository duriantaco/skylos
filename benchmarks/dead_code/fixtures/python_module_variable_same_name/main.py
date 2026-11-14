import by_attribute
from shared import logger as shared_logger
from starred import *

logger.info("bound by the star import")
shared_logger.info("imported by name")
by_attribute.logger.info("module attribute")
