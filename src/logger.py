import logging
import os
from datetime import datetime

# Just the filename, without 'logs/' prefix
LOG_FILE = f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# Full path: logs folder + filename
LOGS_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_FILE_PATH = os.path.join(LOGS_DIR, LOG_FILE)

logging.basicConfig(
    filename=LOG_FILE_PATH,
    format='[%(asctime)s] %(lineno)d %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    encoding='utf-8'  # Add encoding for file handler
)

# Get logger
logger = logging.getLogger(__name__)

# Replace emojis with text in your log messages
logger.info("[TOOL] Applied SAFE numpy division protection")
logger.info("[SEARCH] Looking for agents in directory") 
logger.info("[FOLDER] Files in agents directory: ...")