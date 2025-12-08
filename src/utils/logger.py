from loguru import logger
import sys
import os

# Create logs directory if it doesn't exist
log_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(log_dir, exist_ok=True)

# Configure logger
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO"
)
logger.add(
    os.path.join(log_dir, "app.log"),
    rotation="10 MB",
    retention="10 days",
    compression="zip",
    level="DEBUG",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
)

# Example usage
if __name__ == "__main__":
    logger.info("Logger is configured and ready to use.")
    logger.debug("This is a debug message.")
    logger.error("This is an error message.")