
import logging
import json
import sys

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "file": record.filename,
            "line": record.lineno,
        }
        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logging(level=logging.INFO, json_format=False):
    """
    Sets up centralized logging for the application.
    :param level: Logging level (e.g., logging.INFO, logging.DEBUG).
    :param json_format: If True, use JSON formatter; otherwise, use a standard formatter.
    """
    # Clear existing handlers to prevent duplicate logs
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    for handler in logging.getLogger().handlers[:]:
        logging.getLogger().removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)

    logging.basicConfig(level=level, handlers=[handler])
    logging.getLogger("uvicorn").handlers = [] # Prevent uvicorn from adding its own handlers
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.error").handlers = []

