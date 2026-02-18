import logging
import sys

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    # Redirect uvicorn logs to the root logger to use our format
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        log = logging.getLogger(logger_name)
        log.handlers = logging.root.handlers
        log.propagate = False
