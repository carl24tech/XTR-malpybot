
__version__ = "1.0.0"
__author__ = "XTR Softwares"
__license__ = "MIT"

from .scanner.engine import ScanEngine
from .models.threat import Threat, ThreatLevel
from .utils.logger import setup_logger

logger = setup_logger("xtr_scanner")
