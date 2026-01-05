"""
Base module class for security components
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime
from .config import Config
from .logger import SecurityLogger


class BaseModule(ABC):
    """Abstract base class for all security modules"""

    def __init__(self, name: str):
        self.name = name
        self.config = Config()
        self.logger = SecurityLogger(name)
        self.results: List[Dict[str, Any]] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    @abstractmethod
    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the module's main functionality"""
        pass

    @abstractmethod
    def get_info(self) -> Dict[str, str]:
        """Return module information"""
        pass

    def start(self):
        """Mark module execution start"""
        self.start_time = datetime.utcnow()
        self.results = []
        self.logger.info(f"Module '{self.name}' started")

    def finish(self):
        """Mark module execution end"""
        self.end_time = datetime.utcnow()
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time else 0
        self.logger.info(f"Module '{self.name}' finished in {duration:.2f}s")

    def add_result(self, result: Dict[str, Any]):
        """Add a result to the module's result list"""
        result['timestamp'] = datetime.utcnow().isoformat()
        result['module'] = self.name
        self.results.append(result)

    def get_results(self) -> List[Dict[str, Any]]:
        """Return all results"""
        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Return execution summary"""
        return {
            "module": self.name,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0,
            "results_count": len(self.results),
            "results": self.results
        }
