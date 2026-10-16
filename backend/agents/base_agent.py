import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """Abstract Base Class for all specialized review and security agents."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"agent.{name.replace(' ', '_').lower()}")

    @abstractmethod
    def run(self, **kwargs) -> Any:
        """Executes the agent logic."""
        pass

    def execute_with_telemetry(self, **kwargs) -> Dict[str, Any]:
        """Runs the agent and tracks execution time and status."""
        self.logger.info(f"Starting {self.name}...")
        start_time = time.perf_counter()
        try:
            result = self.run(**kwargs)
            duration = round(time.perf_counter() - start_time, 4)
            self.logger.info(f"Finished {self.name} in {duration}s")
            return {
                "success": True,
                "agent": self.name,
                "duration_seconds": duration,
                "result": result,
            }
        except Exception as e:
            duration = round(time.perf_counter() - start_time, 4)
            self.logger.error(f"Error in {self.name}: {e}", exc_info=True)
            return {
                "success": False,
                "agent": self.name,
                "duration_seconds": duration,
                "error": str(e),
                "result": None,
            }
