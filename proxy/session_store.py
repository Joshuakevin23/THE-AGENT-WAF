from collections import deque
import time
from typing import Dict, Set, Optional

class SessionState:
    def __init__(self, session_id: str):
        self.session_id: str = session_id
        self.allowed_tools: Set[str] = set()
        self.last_allowed_call_time: Optional[float] = None
        self.declared_scope: str = "project_x_"

class SessionStore:
    def __init__(self):
        # Maps session_id -> SessionState
        self.sessions: Dict[str, SessionState] = {}
        # Maps (agent_id, tool_name) -> deque of call timestamps (floats)
        self.rate_limit_history: Dict[tuple[str, str], deque] = {}

    def get_session(self, session_id: str) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id)
        return self.sessions[session_id]

    def record_allowed_call(self, session_id: str, tool_name: str, current_time: float) -> None:
        session = self.get_session(session_id)
        session.allowed_tools.add(tool_name)
        session.last_allowed_call_time = current_time

    def get_rate_limit_history(self, agent_id: str, tool_name: str) -> deque:
        key = (agent_id, tool_name)
        if key not in self.rate_limit_history:
            self.rate_limit_history[key] = deque()
        return self.rate_limit_history[key]

    def record_call_timestamp(self, agent_id: str, tool_name: str, timestamp: float) -> None:
        history = self.get_rate_limit_history(agent_id, tool_name)
        history.append(timestamp)

    def clear(self) -> None:
        self.sessions.clear()
        self.rate_limit_history.clear()

# Singleton instance
session_store = SessionStore()
