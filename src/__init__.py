"""Core modules for the cloud-native network security monitoring project."""

from .collector import CloudWatchLogCollector
from .parser import EventParser, parse_event, parse_flow_log
from .detector import ThreatDetector
from .risk_scorer import RiskScorer
from .database import SecurityDatabase

__all__ = [
    "CloudWatchLogCollector",
    "EventParser",
    "parse_event",
    "parse_flow_log",
    "ThreatDetector",
    "RiskScorer",
    "SecurityDatabase",
]
