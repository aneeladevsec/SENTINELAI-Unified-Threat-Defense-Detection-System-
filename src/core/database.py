"""
Core database module for SentinelAI
Handles all database operations including alerts, incidents, and forensics
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from pathlib import Path

Base = declarative_base()

class Alert(Base):
    """Alert ORM Model"""
    __tablename__ = "alerts"
    
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_type = Column(String)
    severity = Column(String)
    confidence = Column(Float)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    description = Column(Text)
    alert_metadata = Column(JSON)
    status = Column(String, default="open")
    
class Incident(Base):
    """Incident ORM Model"""
    __tablename__ = "incidents"
    
    id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    status = Column(String, default="open")
    affected_assets = Column(JSON)
    root_cause = Column(Text, nullable=True)
    resolution = Column(Text, nullable=True)
    closed_at = Column(DateTime, nullable=True)

class DefenseAction(Base):
    """Defense Action ORM Model"""
    __tablename__ = "defense_actions"
    
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_id = Column(String)
    action_type = Column(String)
    target = Column(String)
    status = Column(String, default="pending")
    result = Column(Text, nullable=True)
    executed_at = Column(DateTime, nullable=True)

class SystemEvent(Base):
    """System Event ORM Model"""
    __tablename__ = "system_events"
    
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String)
    source = Column(String)
    details = Column(JSON)


class DatabaseManager:
    """Database management class"""
    
    def __init__(self, db_path: str = "data/sentinelai.db"):
        self.db_path = db_path
        self.engine = None
        self.SessionLocal = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database connection"""
        db_url = f"sqlite:///{self.db_path}"
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def get_session(self) -> Session:
        """Get database session"""
        return self.SessionLocal()
    
    def add_alert(self, alert_data: Dict[str, Any]) -> str:
        """Add a new alert to database"""
        session = self.get_session()
        try:
            alert_id = f"alert_{datetime.utcnow().timestamp()}"
            alert = Alert(
                id=alert_id,
                timestamp=datetime.utcnow(),
                alert_type=alert_data.get("alert_type"),
                severity=alert_data.get("severity"),
                confidence=alert_data.get("confidence", 0.0),
                source_ip=alert_data.get("source_ip"),
                destination_ip=alert_data.get("destination_ip"),
                description=alert_data.get("description"),
                alert_metadata=alert_data.get("metadata", {}),
                status="open"
            )
            session.add(alert)
            session.commit()
            return alert_id
        finally:
            session.close()
    
    def get_alerts(self, status: str = None, limit: int = 100) -> List[Dict]:
        """Retrieve alerts from database"""
        session = self.get_session()
        try:
            query = session.query(Alert)
            if status:
                query = query.filter(Alert.status == status)
            alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
            
            result = []
            for alert in alerts:
                result.append({
                    "id": alert.id,
                    "timestamp": alert.timestamp.isoformat(),
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "description": alert.description,
                    "metadata": alert.alert_metadata,
                    "status": alert.status
                })
            return result
        finally:
            session.close()
    
    def update_alert_status(self, alert_id: str, status: str):
        """Update alert status"""
        session = self.get_session()
        try:
            alert = session.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.status = status
                session.commit()
        finally:
            session.close()
    
    def add_incident(self, incident_data: Dict[str, Any]) -> str:
        """Add a new incident"""
        session = self.get_session()
        try:
            incident_id = f"incident_{datetime.utcnow().timestamp()}"
            incident = Incident(
                id=incident_id,
                created_at=datetime.utcnow(),
                title=incident_data.get("title"),
                description=incident_data.get("description"),
                severity=incident_data.get("severity"),
                status="open",
                affected_assets=incident_data.get("affected_assets", [])
            )
            session.add(incident)
            session.commit()
            return incident_id
        finally:
            session.close()
    
    def add_defense_action(self, action_data: Dict[str, Any]) -> str:
        """Log a defense action"""
        session = self.get_session()
        try:
            action_id = f"action_{datetime.utcnow().timestamp()}"
            action = DefenseAction(
                id=action_id,
                timestamp=datetime.utcnow(),
                alert_id=action_data.get("alert_id"),
                action_type=action_data.get("action_type"),
                target=action_data.get("target"),
                status="pending"
            )
            session.add(action)
            session.commit()
            return action_id
        finally:
            session.close()
    
    def update_defense_action(self, action_id: str, status: str, result: str = None):
        """Update defense action status"""
        session = self.get_session()
        try:
            action = session.query(DefenseAction).filter(DefenseAction.id == action_id).first()
            if action:
                action.status = status
                action.result = result
                action.executed_at = datetime.utcnow()
                session.commit()
        finally:
            session.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        session = self.get_session()
        try:
            total_alerts = session.query(Alert).count()
            open_alerts = session.query(Alert).filter(Alert.status == "open").count()
            critical_alerts = session.query(Alert).filter(Alert.severity == "critical").count()
            total_incidents = session.query(Incident).count()
            open_incidents = session.query(Incident).filter(Incident.status == "open").count()
            
            return {
                "total_alerts": total_alerts,
                "open_alerts": open_alerts,
                "critical_alerts": critical_alerts,
                "total_incidents": total_incidents,
                "open_incidents": open_incidents
            }
        finally:
            session.close()
