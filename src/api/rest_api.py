"""
FastAPI REST API for SentinelAI
Provides endpoints for alert management, incident response, and system control
"""

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio
import json
from datetime import datetime

from ..core.database import DatabaseManager
from ..core.logger import logger
from ..core.utils import normalize_alert, generate_alert_id
from ..detection import network_analyzer, endpoint_analyzer
from ..defense import response_engine
from ..prediction import risk_forecaster


# Database
db = DatabaseManager()

# FastAPI app
app = FastAPI(
    title="SentinelAI API",
    description="Unified Threat Defense & Detection System API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models
class AlertRequest(BaseModel):
    type: str
    severity: str
    confidence: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    description: str
    metadata: Dict[str, Any] = {}


class IncidentRequest(BaseModel):
    title: str
    description: str
    severity: str
    affected_assets: List[str] = []


class DefenseActionRequest(BaseModel):
    alert_id: str
    action_type: str
    target: str


# Routes

@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """System health check"""
    stats = db.get_statistics()
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "statistics": stats
    }


@app.get("/alerts")
async def get_alerts(status: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    """Retrieve alerts"""
    try:
        alerts = db.get_alerts(status=status, limit=limit)
        return {
            "success": True,
            "count": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        logger.log_error("API.get_alerts", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/alerts")
async def create_alert(alert: AlertRequest) -> Dict[str, Any]:
    """Create a new alert"""
    try:
        alert_data = alert.dict()
        alert_id = db.add_alert(alert_data)
        
        logger.log_detection({
            "id": alert_id,
            **alert_data
        })
        
        return {
            "success": True,
            "alert_id": alert_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.log_error("API.create_alert", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/alerts/{alert_id}")
async def update_alert(alert_id: str, status: str) -> Dict[str, Any]:
    """Update alert status"""
    try:
        db.update_alert_status(alert_id, status)
        return {
            "success": True,
            "alert_id": alert_id,
            "status": status
        }
    except Exception as e:
        logger.log_error("API.update_alert", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents")
async def get_incidents(limit: int = 50) -> Dict[str, Any]:
    """Retrieve incidents"""
    try:
        # For demo, return empty list - would query database in production
        return {
            "success": True,
            "count": 0,
            "incidents": []
        }
    except Exception as e:
        logger.log_error("API.get_incidents", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/incidents")
async def create_incident(incident: IncidentRequest) -> Dict[str, Any]:
    """Create incident"""
    try:
        incident_id = db.add_incident(incident.dict())
        return {
            "success": True,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.log_error("API.create_incident", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/defense/evaluate")
async def evaluate_threat(alert_data: AlertRequest) -> Dict[str, Any]:
    """Evaluate threat and get recommendations"""
    try:
        alert_dict = alert_data.dict()
        alert_dict['id'] = generate_alert_id()
        
        evaluation = response_engine.evaluate_threat(alert_dict)
        
        return {
            "success": True,
            "evaluation": evaluation
        }
    except Exception as e:
        logger.log_error("API.evaluate_threat", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/defense/execute")
async def execute_defense(action_plan: Dict[str, Any]) -> Dict[str, Any]:
    """Execute defense action plan"""
    try:
        result = response_engine.execute_defense_action(action_plan)
        return {
            "success": True,
            "result": result
        }
    except Exception as e:
        logger.log_error("API.execute_defense", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/prediction/risk/{asset_id}")
async def get_risk_forecast(asset_id: str, hours: int = 24) -> Dict[str, Any]:
    """Get risk forecast for asset"""
    try:
        forecast = risk_forecaster.forecast_attack_probability(asset_id, time_window_hours=hours)
        return {
            "success": True,
            "forecast": forecast
        }
    except Exception as e:
        logger.log_error("API.get_risk_forecast", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/prediction/vulnerable-assets")
async def predict_vulnerable_assets(assets: List[Dict]) -> Dict[str, Any]:
    """Predict vulnerable assets"""
    try:
        predictions = risk_forecaster.predict_vulnerable_assets(assets)
        return {
            "success": True,
            "predictions": predictions
        }
    except Exception as e:
        logger.log_error("API.predict_vulnerable_assets", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/statistics")
async def get_statistics() -> Dict[str, Any]:
    """Get system statistics"""
    try:
        stats = db.get_statistics()
        return {
            "success": True,
            "statistics": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.log_error("API.get_statistics", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status")
async def get_system_status() -> Dict[str, Any]:
    """Get system status"""
    return {
        "status": "operational",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "modules": {
            "detection": "active",
            "defense": "active",
            "prediction": "active",
            "database": "active"
        }
    }


# WebSocket for real-time alerts
connected_clients = []

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket for real-time alert streaming"""
    await websocket.accept()
    connected_clients.append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            # Echo data to all connected clients
            for client in connected_clients:
                try:
                    await client.send_text(data)
                except:
                    pass
    except Exception as e:
        logger.log_error("WebSocket.alerts", e)
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


async def broadcast_alert(alert_data: Dict):
    """Broadcast alert to all connected WebSocket clients"""
    message = json.dumps(alert_data)
    for client in connected_clients:
        try:
            await client.send_text(message)
        except:
            if client in connected_clients:
                connected_clients.remove(client)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, workers=4)
