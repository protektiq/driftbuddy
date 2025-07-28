"""
ML and Analytics API endpoints for DriftBuddy
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .auth import get_current_active_user, require_admin
from .database import get_db
from .models import (
    MLModel, MLPrediction, SecurityInsight, RiskScore, AnomalyDetection,
    TrendAnalysis, PredictiveAlert, AnalyticsEvent, User,
    MLModelCreate, MLModelResponse, MLPredictionCreate, MLPredictionResponse,
    SecurityInsightCreate, SecurityInsightResponse, RiskScoreCreate, RiskScoreResponse,
    AnomalyDetectionResponse, TrendAnalysisResponse, PredictiveAlertCreate,
    PredictiveAlertResponse, AnalyticsDashboardResponse
)
from .ml_analytics_service import MLAnalyticsService

router = APIRouter(prefix="/api/analytics", tags=["Analytics & ML"])
ml_service = MLAnalyticsService()


@router.get("/models", response_model=List[MLModelResponse])
async def get_ml_models(
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all ML models"""
    try:
        models = ml_service.get_models(db, active_only)
        return models
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get models: {str(e)}")


@router.post("/models", response_model=MLModelResponse)
async def create_ml_model(
    model_data: MLModelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new ML model"""
    try:
        model = MLModel(
            name=model_data.name,
            model_type=model_data.model_type,
            version=model_data.version,
            description=model_data.description,
            model_metadata=model_data.model_metadata
        )
        db.add(model)
        db.commit()
        db.refresh(model)
        return model
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create model: {str(e)}")


@router.post("/predictions", response_model=MLPredictionResponse)
async def create_prediction(
    prediction_data: MLPredictionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new ML prediction"""
    try:
        prediction = ml_service.create_prediction(db, prediction_data.dict())
        
        # Get model name for response
        model = db.query(MLModel).filter(MLModel.id == prediction.model_id).first()
        model_name = model.name if model else "Unknown Model"
        
        # Create response with model name
        response_data = prediction.__dict__.copy()
        response_data["model_name"] = model_name
        
        return MLPredictionResponse(**response_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create prediction: {str(e)}")


@router.get("/predictions", response_model=List[MLPredictionResponse])
async def get_predictions(
    model_id: Optional[int] = None,
    prediction_type: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get ML predictions"""
    try:
        query = db.query(MLPrediction)
        
        if model_id:
            query = query.filter(MLPrediction.model_id == model_id)
        if prediction_type:
            query = query.filter(MLPrediction.prediction_type == prediction_type)
            
        predictions = query.order_by(MLPrediction.created_at.desc()).limit(limit).all()
        
        # Add model names to responses
        responses = []
        for pred in predictions:
            model = db.query(MLModel).filter(MLModel.id == pred.model_id).first()
            model_name = model.name if model else "Unknown Model"
            
            response_data = pred.__dict__.copy()
            response_data["model_name"] = model_name
            responses.append(MLPredictionResponse(**response_data))
            
        return responses
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get predictions: {str(e)}")


@router.post("/risk-scores", response_model=RiskScoreResponse)
async def calculate_risk_score(
    risk_data: RiskScoreCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Calculate risk score for an entity"""
    try:
        risk_score = ml_service.calculate_risk_score(
            db, 
            risk_data.entity_type, 
            risk_data.entity_id, 
            risk_data.calculation_method
        )
        return risk_score
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate risk score: {str(e)}")


@router.get("/risk-scores", response_model=List[RiskScoreResponse])
async def get_risk_scores(
    entity_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get risk scores"""
    try:
        query = db.query(RiskScore)
        
        if entity_type:
            query = query.filter(RiskScore.entity_type == entity_type)
        if risk_level:
            query = query.filter(RiskScore.risk_level == risk_level)
            
        risk_scores = query.order_by(RiskScore.last_calculated.desc()).limit(limit).all()
        return risk_scores
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get risk scores: {str(e)}")


@router.post("/anomalies/detect")
async def detect_anomaly(
    entity_type: str,
    entity_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Detect anomalies for an entity"""
    try:
        anomaly = ml_service.detect_anomalies(db, entity_type, entity_id)
        return AnomalyDetectionResponse(**anomaly.__dict__)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to detect anomaly: {str(e)}")


@router.get("/anomalies", response_model=List[AnomalyDetectionResponse])
async def get_anomalies(
    entity_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get anomaly detections"""
    try:
        query = db.query(AnomalyDetection)
        
        if entity_type:
            query = query.filter(AnomalyDetection.entity_type == entity_type)
        if severity:
            query = query.filter(AnomalyDetection.severity == severity)
            
        anomalies = query.order_by(AnomalyDetection.created_at.desc()).limit(limit).all()
        return anomalies
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get anomalies: {str(e)}")


@router.post("/insights", response_model=SecurityInsightResponse)
async def create_security_insight(
    insight_data: SecurityInsightCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a security insight"""
    try:
        insight = ml_service.generate_security_insight(db, insight_data.dict())
        return insight
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create insight: {str(e)}")


@router.get("/insights", response_model=List[SecurityInsightResponse])
async def get_security_insights(
    insight_type: Optional[str] = None,
    severity: Optional[str] = None,
    actionable_only: bool = False,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get security insights"""
    try:
        query = db.query(SecurityInsight)
        
        if insight_type:
            query = query.filter(SecurityInsight.insight_type == insight_type)
        if severity:
            query = query.filter(SecurityInsight.severity == severity)
        if actionable_only:
            query = query.filter(SecurityInsight.is_actionable == True)
            
        insights = query.order_by(SecurityInsight.created_at.desc()).limit(limit).all()
        return insights
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get insights: {str(e)}")


@router.put("/insights/{insight_id}/action")
async def mark_insight_actioned(
    insight_id: int,
    action_notes: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Mark an insight as actioned"""
    try:
        insight = db.query(SecurityInsight).filter(SecurityInsight.id == insight_id).first()
        if not insight:
            raise HTTPException(status_code=404, detail="Insight not found")
            
        insight.action_taken = True
        insight.action_notes = action_notes
        
        db.commit()
        db.refresh(insight)
        
        return {"message": "Insight marked as actioned", "insight": SecurityInsightResponse(**insight.__dict__)}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update insight: {str(e)}")


@router.post("/trends/analyze", response_model=TrendAnalysisResponse)
async def analyze_trend(
    trend_type: str,
    time_period: str = "monthly",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Analyze trends for security metrics"""
    try:
        trend = ml_service.analyze_trends(db, trend_type, time_period)
        return trend
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze trend: {str(e)}")


@router.get("/trends", response_model=List[TrendAnalysisResponse])
async def get_trend_analyses(
    trend_type: Optional[str] = None,
    time_period: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get trend analyses"""
    try:
        query = db.query(TrendAnalysis)
        
        if trend_type:
            query = query.filter(TrendAnalysis.trend_type == trend_type)
        if time_period:
            query = query.filter(TrendAnalysis.time_period == time_period)
            
        trends = query.order_by(TrendAnalysis.created_at.desc()).limit(limit).all()
        return trends
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get trends: {str(e)}")


@router.post("/alerts", response_model=PredictiveAlertResponse)
async def create_predictive_alert(
    alert_data: PredictiveAlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a predictive alert"""
    try:
        alert = ml_service.create_predictive_alert(db, alert_data.dict())
        return alert
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create alert: {str(e)}")


@router.get("/alerts", response_model=List[PredictiveAlertResponse])
async def get_predictive_alerts(
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    active_only: bool = True,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get predictive alerts"""
    try:
        query = db.query(PredictiveAlert)
        
        if alert_type:
            query = query.filter(PredictiveAlert.alert_type == alert_type)
        if severity:
            query = query.filter(PredictiveAlert.severity == severity)
        if active_only:
            query = query.filter(PredictiveAlert.is_active == True)
            
        alerts = query.order_by(PredictiveAlert.created_at.desc()).limit(limit).all()
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")


@router.put("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Acknowledge a predictive alert"""
    try:
        alert = db.query(PredictiveAlert).filter(PredictiveAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        alert.acknowledged_by = current_user.id
        alert.acknowledged_at = datetime.utcnow()
        
        db.commit()
        db.refresh(alert)
        
        return {"message": "Alert acknowledged", "alert": PredictiveAlertResponse(**alert.__dict__)}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to acknowledge alert: {str(e)}")


@router.get("/dashboard", response_model=AnalyticsDashboardResponse)
async def get_analytics_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get analytics dashboard data"""
    try:
        dashboard_data = ml_service.get_analytics_dashboard(db, current_user)
        return AnalyticsDashboardResponse(**dashboard_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")


@router.post("/events/track")
async def track_analytics_event(
    event_type: str,
    event_category: str,
    event_data: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Track an analytics event"""
    try:
        event = ml_service.track_analytics_event(
            db, current_user, event_type, event_category, event_data
        )
        return {"message": "Event tracked successfully", "event_id": event.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to track event: {str(e)}")


@router.get("/events", response_model=List[Dict[str, Any]])
async def get_analytics_events(
    event_type: Optional[str] = None,
    event_category: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get analytics events"""
    try:
        query = db.query(AnalyticsEvent)
        
        if event_type:
            query = query.filter(AnalyticsEvent.event_type == event_type)
        if event_category:
            query = query.filter(AnalyticsEvent.event_category == event_category)
            
        events = query.order_by(AnalyticsEvent.created_at.desc()).limit(limit).all()
        
        # Convert to dict for response
        event_list = []
        for event in events:
            event_dict = {
                "id": event.id,
                "event_type": event.event_type,
                "event_category": event.event_category,
                "event_data": event.event_data,
                "created_at": event.created_at
            }
            event_list.append(event_dict)
            
        return event_list
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get events: {str(e)}")


@router.post("/setup-defaults")
async def setup_default_ml_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Set up default ML models"""
    try:
        ml_service.create_default_models(db)
        return {"message": "Default ML models created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to setup defaults: {str(e)}")


@router.post("/predictions/batch")
async def create_batch_predictions(
    predictions: List[MLPredictionCreate],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create multiple predictions in batch"""
    try:
        results = []
        for pred_data in predictions:
            prediction = ml_service.create_prediction(db, pred_data.dict())
            
            # Get model name
            model = db.query(MLModel).filter(MLModel.id == prediction.model_id).first()
            model_name = model.name if model else "Unknown Model"
            
            response_data = prediction.__dict__.copy()
            response_data["model_name"] = model_name
            results.append(MLPredictionResponse(**response_data))
            
        return {"message": f"Created {len(results)} predictions", "predictions": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create batch predictions: {str(e)}")


@router.post("/risk-scores/batch")
async def calculate_batch_risk_scores(
    risk_scores: List[RiskScoreCreate],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Calculate multiple risk scores in batch"""
    try:
        results = []
        for risk_data in risk_scores:
            risk_score = ml_service.calculate_risk_score(
                db, 
                risk_data.entity_type, 
                risk_data.entity_id, 
                risk_data.calculation_method
            )
            results.append(risk_score)
            
        return {"message": f"Calculated {len(results)} risk scores", "risk_scores": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate batch risk scores: {str(e)}")


@router.get("/models/{model_id}/performance")
async def get_model_performance(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get performance metrics for a specific model"""
    try:
        model = db.query(MLModel).filter(MLModel.id == model_id).first()
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
            
        # Get recent predictions for this model
        predictions = db.query(MLPrediction).filter(
            MLPrediction.model_id == model_id
        ).order_by(MLPrediction.created_at.desc()).limit(100).all()
        
        # Calculate performance metrics
        total_predictions = len(predictions)
        avg_confidence = sum(p.confidence_score or 0 for p in predictions) / max(total_predictions, 1)
        avg_prediction_value = sum(p.prediction_value for p in predictions) / max(total_predictions, 1)
        
        performance_data = {
            "model_id": model_id,
            "model_name": model.name,
            "accuracy": model.accuracy,
            "total_predictions": total_predictions,
            "average_confidence": round(avg_confidence, 3),
            "average_prediction_value": round(avg_prediction_value, 3),
            "last_trained": model.last_trained,
            "recent_predictions": [
                {
                    "id": p.id,
                    "prediction_type": p.prediction_type,
                    "prediction_value": p.prediction_value,
                    "confidence_score": p.confidence_score,
                    "created_at": p.created_at
                }
                for p in predictions[:10]  # Last 10 predictions
            ]
        }
        
        return performance_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get model performance: {str(e)}") 