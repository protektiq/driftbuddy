"""
ML and Analytics Service for DriftBuddy
Handles machine learning models, predictions, risk scoring, and analytics
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc

from .models import (
    MLModel,
    MLPrediction,
    MLTrainingData,
    SecurityInsight,
    RiskScore,
    AnomalyDetection,
    AnalyticsEvent,
    TrendAnalysis,
    PredictiveAlert,
    Finding,
    Scan,
    ComplianceAssessment,
    User,
)


class MLAnalyticsService:
    """Service for ML models and analytics"""

    def __init__(self):
        self.default_models = {
            "vulnerability_risk_predictor": {
                "name": "Vulnerability Risk Predictor",
                "model_type": "vulnerability_prediction",
                "version": "1.0.0",
                "description": "Predicts vulnerability risk based on historical data",
                "features": ["severity", "age", "exploit_count", "patch_status", "asset_criticality"]
            },
            "risk_scoring_model": {
                "name": "Risk Scoring Model",
                "model_type": "risk_scoring",
                "version": "1.0.0",
                "description": "Calculates risk scores for findings and assets",
                "features": ["vulnerability_count", "severity_distribution", "compliance_status", "asset_value"]
            },
            "anomaly_detector": {
                "name": "Anomaly Detection Model",
                "model_type": "anomaly_detection",
                "version": "1.0.0",
                "description": "Detects anomalies in security patterns",
                "features": ["scan_frequency", "finding_patterns", "user_behavior", "system_metrics"]
            },
            "compliance_gap_predictor": {
                "name": "Compliance Gap Predictor",
                "model_type": "compliance_prediction",
                "version": "1.0.0",
                "description": "Predicts compliance gaps and risks",
                "features": ["control_status", "assessment_history", "industry_benchmarks", "regulatory_changes"]
            }
        }

    def create_default_models(self, db: Session) -> None:
        """Create default ML models"""
        try:
            for model_key, model_data in self.default_models.items():
                # Check if model already exists
                existing_model = db.query(MLModel).filter(
                    MLModel.name == model_data["name"]
                ).first()
                
                if existing_model:
                    continue
                
                # Create model
                model = MLModel(
                    name=model_data["name"],
                    model_type=model_data["model_type"],
                    version=model_data["version"],
                    description=model_data["description"],
                    model_metadata={
                        "features": model_data["features"],
                        "algorithm": "random_forest",
                        "hyperparameters": {
                            "n_estimators": 100,
                            "max_depth": 10,
                            "random_state": 42
                        }
                    },
                    accuracy=0.85,  # Default accuracy
                    last_trained=datetime.utcnow()
                )
                db.add(model)
                
            db.commit()
            print(f"✅ Created {len(self.default_models)} default ML models")
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to create default models: {str(e)}")
            raise

    def get_models(self, db: Session, active_only: bool = True) -> List[MLModel]:
        """Get all ML models"""
        query = db.query(MLModel)
        if active_only:
            query = query.filter(MLModel.is_active == True)
        return query.all()

    def create_prediction(self, db: Session, prediction_data: Dict[str, Any]) -> MLPrediction:
        """Create a new ML prediction"""
        try:
            # Simulate ML prediction (in production, this would call actual ML models)
            prediction_value = self._simulate_prediction(prediction_data)
            confidence_score = self._calculate_confidence(prediction_data)
            
            prediction = MLPrediction(
                model_id=prediction_data["model_id"],
                prediction_type=prediction_data["prediction_type"],
                target_id=prediction_data.get("target_id"),
                target_type=prediction_data.get("target_type"),
                prediction_value=prediction_value,
                confidence_score=confidence_score,
                prediction_data=prediction_data.get("prediction_data", {}),
                prediction_result={
                    "predicted_value": prediction_value,
                    "confidence": confidence_score,
                    "factors": self._extract_factors(prediction_data),
                    "recommendations": self._generate_recommendations(prediction_value, prediction_data)
                }
            )
            db.add(prediction)
            db.commit()
            db.refresh(prediction)
            
            return prediction
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to create prediction: {str(e)}")
            raise

    def _simulate_prediction(self, prediction_data: Dict[str, Any]) -> float:
        """Simulate ML prediction (replace with actual ML model calls)"""
        # Simple simulation based on input features
        features = prediction_data.get("prediction_data", {})
        
        if prediction_data["prediction_type"] == "vulnerability_risk":
            # Simulate vulnerability risk prediction
            severity_score = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 0.95}
            severity = features.get("severity", "MEDIUM")
            age_factor = min(features.get("age_days", 30) / 365, 1.0)
            exploit_factor = min(features.get("exploit_count", 0) / 10, 1.0)
            
            base_score = severity_score.get(severity, 0.5)
            risk_score = base_score * (0.7 + 0.3 * age_factor + 0.2 * exploit_factor)
            return min(risk_score, 1.0)
            
        elif prediction_data["prediction_type"] == "attack_probability":
            # Simulate attack probability
            vulnerability_count = features.get("vulnerability_count", 0)
            critical_vulns = features.get("critical_vulnerabilities", 0)
            exposure_score = features.get("exposure_score", 0.5)
            
            attack_prob = (vulnerability_count * 0.1 + critical_vulns * 0.3 + exposure_score * 0.4)
            return min(attack_prob, 1.0)
            
        elif prediction_data["prediction_type"] == "compliance_gap":
            # Simulate compliance gap prediction
            control_status = features.get("control_status", "compliant")
            assessment_score = features.get("assessment_score", 0.8)
            industry_benchmark = features.get("industry_benchmark", 0.85)
            
            if control_status == "non_compliant":
                gap_score = 0.8
            elif control_status == "partially_compliant":
                gap_score = 0.4
            else:
                gap_score = 0.1
                
            gap_score += (industry_benchmark - assessment_score) * 0.5
            return min(gap_score, 1.0)
            
        else:
            # Default random prediction
            return np.random.uniform(0.1, 0.9)

    def _calculate_confidence(self, prediction_data: Dict[str, Any]) -> float:
        """Calculate confidence score for prediction"""
        features = prediction_data.get("prediction_data", {})
        
        # Confidence based on data quality and feature completeness
        feature_count = len(features)
        data_quality = min(feature_count / 5, 1.0)  # Assume 5 features is good quality
        
        # Add some randomness for simulation
        confidence = data_quality * 0.8 + np.random.uniform(0, 0.2)
        return min(confidence, 1.0)

    def _extract_factors(self, prediction_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract key factors that influenced the prediction"""
        features = prediction_data.get("prediction_data", {})
        factors = {}
        
        for key, value in features.items():
            if isinstance(value, (int, float)):
                factors[key] = float(value)
            elif isinstance(value, str):
                # Convert string values to numeric factors
                if value.upper() in ["HIGH", "CRITICAL"]:
                    factors[key] = 0.8
                elif value.upper() in ["MEDIUM"]:
                    factors[key] = 0.5
                elif value.upper() in ["LOW"]:
                    factors[key] = 0.2
                else:
                    factors[key] = 0.5
                    
        return factors

    def _generate_recommendations(self, prediction_value: float, prediction_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on prediction"""
        recommendations = []
        
        if prediction_value > 0.8:
            recommendations.append("Immediate action required - high risk detected")
            recommendations.append("Consider implementing additional security controls")
        elif prediction_value > 0.6:
            recommendations.append("Moderate risk - review and address within 30 days")
            recommendations.append("Monitor for changes in risk factors")
        elif prediction_value > 0.4:
            recommendations.append("Low to moderate risk - schedule review")
            recommendations.append("Consider preventive measures")
        else:
            recommendations.append("Low risk - continue monitoring")
            recommendations.append("Maintain current security posture")
            
        return recommendations

    def calculate_risk_score(self, db: Session, entity_type: str, entity_id: int, 
                           calculation_method: str = "hybrid") -> RiskScore:
        """Calculate risk score for an entity"""
        try:
            # Get existing risk score or create new one
            existing_score = db.query(RiskScore).filter(
                RiskScore.entity_type == entity_type,
                RiskScore.entity_id == entity_id
            ).first()
            
            # Calculate risk factors based on entity type
            factors = self._calculate_risk_factors(db, entity_type, entity_id)
            risk_score = self._compute_risk_score(factors, calculation_method)
            risk_level = self._determine_risk_level(risk_score)
            
            if existing_score:
                # Update existing score
                existing_score.risk_score = risk_score
                existing_score.risk_level = risk_level
                existing_score.factors = factors
                existing_score.calculation_method = calculation_method
                existing_score.last_calculated = datetime.utcnow()
                score = existing_score
            else:
                # Create new score
                score = RiskScore(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    factors=factors,
                    calculation_method=calculation_method
                )
                db.add(score)
            
            db.commit()
            db.refresh(score)
            return score
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to calculate risk score: {str(e)}")
            raise

    def _calculate_risk_factors(self, db: Session, entity_type: str, entity_id: int) -> Dict[str, float]:
        """Calculate risk factors for an entity"""
        factors = {}
        
        if entity_type == "finding":
            # Risk factors for findings
            finding = db.query(Finding).filter(Finding.id == entity_id).first()
            if finding:
                severity_scores = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 0.95}
                factors["severity"] = severity_scores.get(finding.severity, 0.5)
                factors["age_days"] = (datetime.utcnow() - finding.created_at).days
                factors["risk_score"] = finding.risk_score or 0.5
                factors["business_impact"] = 0.7 if finding.business_impact else 0.3
                
        elif entity_type == "scan":
            # Risk factors for scans
            scan = db.query(Scan).filter(Scan.id == entity_id).first()
            if scan:
                findings = db.query(Finding).filter(Finding.scan_id == entity_id).all()
                factors["total_findings"] = len(findings)
                factors["high_critical_findings"] = len([f for f in findings if f.severity in ["HIGH", "CRITICAL"]])
                factors["scan_age_days"] = (datetime.utcnow() - scan.created_at).days
                factors["completion_rate"] = 1.0 if scan.status == "completed" else 0.5
                
        elif entity_type == "organization":
            # Risk factors for organizations
            scans = db.query(Scan).filter(Scan.organization_id == entity_id).all()
            findings = db.query(Finding).join(Scan).filter(Scan.organization_id == entity_id).all()
            
            factors["total_scans"] = len(scans)
            factors["total_findings"] = len(findings)
            factors["high_critical_findings"] = len([f for f in findings if f.severity in ["HIGH", "CRITICAL"]])
            factors["avg_findings_per_scan"] = len(findings) / max(len(scans), 1)
            
        return factors

    def _compute_risk_score(self, factors: Dict[str, float], method: str) -> float:
        """Compute risk score from factors"""
        if method == "ml_model":
            # Simulate ML-based scoring
            weights = {
                "severity": 0.3,
                "age_days": 0.2,
                "risk_score": 0.25,
                "business_impact": 0.15,
                "total_findings": 0.1,
                "high_critical_findings": 0.3
            }
        else:
            # Rule-based scoring
            weights = {
                "severity": 0.4,
                "age_days": 0.2,
                "risk_score": 0.2,
                "business_impact": 0.1,
                "total_findings": 0.05,
                "high_critical_findings": 0.25
            }
        
        score = 0.0
        total_weight = 0.0
        
        for factor, value in factors.items():
            weight = weights.get(factor, 0.1)
            score += value * weight
            total_weight += weight
            
        if total_weight > 0:
            score = score / total_weight
            
        return min(score, 100.0)

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score"""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"

    def detect_anomalies(self, db: Session, entity_type: str, entity_id: int) -> AnomalyDetection:
        """Detect anomalies for an entity"""
        try:
            # Simulate anomaly detection
            anomaly_score = self._calculate_anomaly_score(db, entity_type, entity_id)
            severity = "high" if anomaly_score > 0.7 else "medium" if anomaly_score > 0.4 else "low"
            
            description = self._generate_anomaly_description(entity_type, anomaly_score)
            
            anomaly = AnomalyDetection(
                anomaly_type=f"{entity_type}_anomaly",
                entity_type=entity_type,
                entity_id=entity_id,
                anomaly_score=anomaly_score,
                severity=severity,
                description=description,
                detection_data={
                    "anomaly_score": anomaly_score,
                    "baseline_threshold": 0.5,
                    "detection_method": "statistical_analysis"
                },
                baseline_data={
                    "mean": 0.3,
                    "std": 0.2,
                    "threshold": 0.5
                }
            )
            db.add(anomaly)
            db.commit()
            db.refresh(anomaly)
            
            return anomaly
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to detect anomaly: {str(e)}")
            raise

    def _calculate_anomaly_score(self, db: Session, entity_type: str, entity_id: int) -> float:
        """Calculate anomaly score for an entity"""
        if entity_type == "scan":
            # Anomaly detection for scans
            scan = db.query(Scan).filter(Scan.id == entity_id).first()
            if scan:
                findings = db.query(Finding).filter(Finding.scan_id == entity_id).all()
                
                # Calculate anomaly factors
                finding_count = len(findings)
                high_critical_count = len([f for f in findings if f.severity in ["HIGH", "CRITICAL"]])
                
                # Compare with historical averages
                avg_findings = 5.0  # Simulated average
                avg_high_critical = 1.0  # Simulated average
                
                finding_anomaly = abs(finding_count - avg_findings) / max(avg_findings, 1)
                severity_anomaly = abs(high_critical_count - avg_high_critical) / max(avg_high_critical, 1)
                
                anomaly_score = (finding_anomaly + severity_anomaly) / 2
                return min(anomaly_score, 1.0)
                
        elif entity_type == "finding":
            # Anomaly detection for findings
            finding = db.query(Finding).filter(Finding.id == entity_id).first()
            if finding:
                # Check for unusual severity patterns
                severity_scores = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 0.95}
                expected_severity = 0.5  # Simulated baseline
                actual_severity = severity_scores.get(finding.severity, 0.5)
                
                anomaly_score = abs(actual_severity - expected_severity)
                return min(anomaly_score, 1.0)
                
        # Default anomaly score
        return np.random.uniform(0.1, 0.8)

    def _generate_anomaly_description(self, entity_type: str, anomaly_score: float) -> str:
        """Generate description for anomaly"""
        if entity_type == "scan":
            if anomaly_score > 0.7:
                return "Unusually high number of findings detected in scan"
            elif anomaly_score > 0.4:
                return "Moderate anomaly detected in scan results"
            else:
                return "Minor anomaly detected in scan patterns"
        elif entity_type == "finding":
            if anomaly_score > 0.7:
                return "Unusual severity pattern detected in finding"
            elif anomaly_score > 0.4:
                return "Moderate anomaly in finding characteristics"
            else:
                return "Minor anomaly in finding pattern"
        else:
            return f"Anomaly detected in {entity_type} with score {anomaly_score:.2f}"

    def generate_security_insight(self, db: Session, insight_data: Dict[str, Any]) -> SecurityInsight:
        """Generate AI-powered security insight"""
        try:
            insight = SecurityInsight(
                insight_type=insight_data["insight_type"],
                title=insight_data["title"],
                description=insight_data["description"],
                severity=insight_data.get("severity", "medium"),
                confidence=insight_data.get("confidence"),
                insight_data=insight_data.get("insight_data", {}),
                source_data=insight_data.get("source_data", {})
            )
            db.add(insight)
            db.commit()
            db.refresh(insight)
            
            return insight
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to generate insight: {str(e)}")
            raise

    def analyze_trends(self, db: Session, trend_type: str, time_period: str = "monthly") -> TrendAnalysis:
        """Analyze trends for security metrics"""
        try:
            # Get historical data based on trend type
            if trend_type == "vulnerability_trend":
                data_points = self._get_vulnerability_trend_data(db, time_period)
                trend_direction = self._calculate_trend_direction(data_points)
                trend_strength = self._calculate_trend_strength(data_points)
                analysis_summary = self._generate_trend_summary(trend_type, trend_direction, trend_strength)
            else:
                # Default trend analysis
                data_points = {"dates": [], "values": []}
                trend_direction = "stable"
                trend_strength = 0.5
                analysis_summary = "No significant trend detected"
            
            trend = TrendAnalysis(
                trend_type=trend_type,
                metric_name=f"{trend_type}_metric",
                time_period=time_period,
                trend_direction=trend_direction,
                trend_strength=trend_strength,
                data_points=data_points,
                analysis_summary=analysis_summary,
                recommendations=self._generate_trend_recommendations(trend_direction, trend_strength)
            )
            db.add(trend)
            db.commit()
            db.refresh(trend)
            
            return trend
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to analyze trends: {str(e)}")
            raise

    def _get_vulnerability_trend_data(self, db: Session, time_period: str) -> Dict[str, List]:
        """Get vulnerability trend data"""
        # Simulate historical vulnerability data
        dates = []
        values = []
        
        for i in range(12):  # Last 12 periods
            date = datetime.utcnow() - timedelta(days=30 * i)
            dates.append(date.isoformat())
            # Simulate trend with some randomness
            base_value = 10 + i * 2 + np.random.uniform(-3, 3)
            values.append(max(base_value, 0))
            
        return {
            "dates": dates[::-1],  # Reverse to show oldest first
            "values": values[::-1]
        }

    def _calculate_trend_direction(self, data_points: Dict[str, List]) -> str:
        """Calculate trend direction from data points"""
        values = data_points.get("values", [])
        if len(values) < 2:
            return "stable"
            
        # Simple linear trend calculation
        x = np.arange(len(values))
        y = np.array(values)
        
        if len(y) > 1:
            slope = np.polyfit(x, y, 1)[0]
            if slope > 0.5:
                return "increasing"
            elif slope < -0.5:
                return "decreasing"
            else:
                return "stable"
        return "stable"

    def _calculate_trend_strength(self, data_points: Dict[str, List]) -> float:
        """Calculate trend strength"""
        values = data_points.get("values", [])
        if len(values) < 2:
            return 0.0
            
        # Calculate R-squared as trend strength
        x = np.arange(len(values))
        y = np.array(values)
        
        if len(y) > 1:
            correlation = np.corrcoef(x, y)[0, 1]
            return abs(correlation) if not np.isnan(correlation) else 0.0
        return 0.0

    def _generate_trend_summary(self, trend_type: str, direction: str, strength: float) -> str:
        """Generate summary for trend analysis"""
        if direction == "increasing":
            return f"Strong {trend_type} trend showing increase over time"
        elif direction == "decreasing":
            return f"Positive {trend_type} trend showing decrease over time"
        else:
            return f"Stable {trend_type} pattern with no significant change"

    def _generate_trend_recommendations(self, direction: str, strength: float) -> Dict[str, List[str]]:
        """Generate recommendations based on trend"""
        recommendations = []
        
        if direction == "increasing" and strength > 0.7:
            recommendations.append("Immediate action required to address increasing trend")
            recommendations.append("Review security controls and implement additional measures")
        elif direction == "increasing":
            recommendations.append("Monitor trend closely and prepare mitigation strategies")
        elif direction == "decreasing":
            recommendations.append("Continue current security practices")
            recommendations.append("Consider sharing best practices with team")
        else:
            recommendations.append("Maintain current security posture")
            recommendations.append("Continue monitoring for changes")
            
        return {"recommendations": recommendations}

    def create_predictive_alert(self, db: Session, alert_data: Dict[str, Any]) -> PredictiveAlert:
        """Create a predictive alert"""
        try:
            alert = PredictiveAlert(
                alert_type=alert_data["alert_type"],
                title=alert_data["title"],
                description=alert_data["description"],
                predicted_value=alert_data["predicted_value"],
                confidence=alert_data.get("confidence"),
                severity=alert_data.get("severity", "medium"),
                trigger_conditions=alert_data.get("trigger_conditions", {}),
                prediction_horizon=alert_data.get("prediction_horizon")
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            
            return alert
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to create predictive alert: {str(e)}")
            raise

    def get_analytics_dashboard(self, db: Session, user: User) -> Dict[str, Any]:
        """Get analytics dashboard data"""
        try:
            # Get counts
            total_predictions = db.query(MLPrediction).count()
            active_models = db.query(MLModel).filter(MLModel.is_active == True).count()
            recent_insights = db.query(SecurityInsight).filter(
                SecurityInsight.created_at >= datetime.utcnow() - timedelta(days=30)
            ).count()
            anomaly_count = db.query(AnomalyDetection).filter(
                AnomalyDetection.created_at >= datetime.utcnow() - timedelta(days=30)
            ).count()
            trend_analyses = db.query(TrendAnalysis).count()
            predictive_alerts = db.query(PredictiveAlert).filter(PredictiveAlert.is_active == True).count()
            
            # Calculate average risk score
            risk_scores = db.query(RiskScore).all()
            avg_risk_score = sum(rs.risk_score for rs in risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            # Model accuracy
            models = db.query(MLModel).all()
            model_accuracy = {model.name: model.accuracy or 0.0 for model in models}
            
            # Risk distribution
            risk_levels = db.query(RiskScore.risk_level, func.count(RiskScore.id)).group_by(RiskScore.risk_level).all()
            risk_distribution = {level: count for level, count in risk_levels}
            
            # Insight summary
            insights = db.query(SecurityInsight).filter(
                SecurityInsight.created_at >= datetime.utcnow() - timedelta(days=30)
            ).all()
            insight_summary = {
                "total": len(insights),
                "actionable": len([i for i in insights if i.is_actionable]),
                "actioned": len([i for i in insights if i.action_taken]),
                "by_severity": {}
            }
            
            for insight in insights:
                severity = insight.severity
                if severity not in insight_summary["by_severity"]:
                    insight_summary["by_severity"][severity] = 0
                insight_summary["by_severity"][severity] += 1
            
            return {
                "total_predictions": total_predictions,
                "active_models": active_models,
                "recent_insights": recent_insights,
                "average_risk_score": round(avg_risk_score, 2),
                "anomaly_count": anomaly_count,
                "trend_analyses": trend_analyses,
                "predictive_alerts": predictive_alerts,
                "model_accuracy": model_accuracy,
                "risk_distribution": risk_distribution,
                "insight_summary": insight_summary
            }
            
        except Exception as e:
            print(f"❌ Failed to get analytics dashboard: {str(e)}")
            return {}

    def track_analytics_event(self, db: Session, user: User, event_type: str, 
                            event_category: str, event_data: Dict[str, Any] = None) -> AnalyticsEvent:
        """Track analytics event"""
        try:
            event = AnalyticsEvent(
                user_id=user.id,
                event_type=event_type,
                event_category=event_category,
                event_data=event_data or {},
                session_id="session_123",  # In production, get from request
                ip_address="127.0.0.1",  # In production, get from request
                user_agent="DriftBuddy Analytics"
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            
            return event
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to track analytics event: {str(e)}")
            raise 