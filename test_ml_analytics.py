#!/usr/bin/env python3
"""
Test script for ML and Analytics features
Demonstrates all ML and analytics capabilities
"""

import json
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, Any

BASE_URL = "http://localhost:8080"
ADMIN_EMAIL = "admin@driftbuddy.com"
ADMIN_PASSWORD = "admin123"

class MLAnalyticsTester:
    def __init__(self):
        self.session = requests.Session()
        self.admin_token = None
        self.models = {}
        self.predictions = {}
        self.risk_scores = {}
        self.insights = {}

    def login_admin(self) -> bool:
        """Login as admin user"""
        try:
            print("🔐 Logging in as admin...")
            response = self.session.post(
                f"{BASE_URL}/api/auth/login",
                data={
                    "email": ADMIN_EMAIL,
                    "password": ADMIN_PASSWORD
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                self.admin_token = data["access_token"]
                self.session.headers.update({
                    "Authorization": f"Bearer {self.admin_token}"
                })
                print("✅ Login successful")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
            return False

    def test_ml_models(self) -> bool:
        """Test ML model management"""
        try:
            print("\n🤖 Testing ML Models...")
            
            # Get existing models
            response = self.session.get(f"{BASE_URL}/api/analytics/models")
            if response.status_code == 200:
                models = response.json()
                print(f"✅ Found {len(models)} ML models")
                for model in models:
                    print(f"   - {model['name']} ({model['model_type']}) - Accuracy: {model['accuracy']}")
                    self.models[model['id']] = model
            else:
                print(f"❌ Failed to get models: {response.status_code}")
                return False
            
            # Test model performance
            if self.models:
                model_id = list(self.models.keys())[0]
                response = self.session.get(f"{BASE_URL}/api/analytics/models/{model_id}/performance")
                if response.status_code == 200:
                    performance = response.json()
                    print(f"✅ Model performance: {performance['model_name']}")
                    print(f"   - Total predictions: {performance['total_predictions']}")
                    print(f"   - Average confidence: {performance['average_confidence']}")
                else:
                    print(f"❌ Failed to get model performance: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ ML models test failed: {str(e)}")
            return False

    def test_predictions(self) -> bool:
        """Test ML predictions"""
        try:
            print("\n🔮 Testing ML Predictions...")
            
            if not self.models:
                print("❌ No models available for predictions")
                return False
            
            # Create vulnerability risk prediction
            model_id = list(self.models.keys())[0]
            prediction_data = {
                "model_id": model_id,
                "prediction_type": "vulnerability_risk",
                "target_id": 1,
                "target_type": "finding",
                "prediction_data": {
                    "severity": "HIGH",
                    "age_days": 45,
                    "exploit_count": 3,
                    "patch_status": "unpatched",
                    "asset_criticality": "high"
                }
            }
            
            response = self.session.post(
                f"{BASE_URL}/api/analytics/predictions",
                json=prediction_data
            )
            
            if response.status_code == 200:
                prediction = response.json()
                print(f"✅ Created prediction: {prediction['model_name']}")
                print(f"   - Prediction value: {prediction['prediction_value']:.3f}")
                print(f"   - Confidence: {prediction['confidence_score']:.3f}")
                print(f"   - Type: {prediction['prediction_type']}")
                self.predictions[prediction['id']] = prediction
            else:
                print(f"❌ Failed to create prediction: {response.status_code}")
                return False
            
            # Create attack probability prediction
            prediction_data = {
                "model_id": model_id,
                "prediction_type": "attack_probability",
                "target_id": 1,
                "target_type": "scan",
                "prediction_data": {
                    "vulnerability_count": 8,
                    "critical_vulnerabilities": 2,
                    "exposure_score": 0.7,
                    "network_segment": "dmz"
                }
            }
            
            response = self.session.post(
                f"{BASE_URL}/api/analytics/predictions",
                json=prediction_data
            )
            
            if response.status_code == 200:
                prediction = response.json()
                print(f"✅ Created attack probability prediction")
                print(f"   - Attack probability: {prediction['prediction_value']:.3f}")
                print(f"   - Confidence: {prediction['confidence_score']:.3f}")
                self.predictions[prediction['id']] = prediction
            else:
                print(f"❌ Failed to create attack prediction: {response.status_code}")
            
            # Get all predictions
            response = self.session.get(f"{BASE_URL}/api/analytics/predictions")
            if response.status_code == 200:
                predictions = response.json()
                print(f"✅ Retrieved {len(predictions)} predictions")
            else:
                print(f"❌ Failed to get predictions: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Predictions test failed: {str(e)}")
            return False

    def test_risk_scoring(self) -> bool:
        """Test risk scoring"""
        try:
            print("\n⚠️ Testing Risk Scoring...")
            
            # Calculate risk score for a finding
            risk_data = {
                "entity_type": "finding",
                "entity_id": 1,
                "risk_score": 75.0,
                "risk_level": "high",
                "factors": {
                    "severity": 0.8,
                    "age_days": 30,
                    "exploit_available": True
                },
                "calculation_method": "hybrid"
            }
            
            response = self.session.post(
                f"{BASE_URL}/api/analytics/risk-scores",
                json=risk_data
            )
            
            if response.status_code == 200:
                risk_score = response.json()
                print(f"✅ Calculated risk score: {risk_score['risk_score']:.1f}")
                print(f"   - Risk level: {risk_score['risk_level']}")
                print(f"   - Calculation method: {risk_score['calculation_method']}")
                self.risk_scores[risk_score['id']] = risk_score
            else:
                print(f"❌ Failed to calculate risk score: {response.status_code}")
                return False
            
            # Calculate risk score for a scan
            risk_data = {
                "entity_type": "scan",
                "entity_id": 1,
                "risk_score": 65.0,
                "risk_level": "medium",
                "factors": {
                    "total_findings": 12,
                    "high_critical_findings": 3,
                    "scan_age_days": 5
                },
                "calculation_method": "ml_model"
            }
            
            response = self.session.post(
                f"{BASE_URL}/api/analytics/risk-scores",
                json=risk_data
            )
            
            if response.status_code == 200:
                risk_score = response.json()
                print(f"✅ Calculated scan risk score: {risk_score['risk_score']:.1f}")
                print(f"   - Risk level: {risk_score['risk_level']}")
                self.risk_scores[risk_score['id']] = risk_score
            else:
                print(f"❌ Failed to calculate scan risk score: {response.status_code}")
            
            # Get all risk scores
            response = self.session.get(f"{BASE_URL}/api/analytics/risk-scores")
            if response.status_code == 200:
                risk_scores = response.json()
                print(f"✅ Retrieved {len(risk_scores)} risk scores")
            else:
                print(f"❌ Failed to get risk scores: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Risk scoring test failed: {str(e)}")
            return False

    def test_anomaly_detection(self) -> bool:
        """Test anomaly detection"""
        try:
            print("\n🔍 Testing Anomaly Detection...")
            
            # Detect anomaly for a scan
            response = self.session.post(
                f"{BASE_URL}/api/analytics/anomalies/detect",
                params={"entity_type": "scan", "entity_id": 1}
            )
            
            if response.status_code == 200:
                anomaly = response.json()
                print(f"✅ Detected scan anomaly")
                print(f"   - Anomaly score: {anomaly['anomaly_score']:.3f}")
                print(f"   - Severity: {anomaly['severity']}")
                print(f"   - Description: {anomaly['description']}")
            else:
                print(f"❌ Failed to detect scan anomaly: {response.status_code}")
                return False
            
            # Detect anomaly for a finding
            response = self.session.post(
                f"{BASE_URL}/api/analytics/anomalies/detect",
                params={"entity_type": "finding", "entity_id": 1}
            )
            
            if response.status_code == 200:
                anomaly = response.json()
                print(f"✅ Detected finding anomaly")
                print(f"   - Anomaly score: {anomaly['anomaly_score']:.3f}")
                print(f"   - Severity: {anomaly['severity']}")
                print(f"   - Description: {anomaly['description']}")
            else:
                print(f"❌ Failed to detect finding anomaly: {response.status_code}")
            
            # Get all anomalies
            response = self.session.get(f"{BASE_URL}/api/analytics/anomalies")
            if response.status_code == 200:
                anomalies = response.json()
                print(f"✅ Retrieved {len(anomalies)} anomalies")
            else:
                print(f"❌ Failed to get anomalies: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Anomaly detection test failed: {str(e)}")
            return False

    def test_security_insights(self) -> bool:
        """Test security insights"""
        try:
            print("\n💡 Testing Security Insights...")
            
            # Create trend insight
            insight_data = {
                "insight_type": "trend",
                "title": "Increasing Vulnerability Trend",
                "description": "Analysis shows a 25% increase in high-severity vulnerabilities over the past month",
                "severity": "high",
                "confidence": 0.85,
                "insight_data": {
                    "trend_direction": "increasing",
                    "percentage_change": 25,
                    "time_period": "30_days"
                },
                "source_data": {
                    "data_sources": ["scan_results", "vulnerability_database"],
                    "analysis_method": "statistical_analysis"
                }
            }
            
            response = self.session.post(
                f"{BASE_URL}/api/analytics/insights",
                json=insight_data
            )
            
            if response.status_code == 200:
                insight = response.json()
                print(f"✅ Created trend insight: {insight['title']}")
                print(f"   - Severity: {insight['severity']}")
                print(f"   - Confidence: {insight['confidence']}")
                print(f"   - Actionable: {insight['is_actionable']}")
                self.insights[insight['id']] = insight
            else:
                print(f"❌ Failed to create trend insight: {response.status_code}")
                return False
            
            # Create anomaly insight
            insight_data = {
                "insight_type": "anomaly",
                "title": "Unusual Scan Pattern Detected",
                "description": "Scan completed with 3x more findings than historical average",
                "severity": "medium",
                "confidence": 0.78,
                "insight_data": {
                    "anomaly_type": "scan_pattern",
                    "deviation": "3x_above_average",
                    "baseline": "historical_data"
                },
                "source_data": {
                    "data_sources": ["scan_history", "finding_patterns"],
                    "detection_method": "statistical_analysis"
                }
            }
            
            response = self.session.post(
                f"{BASE_URL}/api/analytics/insights",
                json=insight_data
            )
            
            if response.status_code == 200:
                insight = response.json()
                print(f"✅ Created anomaly insight: {insight['title']}")
                print(f"   - Severity: {insight['severity']}")
                print(f"   - Confidence: {insight['confidence']}")
                self.insights[insight['id']] = insight
            else:
                print(f"❌ Failed to create anomaly insight: {response.status_code}")
            
            # Get all insights
            response = self.session.get(f"{BASE_URL}/api/analytics/insights")
            if response.status_code == 200:
                insights = response.json()
                print(f"✅ Retrieved {len(insights)} insights")
            else:
                print(f"❌ Failed to get insights: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Security insights test failed: {str(e)}")
            return False

    def test_trend_analysis(self) -> bool:
        """Test trend analysis"""
        try:
            print("\n📈 Testing Trend Analysis...")
            
            # Analyze vulnerability trend
            response = self.session.post(
                f"{BASE_URL}/api/analytics/trends/analyze",
                params={"trend_type": "vulnerability_trend", "time_period": "monthly"}
            )
            
            if response.status_code == 200:
                trend = response.json()
                print(f"✅ Analyzed vulnerability trend")
                print(f"   - Trend direction: {trend['trend_direction']}")
                print(f"   - Trend strength: {trend['trend_strength']:.3f}")
                print(f"   - Analysis summary: {trend['analysis_summary']}")
            else:
                print(f"❌ Failed to analyze vulnerability trend: {response.status_code}")
                return False
            
            # Get all trend analyses
            response = self.session.get(f"{BASE_URL}/api/analytics/trends")
            if response.status_code == 200:
                trends = response.json()
                print(f"✅ Retrieved {len(trends)} trend analyses")
            else:
                print(f"❌ Failed to get trends: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Trend analysis test failed: {str(e)}")
            return False

    def test_predictive_alerts(self) -> bool:
        """Test predictive alerts"""
        try:
            print("\n🚨 Testing Predictive Alerts...")
            
            # Create vulnerability prediction alert
            alert_data = {
                "alert_type": "vulnerability_prediction",
                "title": "High Risk Vulnerability Predicted",
                "description": "ML model predicts 85% probability of critical vulnerability in next 7 days",
                "predicted_value": 0.85,
                "confidence": 0.78,
                "severity": "high",
                "trigger_conditions": {
                    "threshold": 0.8,
                    "time_horizon": "7_days"
                },
                "prediction_horizon": 7
            }
            
            response = self.session.post(
                f"{BASE_URL}/api/analytics/alerts",
                json=alert_data
            )
            
            if response.status_code == 200:
                alert = response.json()
                print(f"✅ Created predictive alert: {alert['title']}")
                print(f"   - Predicted value: {alert['predicted_value']:.3f}")
                print(f"   - Confidence: {alert['confidence']:.3f}")
                print(f"   - Severity: {alert['severity']}")
            else:
                print(f"❌ Failed to create predictive alert: {response.status_code}")
                return False
            
            # Get all alerts
            response = self.session.get(f"{BASE_URL}/api/analytics/alerts")
            if response.status_code == 200:
                alerts = response.json()
                print(f"✅ Retrieved {len(alerts)} predictive alerts")
            else:
                print(f"❌ Failed to get alerts: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Predictive alerts test failed: {str(e)}")
            return False

    def test_analytics_dashboard(self) -> bool:
        """Test analytics dashboard"""
        try:
            print("\n📊 Testing Analytics Dashboard...")
            
            response = self.session.get(f"{BASE_URL}/api/analytics/dashboard")
            if response.status_code == 200:
                dashboard = response.json()
                print(f"✅ Analytics Dashboard Overview:")
                print(f"   - Total predictions: {dashboard['total_predictions']}")
                print(f"   - Active models: {dashboard['active_models']}")
                print(f"   - Recent insights: {dashboard['recent_insights']}")
                print(f"   - Average risk score: {dashboard['average_risk_score']:.1f}")
                print(f"   - Anomaly count: {dashboard['anomaly_count']}")
                print(f"   - Trend analyses: {dashboard['trend_analyses']}")
                print(f"   - Predictive alerts: {dashboard['predictive_alerts']}")
                
                print(f"\n📈 Model Accuracy:")
                for model, accuracy in dashboard['model_accuracy'].items():
                    print(f"   - {model}: {accuracy:.3f}")
                
                print(f"\n⚠️ Risk Distribution:")
                for level, count in dashboard['risk_distribution'].items():
                    print(f"   - {level}: {count}")
                
                print(f"\n💡 Insight Summary:")
                insight_summary = dashboard['insight_summary']
                print(f"   - Total: {insight_summary['total']}")
                print(f"   - Actionable: {insight_summary['actionable']}")
                print(f"   - Actioned: {insight_summary['actioned']}")
                
            else:
                print(f"❌ Failed to get analytics dashboard: {response.status_code}")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Analytics dashboard test failed: {str(e)}")
            return False

    def test_analytics_events(self) -> bool:
        """Test analytics events tracking"""
        try:
            print("\n📝 Testing Analytics Events...")
            
            # Track some events
            events = [
                {
                    "event_type": "scan_created",
                    "event_category": "user_action",
                    "event_data": {"scan_id": 1, "scan_type": "security"}
                },
                {
                    "event_type": "finding_viewed",
                    "event_category": "user_action",
                    "event_data": {"finding_id": 1, "severity": "HIGH"}
                },
                {
                    "event_type": "prediction_generated",
                    "event_category": "system_event",
                    "event_data": {"model_id": 1, "prediction_type": "vulnerability_risk"}
                }
            ]
            
            for event in events:
                response = self.session.post(
                    f"{BASE_URL}/api/analytics/events/track",
                    json=event
                )
                if response.status_code == 200:
                    print(f"✅ Tracked event: {event['event_type']}")
                else:
                    print(f"❌ Failed to track event: {event['event_type']}")
            
            # Get analytics events
            response = self.session.get(f"{BASE_URL}/api/analytics/events")
            if response.status_code == 200:
                events = response.json()
                print(f"✅ Retrieved {len(events)} analytics events")
            else:
                print(f"❌ Failed to get analytics events: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Analytics events test failed: {str(e)}")
            return False

    def run_comprehensive_test(self):
        """Run comprehensive ML and analytics test"""
        print("🚀 Starting ML and Analytics Test")
        print("=" * 50)
        
        if not self.login_admin():
            return False
        
        tests = [
            ("ML Models", self.test_ml_models),
            ("Predictions", self.test_predictions),
            ("Risk Scoring", self.test_risk_scoring),
            ("Anomaly Detection", self.test_anomaly_detection),
            ("Security Insights", self.test_security_insights),
            ("Trend Analysis", self.test_trend_analysis),
            ("Predictive Alerts", self.test_predictive_alerts),
            ("Analytics Dashboard", self.test_analytics_dashboard),
            ("Analytics Events", self.test_analytics_events)
        ]
        
        results = []
        for test_name, test_func in tests:
            try:
                success = test_func()
                results.append((test_name, success))
                if success:
                    print(f"✅ {test_name} test passed")
                else:
                    print(f"❌ {test_name} test failed")
            except Exception as e:
                print(f"❌ {test_name} test error: {str(e)}")
                results.append((test_name, False))
        
        # Summary
        passed = sum(1 for _, success in results if success)
        total = len(results)
        
        print("\n" + "=" * 50)
        print("📊 Test Results Summary:")
        print(f"✅ Passed: {passed}/{total}")
        print(f"❌ Failed: {total - passed}/{total}")
        
        if passed == total:
            print("🎉 All ML and Analytics tests passed!")
            return True
        else:
            print("⚠️ Some tests failed. Check the output above for details.")
            return False


def main():
    """Main test function"""
    tester = MLAnalyticsTester()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎯 ML and Analytics system is working correctly!")
        print("🔧 Features tested:")
        print("   - ML Model Management")
        print("   - Predictive Analytics")
        print("   - Risk Scoring Algorithms")
        print("   - Anomaly Detection")
        print("   - Security Insights")
        print("   - Trend Analysis")
        print("   - Predictive Alerts")
        print("   - Analytics Dashboard")
        print("   - Event Tracking")
    else:
        print("\n❌ Some ML and Analytics tests failed.")
        print("Please check the server logs and ensure all systems are running.")
    
    return success


if __name__ == "__main__":
    main() 