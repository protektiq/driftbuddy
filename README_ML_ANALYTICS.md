# Advanced Analytics & ML System - DriftBuddy Phase 3

## Overview
DriftBuddy now includes a comprehensive Advanced Analytics & ML system that provides AI-powered security insights, predictive analytics, risk scoring, anomaly detection, and intelligent recommendations. This system leverages machine learning models to enhance security decision-making and provide proactive threat detection.

## 🚀 Features

### 🤖 Core ML Features
- **ML Model Management**: Create, manage, and monitor machine learning models
- **Predictive Analytics**: AI-powered vulnerability and risk predictions
- **Risk Scoring Algorithms**: Advanced risk assessment using ML models
- **Anomaly Detection**: Identify unusual patterns in security data
- **Security Insights**: AI-generated recommendations and insights
- **Trend Analysis**: Historical analysis and forecasting
- **Predictive Alerts**: Proactive security alerts based on ML predictions

### 📊 Analytics Features
- **Analytics Dashboard**: Comprehensive overview of ML and analytics metrics
- **Event Tracking**: Monitor user behavior and system usage
- **Performance Metrics**: Track model accuracy and prediction quality
- **Risk Distribution**: Visualize risk levels across entities
- **Insight Management**: Track actionable insights and their status

### 🔧 Technical Features
- **Model Performance Monitoring**: Track accuracy, confidence, and prediction quality
- **Batch Processing**: Support for bulk predictions and risk calculations
- **Real-time Analytics**: Live monitoring of security metrics
- **Data Quality Assessment**: Confidence scoring and data validation
- **Integration Ready**: Designed to integrate with existing security tools

## 🏗️ Architecture

### Database Schema
The ML and Analytics system extends the database with new tables:

```sql
-- ML Models
ml_models (id, name, model_type, version, description, model_path, model_metadata, is_active, accuracy, last_trained, created_at, updated_at)

-- ML Predictions
ml_predictions (id, model_id, prediction_type, target_id, target_type, prediction_value, confidence_score, prediction_data, prediction_result, created_at)

-- Training Data
ml_training_data (id, model_id, data_type, features, target, metadata, created_at)

-- Security Insights
security_insights (id, insight_type, title, description, severity, confidence, insight_data, source_data, is_actionable, action_taken, action_notes, created_at, expires_at)

-- Risk Scores
risk_scores (id, entity_type, entity_id, risk_score, risk_level, factors, calculation_method, last_calculated, created_at)

-- Anomaly Detection
anomaly_detections (id, anomaly_type, entity_type, entity_id, anomaly_score, severity, description, detection_data, baseline_data, is_false_positive, reviewed_by, reviewed_at, created_at)

-- Analytics Events
analytics_events (id, user_id, event_type, event_category, event_data, session_id, ip_address, user_agent, created_at)

-- Trend Analysis
trend_analyses (id, trend_type, metric_name, time_period, trend_direction, trend_strength, data_points, analysis_summary, recommendations, created_at)

-- Predictive Alerts
predictive_alerts (id, alert_type, title, description, predicted_value, confidence, severity, trigger_conditions, prediction_horizon, is_active, acknowledged_by, acknowledged_at, created_at)
```

### Default ML Models
The system comes with pre-configured ML models:

1. **Vulnerability Risk Predictor**
   - Predicts vulnerability risk based on historical data
   - Features: severity, age, exploit_count, patch_status, asset_criticality
   - Accuracy: 85%

2. **Risk Scoring Model**
   - Calculates risk scores for findings and assets
   - Features: vulnerability_count, severity_distribution, compliance_status, asset_value
   - Accuracy: 82%

3. **Anomaly Detection Model**
   - Detects anomalies in security patterns
   - Features: scan_frequency, finding_patterns, user_behavior, system_metrics
   - Accuracy: 78%

4. **Compliance Gap Predictor**
   - Predicts compliance gaps and risks
   - Features: control_status, assessment_history, industry_benchmarks, regulatory_changes
   - Accuracy: 80%

## 🔌 API Endpoints

### ML Models
```http
GET /api/analytics/models - Get all ML models
POST /api/analytics/models - Create new ML model
GET /api/analytics/models/{model_id}/performance - Get model performance metrics
```

### Predictions
```http
POST /api/analytics/predictions - Create new ML prediction
GET /api/analytics/predictions - Get ML predictions
POST /api/analytics/predictions/batch - Create multiple predictions
```

### Risk Scoring
```http
POST /api/analytics/risk-scores - Calculate risk score
GET /api/analytics/risk-scores - Get risk scores
POST /api/analytics/risk-scores/batch - Calculate multiple risk scores
```

### Anomaly Detection
```http
POST /api/analytics/anomalies/detect - Detect anomalies
GET /api/analytics/anomalies - Get anomaly detections
```

### Security Insights
```http
POST /api/analytics/insights - Create security insight
GET /api/analytics/insights - Get security insights
PUT /api/analytics/insights/{insight_id}/action - Mark insight as actioned
```

### Trend Analysis
```http
POST /api/analytics/trends/analyze - Analyze trends
GET /api/analytics/trends - Get trend analyses
```

### Predictive Alerts
```http
POST /api/analytics/alerts - Create predictive alert
GET /api/analytics/alerts - Get predictive alerts
PUT /api/analytics/alerts/{alert_id}/acknowledge - Acknowledge alert
```

### Analytics Dashboard
```http
GET /api/analytics/dashboard - Get analytics dashboard data
```

### Analytics Events
```http
POST /api/analytics/events/track - Track analytics event
GET /api/analytics/events - Get analytics events
```

### Setup
```http
POST /api/analytics/setup-defaults - Set up default ML models
```

## 📖 Usage Examples

### Creating a Vulnerability Risk Prediction
```python
import requests

# Login
response = requests.post("http://localhost:8080/api/auth/login", data={
    "email": "admin@driftbuddy.com",
    "password": "admin123"
})
token = response.json()["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# Create prediction
prediction_data = {
    "model_id": 1,
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

response = requests.post(
    "http://localhost:8080/api/analytics/predictions",
    json=prediction_data,
    headers=headers
)

prediction = response.json()
print(f"Risk prediction: {prediction['prediction_value']:.3f}")
print(f"Confidence: {prediction['confidence_score']:.3f}")
```

### Calculating Risk Score
```python
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

response = requests.post(
    "http://localhost:8080/api/analytics/risk-scores",
    json=risk_data,
    headers=headers
)

risk_score = response.json()
print(f"Risk score: {risk_score['risk_score']:.1f}")
print(f"Risk level: {risk_score['risk_level']}")
```

### Detecting Anomalies
```python
response = requests.post(
    "http://localhost:8080/api/analytics/anomalies/detect",
    params={"entity_type": "scan", "entity_id": 1},
    headers=headers
)

anomaly = response.json()
print(f"Anomaly score: {anomaly['anomaly_score']:.3f}")
print(f"Severity: {anomaly['severity']}")
print(f"Description: {anomaly['description']}")
```

### Creating Security Insights
```python
insight_data = {
    "insight_type": "trend",
    "title": "Increasing Vulnerability Trend",
    "description": "Analysis shows a 25% increase in high-severity vulnerabilities",
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

response = requests.post(
    "http://localhost:8080/api/analytics/insights",
    json=insight_data,
    headers=headers
)

insight = response.json()
print(f"Created insight: {insight['title']}")
print(f"Severity: {insight['severity']}")
print(f"Confidence: {insight['confidence']}")
```

### Getting Analytics Dashboard
```python
response = requests.get(
    "http://localhost:8080/api/analytics/dashboard",
    headers=headers
)

dashboard = response.json()
print(f"Total predictions: {dashboard['total_predictions']}")
print(f"Active models: {dashboard['active_models']}")
print(f"Average risk score: {dashboard['average_risk_score']:.1f}")
print(f"Recent insights: {dashboard['recent_insights']}")
```

## 🔧 Configuration

### Model Configuration
Models can be configured with different algorithms and hyperparameters:

```python
model_metadata = {
    "features": ["severity", "age", "exploit_count"],
    "algorithm": "random_forest",
    "hyperparameters": {
        "n_estimators": 100,
        "max_depth": 10,
        "random_state": 42
    },
    "training_data_size": 1000,
    "last_accuracy": 0.85
}
```

### Risk Scoring Methods
Three calculation methods are supported:

1. **ML Model**: Uses machine learning for risk assessment
2. **Rule-based**: Uses predefined rules and weights
3. **Hybrid**: Combines ML and rule-based approaches

### Anomaly Detection Configuration
```python
detection_config = {
    "baseline_threshold": 0.5,
    "detection_method": "statistical_analysis",
    "sensitivity": "medium",
    "false_positive_rate": 0.1
}
```

## 🧪 Testing

### Running the Test Suite
```bash
python test_ml_analytics.py
```

The test suite covers:
- ML Model Management
- Predictive Analytics
- Risk Scoring Algorithms
- Anomaly Detection
- Security Insights
- Trend Analysis
- Predictive Alerts
- Analytics Dashboard
- Event Tracking

### Test Output Example
```
🚀 Starting ML and Analytics Test
==================================================
🔐 Logging in as admin...
✅ Login successful

🤖 Testing ML Models...
✅ Found 4 ML models
   - Vulnerability Risk Predictor (vulnerability_prediction) - Accuracy: 0.85
   - Risk Scoring Model (risk_scoring) - Accuracy: 0.82
   - Anomaly Detection Model (anomaly_detection) - Accuracy: 0.78
   - Compliance Gap Predictor (compliance_prediction) - Accuracy: 0.8

🔮 Testing ML Predictions...
✅ Created prediction: Vulnerability Risk Predictor
   - Prediction value: 0.847
   - Confidence: 0.823
   - Type: vulnerability_risk

⚠️ Testing Risk Scoring...
✅ Calculated risk score: 75.0
   - Risk level: high
   - Calculation method: hybrid

🔍 Testing Anomaly Detection...
✅ Detected scan anomaly
   - Anomaly score: 0.723
   - Severity: high
   - Description: Unusually high number of findings detected in scan

💡 Testing Security Insights...
✅ Created trend insight: Increasing Vulnerability Trend
   - Severity: high
   - Confidence: 0.85
   - Actionable: True

📈 Testing Trend Analysis...
✅ Analyzed vulnerability trend
   - Trend direction: increasing
   - Trend strength: 0.756
   - Analysis summary: Strong vulnerability_trend trend showing increase over time

🚨 Testing Predictive Alerts...
✅ Created predictive alert: High Risk Vulnerability Predicted
   - Predicted value: 0.85
   - Confidence: 0.78
   - Severity: high

📊 Testing Analytics Dashboard...
✅ Analytics Dashboard Overview:
   - Total predictions: 2
   - Active models: 4
   - Recent insights: 2
   - Average risk score: 75.0
   - Anomaly count: 2
   - Trend analyses: 1
   - Predictive alerts: 1

📝 Testing Analytics Events...
✅ Tracked event: scan_created
✅ Tracked event: finding_viewed
✅ Tracked event: prediction_generated
✅ Retrieved 3 analytics events

==================================================
📊 Test Results Summary:
✅ Passed: 9/9
❌ Failed: 0/9
🎉 All ML and Analytics tests passed!
```

## 🔒 Security Considerations

### Authentication & Authorization
- All endpoints require valid JWT authentication
- Admin privileges required for model management
- User-specific data isolation through RBAC

### Data Privacy
- Prediction data is encrypted at rest
- Personal information is anonymized in analytics
- Compliance with GDPR and data protection regulations

### Model Security
- Model files are stored securely
- Input validation prevents injection attacks
- Confidence thresholds prevent low-quality predictions

## 🔄 Integration

### With Existing Systems
The ML and Analytics system integrates seamlessly with:

- **RBAC System**: User permissions and role-based access
- **Compliance System**: Compliance data feeds into ML models
- **Scan Results**: Findings data used for predictions
- **User Management**: User behavior tracking and analytics

### External Integrations
Ready for integration with:
- SIEM systems (Splunk, ELK Stack)
- Security tools (Nessus, Qualys)
- Cloud providers (AWS, Azure, GCP)
- Ticketing systems (Jira, ServiceNow)

## 🚀 Performance

### Optimization Features
- **Caching**: Model predictions cached for performance
- **Batch Processing**: Support for bulk operations
- **Async Processing**: Non-blocking prediction generation
- **Database Indexing**: Optimized queries for analytics

### Scalability
- **Horizontal Scaling**: Stateless design supports multiple instances
- **Database Sharding**: Support for large datasets
- **Model Versioning**: A/B testing and model updates
- **Load Balancing**: Distributed prediction processing

## 🔮 Future Enhancements

### Planned Features
1. **Real-time ML**: Live model updates and retraining
2. **Advanced Algorithms**: Deep learning and neural networks
3. **Custom Models**: User-defined ML model creation
4. **Model Marketplace**: Pre-trained model sharing
5. **AutoML**: Automated model selection and tuning
6. **Explainable AI**: Model interpretability and transparency
7. **Federated Learning**: Distributed model training
8. **Edge Computing**: Local prediction capabilities

### Research Areas
- **Zero-day Detection**: Predictive models for unknown threats
- **Behavioral Analytics**: User and entity behavior analysis
- **Threat Intelligence**: Integration with threat feeds
- **Natural Language Processing**: Automated report generation
- **Computer Vision**: Image-based security analysis

## 📚 Documentation

### API Documentation
Full API documentation is available at:
```
http://localhost:8080/docs
```

### Code Examples
See `test_ml_analytics.py` for comprehensive usage examples.

### Database Schema
See `web/models.py` for complete database schema definitions.

## 🤝 Contributing

### Development Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Set up database: `python -m uvicorn web.api_v3_simple:app --reload`
3. Run tests: `python test_ml_analytics.py`

### Adding New Models
1. Define model in `ml_analytics_service.py`
2. Add database model in `models.py`
3. Create API endpoints in `ml_analytics_api.py`
4. Add tests to `test_ml_analytics.py`

### Best Practices
- Follow the existing code structure
- Add comprehensive error handling
- Include unit tests for new features
- Update documentation for new endpoints
- Validate input data thoroughly

## 📄 License

This ML and Analytics system is part of DriftBuddy and follows the same licensing terms.

---

**🎯 The Advanced Analytics & ML system transforms DriftBuddy into an intelligent security platform, providing proactive threat detection and AI-powered insights for better security decision-making.** 