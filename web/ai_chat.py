"""
AI Chat Service for DriftBuddy Web Interface
Provides intelligent security analysis using LangChain integration
"""

import asyncio
import json
import os

# Import DriftBuddy LangChain integration
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from .auth import get_user_permissions
from .models import ChatHistory, Finding, Scan, User

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from driftbuddy.langchain_integration import (
    DriftBuddyLangChain,
    create_langchain_integration,
)


class AIChatService:
    """AI chat service with LangChain integration"""

    def __init__(self):
        self.langchain = None
        self._initialize_langchain()

    def _initialize_langchain(self):
        """Initialize LangChain integration"""
        try:
            self.langchain = create_langchain_integration()
            print("✅ LangChain integration initialized")
        except Exception as e:
            print(f"⚠️ LangChain integration not available: {e}")
            self.langchain = None

    async def process_chat_message(
        self, db: Session, user: User, message: str, scan_id: Optional[int] = None, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Process a chat message and generate AI response"""
        try:
            # Prepare context for AI analysis
            analysis_context = await self._prepare_context(db, user, scan_id, context)

            # Generate AI response
            if self.langchain:
                response = await self._generate_ai_response(message, analysis_context)
            else:
                response = await self._generate_fallback_response(message, analysis_context)

            # Save chat history
            chat_history = ChatHistory(
                user_id=user.id,
                scan_id=scan_id,
                prompt=message,
                response=response["content"],
                metadata={"ai_model": response.get("model", "fallback"), "tokens_used": response.get("tokens", 0), "context": analysis_context},
                created_at=datetime.utcnow(),
            )

            db.add(chat_history)
            db.commit()

            return {"success": True, "response": response["content"], "metadata": response.get("metadata", {}), "chat_id": chat_history.id}

        except Exception as e:
            return {"success": False, "error": f"Failed to process chat message: {str(e)}"}

    async def _prepare_context(self, db: Session, user: User, scan_id: Optional[int], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare context for AI analysis"""
        analysis_context = {"user_role": user.role, "user_permissions": get_user_permissions(user), "timestamp": datetime.utcnow().isoformat()}

        # Add scan context if available
        if scan_id:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                analysis_context["scan"] = {
                    "id": scan.id,
                    "name": scan.name,
                    "type": scan.scan_type,
                    "status": scan.status,
                    "findings_count": len(scan.findings),
                }

                # Add recent findings
                recent_findings = db.query(Finding).filter(Finding.scan_id == scan_id).limit(10).all()

                analysis_context["findings"] = [
                    {"query_name": finding.query_name, "severity": finding.severity, "description": finding.description, "risk_score": finding.risk_score}
                    for finding in recent_findings
                ]

        # Add user's recent scans
        recent_scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc()).limit(5).all()

        analysis_context["recent_scans"] = [
            {"id": scan.id, "name": scan.name, "type": scan.scan_type, "status": scan.status, "findings_count": len(scan.findings)} for scan in recent_scans
        ]

        # Add custom context
        if context:
            analysis_context.update(context)

        return analysis_context

    async def _generate_ai_response(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI response using LangChain"""
        try:
            # Create context-aware prompt
            prompt = self._create_contextual_prompt(message, context)

            # Use LangChain for analysis
            if hasattr(self.langchain, "analyze_with_context"):
                # Use existing LangChain analysis
                analysis_result = self.langchain.analyze_with_context(
                    {"query_name": "chat_analysis", "description": message, "severity": "INFO"}, json.dumps(context)
                )

                response_content = analysis_result.get("ai_analysis", "I'll help you with that.")
            else:
                # Use basic LangChain chain
                chain = self.langchain.create_analysis_chain()
                response_content = chain.invoke({"input": prompt})

            return {
                "content": response_content,
                "model": "langchain",
                "tokens": len(response_content.split()),
                "metadata": {"context_used": True, "analysis_type": "security_analysis"},
            }

        except Exception as e:
            print(f"LangChain analysis failed: {e}")
            return await self._generate_fallback_response(message, context)

    async def _generate_fallback_response(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fallback response when LangChain is not available"""
        # Simple rule-based responses
        message_lower = message.lower()

        if "scan" in message_lower or "security" in message_lower:
            response = (
                "I can help you with security scanning. You can upload IaC files or connect cloud accounts to scan your infrastructure for security issues."
            )
        elif "finding" in message_lower or "vulnerability" in message_lower:
            response = (
                "Security findings are displayed in the dashboard with severity levels and risk scores. Each finding includes remediation recommendations."
            )
        elif "cloud" in message_lower or "aws" in message_lower or "azure" in message_lower or "gcp" in message_lower:
            response = (
                "You can connect your cloud accounts (AWS, Azure, GCP) to scan your cloud infrastructure for security misconfigurations and compliance issues."
            )
        elif "help" in message_lower:
            response = "I'm here to help with security analysis! You can ask me about scans, findings, cloud connections, or any security-related questions."
        else:
            response = "I'm your security analysis assistant. How can I help you with your security scanning and analysis needs?"

        return {"content": response, "model": "fallback", "tokens": len(response.split()), "metadata": {"context_used": False, "analysis_type": "rule_based"}}

    def _create_contextual_prompt(self, message: str, context: Dict[str, Any]) -> str:
        """Create a context-aware prompt for AI analysis"""
        prompt = f"""
        You are a cybersecurity expert assistant for DriftBuddy, an infrastructure security scanning tool.
        
        User Message: {message}
        
        Context:
        - User Role: {context.get('user_role', 'unknown')}
        - Recent Scans: {len(context.get('recent_scans', []))} scans
        - Current Scan: {context.get('scan', {}).get('name', 'None') if context.get('scan') else 'None'}
        - Recent Findings: {len(context.get('findings', []))} findings
        
        Please provide a helpful, security-focused response that:
        1. Addresses the user's question or concern
        2. Provides actionable security advice
        3. References relevant scan data if available
        4. Suggests next steps for security improvement
        
        Keep the response concise and professional.
        """

        return prompt

    async def get_chat_history(self, db: Session, user: User, limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's chat history"""
        chat_history = db.query(ChatHistory).filter(ChatHistory.user_id == user.id).order_by(ChatHistory.created_at.desc()).limit(limit).all()

        return [
            {
                "id": chat.id,
                "prompt": chat.prompt,
                "response": chat.response,
                "scan_id": chat.scan_id,
                "created_at": chat.created_at.isoformat(),
                "metadata": chat.chat_metadata,
            }
            for chat in chat_history
        ]

    async def analyze_findings_with_ai(self, db: Session, scan_id: int, user: User) -> Dict[str, Any]:
        """Analyze scan findings with AI"""
        try:
            # Get scan and findings
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return {"success": False, "error": "Scan not found"}

            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

            if not findings:
                return {"success": False, "error": "No findings to analyze"}

            # Prepare findings for AI analysis
            findings_data = [
                {
                    "query_name": finding.query_name,
                    "severity": finding.severity,
                    "description": finding.description,
                    "risk_score": finding.risk_score,
                    "remediation": finding.remediation,
                }
                for finding in findings
            ]

            # Generate AI analysis
            if self.langchain:
                analysis = self.langchain.run_autonomous_analysis(findings_data)
                analysis_content = analysis.get("agent_analysis", {}).get("output", "Analysis completed.")
            else:
                analysis_content = self._generate_findings_summary(findings_data)

            return {"success": True, "analysis": analysis_content, "findings_count": len(findings), "scan_name": scan.name}

        except Exception as e:
            return {"success": False, "error": f"AI analysis failed: {str(e)}"}

    def _generate_findings_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Generate a summary of findings when AI is not available"""
        if not findings:
            return "No findings to analyze."

        high_severity = len([f for f in findings if f.get("severity") == "HIGH"])
        medium_severity = len([f for f in findings if f.get("severity") == "MEDIUM"])
        low_severity = len([f for f in findings if f.get("severity") == "LOW"])

        total_findings = len(findings)
        avg_risk_score = sum(f.get("risk_score", 0) for f in findings) / total_findings if total_findings > 0 else 0

        summary = f"""
        Security Analysis Summary:
        
        Total Findings: {total_findings}
        - High Severity: {high_severity}
        - Medium Severity: {medium_severity}
        - Low Severity: {low_severity}
        
        Average Risk Score: {avg_risk_score:.1f}/25
        
        Recommendations:
        - Prioritize fixing high severity findings first
        - Review medium severity findings for business impact
        - Consider implementing automated security scanning
        - Regular security reviews are recommended
        """

        return summary

    async def generate_remediation_plan(self, db: Session, scan_id: int, user: User) -> Dict[str, Any]:
        """Generate a comprehensive remediation plan"""
        try:
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

            if not findings:
                return {"success": False, "error": "No findings to remediate"}

            # Group findings by severity
            high_findings = [f for f in findings if f.severity == "HIGH"]
            medium_findings = [f for f in findings if f.severity == "MEDIUM"]
            low_findings = [f for f in findings if f.severity == "LOW"]

            # Generate remediation plan
            plan = {
                "immediate_actions": [
                    {"priority": "Critical", "findings": [f.query_name for f in high_findings], "timeline": "Within 24 hours", "effort": "High"}
                ],
                "short_term_actions": [
                    {"priority": "High", "findings": [f.query_name for f in medium_findings], "timeline": "Within 1 week", "effort": "Medium"}
                ],
                "long_term_actions": [{"priority": "Medium", "findings": [f.query_name for f in low_findings], "timeline": "Within 1 month", "effort": "Low"}],
                "recommendations": [
                    "Implement automated security scanning in CI/CD pipeline",
                    "Regular security training for development teams",
                    "Establish security review processes",
                    "Monitor and track remediation progress",
                ],
            }

            return {"success": True, "plan": plan, "findings_count": len(findings)}

        except Exception as e:
            return {"success": False, "error": f"Failed to generate remediation plan: {str(e)}"}
