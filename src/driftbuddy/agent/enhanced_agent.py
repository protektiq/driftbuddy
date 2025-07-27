#!/usr/bin/env python3
"""
Enhanced Security Agent for DriftBuddy
Integrates LangChain with KICS and Steampipe for advanced AI-powered security analysis.
"""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain.schema import Document
from langchain.tools import BaseTool
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

from ..config import get_config
from ..exceptions import DriftBuddyError
from ..langchain_integration import DriftBuddyLangChain


class KICSAnalysisTool(BaseTool):
    """Tool for analyzing KICS findings with enhanced AI capabilities"""

    name: str = "kics_analysis"
    description: str = "Analyze KICS security findings with business context and risk assessment"
    langchain: Any = None

    def __init__(self, langchain_integration: DriftBuddyLangChain):
        super().__init__()
        self.langchain = langchain_integration

    def _run(self, kics_results: str) -> str:
        """Analyze KICS results using LangChain"""
        try:
            results = json.loads(kics_results)
            enhanced_results = self.langchain.enhance_kics_analysis(results)
            return json.dumps(enhanced_results, indent=2)
        except Exception as e:
            return f"Error analyzing KICS results: {str(e)}"

    async def _arun(self, kics_results: str) -> str:
        """Async analysis of KICS results"""
        try:
            results = json.loads(kics_results)
            enhanced_results = self.langchain.enhance_kics_analysis(results)
            return json.dumps(enhanced_results, indent=2)
        except Exception as e:
            return f"Error analyzing KICS results: {str(e)}"


class SteampipeAnalysisTool(BaseTool):
    """Tool for analyzing Steampipe findings with enhanced AI capabilities"""

    name: str = "steampipe_analysis"
    description: str = "Analyze Steampipe cloud findings with business context and risk assessment"
    langchain: Any = None

    def __init__(self, langchain_integration: DriftBuddyLangChain):
        super().__init__()
        self.langchain = langchain_integration

    def _run(self, steampipe_results: str) -> str:
        """Analyze Steampipe results using LangChain"""
        try:
            results = json.loads(steampipe_results)
            enhanced_results = self.langchain.enhance_steampipe_analysis(results)
            return json.dumps(enhanced_results, indent=2)
        except Exception as e:
            return f"Error analyzing Steampipe results: {str(e)}"

    async def _arun(self, steampipe_results: str) -> str:
        """Async analysis of Steampipe results"""
        try:
            results = json.loads(steampipe_results)
            enhanced_results = self.langchain.enhance_steampipe_analysis(results)
            return json.dumps(enhanced_results, indent=2)
        except Exception as e:
            return f"Error analyzing Steampipe results: {str(e)}"


class SecurityRecommendationTool(BaseTool):
    """Tool for generating comprehensive security recommendations"""

    name: str = "security_recommendations"
    description: str = "Generate comprehensive security recommendations based on findings"
    langchain: Any = None

    def __init__(self, langchain_integration: DriftBuddyLangChain):
        super().__init__()
        self.langchain = langchain_integration

    def _run(self, findings_summary: str) -> str:
        """Generate security recommendations"""
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a cybersecurity expert. Generate comprehensive security recommendations based on the findings."),
                ("human", "Generate security recommendations for: {findings}"),
            ]
        )

        chain = prompt | self.langchain.llm | StrOutputParser()
        return chain.invoke({"findings": findings_summary})

    async def _arun(self, findings_summary: str) -> str:
        """Async generation of security recommendations"""
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a cybersecurity expert. Generate comprehensive security recommendations based on the findings."),
                ("human", "Generate security recommendations for: {findings}"),
            ]
        )

        chain = prompt | self.langchain.llm | StrOutputParser()
        return await chain.ainvoke({"findings": findings_summary})


class EnhancedSecurityAgent:
    """Enhanced security agent that integrates LangChain with KICS and Steampipe"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or get_config()
        self.langchain = DriftBuddyLangChain(config)
        # Initialize memory without deprecated parameters
        self.memory = ConversationBufferMemory(return_messages=True)
        self.agent = self._create_agent()

    def _create_agent(self) -> AgentExecutor:
        """Create the enhanced security agent with all tools"""
        tools = [KICSAnalysisTool(self.langchain), SteampipeAnalysisTool(self.langchain), SecurityRecommendationTool(self.langchain)]

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are an advanced cybersecurity expert agent specializing in infrastructure security analysis. 
            You have access to KICS (Infrastructure as Code security scanner) and Steampipe (cloud infrastructure querying) results.
            
            Your capabilities include:
            - Analyzing KICS findings for IaC security issues
            - Analyzing Steampipe findings for cloud infrastructure issues
            - Generating comprehensive security recommendations
            - Providing business context and risk assessment
            
            Always provide detailed, actionable insights with business impact analysis.""",
                ),
                ("human", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ]
        )

        agent = create_openai_tools_agent(self.langchain.llm, tools, prompt)
        return AgentExecutor(agent=agent, tools=tools, memory=self.memory, verbose=False)  # Reduce verbose output

    def analyze_kics_results(self, kics_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze KICS results with enhanced AI capabilities"""
        print("🔍 Analyzing KICS results with enhanced AI...")

        # Convert results to JSON string for the tool
        kics_json = json.dumps(kics_results)

        # Use the agent to analyze
        result = self.agent.invoke({"input": f"Analyze these KICS security findings and provide comprehensive insights: {kics_json}"})

        return {"original_kics_results": kics_results, "enhanced_analysis": result, "timestamp": datetime.now().isoformat()}

    def analyze_steampipe_results(self, steampipe_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Steampipe results with enhanced AI capabilities"""
        print("🔍 Analyzing Steampipe results with enhanced AI...")

        # Convert results to JSON string for the tool
        steampipe_json = json.dumps(steampipe_results)

        # Use the agent to analyze
        result = self.agent.invoke({"input": f"Analyze these Steampipe cloud findings and provide comprehensive insights: {steampipe_json}"})

        return {"original_steampipe_results": steampipe_results, "enhanced_analysis": result, "timestamp": datetime.now().isoformat()}

    def run_comprehensive_analysis(self, kics_results: Optional[Dict[str, Any]] = None, steampipe_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run comprehensive analysis combining KICS and Steampipe results"""
        print("🚀 Running comprehensive security analysis...")

        analysis_summary = []

        if kics_results:
            kics_analysis = self.analyze_kics_results(kics_results)
            analysis_summary.append(f"KICS Analysis: {len(kics_results.get('queries', []))} queries analyzed")

        if steampipe_results:
            steampipe_analysis = self.analyze_steampipe_results(steampipe_results)
            analysis_summary.append(f"Steampipe Analysis: {len(steampipe_results.get('findings', []))} findings analyzed")

        # Generate comprehensive recommendations
        recommendations_input = "\n".join(analysis_summary)
        recommendations = self.agent.invoke(
            {"input": f"Based on the following analysis summary, provide comprehensive security recommendations: {recommendations_input}"}
        )

        return {
            "kics_analysis": kics_analysis if kics_results else None,
            "steampipe_analysis": steampipe_analysis if steampipe_results else None,
            "comprehensive_recommendations": recommendations,
            "analysis_summary": analysis_summary,
            "timestamp": datetime.now().isoformat(),
        }

    async def async_analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Asynchronously analyze multiple findings"""
        print(f"🔄 Analyzing {len(findings)} findings asynchronously...")

        tasks = []
        for finding in findings:
            task = asyncio.create_task(self._async_analyze_single_finding(finding))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [result for result in results if not isinstance(result, Exception)]

    async def _async_analyze_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Asynchronously analyze a single finding"""
        finding_json = json.dumps(finding)

        result = await self.agent.ainvoke({"input": f"Analyze this security finding: {finding_json}"})

        return {"original_finding": finding, "enhanced_analysis": result, "timestamp": datetime.now().isoformat()}

    def generate_security_report(self, analysis_results: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generate a comprehensive security report"""
        print("📊 Generating comprehensive security report...")

        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"outputs/reports/enhanced_security_report_{timestamp}.json"

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Save the analysis results
        with open(output_path, "w") as f:
            json.dump(analysis_results, f, indent=2, default=str)

        print(f"✅ Enhanced security report saved to: {output_path}")
        return output_path

    def create_knowledge_base(self, documents: List[Document]) -> None:
        """Create a knowledge base for enhanced analysis"""
        print("📚 Creating knowledge base for enhanced analysis...")
        self.langchain.initialize_knowledge_base(documents)
        print("✅ Knowledge base created successfully")

    def query_knowledge_base(self, query: str) -> str:
        """Query the knowledge base for relevant information"""
        if not self.langchain.knowledge_base:
            return "Knowledge base not initialized"

        return self.langchain.create_rag_chain(query)


def create_enhanced_agent(config: Optional[Dict] = None) -> EnhancedSecurityAgent:
    """Factory function to create enhanced security agent"""
    return EnhancedSecurityAgent(config)


def main():
    """Test the enhanced security agent"""
    try:
        # Initialize enhanced agent
        agent = create_enhanced_agent()

        # Test with sample KICS results
        sample_kics_results = {
            "queries": [
                {
                    "query_name": "S3 Bucket Public Access",
                    "severity": "HIGH",
                    "description": "S3 bucket is publicly accessible",
                    "files": [{"file_name": "test.tf", "line": 10}],
                }
            ]
        }

        # Test with sample Steampipe results
        sample_steampipe_results = {
            "findings": [
                {
                    "query_name": "Unencrypted S3 Bucket",
                    "severity": "MEDIUM",
                    "description": "S3 bucket without encryption",
                    "resources": ["bucket1", "bucket2"],
                }
            ]
        }

        # Test comprehensive analysis
        print("🔍 Testing comprehensive analysis...")
        analysis = agent.run_comprehensive_analysis(kics_results=sample_kics_results, steampipe_results=sample_steampipe_results)

        # Generate report
        report_path = agent.generate_security_report(analysis)

        print("🎉 Enhanced security agent test completed successfully!")
        print(f"📄 Report generated: {report_path}")

    except Exception as e:
        print(f"❌ Error testing enhanced security agent: {e}")


if __name__ == "__main__":
    main()
