#!/usr/bin/env python3
"""
LangChain Integration for DriftBuddy
Enhances KICS and Steampipe capabilities with advanced AI features including:
- Memory for context-aware analysis
- Chains for multi-step reasoning
- Agents for autonomous security analysis
- RAG (Retrieval-Augmented Generation) for knowledge base integration
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
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.tools import BaseTool
from langchain_community.vectorstores import FAISS
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from .config import get_config
from .exceptions import DriftBuddyError


class SecurityAnalysisTool(BaseTool):
    """Tool for analyzing security findings with context"""

    name: str = "security_analysis"
    description: str = "Analyze security findings with business context and risk assessment"
    llm: Any = None

    def __init__(self, llm):
        super().__init__()
        self.llm = llm

    def _run(self, query: str) -> str:
        """Run the security analysis tool"""
        prompt = ChatPromptTemplate.from_messages(
            [("system", "You are a cybersecurity expert. Analyze the security finding and provide detailed insights."), ("human", "{query}")]
        )

        chain = prompt | self.llm | StrOutputParser()
        return chain.invoke({"query": query})

    async def _arun(self, query: str) -> str:
        """Async run of the security analysis tool"""
        prompt = ChatPromptTemplate.from_messages(
            [("system", "You are a cybersecurity expert. Analyze the security finding and provide detailed insights."), ("human", "{query}")]
        )

        chain = prompt | self.llm | StrOutputParser()
        return await chain.ainvoke({"query": query})


class RemediationTool(BaseTool):
    """Tool for generating remediation code"""

    name: str = "remediation_generator"
    description: str = "Generate remediation code for security findings"
    llm: Any = None

    def __init__(self, llm):
        super().__init__()
        self.llm = llm

    def _run(self, finding: str) -> str:
        """Generate remediation code for a security finding"""
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a security remediation expert. Generate specific code to fix the security issue."),
                ("human", "Generate remediation code for: {finding}"),
            ]
        )

        chain = prompt | self.llm | StrOutputParser()
        return chain.invoke({"finding": finding})

    async def _arun(self, finding: str) -> str:
        """Async generation of remediation code"""
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a security remediation expert. Generate specific code to fix the security issue."),
                ("human", "Generate remediation code for: {finding}"),
            ]
        )

        chain = prompt | self.llm | StrOutputParser()
        return await chain.ainvoke({"finding": finding})


class DriftBuddyLangChain:
    """LangChain integration for DriftBuddy with advanced AI capabilities"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or get_config()
        self.llm = self._initialize_llm()
        # Initialize memory without deprecated parameters
        self.memory = ConversationBufferMemory(return_messages=True)
        self.vector_store = None
        self.knowledge_base = None

    def _initialize_llm(self) -> ChatOpenAI:
        """Initialize the LangChain LLM with configuration"""
        api_key = self.config.get("openai_api_key")
        if not api_key:
            raise DriftBuddyError("OpenAI API key not configured")

        return ChatOpenAI(model="o4-mini", temperature=0, api_key=api_key, max_tokens=2000)

    def create_analysis_chain(self):
        """Create a chain for security analysis with memory"""
        prompt = ChatPromptTemplate.from_messages(
            [("system", "You are a cybersecurity expert analyzing infrastructure security findings."), ("human", "{input}")]
        )

        chain = prompt | self.llm | StrOutputParser()
        return chain

    def create_remediation_chain(self):
        """Create a chain for generating remediation code"""
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a security remediation expert. Generate specific, actionable code to fix security issues."),
                ("human", "Generate remediation code for: {finding}"),
            ]
        )

        chain = prompt | self.llm | StrOutputParser()
        return chain

    def create_security_agent(self) -> AgentExecutor:
        """Create an agent for autonomous security analysis"""
        tools = [SecurityAnalysisTool(self.llm), RemediationTool(self.llm)]

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a cybersecurity expert agent. Use the available tools to analyze security findings and generate remediation."),
                ("human", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ]
        )

        agent = create_openai_tools_agent(self.llm, tools, prompt)
        return AgentExecutor(agent=agent, tools=tools, memory=self.memory, verbose=False)  # Reduce verbose output

    def initialize_knowledge_base(self, documents: List[Document]) -> None:
        """Initialize a knowledge base with security documents"""
        if not documents:
            return

        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)

        splits = text_splitter.split_documents(documents)

        embeddings = OpenAIEmbeddings(api_key=self.config.get("openai_api_key"))

        self.vector_store = FAISS.from_documents(splits, embeddings)
        self.knowledge_base = self.vector_store.as_retriever()

    def analyze_with_context(self, finding: Dict[str, Any], context: str = "") -> Dict[str, Any]:
        """Analyze a security finding with context using LangChain"""
        chain = self.create_analysis_chain()

        # Prepare the input with context
        input_text = f"""
        Security Finding Analysis:
        
        Query: {finding.get('query_name', 'Unknown')}
        Severity: {finding.get('severity', 'Unknown')}
        Description: {finding.get('description', 'No description')}
        Files Affected: {len(finding.get('files', []))}
        
        Context: {context}
        
        Please provide a comprehensive analysis including:
        1. Technical explanation
        2. Business impact
        3. Risk assessment
        4. Remediation recommendations
        """

        result = chain.invoke({"input": input_text})

        return {"original_finding": finding, "ai_analysis": result, "timestamp": datetime.now().isoformat()}

    def generate_remediation_with_chain(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate remediation code using LangChain chain"""
        chain = self.create_remediation_chain()

        finding_summary = f"""
        Query: {finding.get('query_name', 'Unknown')}
        Severity: {finding.get('severity', 'Unknown')}
        Description: {finding.get('description', 'No description')}
        Files: {finding.get('files', [])}
        """

        remediation_code = chain.invoke({"finding": finding_summary})

        return {"original_finding": finding, "remediation_code": remediation_code, "timestamp": datetime.now().isoformat()}

    def run_autonomous_analysis(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run autonomous analysis using LangChain agent"""
        agent = self.create_security_agent()

        # Prepare comprehensive input for the agent
        findings_summary = "\n\n".join(
            [f"Finding {i+1}: {finding.get('query_name', 'Unknown')} - {finding.get('severity', 'Unknown')}" for i, finding in enumerate(findings)]
        )

        input_text = f"""
        Analyze these security findings and provide comprehensive remediation:
        
        {findings_summary}
        
        Please:
        1. Analyze each finding for business impact
        2. Generate specific remediation code
        3. Provide risk mitigation strategies
        4. Suggest monitoring and alerting
        """

        result = agent.invoke({"input": input_text})

        return {"findings": findings, "agent_analysis": result, "timestamp": datetime.now().isoformat()}

    def enhance_kics_analysis(self, kics_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance KICS results with LangChain analysis"""
        queries = kics_results.get("queries", [])
        enhanced_queries = []

        for query in queries:
            if query.get("files"):  # Only process queries with findings
                enhanced_query = self.analyze_with_context(query)
                enhanced_queries.append(enhanced_query)

        return {"original_kics_results": kics_results, "enhanced_analysis": enhanced_queries, "timestamp": datetime.now().isoformat()}

    def enhance_steampipe_analysis(self, steampipe_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance Steampipe results with LangChain analysis"""
        findings = steampipe_results.get("findings", [])
        enhanced_findings = []

        for finding in findings:
            enhanced_finding = self.analyze_with_context(finding)
            enhanced_findings.append(enhanced_finding)

        return {"original_steampipe_results": steampipe_results, "enhanced_analysis": enhanced_findings, "timestamp": datetime.now().isoformat()}

    def create_rag_chain(self, query: str) -> str:
        """Create a RAG chain for knowledge-based analysis"""
        if not self.knowledge_base:
            return "Knowledge base not initialized"

        # Retrieve relevant documents
        docs = self.knowledge_base.get_relevant_documents(query)

        # Create RAG chain
        rag_prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a cybersecurity expert. Use the provided context to answer the question."),
                ("human", "Context: {context}\n\nQuestion: {question}"),
            ]
        )

        def format_docs(docs):
            return "\n\n".join([doc.page_content for doc in docs])

        rag_chain = (
            {"context": RunnablePassthrough.assign(context=lambda x: format_docs(docs)), "question": RunnablePassthrough.assign(question=lambda x: x)}
            | rag_prompt
            | self.llm
            | StrOutputParser()
        )

        return rag_chain.invoke(query)

    async def async_analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Asynchronously analyze multiple findings"""
        tasks = []

        for finding in findings:
            task = asyncio.create_task(self._async_analyze_single_finding(finding))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [result for result in results if not isinstance(result, Exception)]

    async def _async_analyze_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Asynchronously analyze a single finding"""
        chain = self.create_analysis_chain()

        input_text = f"""
        Analyze this security finding:
        Query: {finding.get('query_name', 'Unknown')}
        Severity: {finding.get('severity', 'Unknown')}
        Description: {finding.get('description', 'No description')}
        """

        result = await chain.arun(input_text)

        return {"original_finding": finding, "ai_analysis": result, "timestamp": datetime.now().isoformat()}

    def save_analysis_to_file(self, analysis: Dict[str, Any], output_path: str) -> None:
        """Save LangChain analysis results to file"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(analysis, f, indent=2, default=str)

        print(f"✅ LangChain analysis saved to: {output_path}")


def create_langchain_integration(config: Optional[Dict] = None) -> DriftBuddyLangChain:
    """Factory function to create LangChain integration"""
    return DriftBuddyLangChain(config)


def main():
    """Test the LangChain integration"""
    try:
        # Initialize LangChain integration
        langchain_integration = create_langchain_integration()

        # Test with sample finding
        sample_finding = {
            "query_name": "S3 Bucket Public Access",
            "severity": "HIGH",
            "description": "S3 bucket is publicly accessible",
            "files": [{"file_name": "test.tf", "line": 10}],
        }

        # Test analysis chain
        print("🔍 Testing LangChain analysis...")
        analysis = langchain_integration.analyze_with_context(sample_finding)
        print("✅ Analysis completed")

        # Test remediation chain
        print("🔧 Testing remediation generation...")
        remediation = langchain_integration.generate_remediation_with_chain(sample_finding)
        print("✅ Remediation generated")

        print("🎉 LangChain integration test completed successfully!")

    except Exception as e:
        print(f"❌ Error testing LangChain integration: {e}")


if __name__ == "__main__":
    main()
