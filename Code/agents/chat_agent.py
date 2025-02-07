from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Literal
from pydantic_ai import Agent, RunContext
from utils.db_helpers import DatabaseManager
from models.base_models import Asset, VulnerabilityRecord, PcapRecord
from datetime import datetime
from agents.knowledge_base_agent import KnowledgeBaseManager

class ChatQueryAnalysisRequest(BaseModel):
    query: str = Field(..., description="User's chat query")
    context: Dict = Field(default_factory=dict, description="Current conversation context")

class ChatQueryAnalysisResponse(BaseModel):
    query_type: Literal["database", "vector_search", "knowledge_base"] = Field(
        ..., 
        description="Type of query to perform"
    )
    data_type: Optional[Literal["assets", "vulnerabilities", "network_flows", "knowledge"]] = Field(
        None,
        description="Type of data to query"
    )
    search_params: Dict = Field(
        default_factory=dict,
        description="Parameters for the search"
    )
    explanation: str = Field(..., description="Explanation of the chosen query approach")

class ChatResponseRequest(BaseModel):
    query: str = Field(..., description="User's original query")
    data: Dict = Field(..., description="Retrieved data to base response on")
    context: Dict = Field(default_factory=dict, description="Additional context")

class ChatResponseFormatted(BaseModel):
    response: str = Field(..., description="Formatted response to the user")
    suggested_followups: List[str] = Field(
        default_factory=list,
        description="Suggested follow-up questions"
    )

# Query analyzer agent
query_analyzer = Agent(
    'openai:gpt-4o',
    result_type=ChatQueryAnalysisResponse,
    system_prompt="""You are a cybersecurity expert assistant that helps analyze user queries.
    Determine whether the query needs:
    1. Direct database lookup (for specific asset/vulnerability info)
    2. Vector search (for semantic similarity or complex queries)
    3. Knowledge base search (for policy/standard related questions)
    Consider the query context and choose the most efficient approach."""
)

# Response formatter agent
response_formatter = Agent(
    'openai:gpt-4o',
    result_type=ChatResponseFormatted,
    system_prompt="""You are a cybersecurity expert assistant that provides clear, 
    actionable responses to user queries. Format the information in a clear, 
    structured way and suggest relevant follow-up questions."""
)

class ChatManager:
    def __init__(self):
        self.db = DatabaseManager()
        self.query_analyzer = query_analyzer
        self.response_formatter = response_formatter
        self.kb_manager = KnowledgeBaseManager()
        self.conversation_history = []
    
    async def process_query(self, query: str) -> Dict:
        """Process a user's chat query and return a response"""
        
        # Analyze the query
        analysis = await self.query_analyzer.run(
            ChatQueryAnalysisRequest(
                query=query,
                context={"history": self.conversation_history[-5:] if self.conversation_history else []}
            )
        )
        
        # Get the data based on analysis
        if analysis.data.query_type == "database":
            data = await self._handle_database_query(
                analysis.data.data_type,
                analysis.data.search_params
            )
        elif analysis.data.query_type == "vector_search":
            data = await self._handle_vector_search(
                analysis.data.data_type,
                query,
                analysis.data.search_params
            )
        else:  # knowledge_base
            data = await self._handle_knowledge_search(
                query,
                analysis.data.search_params
            )
        
        # Format the response
        formatted_response = await self.response_formatter.run(
            ChatResponseRequest(
                query=query,
                data=data,
                context={"query_type": analysis.data.query_type}
            )
        )
        
        # Update conversation history
        self.conversation_history.append({
            "query": query,
            "response": formatted_response.data.response,
            "timestamp": datetime.now()
        })
        
        return {
            "response": formatted_response.data.response,
            "suggested_followups": formatted_response.data.suggested_followups,
            "query_type": analysis.data.query_type,
            "explanation": analysis.data.explanation
        }
    
    async def _handle_database_query(self, data_type: str, params: Dict) -> Dict:
        """Handle direct database queries"""
        if data_type == "assets":
            if "asset_id" in params:
                asset = await self.db.get_asset(params["asset_id"])
                return {"asset": asset.dict() if asset else None}
            # Add more asset query types as needed
            
        elif data_type == "vulnerabilities":
            if "asset_id" in params:
                vulns = await self.db.get_vulnerabilities_for_asset(params["asset_id"])
                return {"vulnerabilities": [v.dict() for v in vulns]}
            # Add more vulnerability query types
            
        elif data_type == "network_flows":
            if "asset_id" in params:
                flows = await self.db.get_pcap_records_for_asset(params["asset_id"])
                return {"flows": [f.dict() for f in flows]}
            # Add more network flow query types
        
        return {}
    
    async def _handle_vector_search(self, collection: str, query: str, params: Dict) -> Dict:
        """Handle semantic vector searches"""
        results = await self.db.search_vector_database(
            collection_name=collection,
            query_text=query,
            filter_params=params.get("filters", {}),
            limit=params.get("limit", 5)
        )
        return {"vector_results": results}
    
    async def _handle_knowledge_search(self, query: str, params: Dict) -> Dict:
        """Handle knowledge base searches using RAG"""
        kb_response = await self.kb_manager.query_knowledge_base(
            query,
            context={"conversation_history": self.conversation_history}
        )
        return {
            "knowledge_results": kb_response["answer"],
            "sources": kb_response["sources"],
            "confidence": kb_response["confidence"]
        } 