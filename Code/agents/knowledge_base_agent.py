from pydantic import BaseModel, Field
from typing import List, Dict
from pydantic_ai import Agent, RunContext
from tools.knowledge_base_tool import KnowledgeBaseTool, KnowledgeBaseDocument
from utils.db_helpers import DatabaseManager
from utils.embedding_manager import EmbeddingManager
from datetime import datetime

class KnowledgeBaseQueryRequest(BaseModel):
    query: str = Field(..., description="User's knowledge base query")
    context: Dict = Field(default_factory=dict, description="Additional context")

class KnowledgeBaseResponse(BaseModel):
    answer: str = Field(..., description="Answer based on knowledge base documents")
    sources: List[str] = Field(..., description="Source documents used")
    confidence: float = Field(..., description="Confidence score for the answer")

knowledge_base_agent = Agent(
    'openai:gpt-4o',
    result_type=KnowledgeBaseResponse,
    system_prompt="""You are a cybersecurity expert assistant that provides answers based on 
    the organization's knowledge base documents. Always cite your sources and provide accurate,
    policy-compliant responses. If information is not found in the provided context, acknowledge this."""
)

class KnowledgeBaseManager:
    def __init__(self):
        self.kb_tool = KnowledgeBaseTool()
        self.agent = knowledge_base_agent
        self.db = DatabaseManager()
        self.embedding_manager = EmbeddingManager()
    
    async def process_documents(self) -> Dict:
        """Process all documents in the knowledge base"""
        documents = self.kb_tool.list_documents()
        processed_count = 0
        
        for doc_name in documents:
            # Process document
            doc = self.kb_tool.process_document(doc_name)
            
            # Get embedding for document content
            embedding = await self.embedding_manager.get_embedding(doc.content)
            
            # Store in vector database
            await self.db.store_vector_embedding(
                collection_name="knowledge_base",
                text=doc.content,
                metadata={
                    "title": doc.title,
                    "document_type": doc.document_type,
                    **doc.metadata
                },
                embedding=embedding
            )
            
            processed_count += 1
        
        return {
            "processed_documents": processed_count
        }
    
    async def query_knowledge_base(self, query: str, context: Dict = None) -> Dict:
        """Query the knowledge base using RAG"""
        # Get relevant documents
        results = await self.db.search_vector_database(
            collection_name="knowledge_base",
            query_text=query,
            limit=3
        )
        
        # Format context for the agent
        context_docs = "\n\n".join([
            f"Document: {r['metadata']['title']}\nContent: {r['document']}"
            for r in results
        ])
        
        # Get AI response
        response = await self.agent.run(
            KnowledgeBaseQueryRequest(
                query=query,
                context={
                    "documents": context_docs,
                    **(context or {})
                }
            )
        )
        
        return {
            "answer": response.data.answer,
            "sources": response.data.sources,
            "confidence": response.data.confidence
        } 