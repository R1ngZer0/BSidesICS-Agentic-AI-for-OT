from typing import Dict, List, Optional
from datetime import datetime
import fitz  # PyMuPDF
import os
from pydantic import BaseModel

class KnowledgeBaseDocument(BaseModel):
    title: str
    content: str
    metadata: Dict
    processed_date: datetime
    source_file: str

class KnowledgeBaseTool:
    def __init__(self):
        self.input_dir = "Data/knowledge_base"
        os.makedirs(self.input_dir, exist_ok=True)
    
    def list_documents(self) -> List[str]:
        """List all PDF files in the knowledge base directory"""
        return [f for f in os.listdir(self.input_dir) if f.endswith('.pdf')]
    
    def process_document(self, filename: str) -> KnowledgeBaseDocument:
        """Process a PDF document and extract its content"""
        file_path = os.path.join(self.input_dir, filename)
        
        try:
            # Open the PDF file
            doc = fitz.open(file_path)
            
            # Extract text from all pages
            content = ""
            for page in doc:
                content += page.get_text()
            
            # Get basic metadata
            metadata = {
                "page_count": len(doc),
                "format": doc.metadata.get("format", ""),
                "title": doc.metadata.get("title", filename),
                "author": doc.metadata.get("author", ""),
                "creation_date": doc.metadata.get("creationDate", "")
            }
            
            doc.close()
            
            return KnowledgeBaseDocument(
                title=metadata["title"],
                content=content,
                metadata=metadata,
                processed_date=datetime.now(),
                source_file=filename
            )
            
        except Exception as e:
            raise Exception(f"Error processing PDF {filename}: {str(e)}") 