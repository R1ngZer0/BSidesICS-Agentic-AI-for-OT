from typing import List, Union
import openai
from config import get_settings
import requests

settings = get_settings()

class EmbeddingManager:
    @staticmethod
    async def get_embedding(text: str) -> List[float]:
        """Get embedding based on current application mode"""
        if settings.app_mode == "cloud":
            return await EmbeddingManager._get_openai_embedding(text)
        else:
            return await EmbeddingManager._get_local_embedding(text)
    
    @staticmethod
    async def _get_openai_embedding(text: str) -> List[float]:
        """Get embedding from OpenAI"""
        response = await openai.Embedding.acreate(
            input=text,
            model=settings.cloud_embedding_model
        )
        return response.data[0].embedding
    
    @staticmethod
    async def _get_local_embedding(text: str) -> List[float]:
        """Get embedding from local model via Ollama"""
        response = requests.post(
            "http://localhost:11434/api/embeddings",
            json={
                "model": settings.local_embedding_model,
                "prompt": text
            }
        )
        return response.json()["embedding"] 