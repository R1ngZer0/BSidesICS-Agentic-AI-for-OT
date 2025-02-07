from pydantic import BaseModel
from typing import Literal
from functools import lru_cache

class Settings(BaseModel):
    # OpenAI Configuration
    openai_api_key: str
    
    # MongoDB Configuration
    mongodb_uri: str
    mongodb_db_name: str
    
    # Chroma Configuration
    chroma_persist_directory: str
    
    # Application Mode
    app_mode: Literal["cloud", "local"] = "cloud"
    
    # Model Configuration
    cloud_llm_model: str = "gpt-4"
    local_llm_model: str = "llama3.1:8b"
    cloud_embedding_model: str = "text-embedding-3-small"
    local_embedding_model: str = "nomic-text-embed"
    
    model_config = {
        "env_file": "Code/.env"
    }

@lru_cache()
def get_settings():
    return Settings()
