from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os
from typing import Literal
from functools import lru_cache

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    # OpenAI Configuration
    openai_api_key: str = os.getenv('OPENAI_API_KEY')
    
    # MongoDB Configuration
    mongodb_uri: str = os.getenv('MONGODB_URI')
    mongodb_db_name: str = os.getenv('MONGODB_DB_NAME')
    
    # Chroma Configuration
    chroma_persist_directory: str = os.getenv('CHROMA_PERSIST_DIRECTORY')
    
    # Application Mode
    app_mode: Literal["cloud", "local"] = "cloud"
    
    # Model Configuration
    cloud_llm_model: str = "gpt-4"
    local_llm_model: str = "llama3.1:8b"
    cloud_embedding_model: str = "text-embedding-3-small"
    local_embedding_model: str = "nomic-text-embed"
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
