from pydantic import BaseModel, Field
from typing import Dict, Optional
from config import Settings, get_settings
import json
import os
from rich.prompt import Prompt, Confirm

class SettingsUpdate(BaseModel):
    app_mode: Optional[str] = Field(None, description="Application mode (cloud/local)")
    openai_api_key: Optional[str] = Field(None, description="OpenAI API key")
    mongodb_uri: Optional[str] = Field(None, description="MongoDB connection URI")
    mongodb_db_name: Optional[str] = Field(None, description="MongoDB database name")
    chroma_persist_directory: Optional[str] = Field(None, description="Chroma persistence directory")

class SettingsManager:
    def __init__(self):
        self.settings = get_settings()
        self.env_file = "Code/.env"
        self.current_settings = self._load_current_settings()
    
    def _load_current_settings(self) -> Dict:
        """Load current settings from .env file"""
        settings = {}
        if os.path.exists(self.env_file):
            with open(self.env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        settings[key.strip()] = value.strip()
        return settings
    
    def _save_settings(self, settings: Dict):
        """Save settings to .env file"""
        with open(self.env_file, 'w') as f:
            for key, value in settings.items():
                f.write(f"{key}={value}\n")
    
    def update_settings(self, updates: SettingsUpdate) -> bool:
        """Update settings with new values"""
        updated = False
        new_settings = self.current_settings.copy()
        
        if updates.app_mode:
            new_settings['APP_MODE'] = updates.app_mode
            updated = True
        
        if updates.openai_api_key:
            new_settings['OPENAI_API_KEY'] = updates.openai_api_key
            updated = True
        
        if updates.mongodb_uri:
            new_settings['MONGODB_URI'] = updates.mongodb_uri
            updated = True
        
        if updates.mongodb_db_name:
            new_settings['MONGODB_DB_NAME'] = updates.mongodb_db_name
            updated = True
        
        if updates.chroma_persist_directory:
            new_settings['CHROMA_PERSIST_DIRECTORY'] = updates.chroma_persist_directory
            updated = True
        
        if updated:
            self._save_settings(new_settings)
            self.current_settings = new_settings
        
        return updated
    
    def validate_settings(self) -> Dict[str, bool]:
        """Validate current settings"""
        validation = {
            "app_mode": self.current_settings.get('APP_MODE') in ['cloud', 'local'],
            "openai_api": bool(self.current_settings.get('OPENAI_API_KEY')),
            "mongodb": bool(self.current_settings.get('MONGODB_URI')),
            "chroma": bool(self.current_settings.get('CHROMA_PERSIST_DIRECTORY'))
        }
        return validation
    
    def get_current_settings(self) -> Dict:
        """Get current settings (with sensitive data masked)"""
        settings = self.current_settings.copy()
        if 'OPENAI_API_KEY' in settings:
            settings['OPENAI_API_KEY'] = '****' + settings['OPENAI_API_KEY'][-4:]
        return settings 