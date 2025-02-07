from motor.motor_asyncio import AsyncIOMotorClient
from config import get_settings
from models.base_models import Asset, VulnerabilityRecord, NetworkScan, PcapRecord
import chromadb
from typing import Any, Dict, List
from utils.embedding_manager import EmbeddingManager

settings = get_settings()

class DatabaseManager:
    def __init__(self):
        self.client = AsyncIOMotorClient(settings.mongodb_uri)
        self.db = self.client[settings.mongodb_db_name]
        self.chroma_client = chromadb.PersistentClient(path=settings.chroma_persist_directory)
        
    async def insert_asset(self, asset: Asset) -> str:
        result = await self.db.assets.insert_one(asset.model_dump())
        return str(result.inserted_id)
    
    async def update_asset(self, asset_id: str, update_data: Dict) -> bool:
        result = await self.db.assets.update_one(
            {"_id": asset_id},
            {"$set": update_data}
        )
        return result.modified_count > 0
    
    async def get_asset(self, asset_id: str) -> Asset:
        result = await self.db.assets.find_one({"_id": asset_id})
        return Asset(**result) if result else None

    async def store_vector_embedding(
        self,
        collection_name: str,
        text: str,
        metadata: Dict[str, Any],
        embedding: List[float] = None
    ):
        """Store text and its embedding in the vector database"""
        collection = self.chroma_client.get_or_create_collection(collection_name)
        
        if embedding is None:
            # Get embedding if not provided
            embedding_manager = EmbeddingManager()
            embedding = await embedding_manager.get_embedding(text)
        
        collection.add(
            embeddings=[embedding],
            documents=[text],
            metadatas=[metadata]
        )

    async def insert_vulnerability(self, vulnerability: VulnerabilityRecord) -> str:
        """Insert a vulnerability record into MongoDB"""
        result = await self.db.vulnerabilities.insert_one(vulnerability.model_dump())
        return str(result.inserted_id)

    async def get_vulnerabilities_for_asset(self, asset_id: str) -> List[VulnerabilityRecord]:
        """Get all vulnerabilities for a specific asset"""
        cursor = self.db.vulnerabilities.find({"asset_id": asset_id})
        vulnerabilities = []
        async for doc in cursor:
            vulnerabilities.append(VulnerabilityRecord(**doc))
        return vulnerabilities 

    async def insert_pcap_record(self, pcap_record: PcapRecord) -> str:
        """Insert a PCAP record into MongoDB"""
        result = await self.db.pcap_records.insert_one(pcap_record.model_dump())
        return str(result.inserted_id)

    async def get_pcap_records_for_asset(self, asset_id: str) -> List[PcapRecord]:
        """Get all PCAP records for a specific asset"""
        cursor = self.db.pcap_records.find({"asset_id": asset_id})
        records = []
        async for doc in cursor:
            records.append(PcapRecord(**doc))
        return records 

    async def search_vector_database(
        self,
        collection_name: str,
        query_text: str,
        filter_params: Dict = None,
        limit: int = 5
    ) -> List[Dict]:
        """Search the vector database"""
        collection = self.chroma_client.get_or_create_collection(collection_name)
        
        # Get embedding for query
        embedding_manager = EmbeddingManager()
        embedding = await embedding_manager.get_embedding(query_text)
        
        results = collection.query(
            query_embeddings=[embedding],
            n_results=limit,
            where=filter_params
        )
        
        return [
            {
                "document": doc,
                "metadata": meta,
                "distance": dist
            }
            for doc, meta, dist in zip(
                results['documents'][0],
                results['metadatas'][0],
                results['distances'][0]
            )
        ] 