from typing import Dict, List, Optional
from models.base_models import Asset, VulnerabilityRecord, PcapRecord
from pydantic import BaseModel

class AssetCorrelation(BaseModel):
    asset: Asset
    vulnerabilities: List[VulnerabilityRecord]
    network_flows: List[PcapRecord]
    confidence_score: float

class AssetCorrelator:
    @staticmethod
    def correlate_by_ip(ip_address: str, assets: List[Asset]) -> Optional[Asset]:
        """Find an asset by IP address"""
        for asset in assets:
            if asset.ip_address == ip_address:
                return asset
        return None
    
    @staticmethod
    def correlate_by_mac(mac_address: str, assets: List[Asset]) -> Optional[Asset]:
        """Find an asset by MAC address"""
        for asset in assets:
            if asset.mac_address == mac_address:
                return asset
        return None
    
    @staticmethod
    def calculate_confidence(matches: Dict) -> float:
        """Calculate confidence score for correlation"""
        score = 0.0
        weights = {
            "ip_match": 0.4,
            "mac_match": 0.4,
            "hostname_match": 0.2
        }
        
        for key, weight in weights.items():
            if matches.get(key, False):
                score += weight
        
        return score 