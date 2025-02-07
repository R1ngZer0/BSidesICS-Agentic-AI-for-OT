from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
from uuid import UUID, uuid4

class Asset(BaseModel):
    id: UUID = uuid4()
    hostname: Optional[str]
    ip_address: str
    mac_address: Optional[str]
    os_info: Optional[Dict]
    services: Optional[List[Dict]]
    vulnerabilities: Optional[List[Dict]]
    network_data: Optional[List[Dict]]
    last_updated: datetime = datetime.now()

class VulnerabilityRecord(BaseModel):
    id: UUID = uuid4()
    asset_id: UUID
    vulnerability_id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    remediation: Optional[str]
    detected_date: datetime = datetime.now()

class NetworkScan(BaseModel):
    id: UUID = uuid4()
    scan_type: str
    scan_parameters: Dict
    start_time: datetime
    end_time: Optional[datetime]
    results: List[Dict]
    raw_data: str

class PcapRecord(BaseModel):
    id: UUID = uuid4()
    asset_id: UUID
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    payload_size: int
    metadata: Optional[Dict] 