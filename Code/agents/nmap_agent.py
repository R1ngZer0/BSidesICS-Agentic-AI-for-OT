from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from pydantic_ai import Agent, RunContext
from tools.nmap_tool import NmapTool, NmapScanParameters
from utils.db_helpers import DatabaseManager
from models.base_models import NetworkScan, Asset
from datetime import datetime
import asyncio

class NmapScanRequest(BaseModel):
    target: str = Field(..., description="The target IP address or hostname to scan")
    description: str = Field(..., description="User's description of what they want to scan for")

class NmapScanResponse(BaseModel):
    scan_type: str = Field(..., description="Type of Nmap scan to perform")
    additional_args: List[str] = Field(default_factory=list, description="Additional Nmap arguments")
    timeout: int = Field(default=3600, description="Scan timeout in seconds")
    explanation: str = Field(..., description="Explanation of the chosen scan parameters")

nmap_agent = Agent(
    'openai:gpt-4o',
    result_type=NmapScanResponse,
    system_prompt="""You are a cybersecurity expert specializing in network scanning. 
    Your task is to determine the appropriate Nmap scan type and parameters based on user requests.
    Available scan types are: basic, aggressive_discovery, service_version, os_detection, vulnerability.
    Always prioritize security and efficiency."""
)

class NmapScanManager:
    def __init__(self):
        self.nmap_tool = NmapTool()
        self.agent = nmap_agent
        self.db = DatabaseManager()
    
    async def run_scan(self, user_request: str, target: str):
        # Determine scan parameters
        scan_request = NmapScanRequest(
            target=target,
            description=user_request
        )
        scan_params = await self.agent.run(scan_request)
        
        # Run the scan
        nmap_params = NmapScanParameters(
            target=target,
            scan_type=scan_params.data.scan_type,
            additional_args=scan_params.data.additional_args,
            timeout=scan_params.data.timeout
        )
        
        xml_output = await self.nmap_tool.run_scan(nmap_params)
        
        # Parse results
        scan_results = self.nmap_tool.parse_xml_output(xml_output)
        
        # Process results into assets
        assets = []
        for host in scan_results["hosts"]:
            ip_address = next((addr["addr"] for addr in host["addresses"] 
                             if addr["addrtype"] == "ipv4"), None)
            if not ip_address:
                continue
                
            mac_address = next((addr["addr"] for addr in host["addresses"] 
                              if addr["addrtype"] == "mac"), None)
            
            asset = Asset(
                ip_address=ip_address,
                mac_address=mac_address,
                os_info={
                    "matches": host["os_matches"]
                } if host["os_matches"] else None,
                services=[{
                    "port": port["portid"],
                    "protocol": port["protocol"],
                    "state": port["state"],
                    "service": port["service"]
                } for port in host["ports"]]
            )
            
            assets.append(asset)
        
        # Store scan record
        network_scan = NetworkScan(
            scan_type=scan_params.data.scan_type,
            scan_parameters=nmap_params.dict(),
            start_time=datetime.fromtimestamp(int(scan_results["scan_info"]["start_time"])),
            end_time=datetime.now(),
            results=scan_results,
            raw_data=xml_output
        )
        
        # Store in database
        for asset in assets:
            await self.db.insert_asset(asset)
        
        return {
            "scan_record": network_scan,
            "assets": assets,
            "explanation": scan_params.data.explanation
        } 