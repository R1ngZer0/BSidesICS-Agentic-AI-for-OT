import asyncio
from typing import Dict, List, Optional
from pydantic import BaseModel
import xml.etree.ElementTree as ET
from datetime import datetime
import os

class NmapScanParameters(BaseModel):
    target: str
    scan_type: str
    additional_args: Optional[List[str]] = []
    timeout: int = 3600  # Default 1 hour timeout

class NmapTool:
    SCAN_TYPES = {
        "basic": ["-sn"],  # Basic ping scan
        "aggressive_discovery": ["-sS", "-T4", "-n"],  # Aggressive host discovery
        "service_version": ["-sS", "-sV", "-T4", "-n"],  # With service version detection
        "os_detection": ["-sS", "-sV", "-O", "-T4", "-n"],  # With OS detection
        "vulnerability": ["-sS", "-sV", "-O", "--script vuln", "-T4", "-n"]  # With vulnerability scan
    }
    
    def __init__(self):
        self.output_dir = "Data/nmap_scans"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run_scan(self, params: NmapScanParameters) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{self.output_dir}/scan_{timestamp}.xml"
        
        base_args = self.SCAN_TYPES.get(params.scan_type, [""])
        cmd = ["nmap"] + base_args + params.additional_args + [
            "-oX", output_file,
            params.target
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            await asyncio.wait_for(process.communicate(), timeout=params.timeout)
        except asyncio.TimeoutError:
            process.terminate()
            raise TimeoutError(f"Scan timed out after {params.timeout} seconds")
        
        return output_file
    
    @staticmethod
    def parse_xml_output(xml_file: str) -> Dict:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        result = {
            "hosts": [],
            "scan_info": {
                "start_time": root.get("start", ""),
                "args": root.get("args", ""),
            }
        }
        
        for host in root.findall("host"):
            host_info = {
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os_matches": []
            }
            
            # Get addresses
            for addr in host.findall("address"):
                host_info["addresses"].append({
                    "addr": addr.get("addr"),
                    "addrtype": addr.get("addrtype")
                })
            
            # Get ports and services
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_info = {
                        "protocol": port.get("protocol"),
                        "portid": port.get("portid"),
                        "state": port.find("state").get("state") if port.find("state") is not None else "",
                        "service": {}
                    }
                    
                    service = port.find("service")
                    if service is not None:
                        port_info["service"] = {
                            "name": service.get("name"),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "extrainfo": service.get("extrainfo", "")
                        }
                    
                    host_info["ports"].append(port_info)
            
            # Get OS detection results
            os_elem = host.find("os")
            if os_elem is not None:
                for match in os_elem.findall("osmatch"):
                    host_info["os_matches"].append({
                        "name": match.get("name"),
                        "accuracy": match.get("accuracy")
                    })
            
            result["hosts"].append(host_info)
        
        return result 