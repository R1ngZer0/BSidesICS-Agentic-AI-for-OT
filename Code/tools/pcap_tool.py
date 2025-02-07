from scapy.all import rdpcap, IP, TCP, UDP
from typing import Dict, List, Optional
from datetime import datetime
import os
from pydantic import BaseModel
import hashlib

class PcapFlowRecord(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    timestamp: datetime
    payload_size: int
    flow_hash: str
    packet_count: int
    metadata: Dict

class PcapTool:
    def __init__(self):
        self.input_dir = "Data/pcap_files"
        os.makedirs(self.input_dir, exist_ok=True)
    
    def list_pcap_files(self) -> List[str]:
        """List all PCAP files in the input directory"""
        return [f for f in os.listdir(self.input_dir) 
                if f.endswith(('.pcap', '.pcapng'))]
    
    def process_pcap_file(self, filename: str) -> List[PcapFlowRecord]:
        """Process a PCAP file and extract network flows"""
        file_path = os.path.join(self.input_dir, filename)
        packets = rdpcap(file_path)
        
        # Track flows using a dictionary
        flows = {}
        
        for packet in packets:
            if IP in packet:
                ip_layer = packet[IP]
                timestamp = datetime.fromtimestamp(float(packet.time))
                
                # Extract protocol information
                if TCP in packet:
                    protocol = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                else:
                    protocol = "OTHER"
                    sport = None
                    dport = None
                
                # Create flow key
                flow_key = self._create_flow_hash(
                    ip_layer.src, ip_layer.dst, 
                    sport, dport, protocol
                )
                
                # Update or create flow record
                if flow_key in flows:
                    flows[flow_key].packet_count += 1
                    flows[flow_key].payload_size += len(packet)
                else:
                    flows[flow_key] = PcapFlowRecord(
                        source_ip=ip_layer.src,
                        destination_ip=ip_layer.dst,
                        source_port=sport,
                        destination_port=dport,
                        protocol=protocol,
                        timestamp=timestamp,
                        payload_size=len(packet),
                        flow_hash=flow_key,
                        packet_count=1,
                        metadata={
                            "first_seen": timestamp,
                            "last_seen": timestamp,
                            "filename": filename
                        }
                    )
                
                # Update last seen timestamp
                flows[flow_key].metadata["last_seen"] = timestamp
        
        return list(flows.values())
    
    @staticmethod
    def _create_flow_hash(src_ip: str, dst_ip: str, 
                         src_port: Optional[int], 
                         dst_port: Optional[int], 
                         protocol: str) -> str:
        """Create a unique hash for a network flow"""
        components = [src_ip, dst_ip, str(src_port), 
                     str(dst_port), protocol]
        flow_string = "|".join(components)
        return hashlib.md5(flow_string.encode()).hexdigest() 