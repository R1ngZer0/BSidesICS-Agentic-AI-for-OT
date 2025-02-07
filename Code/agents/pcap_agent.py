from pydantic import BaseModel, Field
from typing import List, Dict
from pydantic_ai import Agent, RunContext
from tools.pcap_tool import PcapTool, PcapFlowRecord
from utils.db_helpers import DatabaseManager
from models.base_models import PcapRecord, Asset
from datetime import datetime

class NetworkFlowAnalysisRequest(BaseModel):
    flow_data: Dict = Field(..., description="Network flow data to analyze")
    context: Dict = Field(default_factory=dict, description="Additional context about the network")

class NetworkFlowAnalysisResponse(BaseModel):
    flow_type: str = Field(..., description="Type of network flow (e.g., 'Web Traffic', 'Database Connection')")
    risk_assessment: str = Field(..., description="Risk assessment of the flow")
    anomaly_score: float = Field(..., description="Anomaly score (0-1)")
    recommendations: List[str] = Field(..., description="Security recommendations")

pcap_agent = Agent(
    'openai:gpt-4o',
    result_type=NetworkFlowAnalysisResponse,
    system_prompt="""You are a network security expert specializing in traffic analysis.
    Your task is to analyze network flows and identify potential security concerns.
    Consider the protocol, ports, and traffic patterns when assessing risk.
    Provide practical recommendations for improving security."""
)

class PcapAnalysisManager:
    def __init__(self):
        self.pcap_tool = PcapTool()
        self.agent = pcap_agent
        self.db = DatabaseManager()
    
    async def process_pcap_files(self) -> Dict:
        """Process all PCAP files in the input directory"""
        pcap_files = self.pcap_tool.list_pcap_files()
        
        total_flows = 0
        processed_files = 0
        results_summary = {
            "high_risk_flows": 0,
            "medium_risk_flows": 0,
            "low_risk_flows": 0,
            "total_traffic": 0  # in bytes
        }
        
        for pcap_file in pcap_files:
            # Process the PCAP file
            flows = self.pcap_tool.process_pcap_file(pcap_file)
            
            for flow in flows:
                # Get AI analysis
                analysis = await self.agent.run(
                    NetworkFlowAnalysisRequest(
                        flow_data=flow.dict(),
                        context={"file": pcap_file}
                    )
                )
                
                # Create PCAP record
                pcap_record = PcapRecord(
                    asset_id=None,  # Will be updated if asset is found
                    timestamp=flow.timestamp,
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    protocol=flow.protocol,
                    port=flow.destination_port,
                    payload_size=flow.payload_size,
                    metadata={
                        "flow_type": analysis.data.flow_type,
                        "risk_assessment": analysis.data.risk_assessment,
                        "anomaly_score": analysis.data.anomaly_score,
                        "flow_hash": flow.flow_hash,
                        "packet_count": flow.packet_count
                    }
                )
                
                # Store in vector database for semantic search
                await self.db.store_vector_embedding(
                    collection_name="network_flows",
                    text=f"{analysis.data.flow_type}\n{analysis.data.risk_assessment}\n" + \
                         "\n".join(analysis.data.recommendations),
                    metadata={
                        "source_ip": flow.source_ip,
                        "destination_ip": flow.destination_ip,
                        "protocol": flow.protocol,
                        "risk_level": analysis.data.risk_assessment,
                        "anomaly_score": analysis.data.anomaly_score
                    },
                    embedding=None
                )
                
                # Update summary statistics
                results_summary["total_traffic"] += flow.payload_size
                risk_level = analysis.data.risk_assessment.lower()
                if "high" in risk_level:
                    results_summary["high_risk_flows"] += 1
                elif "medium" in risk_level:
                    results_summary["medium_risk_flows"] += 1
                else:
                    results_summary["low_risk_flows"] += 1
                
                # Store in MongoDB
                await self.db.insert_pcap_record(pcap_record)
                
                total_flows += 1
            
            processed_files += 1
        
        return {
            "processed_files": processed_files,
            "total_flows": total_flows,
            "total_traffic_mb": results_summary["total_traffic"] / (1024 * 1024),
            "risk_summary": {
                "high_risk": results_summary["high_risk_flows"],
                "medium_risk": results_summary["medium_risk_flows"],
                "low_risk": results_summary["low_risk_flows"]
            }
        } 