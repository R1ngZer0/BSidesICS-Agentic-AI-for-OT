import typer
from rich.console import Console
from rich.table import Table
from typing import Optional
from config import get_settings
import asyncio
from agents.nmap_agent import NmapScanManager
from rich.progress import Progress
from agents.vulnerability_scan_agent import VulnerabilityScanManager
from agents.pcap_agent import PcapAnalysisManager

app = typer.Typer()
console = Console()
settings = get_settings()

def display_main_menu():
    table = Table(title="OT Cybersecurity Assistant")
    table.add_column("Option", style="cyan")
    table.add_column("Description", style="green")
    
    table.add_row("1", "Process Vulnerability Scans")
    table.add_row("2", "Perform Nmap Scan")
    table.add_row("3", "Process PCAP Files")
    table.add_row("4", "Chat with Assistant")
    table.add_row("5", "Settings")
    table.add_row("6", "Exit")
    
    console.print(table)

@app.command()
def main():
    """
    OT Cybersecurity Assistant - Main Application
    """
    while True:
        display_main_menu()
        choice = typer.prompt("Select an option")
        
        if choice == "1":
            asyncio.run(process_vulnerability_scans())
        elif choice == "2":
            asyncio.run(perform_nmap_scan())
        elif choice == "3":
            asyncio.run(process_pcap_files())
        elif choice == "4":
            chat_with_assistant()
        elif choice == "5":
            change_settings()
        elif choice == "6":
            typer.echo("Goodbye!")
            break
        else:
            typer.echo("Invalid option. Please try again.")

async def process_vulnerability_scans():
    """Process vulnerability scan files"""
    scan_manager = VulnerabilityScanManager()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing vulnerability scans...", total=None)
        
        try:
            results = await scan_manager.process_scan_files()
            
            console.print("\n[green]Vulnerability scan processing completed![/green]")
            
            # Display results summary
            table = Table(title="Vulnerability Scan Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="green")
            
            table.add_row("Files Processed", str(results["processed_files"]))
            table.add_row("Total Vulnerabilities", str(results["total_vulnerabilities"]))
            table.add_row("High Severity", str(results["severity_summary"]["high_severity"]))
            table.add_row("Medium Severity", str(results["severity_summary"]["medium_severity"]))
            table.add_row("Low Severity", str(results["severity_summary"]["low_severity"]))
            
            console.print(table)
            
        except Exception as e:
            console.print(f"\n[red]Error processing vulnerability scans: {str(e)}[/red]")
        
        finally:
            progress.update(task, completed=True)

async def perform_nmap_scan():
    """Perform Nmap scan based on user input"""
    scan_manager = NmapScanManager()
    
    target = typer.prompt("Enter target IP address or hostname")
    description = typer.prompt("Describe what you want to scan for (e.g., 'Check for open ports and vulnerabilities')")
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Running Nmap scan...", total=None)
        
        try:
            results = await scan_manager.run_scan(description, target)
            
            console.print("\n[green]Scan completed successfully![/green]")
            console.print(f"\nScan explanation: {results['explanation']}")
            
            # Display results summary
            table = Table(title="Scan Results Summary")
            table.add_column("Asset", style="cyan")
            table.add_column("Open Ports", style="green")
            table.add_column("OS Detection", style="yellow")
            
            for asset in results["assets"]:
                open_ports = [f"{p['port']}/{p['protocol']}" 
                            for p in asset.services if p["state"] == "open"]
                os_info = asset.os_info["matches"][0]["name"] if asset.os_info else "Unknown"
                
                table.add_row(
                    asset.ip_address,
                    "\n".join(open_ports[:5]) + ("..." if len(open_ports) > 5 else ""),
                    os_info
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"\n[red]Error during scan: {str(e)}[/red]")
        
        finally:
            progress.update(task, completed=True)

async def process_pcap_files():
    """Process PCAP files"""
    pcap_manager = PcapAnalysisManager()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing PCAP files...", total=None)
        
        try:
            results = await pcap_manager.process_pcap_files()
            
            console.print("\n[green]PCAP processing completed![/green]")
            
            # Display results summary
            table = Table(title="PCAP Analysis Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Files Processed", str(results["processed_files"]))
            table.add_row("Total Flows", str(results["total_flows"]))
            table.add_row("Total Traffic", f"{results['total_traffic_mb']:.2f} MB")
            table.add_row("High Risk Flows", str(results["risk_summary"]["high_risk"]))
            table.add_row("Medium Risk Flows", str(results["risk_summary"]["medium_risk"]))
            table.add_row("Low Risk Flows", str(results["risk_summary"]["low_risk"]))
            
            console.print(table)
            
        except Exception as e:
            console.print(f"\n[red]Error processing PCAP files: {str(e)}[/red]")
        
        finally:
            progress.update(task, completed=True)

def chat_with_assistant():
    # TODO: Implement chat functionality
    pass

def change_settings():
    # TODO: Implement settings management
    pass

if __name__ == "__main__":
    app() 