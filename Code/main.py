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
from agents.chat_agent import ChatManager
from utils.settings_manager import SettingsManager, SettingsUpdate
from rich.prompt import Prompt, Confirm
from agents.knowledge_base_agent import KnowledgeBaseManager

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
    table.add_row("5", "Process Knowledge Base")
    table.add_row("6", "Settings")
    table.add_row("7", "Exit")
    
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
            asyncio.run(chat_with_assistant())
        elif choice == "5":
            asyncio.run(process_knowledge_base())
        elif choice == "6":
            change_settings()
        elif choice == "7":
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

async def chat_with_assistant():
    """Chat with the cybersecurity assistant"""
    chat_manager = ChatManager()
    
    console.print("\n[cyan]Chat with OT Cybersecurity Assistant[/cyan]")
    console.print("Type 'exit' to return to main menu\n")
    
    while True:
        query = typer.prompt("You")
        
        if query.lower() == 'exit':
            break
        
        with Progress(transient=True) as progress:
            task = progress.add_task("Thinking...", total=None)
            
            try:
                result = await chat_manager.process_query(query)
                
                # Display response
                console.print(f"\n[green]Assistant:[/green] {result['response']}\n")
                
                # Display suggested follow-ups if any
                if result["suggested_followups"]:
                    console.print("[cyan]Suggested follow-up questions:[/cyan]")
                    for i, question in enumerate(result["suggested_followups"], 1):
                        console.print(f"{i}. {question}")
                    console.print()
                
            except Exception as e:
                console.print(f"\n[red]Error: {str(e)}[/red]\n")
            
            finally:
                progress.update(task, completed=True)

async def process_knowledge_base():
    """Process knowledge base documents"""
    kb_manager = KnowledgeBaseManager()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing knowledge base documents...", total=None)
        
        try:
            results = await kb_manager.process_documents()
            
            console.print("\n[green]Knowledge base processing completed![/green]")
            console.print(f"Processed {results['processed_documents']} documents")
            
        except Exception as e:
            console.print(f"\n[red]Error processing knowledge base: {str(e)}[/red]")
        
        finally:
            progress.update(task, completed=True)

def change_settings():
    """Manage application settings"""
    settings_manager = SettingsManager()
    
    while True:
        console.print("\n[cyan]Settings Management[/cyan]")
        
        # Display current settings
        table = Table(title="Current Settings")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        current_settings = settings_manager.get_current_settings()
        for key, value in current_settings.items():
            table.add_row(key, str(value))
        
        console.print(table)
        
        # Display settings menu
        settings_menu = Table(title="Settings Menu")
        settings_menu.add_column("Option", style="cyan")
        settings_menu.add_column("Description", style="green")
        
        settings_menu.add_row("1", "Change Application Mode")
        settings_menu.add_row("2", "Update OpenAI API Key")
        settings_menu.add_row("3", "Update MongoDB Settings")
        settings_menu.add_row("4", "Update Chroma Settings")
        settings_menu.add_row("5", "Validate Settings")
        settings_menu.add_row("6", "Return to Main Menu")
        
        console.print(settings_menu)
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            app_mode = Prompt.ask(
                "Select application mode",
                choices=["cloud", "local"],
                default=current_settings.get('APP_MODE', 'cloud')
            )
            settings_manager.update_settings(SettingsUpdate(app_mode=app_mode))
            
        elif choice == "2":
            api_key = Prompt.ask("Enter OpenAI API key")
            if Confirm.ask("Are you sure you want to update the API key?"):
                settings_manager.update_settings(SettingsUpdate(openai_api_key=api_key))
            
        elif choice == "3":
            uri = Prompt.ask(
                "Enter MongoDB URI",
                default=current_settings.get('MONGODB_URI', 'mongodb://localhost:27017')
            )
            db_name = Prompt.ask(
                "Enter database name",
                default=current_settings.get('MONGODB_DB_NAME', 'ot_cybersecurity')
            )
            settings_manager.update_settings(SettingsUpdate(
                mongodb_uri=uri,
                mongodb_db_name=db_name
            ))
            
        elif choice == "4":
            chroma_dir = Prompt.ask(
                "Enter Chroma persistence directory",
                default=current_settings.get('CHROMA_PERSIST_DIRECTORY', './Data/chroma_db')
            )
            settings_manager.update_settings(SettingsUpdate(
                chroma_persist_directory=chroma_dir
            ))
            
        elif choice == "5":
            validation = settings_manager.validate_settings()
            
            validation_table = Table(title="Settings Validation")
            validation_table.add_column("Setting", style="cyan")
            validation_table.add_column("Status", style="green")
            
            for setting, is_valid in validation.items():
                validation_table.add_row(
                    setting,
                    "[green]Valid[/green]" if is_valid else "[red]Invalid[/red]"
                )
            
            console.print(validation_table)
            
            if not all(validation.values()):
                console.print("\n[yellow]Warning: Some settings are invalid or missing![/yellow]")
            
            if Prompt.ask("Press Enter to continue..."):
                continue
            
        elif choice == "6":
            break

if __name__ == "__main__":
    app() 