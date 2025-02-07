# BSidesICS

A comprehensive cybersecurity tool for OT environments that provides vulnerability management, network scanning, traffic analysis, and AI-powered assistance.

## Features

- **Vulnerability Management**
  - Process and analyze vulnerability scan results
  - AI-powered severity assessment
  - Correlation with assets and network data

- **Network Scanning**
  - Multiple Nmap scan types (basic, aggressive discovery, service version, OS detection)
  - AI-driven scan parameter selection
  - Automated result processing and storage

- **Traffic Analysis**
  - PCAP file processing
  - Network flow analysis
  - Risk assessment and anomaly detection

- **Knowledge Base**
  - Process security documentation and policies
  - RAG-based query system
  - Source-cited responses

- **Chat Assistant**
  - Context-aware responses
  - Access to all system data
  - Suggested follow-up questions

## Usage

1. Start the application:
   ```bash
   python Code/main.py
   ```

2. Use the interactive menu to:
   - Process vulnerability scans
   - Perform Nmap scans
   - Analyze PCAP files
   - Chat with the assistant
   - Process knowledge base documents
   - Configure settings

## Data Organization

Place your input files in the following directories:
- `Data/vulnerability_scans/` - Vulnerability scan results
- `Data/pcap_files/` - Network capture files
- `Data/knowledge_base/` - PDF documentation
- `Data/nmap_scans/` - Nmap scan results

## Configuration

Configure the application through the settings menu or by editing `Code/.env`:
- Application mode (cloud/local)
- OpenAI API key
- MongoDB connection
- Chroma persistence directory

## Initial Setup

1. Create a `.env` file in the `Code` directory:
   ```bash
   cd Code
   touch .env
   ```

2. Add the following required environment variables to `Code/.env`:
   ```bash
   # OpenAI Configuration
   OPENAI_API_KEY=your_openai_api_key_here
   
   # MongoDB Configuration
   MONGODB_URI=mongodb://localhost:27017
   MONGODB_DB_NAME=ot_cybersecurity
   
   # Chroma Configuration
   CHROMA_PERSIST_DIRECTORY=./Data/chroma_db
   
   # Application Mode (cloud or local)
   APP_MODE=cloud
   ```

3. Create required data directories:
   ```bash
   mkdir -p Data/{vulnerability_scans,pcap_files,knowledge_base,nmap_scans,chroma_db}
   ```

4. Start MongoDB:
   - If using Docker:
     ```bash
     docker run -d -p 27017:27017 --name mongodb mongo:latest
     ```
   - Or use your existing MongoDB installation

# Setting up the Python Environment

This guide will help you set up a Python virtual environment and install the required dependencies.

## Prerequisites

- Python 3.8 or higher installed on your system
- pip (Python package installer)

## Setup Instructions

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```

2. Activate the virtual environment:
   - On Windows:
     ```bash
     .venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source .venv/bin/activate
     ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Verifying the Setup

After installation, you can verify that everything is set up correctly by:

1. Confirming you're in the virtual environment (you should see `(.venv)` in your terminal prompt)
2. Running:
   ```bash
   python -c "import openai, ollama, pydantic; print('Setup successful!')"
   ```

## Deactivating the Environment

When you're done working, you can deactivate the virtual environment:

## Troubleshooting

Common issues:

1. **Missing Environment Variables**
   - Error: `ValidationError: n validation errors for Settings`
   - Solution: Ensure all required variables are set in `Code/.env`

2. **MongoDB Connection**
   - Error: `Cannot connect to MongoDB`
   - Solution: Verify MongoDB is running and the connection URI is correct

3. **OpenAI API Key**
   - Error: `Invalid API key`
   - Solution: Check your OpenAI API key is valid and properly set in `.env`