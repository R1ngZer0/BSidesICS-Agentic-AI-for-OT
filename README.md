# BSidesICS





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