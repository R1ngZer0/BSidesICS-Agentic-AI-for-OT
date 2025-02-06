# Introduction

This repository contains examples and explanations of how to use [PydanticAI](https://ai.pydantic.dev/) - a Python Agent Framework designed to make it easier to build production-grade applications with Generative AI.

## 👋🏻 About Me

Hi there! I’m Dave Ebbelaar, founder of Datalumina®, and I’m passionate about helping data professionals and developers like you succeed in the world of data science and AI. If you enjoy the tutorial, make sure to check out the links below for more resources to help you grow.

At [Datalumina](https://www.datalumina.com/), we help individuals and businesses unlock the full potential of AI and data by turning complexity into capability. Whether you're learning Python, freelancing, or building cutting-edge AI apps, we provide the tools, guidance, and expertise to help you succeed.

### 📚 Explore More Resources

Whether you're a learner, a freelancer, or a business looking for AI expertise, we've got something for you:

1. **Learning Python for AI and Data Science?**  
   Join our **free community, Data Alchemy**, where you’ll find resources, tutorials, and support:  
   [▶︎ Data Alchemy on Skool](https://www.skool.com/data-alchemy)

2. **Ready to start or scale your freelancing career?**  
   Learn how to land clients and grow your business with the **Data Freelancer program**:  
   [▶︎ Data Freelancer](https://www.datalumina.com/data-freelancer)

3. **Need expert help on your next project?**  
   Work with me and my team to solve your data and AI challenges:  
   [▶︎ Consulting Services](https://www.datalumina.com/solutions)

4. **Building AI-powered applications?**  
   Access the **GenAI Launchpad** to accelerate your AI app development:  
   [▶︎ GenAI Launchpad](https://launchpad.datalumina.com/)

## Introduction to PydanticAI

PydanticAI is a Python Agent Framework created by the team behind Pydantic, designed to streamline the development of production-grade applications with Generative AI. Building on the success and widespread adoption of Pydantic in the Python AI ecosystem, PydanticAI offers a type-safe, model-agnostic approach that seamlessly integrates with popular LLM providers like OpenAI, Gemini, and Groq. The framework emphasizes developer ergonomics by combining structured response validation, streamed responses, and a dependency injection system, all while allowing developers to leverage standard Python development practices for control flow and agent composition.

### Pydantic AI Core Concepts

1. [Agents](https://ai.pydantic.dev/agents/): The primary interface for interacting with LLMs, allowing you to define system prompts and manage interactions.
2. [Dependencies](https://ai.pydantic.dev/dependencies/): A type-safe system for injecting runtime context and accessing external services, making testing and integration easier.
3. [Results](https://ai.pydantic.dev/results/): Agents can return plain text, structured data, or streamed responses, all validated by Pydantic models.
4. [Messages and Chat History](https://ai.pydantic.dev/message-history/): Provides access to complete message history and tools for analyzing agent behavior and continuing conversations.
5. [Testing and Evals](https://ai.pydantic.dev/testing-evals/): Supports unit tests and evaluations to assess model performance and ensure application reliability.
6. [Debugging and Monitoring](https://ai.pydantic.dev/logfire/): Integrates with Pydantic Logfire for real-time debugging, performance monitoring, and querying of agent runs.

### Getting Started

To begin using PydanticAI, follow these steps:

1. **Python**: Ensure you have Python installed on your system. PydanticAI requires Python 3.9 or later.

2. **Install Requirements**: Navigate to the root directory of the repository and install the necessary dependencies by running:

    ```bash
    pip install -r requirements.txt
    ```

3. **Set Up Environment Variables**: Copy the provided `.env.example` file to a new file named `.env`. Open the `.env` file and add your OpenAI API key:

    ```bash
    OPENAI_API_KEY=your_openai_api_key_here
    ```

    Make sure to replace `your_openai_api_key_here` with your actual OpenAI API key.

4. **Run the Introduction Script**: To get a feel for how PydanticAI works, execute the `introduction.py` script:


This script will guide you through the basic functionalities of PydanticAI, demonstrating how to interact with language models using the framework.

By following these steps, you'll be set up to explore and build applications with PydanticAI. For more detailed examples and documentation, refer to the [PydanticAI documentation](https://ai.pydantic.dev/).

### Problems I've Encountered

PydanticAI is in early beta, and the API is still subject to change. There is still a lot more to do.

- **Model Parameters**: Currently, I couldn't find a way to adjust model parameters like temperature.

- **Message History with Tools**: There is a problem with message history when using tools. The following error occurs:

  ```
  BadRequestError: Error code: 400 - {'error': {'message': "An assistant message with 'tool_calls' must be followed by tool messages responding to each 'tool_call_id'. The following tool_call_ids did not have response messages: call_KMMn5Bo6wPN3aZosdstleZO2", 'type': 'invalid_request_error', 'param': 'messages.[6].role', 'code': None}}
  ```