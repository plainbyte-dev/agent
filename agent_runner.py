import subprocess
import importlib.util
import tempfile
from pathlib import Path
import json

repo_url = "https://github.com/plainbyte-dev/agent.git"

with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    
    # Clone GitHub repo into temporary directory
    subprocess.run(
        ["git", "clone", repo_url, str(temp_path)],
        check=True,
        timeout=30,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    
    # Check for agent.py
    agent_path = temp_path / "agent.py"
    if not agent_path.exists():
        raise FileNotFoundError(f"agent.py not found in {repo_url}")
    
    # Dynamically load agent.py
    spec = importlib.util.spec_from_file_location("agent", agent_path)
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    
    print("Agent loaded successfully.")
    
    # Load your task.json
    with open("task.json", "r") as f:
        task_data = json.load(f)
    
    # Option 1: If the agent has a main function that accepts task data
    if hasattr(agent, "run"):
        result = agent.run(task_data)
        print("Result:", result)
  
   
    
    
    
    # Option 4: Inspect what's available in the agent module
    else:
        print("Available functions/classes in agent:")
        print([name for name in dir(agent) if not name.startswith("_")])