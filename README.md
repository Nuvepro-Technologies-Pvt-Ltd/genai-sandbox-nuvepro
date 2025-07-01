execution in a secure and scalable lab setup.

⚙️ Lab Virtual MCP Server (Execute Code Remotely via Claude AI)
Create a virtual lab for users to run custom code remotely using the Model Context Protocol (MCP) and integrate with Claude AI or other clients.


🔗 GitHub Repo
📦 https://github.com/Nuvepro-Technologies-Pvt-Ltd/McpSever_Remote_code_execution.git
📂 This repo has moved to base/base-mcp

🚀 What This Lab Server Does
🧠 Enables remote Python code execution through cline AI


🧪 Supports real-time lab scenarios (code evaluation, sandbox testing, etc.)

📋 Prerequisites
Ensure you have the following on your system:

✅ Python 3.10.11

✅ pip (Python package manager)

✅ fastmcp (to serve the MCP endpoint)

✅ uv (virtual environment manager, via scoop or curl)

✅ Access to Claude Desktop or Cursor or cline (for testing)



🧱 Installation Steps
1. Set up Python Environment
Windows
powershell
Copy
Edit
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
iwr -useb get.scoop.sh | iex
scoop install python
scoop install uv
macOS/Linux
bash
Copy
Edit
curl -LsSf https://astral.sh/uv/install.sh | sh
2. Clone the MCP Server Repo
bash
Copy
Edit
git clone https://github.com/Nuvepro-Technologies-Pvt-Ltd/McpSever_Remote_code_execution.git
cd McpSever_Remote_code_execution
3. Set Up Virtual Environment
bash
Copy
Edit
python -m venv .venv
.\.venv\Scripts\activate   # Windows
# OR
source .venv/bin/activate  # macOS/Linux
4. Install Dependencies
bash
Copy
Edit
pip install fastmcp
pip install -r requirements.txt
5. Run the Server
bash
Copy
Edit
fastmcp run app.py
You now have a remote code execution server listening for requests via MCP.

🧪 MCP Client Configuration
For Claude Desktop / Cursor, update your mcp_config.json:

<pre> ```json { "mcpServers": { "lab-virtual": { "command": "python", "args": ["app.py"], "env": { "COINBASE_API_PRIVATE_KEY": "your_private_key", "Baseurl": "your seed phrase here" }, "disabled": false, "autoApprove": [] } } } ``` </pre>


Replace the "env" values if you're integrating with blockchain functions; otherwise leave them empty for pure Python code execution.

✅ Available Tools (Prebuilt in MCP)
Tool	Description
execute_code	Executes user-provided Python code
get-address	Retrieves wallet address (optional usage)

🧑‍🏫 Example Use in Claude
User Prompt:

plaintext
Copy
Edit
Run this Python code in my lab environment:
def greet(name): return f"Hello, {name}"
greet("Alice")
Claude routes this to your MCP server and gets the result.

💡 Recommendations for Lab Admins
✅ Add sandboxing logic to app.py if users can run arbitrary code.

✅ Use Docker or subprocess isolation for safer execution (optional).

✅ Monitor logs and set execution timeouts.

