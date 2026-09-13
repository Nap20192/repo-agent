"""`adk web web --port 8080`: the same graph as `scan full`, driven from the ADK dev UI.

Type the target into the input: a local directory, or https://github.com/<owner>/<repo> (cloned into .targets/ on
demand). The root node prepares the graph for that target and runs it nested; the run is closed like `scan full`
(SARIF + summary under .runs/). Importing this module has no side effects beyond reading .env.
"""

from scanner.app.runner import load_env, target_node

load_env()
root_agent = target_node()
