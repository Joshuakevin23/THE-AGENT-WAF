import os
import sys
import json
import time
import requests
from typing import Dict, Any, List

PROXY_URL = "http://localhost:8000/invoke"

def invoke_waf(agent_id: str, session_id: str, tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Sends a tool call request to the WAF proxy."""
    payload = {
      "agent_id": agent_id,
      "session_id": session_id,
      "tool": tool,
      "params": params
    }
    try:
        response = requests.post(PROXY_URL, json=payload, timeout=10)
        return response.json()
    except Exception as e:
        print(f"Error calling proxy: {e}")
        return {"status": "error", "error": str(e), "disposition": "blocked", "reason": "Proxy connection error"}

def run_groq_agent(user_prompt: str, agent_id: str, session_id: str, model: str = "llama3-70b-8192"):
    """
    Runs a real tool use loop using the Groq API key and OpenAI-compatible endpoint.
    Sends all tools through the WAF proxy.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("Error: GROQ_API_KEY environment variable is not set.")
        return

    print(f"\n--- Starting Groq LLM Agent with prompt: '{user_prompt}' ---")
    print(f"Using Model: {model} | Session ID: {session_id}\n")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    tools_schema = [
        {
            "type": "function",
            "function": {
                "name": "get_schema",
                "description": "Retrieves the database schema showing tables and column definitions."
            }
        },
        {
            "type": "function",
            "function": {
                "name": "validate_sql",
                "description": "Validates the structure of a SQL query prior to execution. Required step before executing SQL.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "The SQL query to check syntax."}
                    },
                    "required": ["sql"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "execute_sql",
                "description": "Runs a SQL query against the database and returns rows. Must only call after validating the SQL.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "The SQL query to run."}
                    },
                    "required": ["sql"]
                }
            }
        }
    ]

    messages = [
        {
            "role": "system",
            "content": (
                "You are an AI assistant that translates natural language questions into SQLite queries and answers them.\n"
                "You must use the provided database tools in order to complete your task.\n"
                "CRITICAL INSTRUCTIONS:\n"
                "1. First, always inspect the schema of the database using get_schema.\n"
                "2. When you build your query, you must first validate it using validate_sql.\n"
                "3. If validation succeeds, execute the query using execute_sql to obtain results.\n"
                "4. All tables you query must start with 'project_x_'. Any other table will fail security restrictions.\n"
                "5. Only call one tool at a time."
            )
        },
        {"role": "user", "content": user_prompt}
    ]

    max_steps = 10
    step = 0

    while step < max_steps:
        step += 1
        print(f"[LLM Agent Step {step}] Planning next action...")
        
        payload = {
            "model": model,
            "messages": messages,
            "tools": tools_schema,
            "tool_choice": "auto"
        }

        try:
            res = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=20)
            if res.status_code != 200:
                print(f"Groq API returned error {res.status_code}: {res.text}")
                break

            res_json = res.json()
            choice = res_json["choices"][0]
            message = choice["message"]
            messages.append(message)

            # Check if model wants to call a tool
            if "tool_calls" in message and message["tool_calls"]:
                tool_call = message["tool_calls"][0]
                tool_name = tool_call["function"]["name"]
                
                try:
                    tool_args = json.loads(tool_call["function"]["arguments"])
                except Exception:
                    tool_args = {}

                print(f"🤖 LLM requested tool: {tool_name} with params: {tool_args}")
                
                # Execute tool call through our WAF Proxy!
                waf_response = invoke_waf(agent_id=agent_id, session_id=session_id, tool=tool_name, params=tool_args)
                print(f"🛡️ WAF Disposition: {waf_response.get('disposition')} | Risk: {waf_response.get('risk_band')} ({waf_response.get('risk_score')})")

                # If WAF blocked the call, stop the execution or feed the error back to the LLM
                if waf_response.get("disposition") == "blocked":
                    print(f"🛑 Tool call BLOCKED by WAF. Reason: {waf_response.get('reason')}")
                    # Feed block result back to LLM so it can report the block to the user
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": tool_name,
                        "content": json.dumps({"status": "blocked", "error": f"Security Policy Violation: {waf_response.get('reason')}"})
                    })
                else:
                    # Success/Shadow Block (both execute the tool and return the output)
                    result_data = waf_response.get("result", {})
                    print(f"✅ Tool result: {str(result_data)[:200]}...")
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": tool_name,
                        "content": json.dumps(result_data)
                    })
            else:
                # No more tool calls, LLM gave its final text response
                print(f"\nFinal LLM Response:\n{message['content']}\n")
                break
        except Exception as e:
            print(f"Exception during LLM loop: {e}")
            break

def run_scripted_agent(session_id: str):
    """
    Runs a pre-defined sequence of calls to verify typical behaviors.
    """
    agent_id = "agent-scripted"
    print(f"\n--- Running Scripted Agent Demo (Session: {session_id}) ---")
    
    # 1. get_schema
    print("\n[Step 1] Calling get_schema...")
    res = invoke_waf(agent_id, session_id, "get_schema", {})
    print(json.dumps(res, indent=2))
    
    # 2. validate_sql
    sql = "SELECT * FROM project_x_customers;"
    print(f"\n[Step 2] Calling validate_sql for query: {sql}")
    res = invoke_waf(agent_id, session_id, "validate_sql", {"sql": sql})
    print(json.dumps(res, indent=2))
    
    # 3. execute_sql
    print(f"\n[Step 3] Calling execute_sql for query: {sql}")
    res = invoke_waf(agent_id, session_id, "execute_sql", {"sql": sql})
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    session_id = f"sess-{int(time.time())}"
    if len(sys.argv) > 1:
        # Prompt query mode
        prompt = sys.argv[1]
        model = sys.argv[2] if len(sys.argv) > 2 else "llama3-70b-8192"
        if not os.environ.get("GROQ_API_KEY"):
            print("To run the LLM loop, set the GROQ_API_KEY environment variable. Running scripted demo instead.")
            run_scripted_agent(session_id)
        else:
            run_groq_agent(prompt, "agent-groq", session_id, model)
    else:
        run_scripted_agent(session_id)
