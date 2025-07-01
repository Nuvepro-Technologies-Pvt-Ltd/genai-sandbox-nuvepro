from fastmcp import FastMCP
import asyncio
import httpx
import json
import os
import sys

mcp = FastMCP("CloudlabMcp")

BASE_URL = "http://localhost:9999/"
USERNAME = "devadmin2"
PASSWORD = "RishAnk@7080"

@mcp.tool
async def ping():
    return "pong"

# Internal authentication method
async def _authenticate_cloudlab():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = {
        "username": USERNAME,
        "password": PASSWORD
    }
    login_url = f"{BASE_URL}v1/users/login"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(login_url, headers=headers, data=payload)
            response.raise_for_status()
            data = response.json()
            return {
                "session_name": data.get("session_name"),
                "sessid": data.get("sessid"),
                "token": data.get("token")
            }
        except httpx.RequestError as exc:
            print(f"[AUTH REQUEST ERROR] {str(exc)}", file=sys.stderr)
            return {"error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            print(f"[AUTH HTTP ERROR] {exc.response.status_code} - {exc.response.text}", file=sys.stderr)
            return {"error": f"HTTP error: {exc.response.status_code} - {exc.response.text}"}

# Internal method to get DNS from lab details
async def show_lab_deatils():
    auth_data = await _authenticate_cloudlab()

    if "error" in auth_data:
        return {"error": auth_data["error"]}

    session_name = auth_data.get("session_name")
    sessid = auth_data.get("sessid")
    csrf_token = auth_data.get("token")

    if not all([session_name, sessid, csrf_token]):
        return {"error": "Missing authentication values."}

    cookies = {session_name: sessid}
    headers = {
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    lab_details_url = f"{BASE_URL}v1/subscriptions/launch"
    payload = {"subscriptionId": 731}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(lab_details_url, headers=headers, data=payload, cookies=cookies)
            response.raise_for_status()
            lab_info = response.json()
            access_details = lab_info.get("data", {}).get("accessDetails")

            if not access_details:
                return {"error": "Access details not found in lab response."}

            dns_name = access_details.get("dnsName")
            if not dns_name:
                return {"error": "DNS name not found in access details."}

            return {"dns": dns_name}

        except httpx.RequestError as exc:
            print(f"[LAB REQUEST ERROR] {str(exc)}", file=sys.stderr)
            return {"error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            print(f"[LAB HTTP ERROR] {exc.response.status_code}: {exc.response.text}", file=sys.stderr)
            return {"error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}

@mcp.tool(
    name="read_latest_generated_code_and_execute_code",
    description="Allows the user to choose a sandbox (Python or Java) and executes the latest code accordingly."
)
async def read_latest_generated_code_and_execute_code(latest_code: str, language: str = "python"):
    """
    Accepts latest generated code and executes it in a selected sandbox.

    Parameters:
    - latest_code: str = The code to be executed.
    - language: str = "python" or "java" (default: python)

    Returns:
    - JSON with execution result.
    """
    dns_result = await show_lab_deatils()
    if "error" in dns_result:
        return {
            "status": "error",
            "message": dns_result["error"]
        }

    dns_name = dns_result["dns"]
    sandbox_urls = {
        "python": f"http://{dns_name}:8000/run_python_code",
        "java": f"http://{dns_name}:8000/run_java_code"
    }

    if language.lower() not in sandbox_urls:
        return {
            "status": "error",
            "message": f"Unsupported language '{language}'. Please choose 'python' or 'java'."
        }

    url = sandbox_urls[language.lower()]
    headers = {"Content-Type": "application/json"}
    payload = {"code": latest_code}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()

        return {
            "status": "success",
            "language": language.lower(),
            "message": "Code executed successfully.",
            "result": result
        }

    except httpx.RequestError as exc:
        return {
            "status": "error",
            "message": f"Request error: {str(exc)}"
        }
    except httpx.HTTPStatusError as exc:
        return {
            "status": "error",
            "message": f"HTTP error {exc.response.status_code}: {exc.response.text}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }

if __name__ == "__main__":
    asyncio.run(mcp.run())
