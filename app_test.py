import httpx
import asyncio
import logging
import random
import string
import json
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP("CloudlabMcp")

# Base URLs
LOGIN_URL = "http://localhost:9999/v1/users/login"
CREATE_USER_URL = "http://localhost:9999/v1/users"
CREATE_LAB_URL = "http://localhost:9999/v1/subscriptions"
CLOUD_LAB_BASE_URL = "http://localhost:9999/v1/"

# authenication user 

@mcp.tool()
async def authenticate_cloudlab():
    """
    Authenticates to CloudLab and returns session_name, sessid, and token.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = {
        "username": "devadmin2",
        "password": "RishAnk@7080"
    }

    async with httpx.AsyncClient() as client:
        try:
            logger.info("Authenticating with Cloudlab...")
            response = await client.post(LOGIN_URL, headers=headers, data=payload)
            response.raise_for_status()
            data = response.json()
            logger.info("Authentication successful.")
            return {
                "session_name": data.get("session_name"),
                "sessid": data.get("sessid"),
                "token": data.get("token")
            }
        except httpx.RequestError as exc:
            logger.error(f"Request error: {exc}")
            return {"error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            logger.error(f"HTTP error: {exc.response.status_code} - {exc.response.text}")
            return {"error": f"HTTP error: {exc.response.status_code} - {exc.response.text}"}


# create user 
@mcp.tool()
async def create_user(auth_data: str, userEmailId: str):
    """
    Creates a user in CloudLab using provided session_name, sessid, and token as JSON string.
    """
    try:
        auth_data = json.loads(auth_data)
    except Exception as e:
        return {"status": "failed", "error": f"Invalid JSON input: {str(e)}"}

    session_name = auth_data.get("session_name")
    sessid = auth_data.get("sessid")
    csrf_token = auth_data.get("token")

    if not all([session_name, sessid, csrf_token]):
        return {"status": "failed", "error": "Missing authentication values."}

    # Construct cookie and headers
    cookies = {session_name: sessid}
    headers = {
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache"
    }

    # Generate unique email
   # randomstring = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
   # useremailid = f"pintushuka+{randomstring}@mail.com"

    payload = {
        "userName": userEmailId,
        "password": "Welcome123$",
        "firstName": "redirectlabtestfn",
        "lastName": "ln",
        "companyId": "3",
        "teamId":"6"
    }

    async with httpx.AsyncClient(verify=False) as client:
        try:
            logger.info("Creating user...")
            response = await client.post(CREATE_USER_URL, headers=headers, data=payload, cookies=cookies)
            response.raise_for_status()
            result = response.json()
            logger.info("user created successfully.")
            return {"status": "success", "data": result}
        except httpx.RequestError as exc:
            return {"status": "failed", "error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            return {"status": "failed", "error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}



# create lab 

@mcp.tool()
async def create_lab(auth_data: str, userEmailId: str):
    """
    Provisions a Lab for a given user in CloudLab.

    This function is typically used after authentication and user creation are complete.
    It uses session authentication values (session_name, sessid, token) and a unique user email
    to create a lab environment for learning or training purposes.

    Prerequisites:
    - Must call `authenticate_cloudlab()` first to get the auth session.
    - Must call `create_user()` to create a valid user before provisioning a lab.
    - Pass the same `auth_data` and `userEmailId` used in the previous steps.

    Parameters:
        auth_data (str): JSON string containing session_name, sessid, and token returned from authentication.
        userEmailId (str): Email ID of the user for whom the lab should be provisioned.

    Returns:
        dict: A response dict indicating success or failure with details from the CloudLab API.

    Example:
        auth = authenticate_cloudlab()
        create_user(auth, "student@example.com")
        create_lab(auth, "student@example.com")
    """
    try:
        auth_data = json.loads(auth_data)
    except Exception as e:
        return {"status": "failed", "error": f"Invalid JSON input: {str(e)}"}

    session_name = auth_data.get("session_name")
    sessid = auth_data.get("sessid")
    csrf_token = auth_data.get("token")

    if not all([session_name, sessid, csrf_token]):
        return {"status": "failed", "error": "Missing authentication values."}

    # Construct cookie and headers
    cookies = {session_name: sessid}
    headers = {
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache"
    }

    # Generate unique email
   # randomstring = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
   # useremailid = f"pintushuka+{randomstring}@mail.com"

    
    createLabPayload = {
        "planId": "5",
        "userName": userEmailId,
        "companyId": "3",
        "teamId": "6"
    }

    async with httpx.AsyncClient(verify=False) as client:
        try:
            logger.info("Creating user...")
            response = await client.post(CREATE_LAB_URL, headers=headers, data=createLabPayload, cookies=cookies)
            response.raise_for_status()
            result = response.json()
            logger.info("Lab created successfully.")
            return {"status": "success", "data": result}
        except httpx.RequestError as exc:
            return {"status": "failed", "error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            return {"status": "failed", "error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}



# Delete Lab
@mcp.tool()
async def delete_lab(auth_data: str, subscriptionId: str):
    """
    Deletes a lab (subscription) in CloudLab by subscriptionId.

    Parameters:
        auth_data (str): JSON string with session_name, sessid, and token.
        subscriptionId (str): The ID of the lab subscription to delete.

    Returns:
        dict: Success or failure message with server response.
    """
    if not subscriptionId or subscriptionId.strip() == "":
        return {
            "status": "failed",
            "error": "Missing or empty subscriptionId. Please provide a valid subscription ID to delete the lab."
        }
    
    try:
        auth_data = json.loads(auth_data)
    except Exception as e:
        return {"status": "failed", "error": f"Invalid JSON input: {str(e)}"}

    session_name = auth_data.get("session_name")
    sessid = auth_data.get("sessid")
    csrf_token = auth_data.get("token")

    if not all([session_name, sessid, csrf_token]):
        return {"status": "failed", "error": "Missing authentication values."}

    cookies = {session_name: sessid}
    headers = {
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    delete_url = f"{CLOUD_LAB_BASE_URL}subscriptions/{subscriptionId}"

    async with httpx.AsyncClient(verify=False) as client:
        try:
            logger.info(f"Deleting lab for subscriptionId: {subscriptionId}")
            response = await client.delete(delete_url, headers=headers, cookies=cookies)
            response.raise_for_status()

            # Sometimes DELETE returns no JSON body
            try:
                result = response.json()
            except Exception:
                result = {"message": "Deleted successfully"}

            return {"status": "success", "data": result}

        except httpx.RequestError as exc:
            logger.error(f"Request error: {exc}")
            return {"status": "failed", "error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            logger.error(f"HTTP error {exc.response.status_code}: {exc.response.text}")
            return {"status": "failed", "error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}



# perfrom Action
@mcp.tool()
async def perform_action(auth_json: str, subscriptionId: str, actionName: str, userEmailId: str):
    """
    Performs an action on a lab subscription in CloudLab.
    
    Common actions: start, stop, suspend, resume.

    Parameters:
        auth_json (str): JSON string with session_name, sessid, and token.
        subscriptionId (str): The ID of the lab subscription to act upon.
        actionName (str): The action to perform ("start", "stop", etc.).
        userEmailId (str): The user associated with the lab.

    Returns:
        dict: Result of the action execution.
    """
    # Validate input
    if not subscriptionId or not actionName or not userEmailId:
        return {"status": "failed", "error": "Missing required parameters: subscriptionId, actionName, or userEmailId."}

    try:
        auth_data = json.loads(auth_json)
    except Exception as e:
        return {"status": "failed", "error": f"Invalid JSON input: {str(e)}"}

    session_name = auth_data.get("session_name")
    sessid = auth_data.get("sessid")
    csrf_token = auth_data.get("token")

    if not all([session_name, sessid, csrf_token]):
        return {"status": "failed", "error": "Missing authentication values."}

    cookies = {session_name: sessid}
    headers = {
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache"
    }
    actionName = actionName[:1].upper() + actionName[1:].lower()
    payload = {
        "subscriptionId": subscriptionId,
        "actionName": actionName,
        "userName": userEmailId
    }

    perform_action_url = f"{CLOUD_LAB_BASE_URL}subscriptions/performAction"

    async with httpx.AsyncClient(verify=False) as client:
        try:
            logger.info(f"Performing action '{actionName}' on subscription {subscriptionId}...")
            response = await client.post(perform_action_url, headers=headers, data=payload, cookies=cookies)
            response.raise_for_status()
            result = response.json()
            logger.info(f"Action '{actionName}' performed successfully.")
            return {"status": "success", "data": result}
        except httpx.RequestError as exc:
            logger.error(f"Request error: {exc}")
            return {"status": "failed", "error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            logger.error(f"HTTP error {exc.response.status_code}: {exc.response.text}")
            return {"status": "failed", "error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}



# Optional: manual runner
async def main():
    auth = await authenticate_cloudlab()
    if "error" in auth:
        print("Auth failed:", auth["error"])
        return
    userEmailId = ""

   # Create user
    auth_json = json.dumps(auth)
    user_result = await create_user(auth_json, userEmailId)
    if user_result["status"] == "failed":
        print("Create user failed:", user_result["error"])
        return
    
    # Create lab
    lab_result = await create_lab(auth_json, userEmailId)
    if lab_result["status"] == "failed":
        print("Create lab failed:", lab_result["error"])
      #  return
    
     # Delete lab
    subscriptionId = ""
    lab_result = await delete_lab(auth_json, subscriptionId )
    if lab_result["status"] == "failed":
        print("Create lab failed:", lab_result["error"])
        return
    
     # perfrom Action
    actionName = ""
    perfrom_action=await perform_action(auth_json,subscriptionId,actionName,userEmailId)
    if perfrom_action["status"] == "failed":
        print("Create lab failed:", perfrom_action["error"])
        return


if __name__ == "__main__":
    asyncio.run(main())
