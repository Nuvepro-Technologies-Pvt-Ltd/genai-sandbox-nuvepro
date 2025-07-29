from fastmcp import FastMCP
import random
import string
import asyncio
import os
import json
import sys
import httpx
import sys
import io
import re
import shelve
import uuid
from typing import Optional

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Create an MCP server
mcp = FastMCP("CloudlabMcp")

# Read for property file
API_key = os.environ.get("API_KEY")
BASE_URL = os.environ.get("Baseurl")
SESSION_DB_PATH = os.path.join("data", "session_store")
#planId = os.environ.get("planId")
#companyId = os.environ.get("companyId")
#teamId = os.environ.get("teamId")
compnaykey = os.environ.get("compnaykey")


# Simulated in-memory session store
session_store = {}

def generate_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def decrypt_from_api_key(api_key: str, passphrase: str) -> dict:
    try:
        salt_hex, nonce_hex, ciphertext_hex = api_key.split('.')
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)

        key = generate_key(passphrase, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return json.loads(plaintext.decode('utf-8'))

    except Exception as e:
        return {"error": str(e)}


# ✅ Utility: Detect language from code string
def detect_language(code: str) -> str:
    code = code.strip()
    if code.startswith("def ") or "import " in code:
        return "python"
    elif "console.log" in code or "function(" in code:
        return "javascript"
    elif "#include" in code or "int main()" in code:
        return "cpp"
    elif "public class" in code or "System.out.println" in code:
        return "java"
    else:
        return "unknown"  # fallback


# ✅ Internal helper method
def create_lab_session(useremailid: str) -> str:
    """
    Creates a new session if one doesn't exist and returns the generated username.
    """
    if useremailid not in session_store:
        generated_username = generate_admin_email()
        session_store[useremailid] = {
            "username": generated_username
        }
    else:
        generated_username = session_store[useremailid]["username"]

    return generated_username


# ✅ generaye default email id 
def generate_admin_email() -> str:
    """Generate a unique admin email."""
    return f"user_{uuid.uuid4().hex[:8]}@lab.nuvepro.com"

def create_lab_sessionInfo() -> str:
    os.makedirs("data", exist_ok=True)
    with shelve.open(SESSION_DB_PATH) as session_store:
        
        # keys_to_delete = [key for key in session_store if "username" in session_store[key]]
        # for key in keys_to_delete:
        #   del session_store[key]
        # ✅ If any user is already stored, return their username
        if session_store:
            first_key = next(iter(session_store))
            
            return session_store[first_key]["username"]
        
        # ❌ No users stored yet, create one
        generated_username = generate_admin_email()
        unique_key = str(uuid.uuid4())  # Random unique ID as key
        session_store[unique_key] = {"username": generated_username}
        return generated_username


# Internal auth function (not exposed to user)
async def _authenticate_cloudlab():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    decrypted_payload = decrypt_from_api_key(API_key, "MySuperSecretKey")

    if isinstance(decrypted_payload, dict) and "error" in decrypted_payload:
      return decrypted_payload  # Return error message

    USERNAME = decrypted_payload.get("USERNAME")
    PASSWORD = decrypted_payload.get("PASSWORD")

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


# ✅ Get subscription plan details based on sandbox (language)
async def _get_subscription_info(cookies, headers, sandbox: str):
    
    # Handle decryption failure
    decrypted_payload = decrypt_from_api_key(compnaykey, "MySuperSecretKey")

    if isinstance(decrypted_payload, dict) and "error" in decrypted_payload:
      return decrypted_payload  # Return error message

    planId = decrypted_payload.get("planId")
    companyId = decrypted_payload.get("companyId")
    teamId = decrypted_payload.get("teamId")
    # Unpack decrypted values safely
    
    return {
                "companyId": str(companyId),
                "teamId": str(teamId),
                "planId": str(planId)
        }
    

       

# ✅ Updated user creation accepting team/company
async def _createuser(cookies, headers, userEmailId: str, companyId: str, teamId: str):
    payload = {
        "userName": userEmailId,
        "password": "Welcome123$",
        "firstName": "redirectlabtestfn",
        "lastName": "redirectlabtestln",
        "companyId": companyId,
        "teamId": teamId
    }

    CREATE_USER_URL = f"{BASE_URL}v1/users"

    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.post(CREATE_USER_URL,headers=headers,data=payload,cookies=cookies)
            result = response.json()
        
            print("✅ User created successfully!")
            return {
                    "status": "created",
                    "result": result,
                    "userEmailId": userEmailId
                    }  
        except httpx.HTTPStatusError as e:
            print(f"🚨 HTTP error: {e.response.status_code} - {e.response.text}")
            return {"status": "failed", "error": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            print(f"⚠️ Unexpected error: {str(e)}")
            return {"status": "failed", "error": str(e)}




# ✅ Handle creation logic (e.g. log, print, or prep something)
async def _create_lab(username: str ,detected_lang:str) -> dict:
    
    auth_data = await _authenticate_cloudlab()
    
    if "error" in auth_data:
        return {"status": "failed", "error": auth_data["error"]}

    session_name = auth_data.get("session_name")
    sessid = auth_data.get("sessid")
    csrf_token = auth_data.get("token")

    if not all([session_name, sessid, csrf_token]):
        return {"status": "failed", "error": "Missing authentication values."}

    cookies = {session_name: sessid}
    headers = {
        "X-CSRF-Token": csrf_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
     

    #✅ Get plan/team/company info for selected sandbox type
    subscription_info = await _get_subscription_info(cookies, headers, detected_lang)
   
    if "error" in subscription_info:
        return {"status": "failed", "error": subscription_info["error"]}

    companyId = subscription_info["companyId"]
    teamId = subscription_info["teamId"]
    planId = subscription_info["planId"]

    if not all([companyId, teamId, planId]):
        return {"status": "failed", "error": "Missing required subscription info."} 
    
    #  #✅ Create user (or detect existing)
    user_result = await _createuser(cookies, headers, username, companyId, teamId)
    if user_result is None or "status" not in user_result:
        return {"status": "failed", "error": "User creation failed or incomplete."}
    
    
    #Step 4: Create lab (or handle "Lab already exists")
    
    #Step 3: Create or reuse lab
    CREATE_LAB_URL = f"{BASE_URL}v1/subscriptions"
    payload = {
        "planId": planId,
        "userName": username,
        "companyId": companyId,
        "teamId": teamId
    }

    subscription_id = None
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.post(
                CREATE_LAB_URL,
                headers=headers,
                data=payload,
                cookies=cookies
            )
            result = response.json()
            if result.get("MessageCode") == "1012":  # Lab already exists
                subscription_ids = result.get("subscriptionIds", [])
                if subscription_ids:
                    subscription_id= subscription_ids[0]
                else:
                    return {"status": "failed", "error": "Lab exists but no subscription ID found."}
            else:
               subscription_id= result.get("subscriptionId")
                
        except httpx.HTTPStatusError as e:
            return {"status": "failed", "error": f"HTTP error: {e.response.status_code} - {e.response.text}"}
        except Exception as e:
           return {"status": "failed", "error": f"Unexpected error: {str(e)}"}
     
    
    
      # Step 4: Retry launch until userAccess is available (max 6 mins)
    LAUNCH_URL = f"{BASE_URL}v1/subscriptions/launch"
    launch_payload = {"subscriptionId": subscription_id}

    max_retries = 10
    delay_between_retries = 60  # seconds
    async with httpx.AsyncClient(verify=False) as client:
        for attempt in range(1, max_retries + 1):
            try:
               print(f"⏳ Launch attempt {attempt}/{max_retries} for subscriptionId {subscription_id}")
               launch_resp = await client.post(LAUNCH_URL,headers=headers,data=launch_payload,cookies=cookies)
               launch_result = launch_resp.json()
               user_access = launch_result.get("userAccess")
               if user_access:
                   print("✅ User access available!")
                   return {
                       "userAccess": user_access,
                   }

               print("⚠️ Lab not ready yet. Retrying in 60 seconds...")
               await asyncio.sleep(delay_between_retries)
            except Exception as e:
               print(f"⚠️ Error during launch attempt {attempt}: {str(e)}")
               await asyncio.sleep(delay_between_retries)
        

async def handle_code_execution(payload: str) -> str:
    username = create_lab_sessionInfo()
    detected_lang = detect_language(payload)
    user_access = await _create_lab(username, detected_lang)
    return user_access
    


async def run_code_in_sandbox(host_id: str, code: str) -> dict:
    url = f"http://{host_id}:8000/run_code"
    headers = {"Content-Type": "application/json"}
    payload = {"code": code}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()
        
        return json.dumps({
            "status": "success",
            "message": "Code executed successfully.",
            "result": result
        })

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






# Synchronous function to read code if file path is given
def read_code_input(payload: Optional[str], filepath: Optional[str], latest_generated: Optional[str]) -> str:
    if payload:
        return payload

    if filepath and os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                return f.read()
        except Exception as e:
            return f"# Error reading file: {str(e)}"

    if latest_generated:
        return latest_generated

    # Fallback
    return 'print("Welcome to Nuvelink")'


# ✅ Exposed async tool
@mcp.tool(name="execute_code", description="Execute code in a secure sandbox environment.")
async def execute_code(
    payload: Optional[str] = None,
    filepath: Optional[str] = None,
    latest_generated: Optional[str] = None
) -> str:
    """
    Executes code in a secure sandbox.
    Accepts:
    - payload: code directly
    - filepath: path to code file
    - latest_generated: fallback prompt-generated code
    """
    host_id=""
    sample_code = read_code_input(payload, filepath, latest_generated)
    
    user_access = await handle_code_execution(sample_code)

    if "error" in user_access:
        return f"Error: {user_access['error']}"
    
    user_access_list = json.loads(user_access['userAccess'])

    # # Extract the ServerIP
    server_ip = next(item['value'] for item in user_access_list if item['key'] == 'ServerIP')
    
    return await run_code_in_sandbox(server_ip, sample_code)




# ✅ Start the MCP server
if __name__ == "__main__":
    asyncio.run(mcp.run())
