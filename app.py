from fastmcp import FastMCP
import asyncio
import os
import httpx
import asyncio
import json
import random
import string
from typing import List, Union


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

mcp = FastMCP("CloudlabMcp")

API_key = os.environ.get("API_KEY")
BASE_URL = os.environ.get("Baseurl")
planId = os.environ.get("planId")
companyId = os.environ.get("companyId")
teamId = os.environ.get("teamId")




def generate_random_email(domain="cloudlab.com"):
    name = ''.join(random.choices(string.ascii_lowercase, k=7))
    number = str(random.randint(100, 999))
    return f"{name}{number}@{domain}"

@mcp.tool
async def ping():
    return "pong"

def generate_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def decrypt_from_api_key(api_key: str, passphrase: str):
    try:
        salt_hex, nonce_hex, ciphertext_hex = api_key.split(".")
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)

        key = generate_key(passphrase, salt)
        aesgcm = AESGCM(key)

        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        creds = json.loads(decrypted.decode())
        return creds["username"], creds["password"]

    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}

# Internal auth function (not exposed to user)
async def _authenticate_cloudlab():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    decrypted = decrypt_from_api_key(API_key, "MySuperSecretKey")
    
    if isinstance(decrypted, dict) and "error" in decrypted:
        return decrypted  # Return error message

    USERNAME, PASSWORD = decrypted

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


# Create user
import httpx

async def _createuser(cookies, headers, userEmailId):
   
    userEmailId = generate_random_email()
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
            response = await client.post(
                CREATE_USER_URL,
                headers=headers,
                data=payload,
                cookies=cookies
            )
            response.raise_for_status()
            result = response.json()
            user_id = result.get("userId")

            if not user_id:
                print("❌ User ID not found in response.")
                return None

            print(f"✅ User created with ID: {user_id}")
            return result

        except httpx.HTTPStatusError as e:
            print(f"🚨 HTTP error: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"⚠️ Unexpected error: {str(e)}")

    return None




# Create lab 
async def _createlab(cookies, headers):
    
    userEmailId=_createuser(cookies, headers)
    payload = {
        "planId": planId,
        "userName": userEmailId,
        "companyId": companyId,
        "teamId": teamId
    }

    CREATE_LAB_URL = f"{BASE_URL}v1/subscriptions"

    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.post(
                CREATE_LAB_URL,
                headers=headers,
                data=payload,  # fixed variable name
                cookies=cookies
            )
            response.raise_for_status()
            result = response.json()
            subscriptionId = result.get("subscriptionId")

            if not subscriptionId:
                print("❌ Subscription ID not found in response.")
                return None

            print(f"✅ Subscription created with ID: {subscriptionId}")
            return result

        except httpx.HTTPStatusError as e:
            print(f"🚨 HTTP error occurred: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"⚠️ Other error: {str(e)}")

    return None




@mcp.tool(name="show_lab_deatils", description="Fetches Cloudlab lab details using authenticated session.")
async def show_lab_deatils():
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
    
    # Create lab details request
    create_lab = await _createlab(cookies,headers)

    lab_details_url = f"{BASE_URL}v1/subscriptions/launch"
    payload = {"subscriptionId": 731}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(lab_details_url, headers=headers, data=payload, cookies=cookies)
            response.raise_for_status()
            lab_details = response.json()
            return {"status": "success", "data": lab_details}
        except httpx.RequestError as exc:
            print(f"[LAB REQUEST ERROR] {str(exc)}", file=sys.stderr)
            return {"status": "failed", "error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
            print(f"[LAB HTTP ERROR] {exc.response.status_code}: {exc.response.text}", file=sys.stderr)
            return {"status": "failed", "error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}
        
        
@mcp.tool(
    name="execute_code",
    description="Allows the user to choose a sandbox (Python or Java) and executes the latest code accordingly."
)
async def execute_code(latest_code: str, language: str = "python"):
    """
    Accepts latest generated code and executes it in a selected sandbox.
    
    Parameters:
    - latest_code: str = The code to be executed.
    - language: str = "python" or "java" (default: python)

    Returns:
    - JSON with execution result.
    """
    ##  call this method and get show_lab_deatils check access details is there or not if there pic dns server value and create url https:{dnssvervalue}:8000
    # Map language to endpoint
    sandbox_urls = {
        "python": "http://winpydy7730f.cloudloka.com:8000/run_python_code",
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


# @mcp.tool(
#     name="execute_code",
#     description="Prompts user to confirm before executing latest code in Python or Java sandbox."
# )
# async def execute_code(latest_code: str, language: str = "python"):
#     """
#     Prompts the user to confirm before executing the latest code.

#     Parameters:
#     - latest_code: str = The code to be executed.
#     - language: str = "python" or "java" (default: python)

#     Returns:
#     - JSON with execution result or cancellation.
#     """

#     # Ask user for confirmation before running
#     confirmation = await mcp.ask_user(
#         prompt="🚀 Do you want to execute the latest code?",
#         options=["Run", "Cancel"]
#     )

#     if confirmation != "Run":
#         return {
#             "status": "cancelled",
#             "message": "Execution cancelled by the user."
#         }

#     # OPTIONAL: Placeholder to fetch dynamic DNS or check access (can be replaced)
#     dns_server_value = "winpydy7730f.cloudloka.com"
#     url = f"http://{dns_server_value}:8000/run_python_code"

#     headers = {"Content-Type": "application/json"}
#     payload = {"code": latest_code}

#     try:
#         async with httpx.AsyncClient() as client:
#             response = await client.post(url, headers=headers, json=payload)
#             response.raise_for_status()
#             result = response.json()

#         return {
#             "status": "success",
#             "language": language.lower(),
#             "message": "Code executed successfully.",
#             "result": result
#         }

#     except httpx.RequestError as exc:
#         return {
#             "status": "error",
#             "message": f"Request error: {str(exc)}"
#         }
#     except httpx.HTTPStatusError as exc:
#         return {
#             "status": "error",
#             "message": f"HTTP error {exc.response.status_code}: {exc.response.text}"
#         }
#     except Exception as e:
#         return {
#             "status": "error",
#             "message": f"Unexpected error: {str(e)}"
#         }



@mcp.tool(
    name="execute_code_from_file_or_directory",
    description="Executes Python or Java code from a file or directory. Auto-selects file if only one is found."
)
async def execute_code_from_file_or_directory(path: str, language: str = "python", filename: str = None):
    """
    Executes code from a file or picks from directory if only one file found.
    Prompts user if multiple valid files are found.
    """

    if not os.path.exists(path):
        return {"status": "error", "message": f"Path not found: {path}"}

    # If it's a directory, handle accordingly
    if os.path.isdir(path):
        code_files = [f for f in os.listdir(path) if f.endswith(".py") or f.endswith(".java")]
        
        if not code_files:
            return {"status": "error", "message": "No Python or Java files found in the directory."}
        
        # Auto-pick if only one file found
        if len(code_files) == 1:
            file_path = os.path.join(path, code_files[0])
        else:
            # Require user to specify which file
            if not filename:
                return {
                    "status": "select_required",
                    "message": f"Multiple code files found. Please specify the file to execute.",
                    "available_files": code_files
                }
            file_path = os.path.join(path, filename)

        if not os.path.isfile(file_path):
            return {"status": "error", "message": f"File not found in directory: {filename}"}
    else:
        # It's a direct file
        file_path = path

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        return {"status": "error", "message": f"Failed to read file: {str(e)}"}

    sandbox_urls = {
        "python": "http://winpydy7730f.cloudloka.com:8000/run_python_code",
        "java": "http://winpydy7730f.cloudloka.com:8000/run_java_code"
    }

    if language.lower() not in sandbox_urls:
        return {"status": "error", "message": f"Unsupported language '{language}'."}

    url = sandbox_urls[language.lower()]
    headers = {"Content-Type": "application/json"}
    payload = {"code": code}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()

        return {
            "status": "success",
            "language": language.lower(),
            "executed_file": os.path.basename(file_path),
            "message": "Code executed successfully.",
            "result": result
        }

    except httpx.RequestError as exc:
        return {"status": "error", "message": f"Request error: {str(exc)}"}
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "message": f"HTTP error {exc.response.status_code}: {exc.response.text}"}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}




# @mcp.tool(
#     name="execute_code_from_file",
#     description="Reads code from a file and executes it in a remote sandbox (Python or Java)."
# )
# async def execute_code_from_file(file_path: str, language: str = "python"):
#     """
#     Reads the content of a code file and executes it remotely.

#     Parameters:
#     - file_path: str = Path to the code file (local path).
#     - language: str = "python" or "java" (default: python)

#     Returns:
#     - JSON with execution result or error message.
#     """
#     # Validate file existence
#     if not os.path.isfile(file_path):
#         return {
#             "status": "error",
#             "message": f"File not found: {file_path}"
#         }

#     try:
#         with open(file_path, "r", encoding="utf-8") as f:
#             code = f.read()
#     except Exception as e:
#         return {
#             "status": "error",
#             "message": f"Failed to read file: {str(e)}"
#         }

#     # Map language to endpoint
#     sandbox_urls = {
#         "python": "http://winpydy7730f.cloudloka.com:8000/run_python_code",
#         "java": "http://winpydy7730f.cloudloka.com:8000/run_java_code"
#     }

#     if language.lower() not in sandbox_urls:
#         return {
#             "status": "error",
#             "message": f"Unsupported language '{language}'. Please use 'python' or 'java'."
#         }

#     url = sandbox_urls[language.lower()]
#     headers = {"Content-Type": "application/json"}
#     payload = {"code": code}

#     try:
#         async with httpx.AsyncClient() as client:
#             response = await client.post(url, headers=headers, json=payload)
#             response.raise_for_status()
#             result = response.json()

#         return {
#             "status": "success",
#             "language": language.lower(),
#             "message": "File code executed successfully.",
#             "result": result
#         }

#     except httpx.RequestError as exc:
#         return {
#             "status": "error",
#             "message": f"Request error: {str(exc)}"
#         }
#     except httpx.HTTPStatusError as exc:
#         return {
#             "status": "error",
#             "message": f"HTTP error {exc.response.status_code}: {exc.response.text}"
#         }
#     except Exception as e:
#         return {
#             "status": "error",
#             "message": f"Unexpected error: {str(e)}"
#         }

if __name__ == "__main__":
    asyncio.run(mcp.run())
