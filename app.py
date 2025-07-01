from fastmcp import FastMCP
import asyncio

import httpx
import asyncio
import json
from typing import List, Union
mcp = FastMCP("CloudlabMcp")

BASE_URL="http://localhost:9999/";
USERNAME = "devadmin2"
PASSWORD = "RishAnk@7080"
@mcp.tool
async def ping():
    return "pong"


# Internal auth function (not exposed to user)
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
    
    # Map language to endpoint
    sandbox_urls = {
        "python": "http://winpydy7730f.cloudloka.com:8000/run_python_code",
        "java": "http://winpydy7730f.cloudloka.com:8000/run_java_code"
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

@mcp.tool()
async def get_movie_basedon_name(movie_name: str) -> Union[List[dict], dict]:
    """
    Fetch all movies from the Movie Booking API and filter them by the provided movie name.

    Args:
        movie_name (str): Name (or partial name) of the movie to search for.

    Returns:
        List of matching movies or an error message.
    """
    url = "https://d8ad-223-185-135-56.ngrok-free.app/api/movies"

    async with httpx.AsyncClient() as client:
        try:
           
            response = await client.get(url)
            response.raise_for_status()

            movies = response.json()

            # Log the raw response to inspect structure
           

            # Handle if wrapped in "data" or other keys
            if isinstance(movies, dict):
                if "data" in movies:
                    movies = movies["data"]
                elif "movies" in movies:
                    movies = movies["movies"]
                else:
                   
                    return {"error": "Unexpected API structure: no 'data' or 'movies' key."}

            if not isinstance(movies, list):
                
                return {"error": "Expected a list of movies but got something else."}

            # Detect actual title key
            sample_movie = movies[0] if movies else {}
            movie_key = None
            for key in ["movieName", "title", "name"]:
                if key in sample_movie:
                    movie_key = key
                    break

            if not movie_key:
                
                return {"error": "Could not detect movie title key in API response."}

           

            # Case-insensitive filter
            movie_name = movie_name.strip().lower()
            filtered_movies = [
                movie for movie in movies
                if movie_name in movie.get(movie_key, "").lower()
            ]

            if not filtered_movies:
                
                return {"message": f"No movies found with name containing '{movie_name}'."}

            
            return filtered_movies

        except httpx.RequestError as exc:
           
            return {"error": f"Request error: {str(exc)}"}
        except httpx.HTTPStatusError as exc:
           
            return {"error": f"HTTP error: {exc.response.status_code} - {exc.response.text}"}
        except Exception as e:
            
            return {"error": f"Unexpected error: {str(e)}"}

if __name__ == "__main__":
    asyncio.run(mcp.run())
