# main.py
import os
import hmac
import hashlib
import json
import logging
import re
from functools import lru_cache
from typing import Dict, Any, Optional, List

import requests
from fastapi import FastAPI, Request, Header, HTTPException, Response

# Environment variables for Docker compatibility
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
PLANE_WEBHOOK_SECRET = os.getenv("PLANE_WEBHOOK_SECRET")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
PLANE_WORKSPACE_URL = os.getenv("PLANE_WORKSPACE_URL", "").rstrip('/') # This should be the full URL to the workspace such as https://plane.example.com/example
PERSONAL_ACCESS_TOKEN = os.getenv("PERSONAL_ACCESS_TOKEN")

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

# Figure out base URL from workspace URL (converts https://plane.example.com/example-workspace -> https://plane.example.com)
plane_base_url = PLANE_WORKSPACE_URL.rsplit('/', 1)[0] if PLANE_WORKSPACE_URL else None
# Construct the base API URL from the workspace URL (includes the workspace ID)
plane_api_base_url = f"{plane_base_url}/api/v1/workspaces/{PLANE_WORKSPACE_URL.split('/')[-1]}" if plane_base_url else None

class PlaneAPIClient:
    """Client to interact with the Plane API"""
    def __init__(self, api_base_url: Optional[str], token: Optional[str]):
        if not api_base_url or not token:
            self._session = None
            logger.warning("Plane API client not initialized due to missing URL or TOKEN.")
        else:
            self._session = requests.Session()
            self._session.headers.update({"Authorization": f"Bearer {token}"})
            self.api_base_url = api_base_url

    @lru_cache(maxsize=128)
    def _make_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Internal method to make and cache API requests"""
        if not self._session:
            return None
        try:
            url = f"{self.api_base_url}{endpoint}"
            logger.debug(f"Making API request to: {url}")
            response = self._session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to make API request to {endpoint}: {e}")
            return None

    def get_project_details(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Fetches details for a specific project"""
        return self._make_request(f"/projects/{project_id}/")

    def get_issue_details(self, project_id: str, issue_id: str) -> Optional[Dict[str, Any]]:
        """Fetches details for a specific issue"""
        return self._make_request(f"/projects/{project_id}/issues/{issue_id}/")

plane_api = PlaneAPIClient(plane_api_base_url, PERSONAL_ACCESS_TOKEN)

app = FastAPI(
    title="Plane to Discord Webhook Bridge",
    description="API to receive and verify Plane webhooks and forward them to a Discord channel",
    version="1.0.0"
)

# --- Helper Functions ---
def verify_signature(payload_body: bytes, secret_token: str, signature_header: str) -> bool:
    """Verify the incoming webhook signature from Plane"""
    if not secret_token:
        logger.error("Cannot verify signature because PLANE_WEBHOOK_SECRET is not set")
        return False
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

def hex_to_int(hex_string: Optional[str]) -> int:
    """Convert a hex color string #RRGGBB to an integer for Discord embeds"""
    if not hex_string:
        return 8359053  # Default grey
    return int(hex_string.lstrip('#'), 16)

def strip_html(html_string: str) -> str:
    """Removes HTML tags from a string"""
    if not html_string:
        return ""
    return re.sub('<[^<]+?>', '', html_string)

def get_full_name(person: Dict[str, Any]) -> str:
    """Constructs a full name string from first and last name fields"""
    first = person.get("first_name", "")
    last = person.get("last_name", "")
    return f"{first} {last}".strip() or person.get("display_name", "Unknown User")

def get_author_info(actor: Dict[str, Any]) -> Dict[str, str]:
    """Creates the author object for a Discord embed"""
    icon_url = f"{plane_base_url}{actor.get('avatar_url')}" if actor.get("avatar_url") and plane_base_url else ""
    return {
        "name": get_full_name(actor),
        "icon_url": icon_url
    }

def format_update_description(activity: Dict[str, Any]) -> str:
    """Creates a human-readable string for an updated action from Plane"""
    field = activity.get("field")
    old_value = activity.get("old_value") or "None"
    new_value = activity.get("new_value") or "None"

    if isinstance(old_value, list): old_value = f"[{len(old_value)} items]"
    if isinstance(new_value, list): new_value = f"[{len(new_value)} items]"

    if field:
        return f"**{field.replace('_', ' ').title()}** changed from `{old_value}` to `{new_value}`."
    return "Issue details updated"

def format_assignees(webhook_assignees: List[Dict[str, Any]], api_assignee_ids: List[str]) -> str:
    """Formats a list of assignees, filtering against the live API data to ensure accuracy"""
    if not webhook_assignees or not api_assignee_ids:
        return "None"
    
    # Filter assignees from webhook payload to only include those present in the API response
    live_assignees = {p['id']: p for p in webhook_assignees if p['id'] in api_assignee_ids}
    return ", ".join([get_full_name(p) for p in live_assignees.values()]) or "None"

def format_issue_message(plane_payload: Dict[str, Any], api_client: PlaneAPIClient) -> Optional[Dict[str, Any]]:
    """Formats an 'issue' event into an embed message using live API data"""
    action = plane_payload.get("action", "created")
    data = plane_payload.get("data", {})
    actor = plane_payload.get("activity", {}).get("actor", {})

    project_id, issue_id = data.get("project"), data.get("id")
    if not project_id or not issue_id: return None

    project_details = api_client.get_project_details(project_id)
    issue_details = api_client.get_issue_details(project_id, issue_id)
    if not project_details or not issue_details:
        logger.warning(f"Could not fetch API details for issue {issue_id} in project {project_id}. Skipping notification.")
        return None

    project_identifier = project_details.get("identifier", "PROJ")
    project_emoji = project_details.get("emoji") or ""
    issue_seq_id = issue_details.get("sequence_id")
    
    embed_title = f"{project_emoji} Work item {action}: {project_identifier}-{issue_seq_id}"
    embed_url = f"{PLANE_WORKSPACE_URL}/projects/{project_id}/issues/{issue_id}"
    
    description_html = issue_details.get("description_html", "")
    description_text = f"**[{issue_details.get('name', 'Untitled Issue')}]({embed_url})**"
    stripped_description = strip_html(description_html)
    if stripped_description:
        description_text += f"\n\n{stripped_description}"

    if action == "updated":
        description_text = f"{format_update_description(plane_payload.get('activity', {}))}\n\n{description_text}"

    fields = [
        {"name": "Status", "value": data.get("state", {}).get("name", "N/A"), "inline": True},
        {"name": "Priority", "value": data.get("priority", "none").title(), "inline": True},
        {"name": "Assignees", "value": format_assignees(data.get("assignees", []), issue_details.get("assignees", [])), "inline": False}
    ]

    return {
        "embeds": [{
            "author": get_author_info(actor),
            "title": embed_title,
            "url": embed_url,
            "description": description_text,
            "color": hex_to_int(data.get("state", {}).get("color")),
            "fields": fields,
            "timestamp": data.get("updated_at") or data.get("created_at")
        }]
    }

def format_project_message(plane_payload: Dict[str, Any], api_client: PlaneAPIClient) -> Optional[Dict[str, Any]]:
    """Formats a project event into an embed message"""
    action = plane_payload.get("action", "created")
    data = plane_payload.get("data", {})
    actor = plane_payload.get("activity", {}).get("actor", {})

    project_emoji = data.get("emoji") or ""
    project_name = data.get("name", "Untitled Project")
    project_identifier = data.get("identifier")
    title_suffix = f"{project_name} [{project_identifier}]" if project_identifier else project_name
    embed_title = f"{project_emoji} Project {action.title()}: {title_suffix}"
    
    project_id = data.get("id")
    embed_url = f"{PLANE_WORKSPACE_URL}/projects/{project_id}/" if project_id and PLANE_WORKSPACE_URL else None

    return {
        "embeds": [{
            "author": get_author_info(actor),
            "title": embed_title,
            "url": embed_url,
            "description": f"The project **{project_name}** was {action}.",
            "color": 3447003,  # Blue
            "timestamp": data.get("updated_at") or data.get("created_at")
        }]
    }

def format_issue_comment_message(plane_payload: Dict[str, Any], api_client: PlaneAPIClient) -> Optional[Dict[str, Any]]:
    """Formats an issue_comment event into an embed message"""
    data = plane_payload.get("data", {})
    actor = plane_payload.get("activity", {}).get("actor", {})

    project_id, issue_id = data.get("project"), data.get("issue")
    if not project_id or not issue_id: return None
    
    project_details = api_client.get_project_details(project_id)
    issue_details = api_client.get_issue_details(project_id, issue_id)
    if not project_details or not issue_details:
        logger.warning(f"Could not fetch API details for comment on issue {issue_id}. Skipping notification.")
        return None

    project_identifier = project_details.get("identifier", "PROJ")
    project_emoji = project_details.get("emoji") or "📄"
    issue_seq_id = issue_details.get("sequence_id")
    issue_name = issue_details.get("name", "Untitled Issue")

    embed_title = f"New comment on: {project_emoji} {project_identifier}-{issue_seq_id} {issue_name}"
    embed_url = f"{PLANE_WORKSPACE_URL}/projects/{project_id}/issues/{issue_id}"
    
    comment_text = strip_html(data.get("comment_html", ""))
    embed_description = f">>> {comment_text}"

    return {
        "embeds": [{
            "author": get_author_info(actor),
            "title": embed_title,
            "url": embed_url,
            "description": embed_description,
            "color": 8359053,  # Neutral Grey
            "timestamp": data.get("created_at")
        }]
    }

def format_plaintext(message: str) -> Dict[str, str]:
    """Formats a plaintext message to be sent to Discord"""
    return {"content": message}

def format_unsupported_message(plane_payload: Dict[str, Any], api_client: PlaneAPIClient) -> Dict[str, Any]:
    """Creates a generic message for unsupported event types"""
    event_type = plane_payload.get("event", "unknown")
    return format_plaintext(f"Received an unhandled webhook event: `{event_type}`")

def forward_to_discord(discord_payload: Dict[str, Any]) -> bool:
    """Forwards the formatted payload to the configured Discord webhook URL"""
    if not DISCORD_WEBHOOK_URL:
        logger.error("Cannot forward to Discord because DISCORD_WEBHOOK_URL is not set")
        return False
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=discord_payload, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send webhook to Discord: {e}")
        return False

@app.on_event("startup")
async def startup_event():
    """Checks for environment variables and sends a startup message"""
    if not all([DISCORD_WEBHOOK_URL, PLANE_WEBHOOK_SECRET, PLANE_WORKSPACE_URL, PERSONAL_ACCESS_TOKEN]):
        logger.warning("One or more required environment variables are missing. API features may be disabled.")
    else:
        logger.info("All required environment variables are set.")
        forward_to_discord(format_plaintext("plane-discord-webhook-bridge started successfully!"))

@app.get("/", summary="Health Check")
async def health_check():
    """A simple health check endpoint to confirm the service is running"""
    return {"status": "ok", "message": "plane-discord-webhook-bridge is running"}

@app.post("/webhook", summary="Plane Webhook Receiver")
async def plane_webhook_handler(request: Request, x_plane_signature: str = Header(None), x_plane_event: str = Header(None)):
    """Receives, verifies, formats, and forwards requests"""
    if not x_plane_signature:
        raise HTTPException(status_code=400, detail="X-Plane-Signature header is missing")

    payload_bytes = await request.body()
    if not verify_signature(payload_bytes, PLANE_WEBHOOK_SECRET, x_plane_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    logger.info(f"Signature verified for event: {x_plane_event}")
    plane_payload = json.loads(payload_bytes)
    logger.debug(f"Received webhook contents:\n{json.dumps(plane_payload, indent=2)}")

    formatter = {
        "issue": format_issue_message,
        "project": format_project_message,
        "issue_comment": format_issue_comment_message,
    }.get(plane_payload.get("event"), format_unsupported_message)
    
    discord_payload = formatter(plane_payload, plane_api)
    if not discord_payload:
        return Response(content="Webhook received but could not be processed (potentially failed API lookup)", status_code=200)

    logger.debug(f"Formatted Discord payload:\n{json.dumps(discord_payload, indent=2)}")
    
    if forward_to_discord(discord_payload):
        logger.info(f"Successfully forwarded webhook event '{x_plane_event}' to Discord")
        return {"status": "success", "detail": "Webhook forwarded to Discord"}
    else:
        # The forward_to_discord function already logs the specific error
        return Response(content="Webhook received but failed to forward to Discord", status_code=502)
