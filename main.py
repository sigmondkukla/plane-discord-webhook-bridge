# main.py
import os
import hmac
import hashlib
import json
import logging
import re
from typing import Dict, Any, Optional, List

import requests
from fastapi import FastAPI, Request, Header, HTTPException, Response

# Environment variables for Docker compatibility
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
PLANE_WEBHOOK_SECRET = os.getenv("PLANE_WEBHOOK_SECRET")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
PLANE_WORKSPACE_URL = os.getenv("PLANE_WORKSPACE_URL", "").rstrip('/') # This should be the full URL to the workspace such as https://plane.example.com/example

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

# Figure out base URL from workspace URL (converts https://plane.example.com/example-workspace -> https://plane.example.com)
plane_base_url = PLANE_WORKSPACE_URL.rsplit('/', 1)[0] if PLANE_WORKSPACE_URL else None

app = FastAPI(
    title="Plane to Discord Webhook Bridge",
    description="API to receive and verify Plane webhooks and forward them to a Discord channel",
    version="1.0.0"
)

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

def format_assignees(assignee_list: List[Dict[str, Any]]) -> str:
    """Formats a list of assignees for a work item"""
    if not assignee_list:
        return "None"
    unique_assignees = {p['id']: p for p in assignee_list}.values() # Use a dict to deduplicate by ID
    return ", ".join([get_full_name(p) for p in unique_assignees])

def format_issue_message(plane_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Formats an issue event into an embed message"""
    action = plane_payload.get("action", "created")
    data = plane_payload.get("data", {})
    activity = plane_payload.get("activity", {})
    actor = activity.get("actor", {})

    # issue_seq_id = data.get("sequence_id") # this isn't too useful until we can figure out the slug for each project name...
    issue_name = data.get("name", "Untitled Issue")
    embed_title = f"Issue created: {issue_name}"
    
    project_uuid = data.get("project")
    issue_uuid = data.get("id")
    embed_url = f"{PLANE_WORKSPACE_URL}/projects/{project_uuid}/issues/{issue_uuid}" if all([project_uuid, issue_uuid, PLANE_WORKSPACE_URL]) else None

    if action == "updated":
        embed_description = format_update_description(activity)
    elif action == "deleted":
        embed_description = f"Issue was deleted by **{get_full_name(actor)}**."
        embed_title = f"Issue Deleted: {issue_name}"
    else: # must have been created
        embed_description = "A new issue was created."

    fields = []
    if state_name := data.get("state", {}).get("name"):
        fields.append({"name": "State", "value": state_name, "inline": True})
    if priority := data.get("priority"):
        fields.append({"name": "Priority", "value": priority.title(), "inline": True})
    if assignees := data.get("assignees"):
        fields.append({"name": "Assignees", "value": format_assignees(assignees), "inline": False})
    
    return {
        "embeds": [{
            "author": get_author_info(actor),
            "title": embed_title,
            "url": embed_url,
            "description": embed_description,
            "color": hex_to_int(data.get("state", {}).get("color")),
            "fields": fields,
            "timestamp": data.get("updated_at") or data.get("created_at")
        }]
    }

def format_project_message(plane_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Formats a project event into an embed message"""
    action = plane_payload.get("action", "created")
    data = plane_payload.get("data", {})
    activity = plane_payload.get("activity", {})
    actor = activity.get("actor", {})

    project_name = data.get("name", "Untitled Project")
    project_identifier = data.get("identifier")
    title_suffix = f"{project_name} [{project_identifier}]" if project_identifier else project_name
    embed_title = f"Project {action.title()}: {title_suffix}"
    
    project_uuid = data.get("id")
    embed_url = f"{PLANE_WORKSPACE_URL}/projects/{project_uuid}/" if project_uuid and PLANE_WORKSPACE_URL else None

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

def format_issue_comment_message(plane_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Formats an issue_comment event into an embed message"""
    action = plane_payload.get("action", "created")
    data = plane_payload.get("data", {})
    activity = plane_payload.get("activity", {})
    actor = activity.get("actor", {})

    project_uuid = data.get("project")
    issue_uuid = data.get("issue")
    embed_title = "New Comment on an Issue"
    embed_url = f"{PLANE_WORKSPACE_URL}/projects/{project_uuid}/issues/{issue_uuid}" if all([project_uuid, issue_uuid, PLANE_WORKSPACE_URL]) else None

    comment_text = strip_html(data.get("comment_html", ""))
    if action == "deleted":
        embed_description = "A comment was deleted."
    elif action == "updated":
        embed_description = f"Comment updated:\n>>> {comment_text}"
    else: # created
        embed_description = f">>> {comment_text}"

    return {
        "embeds": [{
            "author": get_author_info(actor),
            "title": embed_title,
            "url": embed_url,
            "description": embed_description,
            "color": 8359053,  # Neutral Grey
            "timestamp": data.get("updated_at") or data.get("created_at")
        }]
    }

def format_plaintext(message: str) -> Dict[str, str]:
    """Formats a plaintext message to be sent to Discord"""
    return {"content": message}

def format_unsupported_message(plane_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Creates a generic message for unsupported event types"""
    event_type = plane_payload.get("event", "unknown")
    return format_plaintext(f"Received an unhandled webhook event: `{event_type}`")

def forward_to_discord(discord_payload: Dict[str, Any]) -> bool:
    """Forwards the formatted payload to the configured Discord webhook URL"""
    if not DISCORD_WEBHOOK_URL:
        logger.error("Cannot forward to Discord because DISCORD_WEBHOOK_URL is not set")
        return False
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=discord_payload, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send webhook to Discord: {e}")
        return False

@app.on_event("startup")
async def startup_event():
    """Checks for environment variables and sends a startup message"""
    if not all([DISCORD_WEBHOOK_URL, PLANE_WEBHOOK_SECRET, PLANE_WORKSPACE_URL]):
        logger.warning("At least one required environment variable is missing")
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
    
    discord_payload = formatter(plane_payload)
    if not discord_payload:
        return Response(content="Webhook received but could not be processed", status_code=200)

    logger.debug(f"Formatted Discord payload:\n{json.dumps(discord_payload, indent=2)}")
    
    if forward_to_discord(discord_payload):
        logger.info(f"Successfully forwarded webhook event '{x_plane_event}' to Discord")
        return {"status": "success", "detail": "Webhook forwarded to Discord"}
    else:
        logger.error(f"Failed to forward webhook event '{x_plane_event}' to Discord")
        return Response(content="Webhook received but failed to forward to Discord", status_code=502)
