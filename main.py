# main.py
import os
import hmac
import hashlib
import json
import logging
from typing import Dict, Any, Optional

import requests
from fastapi import FastAPI, Request, Header, HTTPException, Response

# environment variables for docker compatibility
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
PLANE_WEBHOOK_SECRET = os.getenv("PLANE_WEBHOOK_SECRET")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
PLANE_WORKSPACE_URL = os.getenv("PLANE_WORKSPACE_URL", "").rstrip('/') # should include the workspace name

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

# figure out base URL from workspace URL (https://plane.example.com/workspace_name -> https://plane.example.com)
plane_base_url = PLANE_WORKSPACE_URL.rstrip('/').rsplit('/', 1)[0] if PLANE_WORKSPACE_URL else None

app = FastAPI(
    title="Plane to Discord Webhook Bridge",
    description="API to receive and verify Plane webhooks and forward them to a Discord channel",
    version="1.0.0"
)

def verify_signature(payload_body: bytes, secret_token: str, signature_header: str) -> bool:
    """
    Verify the incoming webhook signature from Plane

    Args:
        payload_body: The raw request body
        secret_token: The webhook secret from Plane
        signature_header: The value of the 'X-Plane-Signature' header

    Returns:
        bool: if the signature is valid
    """
    if not secret_token:
        logger.error("Cannot verify signature because PLANE_WEBHOOK_SECRET is not set")
        return False
        
    hash_object = hmac.new(
        secret_token.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

def hex_to_int(hex_string: str) -> int:
    """
    Convert a hex color string (formatted #RRGGBB) to an integer for Discord embeds
    
    Args:
        hex_string: The hex color string
        
    Returns:
        int: The integer representation of the color
    """
    if not hex_string:
        return 0
    return int(hex_string.lstrip('#'), 16)

def format_update_description(activity: Dict[str, Any]) -> str:
    """Creates a human-readable string for an 'updated' action from Plane, detailing what changed"""
    field = activity.get("field")
    old_value = activity.get("old_value") or "None"
    new_value = activity.get("new_value") or "None"

    if isinstance(old_value, list): old_value = f"[{len(old_value)} items]"
    if isinstance(new_value, list): new_value = f"[{len(new_value)} items]"

    if field:
        return f"**{field.replace('_', ' ').title()}** changed from `{old_value}` to `{new_value}`."
    return "Issue details were updated."

def format_issue_message(plane_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Formats an 'issue' event into a rich Discord embed message."""
    action = plane_payload.get("action", "created")
    data = plane_payload.get("data", {})
    activity = plane_payload.get("activity", {})
    actor = activity.get("actor", {})

    # Build Title
    issue_seq_id = data.get("sequence_id")
    issue_name = data.get("name", "Untitled Issue")
    embed_title = f"Issue #{issue_seq_id}: {issue_name}"
    
    # Build URL to the parent project's issue list
    project_uuid = data.get("project")
    embed_url = f"{PLANE_WORKSPACE_URL}/projects/{project_uuid}/issues/" if project_uuid and PLANE_WORKSPACE_URL else None

    # Build Author (the user who performed the action)
    author_info = {
        "name": actor.get("display_name", "Unknown User"),
        "icon_url": f"{plane_base_url}{actor.get('avatar_url')}" if actor.get("avatar_url") and plane_base_url else ""
    }

    # Build Description (what happened)
    if action == "updated":
        embed_description = format_update_description(activity)
    elif action == "deleted":
        embed_description = f"Issue was deleted by **{actor.get('display_name', 'Unknown User')}**."
        embed_title = f"Issue Deleted: #{issue_seq_id} {issue_name}"
    else: # created
        embed_description = f"A new issue was created."

    # Build Fields for additional details
    fields = []
    if state_name := data.get("state", {}).get("name"):
        fields.append({"name": "State", "value": state_name, "inline": True})
    if priority := data.get("priority"):
        fields.append({"name": "Priority", "value": priority.title(), "inline": True})
    if assignees := data.get("assignees"):
        assignee_names = ", ".join(list(set([a.get("display_name", "Unknown") for a in assignees]))) # for some reason, there are duplicates sometimes
        fields.append({"name": "Assignees", "value": assignee_names or "None", "inline": False})
    if project_uuid:
        fields.append({"name": "Project ID", "value": f"`{project_uuid}`", "inline": False})
    
    return {
        "embeds": [{
            "author": author_info,
            "title": embed_title,
            "url": embed_url,
            "description": embed_description,
            "color": hex_to_int(data.get("state", {}).get("color")),
            "fields": fields,
            "timestamp": data.get("updated_at") or data.get("created_at")
        }]
    }

def format_project_message(plane_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Formats a 'project' event into a rich Discord embed message."""
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

    author_info = {"name": actor.get("display_name", "Unknown User")}

    return {
        "embeds": [{
            "author": author_info,
            "title": embed_title,
            "url": embed_url,
            "description": f"The project **{project_name}** was {action}.",
            "color": 3447003,  # Blue
            "timestamp": data.get("updated_at") or data.get("created_at")
        }]
    }

def format_plaintext(message: str) -> Dict[str, str]:
    """
    Format a simple message to be sent to Discord
    
    Args:
        message: The message content
    
    Returns:
        Dict[str, str]: The formatted message payload
    """
    return {
        "content": message
    }

def format_unsupported_message(plane_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Creates a generic message for unsupported event types"""
    event_type = plane_payload.get("event", "unknown")
    return format_plaintext(f"Received an unhandled webhook event: `{event_type}`")


def forward_discord_webhook(discord_payload: Dict[str, Any]) -> bool:
    """
    Forward the formatted Discord payload to the configured Discord webhook URL.
    
    Args:
        discord_payload: The payload to send to Discord
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not DISCORD_WEBHOOK_URL:
        logger.error("Cannot make request to forward to Discord as DISCORD_WEBHOOK_URL is not set")
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
    """Check for necessary environment variables on startup."""
    if not DISCORD_WEBHOOK_URL:
        logger.warning("DISCORD_WEBHOOK_URL environment variable not set")
    elif not PLANE_WEBHOOK_SECRET:
        logger.warning("PLANE_WEBHOOK_SECRET environment variable not set")
    elif not PLANE_WORKSPACE_URL:
        logger.warning("PLANE_WORKSPACE_URL not set")
    else:
        logger.info("All required environment variables are set")
        forward_discord_webhook(format_plaintext("Plane to Discord webhook bridge started successfully!"))


@app.get("/", summary="Health Check", description="Verify that the service is running")
async def health_check():
    """
    Health check endpoint to confirm the service is running, useful for monitoring.
    Could be expanded later.
    """
    return {"status": "ok", "message": "Plane to Discord webhook bridge is running"}


@app.post("/webhook", summary="Plane Webhook Receiver")
async def plane_webhook_handler(
    request: Request,
    x_plane_signature: str = Header(None, description="Signature from Plane webhook to verify authenticity"),
    x_plane_event: str = Header(None, description="Event type from Plane")
):
    """
    This endpoint receives webhooks from Plane, verifies their signature,
    formats an embed with them, and forwards it to a Discord webhook
    """
    if not x_plane_signature:
        logger.error("Request received without X-Plane-Signature header")
        raise HTTPException(status_code=400, detail="X-Plane-Signature header is missing")

    payload_bytes = await request.body() # get raw bytes from the request body

    if not verify_signature(payload_bytes, PLANE_WEBHOOK_SECRET, x_plane_signature): # verify its authenticity
        logger.warning("Invalid signature received")
        raise HTTPException(status_code=403, detail="Invalid signature")

    logger.info(f"Signature verified for event: {x_plane_event}")

    # if signature is valid parse the JSON payload
    try:
        plane_payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON payload")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # debug the received webhook contents
    logger.debug(f"Received webhook contents:\n{json.dumps(plane_payload, indent=2)}")

    event_type = plane_payload.get("event")
    formatter = {
        "issue": format_issue_message,
        "project": format_project_message,
    }.get(event_type, format_unsupported_message)
    
    discord_payload = formatter(plane_payload)

    logger.debug(f"Formatted Discord payload:\n{json.dumps(discord_payload, indent=2)}")

    if not discord_payload:
        return Response(content="Webhook received but could not be processed", status_code=200)

    # forward the message to Discord
    ret = forward_discord_webhook(discord_payload)
    if ret:
        logger.info(f"Successfully forwarded webhook event '{x_plane_event}' to Discord")
    else:
        logger.error(f"Failed to forward webhook event '{x_plane_event}' to Discord")
        return Response(content="Webhook received but failed to forward to Discord", status_code=200)
    
    return {"status": "success", "detail": "Webhook forwarded to Discord"}
