# main.py
import os
import hmac
import hashlib
import json
import logging
from typing import Dict, Any

import requests
from fastapi import FastAPI, Request, Header, HTTPException, Response

# environment variables for docker compatibility
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
PLANE_WEBHOOK_SECRET = os.getenv("PLANE_WEBHOOK_SECRET")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

# --- FastAPI Application ---
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

def format_discord_message(plane_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Formats the Plane webhook data into a Discord embed message

    Args:
        plane_payload: The parsed JSON payload from Plane

    Returns:
        A dictionary formatted for the Discord webhook API
    """
    logger.info(f"Formatting Plane payload for Discord: {json.dumps(plane_payload, indent=2)}")
    event = plane_payload.get("event", "unknown_event")
    action = plane_payload.get("action", "unknown_action")
    data = plane_payload.get("data", {})
    workspace_detail = data.get("workspace_detail", {})
    
    # embed color chosen based on action
    color_map = {
        "create": 3066993, # green
        "update": 3447003, # blue
        "delete": 15158332 # red
    }
    embed_color = color_map.get(action, 8359053) # grey for other actions

    title = f"{event.replace('_', ' ').title()} {action.title()}"
    
    description = ""
    if data.get("name"):
        description = f"**Name:** {data.get('name')}"
    elif data.get("id"):
         description = f"**ID:** `{data.get('id')}`"

    # embed fields for additional data
    fields = []
    if data.get("identifier"):
        fields.append({"name": "Identifier", "value": data["identifier"], "inline": True})
    if data.get("state_detail", {}).get("name"):
        fields.append({"name": "State", "value": data["state_detail"]["name"], "inline": True})
    if data.get("project_detail", {}).get("name"):
        fields.append({"name": "Project", "value": data["project_detail"]["name"], "inline": True})
        
    # build the payload for the discord post request
    discord_payload = {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": embed_color,
                "fields": fields,
                "footer": {
                    "text": f"Workspace: {workspace_detail.get('name', 'N/A')}"
                },
                "timestamp": plane_payload.get("created_at")
            }
        ]
    }
    return discord_payload

@app.on_event("startup")
async def startup_event():
    """
    (debug) check for environment variables
    """
    if not DISCORD_WEBHOOK_URL:
        logger.warning("DISCORD_WEBHOOK_URL environment variable not set")
    if not PLANE_WEBHOOK_SECRET:
        logger.warning("PLANE_WEBHOOK_SECRET environment variable not set")


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

    # create embed message for Discord
    discord_payload = format_discord_message(plane_payload)
    logger.info(f"Formatted Discord message: {json.dumps(discord_payload, indent=2)}")


    # forward the message to Discord
    if not DISCORD_WEBHOOK_URL:
        logger.error("Cannot send to Discord because DISCORD_WEBHOOK_URL is not set")
        # Return 200 to Plane so it doesn't retry, but log the error, maybe not a good idea idk
        return Response(content="Webhook received but not forwarded due to missing DISCORD_WEBHOOK_URL", status_code=200)

    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=discord_payload, timeout=5)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        logger.info(f"Successfully forwarded webhook event '{x_plane_event}' to Discord")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send webhook to Discord: {e}")
        # We don't raise an HTTPException here because Plane would retry
        # It's better to acknowledge the webhook and log the forwarding error
        return Response(content="Webhook received but failed to forward to Discord", status_code=502)

    return {"status": "success", "detail": "Webhook forwarded to Discord"}
