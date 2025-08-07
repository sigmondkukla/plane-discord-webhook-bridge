# plane-discord-webhook-bridge

A service that parses Plane webhooks and forwards them to a Discord webhook as embed messages.
Designed to be deployed with Docker Compose alongside Plane CE.

## Prerequisites

- A self-hosted instance of Plane
- Docker with the Compose extension installed

## Usage

1. Clone this repo into your plane-selfhost/plane-app directory
2. Copy and paste the following into your Plane `docker-compose.yml` file:
```yaml
  plane-discord-webhook-bridge:
    build: ./plane-discord-webhook-bridge
    restart: unless-stopped
    ports:
      - 8000
    environment:
      - DISCORD_WEBHOOK_URL=paste_here
      - PLANE_WEBHOOK_SECRET=paste_here
      - PLANE_BASE_URL=https://plane.example.com/workspace_name
```
3. Set your `DISCORD_WEBHOOK_URL` environment variable to the webhook URL from Discord
4. Leave `PLANE_WEBHOOK_SECRET` blank for now
5. Use Plane's `setup.sh` script to restart the Plane stack
6. Set your Plane webhook URL to something like `https://plane-discord-webhook-bridge.example.com/webhook` if using reverse proxy, or to a local IP address (URL including service name doesn't appear to be available yet, see [makeplane/plane #7555](https://github.com/makeplane/plane/issues/7555))
7. Copy the secret key that Plane gives you after making an initial request to the webhook server
8. Paste the secret key into your `PLANE_WEBHOOK_SECRET` environment variable
9. Restart the Plane stack again using `setup.sh`. (maybe only this bridge container needs to be restarted, I'm not sure)
10. Test the service by making changes to your Plane projects!
