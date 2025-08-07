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
      - PLANE_WORKSPACE_URL=https://plane.example.com/workspace_name
      - PERSONAL_ACCESS_TOKEN=paste_here
```
3. Set your `DISCORD_WEBHOOK_URL` environment variable to the webhook URL from Discord
4. Leave `PLANE_WEBHOOK_SECRET` blank for now
5. Set your `PERSONAL_ACCESS_TOKEN` to a Plane API key obtained from your user settings. You may need to create a Plane account with access to every project in your workspace for complete functionality.
6. Use Plane's `setup.sh` script to restart the Plane stack
7. Set your Plane webhook URL to something like `https://plane-discord-webhook-bridge.example.com/webhook` if using reverse proxy, or to a local IP address (URL including service name doesn't appear to be available yet, see [makeplane/plane #7555](https://github.com/makeplane/plane/issues/7555))
8. Copy the secret key that Plane gives you after making an initial request to the webhook server
9. Paste the secret key into your `PLANE_WEBHOOK_SECRET` environment variable
10. Restart the Plane stack again using `setup.sh`. (maybe only this bridge container needs to be restarted, I'm not sure)
11. Test the service by making changes to your Plane projects!

### Updating

1. Navigate to the `plane-selfhost/plane-app/plane-discord-webhook-bridge` directory
2. Pull the lastest changes: `git pull`
3. Navigate to the parent `plane-app` directory
4. Rebuild the container with `docker compose build --no-cache plane-discord-webhook-bridge`
5. Restart Plane using `setup.sh`
