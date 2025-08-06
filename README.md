# plane-discord-webhook-bridge

A service that parses Plane webhooks and forwards them to a Discord webhook as embed messages.
Designed to be deployed with Docker Compose alongside Plane CE.

## Prerequisites

- A self-hosted instance of Plane
- Docker with the Compose extension installed

## Usage

1. Clone this repo into your plane-selfhost/plane-app directory
2. Copy and paste the contents of `docker-compose.yml` into your Plane Compose file
3. Edit the build direcory to `./plane-discord-webhook-bridge`
4. Set your environment variables to match your Plane secret key for verification and Discord webhook URL to forward to
6. Use Plane's `start.sh` script to restart the Plane stack
