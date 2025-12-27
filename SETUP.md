# Firewalla-Wazuh Setup Guide

Complete installation and configuration guide for the Firewalla-Wazuh SIEM integration.

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 20GB free space
- **Docker**: Docker Engine 20.10+ and Docker Compose v2

### Firewalla Requirements

- Firewalla device (Purple, Gold, or Blue Plus)
- Firewalla MSP account with API access
- MSP API token (generated from MSP portal)

## Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/firewalla-wazuh.git
cd firewalla-wazuh
```

### Step 2: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit with your credentials
nano .env
```

Required settings:

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `INDEXER_PASSWORD` | OpenSearch admin password | `openssl rand -base64 32` |
| `API_PASSWORD` | Wazuh API password | `openssl rand -base64 24` |
| `MSP_DOMAIN` | Your Firewalla MSP domain | From MSP portal |
| `MSP_TOKEN` | MSP API token | Generate in MSP portal |

### Step 3: Set Memory Limit (Linux only)

```bash
# Required for OpenSearch
sudo sysctl -w vm.max_map_count=262144

# Make permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Step 4: Generate SSL Certificates

```bash
docker compose -f generate-certs.yml run --rm generator
```

### Step 5: Configure Dashboard API Connection

```bash
# Copy template
cp config/wazuh_dashboard/wazuh.yml.example config/wazuh_dashboard/wazuh.yml

# Edit and set your API_PASSWORD
nano config/wazuh_dashboard/wazuh.yml
```

### Step 6: Start Services

```bash
docker compose up -d
```

Wait approximately 2 minutes for all services to initialize.

### Step 7: Verify Deployment

```bash
# Check container status
docker compose ps

# Check manager health
docker compose logs wazuh.manager | tail -20

# Check MSP poller
docker compose logs msp-poller | tail -20
```

### Step 8: Access Dashboard

Open https://localhost:443 in your browser.

- **Username**: `admin`
- **Password**: Your `INDEXER_PASSWORD` from `.env`

Accept the self-signed certificate warning.

## Post-Installation

### Import Firewalla Dashboard

1. Go to **Menu** > **Dashboards Management** > **Saved Objects**
2. Click **Import**
3. Select `dashboards/firewalla-dashboard.ndjson`
4. Click **Import**
5. Navigate to **Dashboards** > **Firewalla Security Dashboard**

### Verify Data Flow

1. Check **Security Events** in Wazuh Dashboard
2. Filter by `rule.groups: firewalla`
3. You should see events within 5-15 minutes

### Configure Alerting (Optional)

For email/Slack notifications on high-severity events, configure Wazuh integrations:

```bash
# Edit manager config
docker exec -it firewalla-wazuh-wazuh.manager-1 nano /var/ossec/etc/ossec.conf
```

## Troubleshooting

### No Events Appearing

1. Check MSP poller logs:
   ```bash
   docker compose logs msp-poller
   ```

2. Verify API connectivity:
   ```bash
   docker exec msp-poller python -c "
   import os, requests
   r = requests.get(f'https://{os.environ[\"MSP_DOMAIN\"]}/v2/boxes',
                    headers={'Authorization': f'Token {os.environ[\"MSP_TOKEN\"]}'})
   print(r.status_code, r.text[:200])
   "
   ```

3. Check Wazuh manager is ingesting:
   ```bash
   docker exec -it firewalla-wazuh-wazuh.manager-1 \
     tail -f /var/ossec/logs/ossec.log | grep firewalla
   ```

### Dashboard Not Loading

1. Wait 2-3 minutes after startup
2. Check indexer health:
   ```bash
   curl -sk -u admin:$INDEXER_PASSWORD https://localhost:9200/_cluster/health
   ```

### Certificate Errors

Regenerate certificates:

```bash
docker compose down
rm -rf config/certs/*
docker compose -f generate-certs.yml run --rm generator
docker compose up -d
```

## Maintenance

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f msp-poller
```

### Restart Services

```bash
# Single service
docker compose restart msp-poller

# All services
docker compose restart
```

### Update Components

```bash
git pull
docker compose build --no-cache msp-poller threat-intel
docker compose up -d
```

### Backup Data

```bash
# Stop services
docker compose stop

# Backup volumes
docker run --rm -v firewalla-wazuh_wazuh-indexer-data:/data \
  -v $(pwd)/backups:/backup alpine \
  tar czf /backup/indexer-data-$(date +%Y%m%d).tar.gz /data

# Restart
docker compose start
```

## Security Notes

- Never commit `.env` to version control
- Rotate passwords periodically
- SSL certificates in `config/certs/` are deployment-specific
- MSP tokens should be treated as sensitive credentials
