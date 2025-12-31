# Firewalla-Wazuh SIEM Integration

Integrate your [Firewalla](https://firewalla.com) network security device with [Wazuh](https://wazuh.com) SIEM for centralized security monitoring, threat intelligence correlation, and custom alerting.

## Features

- **MSP API Integration** - Polls Firewalla MSP API for alarms, flows, and device inventory
- **Threat Intelligence** - Automatic correlation with Feodo Tracker and ThreatFox C2 feeds
- **Custom Detection Rules** - 40+ Wazuh rules for Firewalla events with MITRE ATT&CK mappings
- **Security Dashboard** - Pre-built OpenSearch dashboard for network visibility
- **Store-and-Forward** - Resilient to container downtime with 30-day MSP API retention

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yasirhamza/firewalla-wazuh.git
cd firewalla-wazuh

# Configure credentials
cp .env.example .env
nano .env  # Set your passwords and MSP token

# Generate SSL certificates
docker compose -f generate-certs.yml run --rm generator

# Start the stack
docker compose up -d

# Wait ~2 minutes, then access dashboard
# https://localhost:443
# Username: admin
# Password: (your INDEXER_PASSWORD from .env)
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Firewalla MSP  │────▶│   msp-poller     │────▶│  Wazuh Manager  │
│      API        │     │   (sidecar)      │     │   + Filebeat    │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
┌─────────────────┐     ┌──────────────────┐     ┌────────▼────────┐
│  Threat Feeds   │────▶│  threat-intel    │────▶│  Wazuh Indexer  │
│ (Feodo/ThreatFox)     │   (sidecar)      │     │  (OpenSearch)   │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                                 ┌────────▼────────┐
                                                 │ Wazuh Dashboard │
                                                 │   (port 443)    │
                                                 └─────────────────┘
```

## Detection Rules

| Rule ID Range | Category | Description |
|---------------|----------|-------------|
| 100200-100299 | Alarms | Firewalla security alerts (new device, port scan, spoofing) |
| 100300-100399 | Devices | Device inventory changes |
| 100400-100449 | Flows | Network flow analysis (blocked, high bandwidth) |
| 100450-100499 | Threat Intel | C2 IP correlation matches |
| 100500-100504 | Sidecar | Poller health monitoring |

## Requirements

- Docker Engine 20.10+
- Docker Compose v2
- 4GB RAM minimum
- Firewalla MSP account (for API access)

## Documentation

- [SETUP.md](SETUP.md) - Detailed installation guide
- [docs/](docs/) - Configuration and troubleshooting

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Wazuh](https://wazuh.com) - Open source security platform
- [Firewalla](https://firewalla.com) - Network security appliance
- [abuse.ch](https://abuse.ch) - Threat intelligence feeds
