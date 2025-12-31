# Wazuh-Firewalla Integration Tests

Integration test suite for the Wazuh-Firewalla security monitoring stack.

## Prerequisites

- Docker and Docker Compose
- Python 3.8+
- Running Wazuh stack (`docker compose up -d`)

## Quick Start

```bash
# Run all integration tests
./scripts/run_integration_tests.sh

# Or with pytest directly
pip install -r requirements.txt
pytest integration/ -v
```

## Test Categories

### Container Health (`TestContainerHealth`)
- Verifies all containers are running
- Checks Wazuh manager services are healthy

### Wazuh Rules (`TestWazuhRules`)
- Tests rule matching via `wazuh-logtest`
- Validates sidecar status rules (100500-100504)
- Validates Windows SRP rules (100651-100663)

### Sidecar Status (`TestSidecarStatus`)
- Verifies MSP poller writes status events
- Checks threat-intel CDB lists are created

### OpenSearch Integration (`TestOpenSearchIntegration`)
- Validates cluster health
- Confirms wazuh-alerts indices exist

### Event Flow (`TestEventFlow`)
- End-to-end verification of events reaching alerts
- Validates logcollector is monitoring files

### Configuration (`TestConfiguration`)
- Verifies custom rules are loaded
- Verifies custom decoders are loaded
- Confirms CDB lists are accessible

## Environment Variables

Set these in `.env` or export before running:

```bash
INDEXER_USER=admin
INDEXER_PASSWORD=YourPassword
```

## Adding New Tests

1. Create test file in `integration/`
2. Use `docker_run()` helper for container commands
3. Follow pytest conventions
4. Test both success and failure scenarios

## CI Integration

Add to GitHub Actions:

```yaml
- name: Run integration tests
  run: |
    pip install -r tests/requirements.txt
    pytest tests/integration/ -v
```
