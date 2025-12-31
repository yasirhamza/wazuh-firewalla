# Contributing to Wazuh-Firewalla Integration

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Development Setup

### Prerequisites

- Docker and Docker Compose
- Python 3.8+
- Firewalla device with MSP API access (for full testing)

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/yasirhamza/wazuh-firewalla.git
   cd wazuh-firewalla
   ```

2. Copy and configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

3. Start the stack:
   ```bash
   docker compose -f generate-certs.yml run --rm generator
   docker compose up -d
   ```

4. Run tests:
   ```bash
   cd tests
   ./scripts/run_integration_tests.sh
   ```

## Making Changes

### Code Style

- Python code should follow PEP 8
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and single-purpose

### Testing

- Add tests for new features
- Ensure existing tests pass before submitting
- Test with `wazuh-logtest` for rule changes:
  ```bash
  echo 'your test event' | docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
  ```

### Wazuh Rules

When adding or modifying Wazuh rules:

- Use rule IDs in assigned ranges:
  - 100200-100499: Firewalla MSP rules
  - 100500-100599: Sidecar status rules
  - 100600-100699: Windows SRP rules
- Include MITRE ATT&CK mappings where applicable
- Test rule matching before committing
- Document new rules in README

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests to ensure nothing is broken
5. Commit with clear, descriptive messages
6. Push to your fork
7. Open a Pull Request with:
   - Clear description of changes
   - Any relevant issue references
   - Test results or screenshots if applicable

## Reporting Issues

When reporting issues, please include:

- Description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Wazuh and Docker versions
- Relevant log excerpts

## Questions?

Open an issue for questions or discussions about the project.
