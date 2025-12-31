# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-31

### Features
- Firewalla MSP API integration with store-and-forward model
- Threat intelligence feeds (Feodo Tracker, ThreatFox)
- Windows Software Restriction Policy (SRP) monitoring with baseline detection
- Pre-built OpenSearch dashboard for security visualization
- Integration test suite for stack validation

### Components
- **msp-poller**: Sidecar container for Firewalla MSP API polling
  - Alarm, flow, and device data collection
  - Cursor-based pagination for complete data retrieval
  - State persistence for resilience across restarts
  - Automatic log rotation
- **threat-intel**: Sidecar container for threat feed updates
  - Feodo Tracker and ThreatFox integration
  - CDB list generation for Wazuh rule matching
  - 24-hour automatic refresh cycle
- **Custom Wazuh Rules**: Detection rules with MITRE ATT&CK mappings
  - Firewalla alarm rules (100200-100504)
  - Windows SRP rules (100600-100699)
  - Threat intelligence matching rules (100450-100451)
- **Filebeat Pipeline**: Custom ingest pipeline for timestamp handling
  - Microsecond precision timestamp parsing
  - Store-and-forward timestamp preservation

### Documentation
- Comprehensive setup guide (SETUP.md)
- Integration testing documentation
- Rule reference tables
