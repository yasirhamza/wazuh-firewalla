# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-01-02

### Added
- Enriched SRP log format support with timestamp and file hashes
  - New `windows-srp-enriched` decoder extracts `srp.timestamp`, `srp.sha256`, `srp.sha1`
  - Backwards compatible with standard (non-enriched) log format
- ExeMonitor.ps1 `-ConvertAndEnrichSaferLog` flag for SIEM-ready log enrichment
- ExeMonitor.ps1 `-ExportCDB` flag to export baseline in Wazuh CDB format
- Manager-side `scripts/sync-baseline.sh` for syncing baseline from Windows agents
- Updated agent configuration with baseline-sync.log collection

### Changed
- Updated `windows_srp_decoders.xml` to support both standard and enriched formats

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
