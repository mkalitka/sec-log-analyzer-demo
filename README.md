# Security Log Analyzer

A simple configurable security log analyzer that helps detect various security threats and suspicious activities in your log files. The analyzer supports multiple detection mechanisms and provides flexible output formats.

## Features

- **Multiple Detection Mechanisms:**
  - SQL Injection attempts detection
  - Brute force attack detection
  - Port scanning detection
  - Unusual access patterns detection

- **Flexible Configuration:**
  - YAML-based configuration
  - Adjustable detection thresholds
  - Configurable time windows for pattern detection
  - Customizable sensitive paths and trusted IPs

- **Output Formats:**
  - Human-readable table format
  - JSON format for integration with other tools

## Installation

The package requires Python 3.12 or higher. You can install it using pip:

```bash
pip install .
```

Or using Poetry (recommended):

```bash
poetry install
```

## Configuration

The analyzer can be configured using a YAML configuration file. Below is the default configuration:

```yaml
brute_force:
  enabled: true
  threshold: 3          # Number of failed attempts before triggering an alert
  window_seconds: 10    # Time window for detection

port_scan:
  enabled: true
  threshold: 3          # Number of port scan attempts before triggering an alert
  window_seconds: 10    # Time window for detection

sql_injection:
  enabled: true

unusual_access:
  enabled: true
  sensitive_paths:      # Paths to monitor
    - /etc/passwd
    - /var/log/auth.log
    - /root/.bashrc
    - /admin/panel
  trusted_ips:         # IPs to exclude from detection
    - 127.0.0.1
```

## Usage

Basic usage:

```bash
seclog path/to/logfile.log
```

With configuration file:

```bash
seclog path/to/logfile.log -c config.yaml
```

Output in JSON format:

```bash
seclog path/to/logfile.log --json
```

### Log Format

The analyzer expects logs sorted ascending by timestamp in the following format:

```
[YYYY-MM-DD HH:MM:SS] SEVERITY SOURCE_IP EVENT_TYPE MESSAGE
```

Example:

```
[2025-07-03 10:00:01] INFO 192.168.1.10 GET /index.html 200
[2025-07-03 10:00:05] WARNING 203.0.113.5 FAILED_LOGIN user=admin
[2025-07-03 10:00:10] ERROR 10.0.0.22 SQL_INJECTION_ATTEMPT user_input=' OR 1=1--
[2025-07-03 10:00:16] ERROR 10.0.0.23 UNUSUAL_ACCESS /etc/passwd
[2025-07-03 10:00:20] WARNING 172.16.0.10 PORT_SCAN_ATTEMPT target=22
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
