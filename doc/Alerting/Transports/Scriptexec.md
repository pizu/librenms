# Scriptexec Transport

The Scriptexec transport allows LibreNMS to execute a custom script when an alert is triggered.
This provides a flexible method for handling alerts externally without modifying LibreNMS itself.
The alert payload is sent to the script as **JSON via STDIN**, allowing the script to process the alert information as required.

## Overview

When an alert is triggered, LibreNMS invokes the Scriptexec transport which executes the configured command.  
The alert data is passed to the script through **standard input (STDIN)** in JSON format.

The script can then process the alert data as required.

## Configuration

| Config | Description | Example |
|------|-------------|------|
| Command | Command executed when an alert is triggered. The command must accept JSON input from STDIN. | `/usr/bin/python3 /opt/librenms/scripts/alert_handler.py` |
| Allowed prefix | Restricts script execution to commands starting with this path for security reasons. | `/opt/librenms/scripts/` |
| Payload mode | Defines which part of the alert payload is sent to the script. `full` sends the entire alert payload, `details` sends only the alert details section. | `full` |
| Timeout | Maximum execution time for the script in seconds. If exceeded, the script is terminated. | `20` |
| Log stdout | If enabled, any output printed by the script is written to the LibreNMS log. | `enabled` |

## Script Input Format

The script receives alert data through **STDIN** as a JSON object.

Example:

```json
{
  "sysName": "switch01.example.net",
  "hostname": "10.1.1.1",
  "name": "Port Down",
  "severity": "critical",
  "state": 1,
  "faults": [
    {
      "ifName": "Fa0/5",
      "ifOperStatus": "down"
    }
  ]
}
