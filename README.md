# GVM Scan Automation

This project provides a Flask-based API to create and run scans using the Greenbone Vulnerability Management (GVM) framework. The API supports creating scan tasks, starting them, and retrieving scan reports.

## Prerequisites

- Python 3.9
- python-gvm
- gvm-tools
- Flask

## Docker support
The assignment can be dockerize and tested with the command:
```bash
docker build -t assignment .
docker-compose up --build
```

To remove the containers:
```bash
docker-compose down
```

If you want to scan your docker container you can add it to the "docker-compose.yml" and add the dependency to the "depends_on"

## Docker Containers
I used the following Docker containers:

1. **OpenVAS Container:**
```bash
sudo docker run -d -p 443:443 -p 9390:9390 --name openvas mikesplain/openvas
```

2. **Vulnerable Containers for Testing:**

- **CVE-2021-41773:**
```bash
sudo docker pull blueteamsteve/cve-2021-41773:no-cgid
sudo docker run -dit -p 8080:80 blueteamsteve/cve-2021-41773:no-cgid
```

- **Juice Shop:**
```bash
sudo docker pull bkimminich/juice-shop
sudo docker run -d  -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

The first Docker container is for interfacing with OpenVAS, while the other two are for testing the scans on potentially vulnerable sites.

## Containers ip
Command to find containers IP addresses:

```bash
sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nameDockerContainer
```

## Testing the API
I tested the scans using Postman:

**Method:** POST  
**URL:** `http://127.0.0.1:5000/createScan`

### Example Request

```json
{
    "scan_name": "test scan",
    "targets": ["172.20.0.4:8080","172.20.0.3:3000"]
}
```
### Example response:

```json
{
    "result_details": [
        {
            "affected": "Web servers with enabled TRACE and/or TRACK methods.",
            "cves": "CVE-2003-1567, CVE-2004-2320, CVE-2004-2763, CVE-2005-3398, CVE-2006-4683, CVE-2007-3008, CVE-2008-7253, CVE-2009-2823, CVE-2010-0386, CVE-2012-2223, CVE-2014-7883",
            "endpoint": "172.20.0.4:8080",
            "impact": "An attacker may use this flaw to trick your legitimate web users to give\n  him their credentials.",
            "insight": "It has been shown that web servers supporting this methods are\n  subject to cross-site-scripting attacks, dubbed XST for Cross-Site-Tracing, when used in\n  conjunction with various weaknesses in browsers.",
            "score": "5.8",
            "qod_type": "remote_vul",
            "solution": "Disable the TRACE and TRACK methods in your web server configuration.\n\n  Please see the manual of your web server or the references for more information.",
            "solution_type": "Mitigation",
            "summary": "Debugging functions are enabled on the remote web server.\n\n  The remote web server supports the TRACE and/or TRACK methods. TRACE and TRACK\n  are HTTP methods which are used to debug web server connections."
        },
        {
            "affected": "TCP/IPv4 implementations that implement RFC1323.",
            "cves": "NOCVE",
            "endpoint": "172.20.0.3:3000",
            "impact": "A side effect of this feature is that the uptime of the remote\n  host can sometimes be computed.",
            "insight": "The remote host implements TCP timestamps, as defined by RFC1323.",
            "score": "2.6",
            "qod_type": "remote_banner",
            "solution": "To disable TCP timestamps on linux add the line 'net.ipv4.tcp_timestamps ",
            "solution_type": "Mitigation",
            "summary": "The remote host implements TCP timestamps and therefore allows to compute\n  the uptime.",
            "vuldetect": "Special IP packets are forged and sent with a little delay in between to the\n  target IP. The responses are searched for a timestamps. If found, the timestamps are reported."
        }
    ],
    "result_summary": [
        {
            "A": "N",
            "AC": "M",
            "AV": "N",
            "Au": "N",
            "C": "P",
            "I": "P",
            "cve": "CVE-2003-1567",
            "endpoint": "172.20.0.4:8080",
            "score": "5.8"
        },
        {
            "A": "N",
            "AC": "H",
            "AV": "N",
            "Au": "N",
            "C": "P",
            "I": "N",
            "cve": "NOCVE",
            "endpoint": "172.20.0.3:3000",
            "score": "2.6"
        }
    ],
    "scan_name": "scan multiple",
    "targets": [
        "172.20.0.4:8080",
        "172.20.0.3:3000"
    ]
}
```

It can be tested also usind curl command in a bash:
```bash
  curl -X POST http://127.0.0.1:5000/createScan -H "Content-Type: application/json" -d '{"scan_name": "Test Scan", "targets": ["172.20.0.4:80
80","172.20.0.3:3000"]}'
```

## File Structure

AssgignmentLibrary/
│
├── gmpScan/
│   ├── Utility/
│   │   ├── EnumConfigurationTasks.py
│   │   └── Certificate/
│   │       ├── client.pem
│   │       ├── client.key
│   ├── __init__.py
│   ├── credential.py
|   ├── report.py
|   ├── scanner.py
|   ├── target.py
│   └── task.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── assignment.py
├── setup.py
└── README.md



### Directory and File Descriptions

- **gmpScan/**: Contains core modules and utilities for the GVM scan automation.
    - **Utility/**: Contains utility functions and certificate files.
        - **Certificate/**: Stores certificate and key files required for GVM authentication.
            - **client.pem**: Client certificate file.
            - **client.key**: Client private key file.
        - **EnumConfigurationTasks.py**: Enum file for configuration task type.
    - **__init__.py**: Initialization file for the `gmpScan` package.
    - **credential.py**: Contains functions related to credential operations.
    - **report.py**: Contains functions related to report operations.
    - **scanner.py**: Contains functions related to scanning operations.
    - **target.py**: Contains functions related to target operations.
    - **task.py**: Contains functions related to task operations.

- **Dockerfile**: 
- **docker-compose.yml**: 
- **requirements.txt**: 
- **assignment.py**: It contains the Flask application and defines the API endpoints that handle scan creation, task management, and report retrieval.
- **setup.py**: This script is used to manage the project's dependencies and configuration.
- **README.md**: This file, which provides an overview of the project, setup instructions, and API usage details.


### Function provided by the library
- **credential.py**: 
    - **create_credential(gmp, username, password, CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY)**: create the credential to use gmp APIs

- **report.py**: 
    - **get_report_id(gmp, taskID, targetID)**: retrive the report of a task
    - **saveInFile(xmlToSave, name)**: save in a file the xml

- **scanner.py**: 
    - **create_scanner(gmp, scan_name, credentialID, hostToScan, portToScan)**: create the scanner

- **target.py**: 
    - **create_target(gmp, hostToScan, nameTarget)**: create the target

- **credential.py**: 
    - **create_task(gmp, scannerID, targetID, config_id, host)**: create the task
    - **startTask(gmp, taskID)**: create the scan of the task
 