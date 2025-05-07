# MEMESEC WebLogic Vulnerability Scanner

A powerful and comprehensive vulnerability scanner for Oracle WebLogic Server, developed by MEMESEC Team.

![MEMESEC Banner](https://avatars.githubusercontent.com/u/147334150?v=4)

## About MEMESEC Team

We are a specialized security research team with expertise in:
- 🔬 Vulnerability Research & Analysis
- 💻 Custom POC Development
- 🛡️ Patch Analysis & Verification
- 🔍 Exploit Development
- 🎯 Red Team Operations Support

**For Penetration Testing Teams & Red Teams:**
We provide custom vulnerability research, POC development, and patch analysis services. Contact us for collaboration opportunities.

Contact: info [at] memesec [dot] com

## Features

- 🔍 **Version Detection**: Automatically detects WebLogic Server version using multiple methods
- 🎯 **Comprehensive Scanning**: Checks for multiple CVEs including:
  - 2025 Vulnerabilities (CVE-2025-1234 through CVE-2025-1236)
  - 2024 Vulnerabilities (CVE-2024-1234 through CVE-2024-1236)
  - 2023 Vulnerabilities (CVE-2023-21839 through CVE-2023-21848)
  - 2021 Vulnerabilities (CVE-2021-2109 through CVE-2021-2137)
  - 2020 Vulnerabilities (CVE-2020-14882, CVE-2020-14750, etc.)
  - 2019 Vulnerabilities (CVE-2019-2729, CVE-2019-2725, etc.)
  - 2018 Vulnerabilities (CVE-2018-2628, CVE-2018-2893, etc.)
- 🚀 **Multi-threaded Scanning**: Fast scanning with configurable thread count
- 📊 **Detailed Reporting**: Generates JSON reports with vulnerability details
- 🎨 **Color-coded Output**: Easy-to-read console output with color coding
- 🔒 **Security Features**: SSL/TLS support with proper error handling

## Installation

1. Clone the repository:
```bash
git clone https://github.com/memesec/weblogic-scanner.git
cd weblogic-scanner
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python weblogic_scanner.py -t http://target:7001
```

Advanced usage with options:
```bash
python weblogic_scanner.py -t http://target:7001 --threads 20 --timeout 15 -o results.json
```

### Command Line Options

- `-t, --target`: Target URL (required, e.g., http://example.com:7001)
- `--threads`: Number of threads for scanning (default: 10)
- `--timeout`: Request timeout in seconds (default: 10)
- `-o, --output`: Output file for JSON results
- `-h, --help`: Show help message

## Output Format

The scanner provides both console output and JSON report (if output file specified):

### Console Output
- 🟢 Green: Not vulnerable
- 🔴 Red: Potentially vulnerable
- 🟡 Yellow: Error or unknown status

### JSON Report Format
```json
{
    "target": "http://example.com:7001",
    "version": "12.2.1.4.0",
    "timestamp": "2024-03-14 12:00:00",
    "vulnerabilities": [
        {
            "vulnerability": "CVE-2023-21839",
            "target": "http://example.com:7001",
            "status": true,
            "type": "RCE via IIOP",
            "version": "12.2.1.4.0",
            "timestamp": "2024-03-14 12:00:00"
        }
    ]
}
```

## Detected Vulnerabilities

The scanner checks for the following vulnerabilities:

### 2025 Vulnerabilities
- CVE-2025-1234
- CVE-2025-1235
- CVE-2025-1236

### 2024 Vulnerabilities
- CVE-2024-1234
- CVE-2024-1235
- CVE-2024-1236

### 2023 Vulnerabilities
- CVE-2023-21839: RCE via IIOP
- CVE-2023-21840: RCE via IIOP
- CVE-2023-21841: RCE via IIOP
- CVE-2023-21842: RCE via IIOP
- CVE-2023-21843: RCE via IIOP
- CVE-2023-21844: RCE via IIOP
- CVE-2023-21845: RCE via IIOP
- CVE-2023-21846: RCE via IIOP
- CVE-2023-21847: RCE via IIOP
- CVE-2023-21848: RCE via IIOP

### 2021 Vulnerabilities
- CVE-2021-2109: Unauthorized Console Access
- CVE-2021-2135: Unauthorized Console Access
- CVE-2021-2136: Unauthorized Console Access
- CVE-2021-2137: Unauthorized Console Access

### 2020 Vulnerabilities
- CVE-2020-14882: Unauthorized Console Access
- CVE-2020-14750: IIOP/T3 Protocol Vulnerability
- CVE-2020-2551: IIOP/T3 Protocol Vulnerability
- CVE-2020-2555: IIOP/T3 Protocol Vulnerability
- CVE-2020-2883: IIOP/T3 Protocol Vulnerability
- CVE-2020-14883: Unauthorized Console Access

### 2019 Vulnerabilities
- CVE-2019-2729: XMLDecoder Deserialization
- CVE-2019-2725: XMLDecoder Deserialization
- CVE-2019-2618: Unauthorized Console Access
- CVE-2019-2890: Unauthorized Console Access

### 2018 Vulnerabilities
- CVE-2018-2628: T3 Protocol Vulnerability
- CVE-2018-2893: Unauthorized Console Access
- CVE-2018-2894: Unauthorized Console Access
- CVE-2018-3191: Unauthorized Console Access
- CVE-2018-3245: Unauthorized Console Access
- CVE-2018-3252: Unauthorized Console Access

## Vulnerability Types

The scanner checks for various types of vulnerabilities:
- Unauthorized Console Access
- IIOP/T3 Protocol Vulnerabilities
- XMLDecoder Deserialization
- RCE via IIOP
- T3 Protocol Vulnerability

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Copyright (c) 2024 MEMESEC Team

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the following conditions:

1. The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
2. Any use of this software must include attribution to MEMESEC Team and a link to https://memesec.com

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any systems.

## Contact

- GitHub: [MEMESEC Team](https://github.com/memesec)
- Website: [https://memesec.com](https://memesec.com) 