
# Exposed .git Detector

A modern and efficient Go application designed to detect exposed `.git` repositories on web servers. This tool helps identify security risks and provides actionable recommendations to prevent potential exploits. 

## Features

- Scans a list of URLs for exposed `.git` endpoints.
- Detects leaked files such as `.git/config`, `.git/index`, `.git/logs`, and more.
- Extracts branch names from `.git/HEAD`.
- Identifies potential risks associated with exposed `.git` files.
- Provides detailed recommendations for securing repositories.
- Supports error detection in responses to ensure accurate findings.
- Fast and concurrent scanning with a configurable timeout.

## Table of Contents

- [Getting Started](#getting-started)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output](#output)
- [Potential Risks](#potential-risks)
- [Recommended Fix](#recommended-fix)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

### Prerequisites

- Go 1.18 or higher.
- Internet connection for scanning live URLs.

## Installation

Clone the repository and build the application:

```bash
git clone https://github.com/Karthikdude/Gitx
cd Gitx
go build -o exposed-git-detector
```

## Usage

Run the application with a list of URLs:

```bash
gitx -file urls.txt
```

### Flags

- `-file`: Specify the path to the file containing a list of URLs (one URL per line).
- `-timeout`: (Optional) Timeout for HTTP requests in seconds (default: 5 seconds).

### Example

```bash
gitx -file urls.txt -timeout 10
```

## Configuration

You can configure the paths to check for `.git` exposure by modifying the `paths` variable in the source code.

## Output

The results are output in JSON format for easy parsing and analysis. Each result includes:

- `url`: The scanned URL.
- `exposed`: Whether the `.git` directory is exposed.
- `leaked_files`: List of leaked `.git` files.
- `branch_name`: Detected branch name (if applicable).
- `potential_risks`: Security risks associated with the exposure.
- `recommended_fix`: Suggested actions to secure the repository.
- `status_codes`: HTTP status codes for each scanned path.
- `verification`: Verification status for each path.
- `error_messages`: Any error messages found in the response body.

### Sample Output

```json
{
  "url": "http://example.com",
  "exposed": true,
  "leaked_files": ["/.git/config", "/.git/index"],
  "branch_name": "main",
  "potential_risks": [
    "Attackers can download the entire repository.",
    "Leaked .git/config may expose repository URLs or sensitive settings."
  ],
  "recommended_fix": "Restrict access to the .git directory via web server settings.",
  "status_codes": {
    "/.git/": "200 OK",
    "/.git/config": "200 OK"
  },
  "verification": {
    "/.git/": true,
    "/.git/config": true
  },
  "error_messages": {
    "/.git/config": "No Error Messages Found"
  }
}
```

## Potential Risks

Exposing the `.git` directory can lead to:

- Full repository compromise.
- Exposure of sensitive information, such as credentials or API keys.
- Access to commit history and file structure.
- Enumeration of tracked files.

## Recommended Fix

To secure your `.git` directory:

1. Restrict access using your web server configuration (e.g., Apache `.htaccess`, Nginx `location` block).
2. Use tools like `git-secret` to encrypt sensitive data.
3. Audit your `.gitignore` file to ensure sensitive files are not tracked.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any bugs or improvements.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

**Author:** Your Name  
**Contact:** [your-email@example.com](mailto:your-email@example.com)
```

This README is detailed, modern, and includes all essential sections to guide users and contributors. Let me know if you'd like to customize any part further!
