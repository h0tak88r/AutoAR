# autoAr

## Setup Instructions

1. **Clone the repository and enter the directory:**
   ```bash
   git clone https://github.com/h0tak88r/autoar.git
   cd autoar
   ```

2. **Install required tools:**
   Make sure you have all the required tools installed (subfinder, httpx, naabu, nuclei, ffuf, kxss, qsreplace, paramx, dalfox, urlfinder, interlace, jsleak, etc.).

3. **Download regex patterns for secrets detection:**
   - Visit [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db)
   - Download the regex YAML files you want to use (e.g., `rules-stable.yaml`, `trufflehog-v3.yaml`, `nuclei-generic.yaml`, etc.)
   - Place them in the `regexes/` directory in your project root.
   - Example:
     ```bash
     mkdir -p regexes
     cp /path/to/secrets-patterns-db/db/rules-stable.yaml regexes/
     cp /path/to/secrets-patterns-db/db/trufflehog-v3.yaml regexes/
     cp /path/to/secrets-patterns-db/db/nuclei-generic.yaml regexes/
     # ...add more as needed
     ```

4. **Run the script:**
   ```bash
   ./autoAr.sh -d example.com
   ```

## Notes
- All log and status messages will appear in your terminal with color and emoji formatting.
- Only data files (not log messages) will be sent to Discord if you configure a webhook.
- For best results, keep your regexes up to date from the [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db). 
