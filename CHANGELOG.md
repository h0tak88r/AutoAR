# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0] - 2025-01-27

### Added
- **S3 Bucket Scanning**: Complete AWS S3 bucket permission testing and vulnerability assessment
- **Enhanced API Management**: Built-in API server management with systemd service support
- **Automatic Cleanup System**: Smart results cleanup with optional preservation
- **Simplified Output**: Streamlined, professional scan results for better readability
- **Enhanced Security**: Improved secret detection and Azure/AWS takeover detection
- **Performance Optimizations**: Faster scans and improved resource management
- **Tool Validation**: Comprehensive tool checking before scan execution
- **SQLite Database Handler**: Complete database management system for scan data

### Changed
- **API Integration**: All scan types now available through REST API
- **Output Format**: Simplified and professional scan result formatting
- **Cleanup Behavior**: Results automatically cleaned up on exit (configurable)
- **Error Handling**: Improved error handling and logging throughout

### Fixed
- **S3 Scan Results**: Fixed API results path handling for S3 scans
- **File Creation**: Fixed file creation issues in S3 scanning
- **Logging**: Corrected logging level inconsistencies
- **Argument Parsing**: Fixed global option handling in CLI

### Security
- **Secret Sanitization**: Ensured no secrets are exposed in configuration files
- **API Key Protection**: Added .gitignore to prevent accidental secret commits
- **Configuration Sample**: Created sanitized configuration template

## [2.0.0] - Previous Release

### Added
- **REST API**: Complete programmatic access to all AutoAR functionality
- **Async Processing**: Non-blocking scan execution with real-time status updates
- **Structured Results**: JSON-formatted results with comprehensive summaries
- **File Downloads**: Direct access to all generated result files
- **Job Management**: Track, monitor, and manage scan jobs
- **Auto Documentation**: Interactive API docs at `/docs`

### Changed
- **Architecture**: Moved to API-first architecture
- **Integration**: Enhanced integration capabilities for external tools
- **Performance**: Improved scan performance and resource management
