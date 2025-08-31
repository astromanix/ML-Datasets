# ML-Datasets

This repository contains datasets and parsers for machine learning research.

## CRX File Parser

A comprehensive parser for Chrome Extension (.crx) files that extracts metadata and features useful for machine learning analysis.

### Features

- **Complete CRX Format Support**: Parses CRX v2 and v3 files with proper header validation
- **Manifest Analysis**: Extracts and analyzes extension manifest.json data
- **ML Feature Extraction**: Generates 30+ features for machine learning analysis
- **File Content Access**: Provides access to individual files within the extension
- **Security Analysis**: Extracts public keys, signatures, and permission data
- **Batch Processing**: Supports analyzing multiple CRX files at once

### Usage

#### Basic Usage

```python
from crx_parser import parse_crx_file

# Parse a single CRX file
result = parse_crx_file('my_extension.crx')

print(f"Extension name: {result['manifest']['name']}")
print(f"Number of files: {result['metadata']['file_count']}")
print(f"Permissions: {result['manifest']['permissions']}")
```

#### Command Line Usage

```bash
# Analyze a single CRX file
python crx_parser.py my_extension.crx

# Batch analyze a directory of CRX files
python example_usage.py /path/to/crx/files/

# Save analysis results to JSON
python example_usage.py /path/to/crx/files/ results.json
```

#### Advanced Usage

```python
from crx_parser import CRXParser

parser = CRXParser()
result = parser.parse_file('extension.crx')

# Access ML features for analysis
features = result['features']
print(f"Has JavaScript files: {features['has_js_files']}")
print(f"Permission count: {features['permission_count']}")
print(f"File type distribution: {features['file_extensions']}")

# Extract individual file content
background_js = parser.get_file_content('background.js')
manifest_content = parser.get_file_content('manifest.json')

# Extract all files to directory
parser.extract_all_files('./extracted_extension/')
```

### ML Features Extracted

The parser extracts over 30 features useful for machine learning analysis:

#### File Structure Features
- `file_size`: Total size of the CRX file
- `zip_size`: Size of the embedded ZIP archive
- `compression_ratio`: Compression efficiency
- `file_count`: Number of files in the extension
- `file_extensions`: Distribution of file types

#### Security Features
- `crx_version`: CRX format version
- `public_key_size`: Size of the public key
- `signature_size`: Size of the signature
- `file_hash`: SHA256 hash for uniqueness detection
- `public_key_hash`: Hash of the public key

#### Extension Features
- `manifest_version`: Manifest format version
- `has_background_scripts`: Whether extension has background scripts
- `has_content_scripts`: Whether extension has content scripts
- `permission_count`: Number of permissions requested
- `has_*_permission`: Boolean flags for specific permissions
- `has_*_files`: Boolean flags for file types (JS, HTML, CSS, etc.)

### Testing

Run the test suite to validate the parser:

```bash
python test_crx_parser.py
```

### Requirements

- Python 3.6+
- Standard library only (no external dependencies)

### File Format Support

The parser supports Chrome Extension (.crx) files which contain:
- CRX header with magic number "Cr24"
- Public key and signature data
- ZIP archive with extension files
- Manifest.json with extension metadata

### Example Output

```json
{
  "header": {
    "magic": "Cr24",
    "version": 2,
    "public_key_length": 294,
    "signature_length": 256
  },
  "manifest": {
    "manifest_version": 3,
    "name": "My Extension",
    "version": "1.0.0",
    "permissions": ["storage", "tabs"]
  },
  "features": {
    "file_count": 15,
    "has_js_files": true,
    "permission_count": 2,
    "has_background_scripts": true,
    "compression_ratio": 0.75
  }
}
```