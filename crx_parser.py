#!/usr/bin/env python3
"""
CRX File Parser for ML-Datasets

A parser for Chrome Extension (.crx) files that extracts metadata and features
useful for machine learning analysis.

CRX file format:
- Magic number (4 bytes): "Cr24"
- Version (4 bytes)
- Public key length (4 bytes)
- Signature length (4 bytes)
- Public key (variable length)
- Signature (variable length)
- ZIP archive (remaining bytes)
"""

import struct
import zipfile
import json
import io
import hashlib
from typing import Dict, Any, Optional, List
from pathlib import Path


class CRXParseError(Exception):
    """Exception raised when CRX file parsing fails."""
    pass


class CRXParser:
    """Parser for Chrome Extension (.crx) files."""
    
    CRX_MAGIC = b'Cr24'
    SUPPORTED_VERSIONS = [2, 3]
    
    def __init__(self):
        """Initialize the CRX parser."""
        self.reset()
    
    def reset(self):
        """Reset parser state."""
        self.header = {}
        self.manifest = {}
        self.file_list = []
        self.raw_data = b''
        self.zip_data = b''
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a .crx file and extract all available information.
        
        Args:
            file_path: Path to the .crx file
            
        Returns:
            Dictionary containing parsed data and extracted features
            
        Raises:
            CRXParseError: If the file cannot be parsed
        """
        try:
            with open(file_path, 'rb') as f:
                self.raw_data = f.read()
        except IOError as e:
            raise CRXParseError(f"Cannot read file {file_path}: {e}")
        
        return self.parse_data(self.raw_data)
    
    def parse_data(self, data: bytes) -> Dict[str, Any]:
        """
        Parse raw .crx file data.
        
        Args:
            data: Raw bytes of the .crx file
            
        Returns:
            Dictionary containing parsed data and extracted features
        """
        self.reset()
        self.raw_data = data
        
        # Parse CRX header
        self._parse_header()
        
        # Extract ZIP archive
        self._extract_zip_archive()
        
        # Parse manifest.json
        self._parse_manifest()
        
        # Generate feature set for ML analysis
        features = self._extract_features()
        
        return {
            'header': self.header,
            'manifest': self.manifest,
            'file_list': self.file_list,
            'features': features,
            'metadata': {
                'file_size': len(self.raw_data),
                'zip_size': len(self.zip_data),
                'file_count': len(self.file_list),
                'has_manifest': bool(self.manifest)
            }
        }
    
    def _parse_header(self):
        """Parse the CRX file header."""
        if len(self.raw_data) < 16:
            raise CRXParseError("File too small to contain valid CRX header")
        
        # Check magic number
        magic = self.raw_data[:4]
        if magic != self.CRX_MAGIC:
            raise CRXParseError(f"Invalid magic number: {magic}")
        
        # Parse version
        version = struct.unpack('<I', self.raw_data[4:8])[0]
        if version not in self.SUPPORTED_VERSIONS:
            raise CRXParseError(f"Unsupported CRX version: {version}")
        
        # Parse lengths
        public_key_length = struct.unpack('<I', self.raw_data[8:12])[0]
        signature_length = struct.unpack('<I', self.raw_data[12:16])[0]
        
        # Calculate offsets
        public_key_offset = 16
        signature_offset = public_key_offset + public_key_length
        zip_offset = signature_offset + signature_length
        
        # Validate lengths
        if zip_offset > len(self.raw_data):
            raise CRXParseError("Invalid header lengths")
        
        # Extract public key and signature
        public_key = self.raw_data[public_key_offset:signature_offset]
        signature = self.raw_data[signature_offset:zip_offset]
        
        self.header = {
            'magic': magic.decode('ascii'),
            'version': version,
            'public_key_length': public_key_length,
            'signature_length': signature_length,
            'public_key': public_key,
            'signature': signature,
            'zip_offset': zip_offset
        }
    
    def _extract_zip_archive(self):
        """Extract the ZIP archive from the CRX file."""
        zip_offset = self.header['zip_offset']
        self.zip_data = self.raw_data[zip_offset:]
        
        try:
            with zipfile.ZipFile(io.BytesIO(self.zip_data), 'r') as zip_file:
                self.file_list = zip_file.namelist()
        except zipfile.BadZipFile:
            raise CRXParseError("Invalid ZIP archive in CRX file")
    
    def _parse_manifest(self):
        """Parse the manifest.json file from the ZIP archive."""
        try:
            with zipfile.ZipFile(io.BytesIO(self.zip_data), 'r') as zip_file:
                if 'manifest.json' in zip_file.namelist():
                    manifest_data = zip_file.read('manifest.json')
                    self.manifest = json.loads(manifest_data.decode('utf-8'))
        except (zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError):
            # If manifest parsing fails, continue with empty manifest
            self.manifest = {}
    
    def _extract_features(self) -> Dict[str, Any]:
        """
        Extract features useful for machine learning analysis.
        
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Basic file features
        features['file_size'] = len(self.raw_data)
        features['zip_size'] = len(self.zip_data)
        features['compression_ratio'] = len(self.zip_data) / len(self.raw_data) if self.raw_data else 0
        features['file_count'] = len(self.file_list)
        
        # Header features
        features['crx_version'] = self.header.get('version', 0)
        features['public_key_size'] = self.header.get('public_key_length', 0)
        features['signature_size'] = self.header.get('signature_length', 0)
        
        # File type analysis
        file_extensions = {}
        for file_path in self.file_list:
            ext = Path(file_path).suffix.lower()
            file_extensions[ext] = file_extensions.get(ext, 0) + 1
        
        features['file_extensions'] = file_extensions
        features['has_js_files'] = '.js' in file_extensions
        features['has_html_files'] = '.html' in file_extensions
        features['has_css_files'] = '.css' in file_extensions
        features['has_json_files'] = '.json' in file_extensions
        
        # Manifest features
        if self.manifest:
            features['manifest_version'] = self.manifest.get('manifest_version', 0)
            features['has_background_scripts'] = 'background' in self.manifest
            features['has_content_scripts'] = 'content_scripts' in self.manifest
            features['has_permissions'] = 'permissions' in self.manifest
            features['permission_count'] = len(self.manifest.get('permissions', []))
            features['has_host_permissions'] = 'host_permissions' in self.manifest
            
            # Extract specific permissions
            permissions = self.manifest.get('permissions', [])
            features['has_tabs_permission'] = 'tabs' in permissions
            features['has_storage_permission'] = 'storage' in permissions
            features['has_activeTab_permission'] = 'activeTab' in permissions
            
            # Extension metadata
            features['has_name'] = 'name' in self.manifest
            features['has_description'] = 'description' in self.manifest
            features['has_version'] = 'version' in self.manifest
            features['has_author'] = 'author' in self.manifest
        else:
            # Set defaults if no manifest
            for key in ['manifest_version', 'has_background_scripts', 'has_content_scripts', 
                       'has_permissions', 'permission_count', 'has_host_permissions',
                       'has_tabs_permission', 'has_storage_permission', 'has_activeTab_permission',
                       'has_name', 'has_description', 'has_version', 'has_author']:
                features[key] = 0 if 'count' in key or 'version' in key else False
        
        # Hash features for uniqueness detection
        features['file_hash'] = hashlib.sha256(self.raw_data).hexdigest()
        features['zip_hash'] = hashlib.sha256(self.zip_data).hexdigest()
        
        if self.header.get('public_key'):
            features['public_key_hash'] = hashlib.sha256(self.header['public_key']).hexdigest()
        
        return features
    
    def get_file_content(self, file_path: str) -> Optional[bytes]:
        """
        Extract content of a specific file from the ZIP archive.
        
        Args:
            file_path: Path of the file within the ZIP archive
            
        Returns:
            File content as bytes, or None if file not found
        """
        try:
            with zipfile.ZipFile(io.BytesIO(self.zip_data), 'r') as zip_file:
                if file_path in zip_file.namelist():
                    return zip_file.read(file_path)
        except zipfile.BadZipFile:
            pass
        return None
    
    def extract_all_files(self, output_dir: str):
        """
        Extract all files from the ZIP archive to a directory.
        
        Args:
            output_dir: Directory to extract files to
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        try:
            with zipfile.ZipFile(io.BytesIO(self.zip_data), 'r') as zip_file:
                zip_file.extractall(output_path)
        except zipfile.BadZipFile:
            raise CRXParseError("Cannot extract files: invalid ZIP archive")


def parse_crx_file(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to parse a single .crx file.
    
    Args:
        file_path: Path to the .crx file
        
    Returns:
        Dictionary containing parsed data and features
    """
    parser = CRXParser()
    return parser.parse_file(file_path)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python crx_parser.py <path_to_crx_file>")
        sys.exit(1)
    
    crx_file = sys.argv[1]
    
    try:
        result = parse_crx_file(crx_file)
        
        print(f"CRX File Analysis: {crx_file}")
        print("=" * 50)
        
        print("\nHeader Information:")
        header = result['header']
        print(f"  Magic: {header['magic']}")
        print(f"  Version: {header['version']}")
        print(f"  Public Key Length: {header['public_key_length']}")
        print(f"  Signature Length: {header['signature_length']}")
        
        print("\nManifest Information:")
        manifest = result['manifest']
        if manifest:
            print(f"  Name: {manifest.get('name', 'N/A')}")
            print(f"  Version: {manifest.get('version', 'N/A')}")
            print(f"  Description: {manifest.get('description', 'N/A')}")
            print(f"  Manifest Version: {manifest.get('manifest_version', 'N/A')}")
            print(f"  Permissions: {manifest.get('permissions', [])}")
        else:
            print("  No manifest.json found")
        
        print("\nFile Information:")
        metadata = result['metadata']
        print(f"  Total Files: {metadata['file_count']}")
        print(f"  File Size: {metadata['file_size']} bytes")
        print(f"  ZIP Size: {metadata['zip_size']} bytes")
        
        print("\nFiles in extension:")
        for file_name in result['file_list'][:10]:  # Show first 10 files
            print(f"  {file_name}")
        if len(result['file_list']) > 10:
            print(f"  ... and {len(result['file_list']) - 10} more files")
        
        print("\nML Features:")
        features = result['features']
        for key, value in features.items():
            if not key.endswith('_hash'):  # Skip hash values for readability
                print(f"  {key}: {value}")
        
    except CRXParseError as e:
        print(f"Error parsing CRX file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)