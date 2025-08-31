#!/usr/bin/env python3
"""
Test script for CRX Parser

This script tests the CRX parser functionality with a minimal test case.
"""

import struct
import zipfile
import json
import io
import tempfile
import os
from crx_parser import CRXParser, CRXParseError


def create_test_crx() -> bytes:
    """
    Create a minimal valid .crx file for testing.
    
    Returns:
        Raw bytes of a test .crx file
    """
    # Create a simple test extension
    manifest = {
        "manifest_version": 3,
        "name": "Test Extension",
        "version": "1.0.0",
        "description": "A test extension for CRX parser validation",
        "permissions": ["storage", "tabs"],
        "background": {
            "service_worker": "background.js"
        }
    }
    
    background_js = """
// Test background script
chrome.tabs.onActivated.addListener((activeInfo) => {
    console.log('Tab activated:', activeInfo);
});
"""
    
    content_js = """
// Test content script
console.log('Content script loaded');
"""
    
    # Create ZIP archive
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('manifest.json', json.dumps(manifest, indent=2))
        zip_file.writestr('background.js', background_js)
        zip_file.writestr('content.js', content_js)
        zip_file.writestr('README.txt', 'This is a test extension')
    
    zip_data = zip_buffer.getvalue()
    
    # Create dummy public key and signature
    public_key = b'test_public_key_data_1234567890'
    signature = b'test_signature_data_abcdefghijk'
    
    # Build CRX header
    magic = b'Cr24'
    version = 2
    public_key_length = len(public_key)
    signature_length = len(signature)
    
    header = struct.pack('<4sIII', magic, version, public_key_length, signature_length)
    
    # Combine all parts
    crx_data = header + public_key + signature + zip_data
    
    return crx_data


def test_basic_parsing():
    """Test basic CRX parsing functionality."""
    print("🧪 Testing basic CRX parsing...")
    
    # Create test CRX
    test_crx_data = create_test_crx()
    print(f"  Created test CRX with {len(test_crx_data)} bytes")
    
    # Parse with CRXParser
    parser = CRXParser()
    result = parser.parse_data(test_crx_data)
    
    # Validate results
    assert result['header']['magic'] == 'Cr24'
    assert result['header']['version'] == 2
    assert result['header']['public_key_length'] == 31  # len(b'test_public_key_data_1234567890')
    assert result['header']['signature_length'] == 31   # len(b'test_signature_data_abcdefghijk')
    
    assert result['manifest']['name'] == 'Test Extension'
    assert result['manifest']['version'] == '1.0.0'
    assert result['manifest']['manifest_version'] == 3
    assert 'storage' in result['manifest']['permissions']
    assert 'tabs' in result['manifest']['permissions']
    
    assert len(result['file_list']) == 4  # manifest.json, background.js, content.js, README.txt
    assert 'manifest.json' in result['file_list']
    assert 'background.js' in result['file_list']
    assert 'content.js' in result['file_list']
    assert 'README.txt' in result['file_list']
    
    print("  ✅ Header parsing successful")
    print("  ✅ Manifest parsing successful")
    print("  ✅ File list extraction successful")


def test_feature_extraction():
    """Test ML feature extraction."""
    print("🧪 Testing ML feature extraction...")
    
    test_crx_data = create_test_crx()
    parser = CRXParser()
    result = parser.parse_data(test_crx_data)
    
    features = result['features']
    
    # Test basic features
    assert features['file_count'] == 4
    assert features['crx_version'] == 2
    assert features['has_js_files'] == True
    assert features['has_json_files'] == True
    assert features['has_background_scripts'] == True
    assert features['has_permissions'] == True
    assert features['permission_count'] == 2
    assert features['has_tabs_permission'] == True
    assert features['has_storage_permission'] == True
    assert features['has_name'] == True
    assert features['has_description'] == True
    assert features['has_version'] == True
    
    # Test file extensions
    assert '.js' in features['file_extensions']
    assert '.json' in features['file_extensions']
    assert '.txt' in features['file_extensions']
    assert features['file_extensions']['.js'] == 2  # background.js, content.js
    
    print("  ✅ Basic features extraction successful")
    print("  ✅ Permission analysis successful")
    print("  ✅ File type analysis successful")


def test_file_extraction():
    """Test individual file content extraction."""
    print("🧪 Testing file content extraction...")
    
    test_crx_data = create_test_crx()
    parser = CRXParser()
    parser.parse_data(test_crx_data)
    
    # Test manifest content
    manifest_content = parser.get_file_content('manifest.json')
    assert manifest_content is not None
    manifest_json = json.loads(manifest_content.decode('utf-8'))
    assert manifest_json['name'] == 'Test Extension'
    
    # Test JavaScript file content
    background_content = parser.get_file_content('background.js')
    assert background_content is not None
    assert b'chrome.tabs.onActivated' in background_content
    
    # Test non-existent file
    missing_content = parser.get_file_content('non_existent.js')
    assert missing_content is None
    
    print("  ✅ File content extraction successful")
    print("  ✅ Non-existent file handling successful")


def test_error_handling():
    """Test error handling for invalid CRX files."""
    print("🧪 Testing error handling...")
    
    parser = CRXParser()
    
    # Test invalid magic number
    try:
        invalid_data = b'XXXX' + b'0' * 100
        parser.parse_data(invalid_data)
        assert False, "Should have raised CRXParseError"
    except CRXParseError:
        pass
    
    # Test file too small
    try:
        parser.parse_data(b'Cr24')
        assert False, "Should have raised CRXParseError"
    except CRXParseError:
        pass
    
    # Test unsupported version
    try:
        invalid_header = struct.pack('<4sIII', b'Cr24', 999, 0, 0)
        parser.parse_data(invalid_header)
        assert False, "Should have raised CRXParseError"
    except CRXParseError:
        pass
    
    print("  ✅ Invalid magic number handling successful")
    print("  ✅ File size validation successful")
    print("  ✅ Version validation successful")


def test_file_operations():
    """Test file read/write operations."""
    print("🧪 Testing file operations...")
    
    test_crx_data = create_test_crx()
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(suffix='.crx', delete=False) as tmp_file:
        tmp_file.write(test_crx_data)
        tmp_file_path = tmp_file.name
    
    try:
        # Test file parsing
        parser = CRXParser()
        result = parser.parse_file(tmp_file_path)
        
        assert result['manifest']['name'] == 'Test Extension'
        assert len(result['file_list']) == 4
        
        # Test file extraction
        with tempfile.TemporaryDirectory() as tmp_dir:
            parser.extract_all_files(tmp_dir)
            
            # Check if files were extracted
            assert os.path.exists(os.path.join(tmp_dir, 'manifest.json'))
            assert os.path.exists(os.path.join(tmp_dir, 'background.js'))
            assert os.path.exists(os.path.join(tmp_dir, 'content.js'))
            assert os.path.exists(os.path.join(tmp_dir, 'README.txt'))
        
        print("  ✅ File reading successful")
        print("  ✅ File extraction successful")
        
    finally:
        # Clean up
        os.unlink(tmp_file_path)


def run_all_tests():
    """Run all tests."""
    print("🚀 Starting CRX Parser Tests")
    print("=" * 50)
    
    try:
        test_basic_parsing()
        test_feature_extraction()
        test_file_extraction()
        test_error_handling()
        test_file_operations()
        
        print("\n✅ All tests passed successfully!")
        print("🎉 CRX Parser is working correctly")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error during testing: {e}")
        return False
    
    return True


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)