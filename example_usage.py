#!/usr/bin/env python3
"""
Example usage of the CRX Parser for ML-Datasets

This script demonstrates how to use the CRX parser to extract features
from Chrome extension files for machine learning analysis.
"""

import json
import sys
from pathlib import Path
from crx_parser import CRXParser, parse_crx_file, CRXParseError


def analyze_single_crx(file_path: str):
    """Analyze a single .crx file and print detailed information."""
    print(f"Analyzing CRX file: {file_path}")
    print("=" * 60)
    
    try:
        result = parse_crx_file(file_path)
        
        # Print basic information
        print("\n📦 Basic Information:")
        metadata = result['metadata']
        print(f"  File Size: {metadata['file_size']:,} bytes")
        print(f"  ZIP Size: {metadata['zip_size']:,} bytes")
        print(f"  Compression Ratio: {result['features']['compression_ratio']:.2%}")
        print(f"  Number of Files: {metadata['file_count']}")
        
        # Print header information
        print("\n🔐 CRX Header:")
        header = result['header']
        print(f"  Version: {header['version']}")
        print(f"  Public Key Size: {header['public_key_length']} bytes")
        print(f"  Signature Size: {header['signature_length']} bytes")
        
        # Print manifest information
        print("\n📋 Extension Manifest:")
        manifest = result['manifest']
        if manifest:
            print(f"  Name: {manifest.get('name', 'N/A')}")
            print(f"  Version: {manifest.get('version', 'N/A')}")
            print(f"  Manifest Version: {manifest.get('manifest_version', 'N/A')}")
            print(f"  Description: {manifest.get('description', 'N/A')[:100]}...")
            
            permissions = manifest.get('permissions', [])
            if permissions:
                print(f"  Permissions ({len(permissions)}):")
                for perm in permissions[:5]:  # Show first 5 permissions
                    print(f"    - {perm}")
                if len(permissions) > 5:
                    print(f"    ... and {len(permissions) - 5} more")
        else:
            print("  No manifest.json found")
        
        # Print file type analysis
        print("\n📁 File Type Analysis:")
        extensions = result['features']['file_extensions']
        if extensions:
            for ext, count in sorted(extensions.items(), key=lambda x: x[1], reverse=True):
                ext_name = ext if ext else "(no extension)"
                print(f"  {ext_name}: {count} files")
        
        # Print ML features summary
        print("\n🤖 ML Features Summary:")
        features = result['features']
        print(f"  Has JavaScript: {features['has_js_files']}")
        print(f"  Has HTML: {features['has_html_files']}")
        print(f"  Has CSS: {features['has_css_files']}")
        print(f"  Has Background Scripts: {features['has_background_scripts']}")
        print(f"  Has Content Scripts: {features['has_content_scripts']}")
        print(f"  Permission Count: {features['permission_count']}")
        print(f"  Has Tabs Permission: {features['has_tabs_permission']}")
        print(f"  Has Storage Permission: {features['has_storage_permission']}")
        
        # Print file hashes for uniqueness
        print("\n🔍 Identity Hashes:")
        print(f"  File Hash: {features['file_hash'][:16]}...")
        print(f"  ZIP Hash: {features['zip_hash'][:16]}...")
        if 'public_key_hash' in features:
            print(f"  Public Key Hash: {features['public_key_hash'][:16]}...")
        
        return result
        
    except CRXParseError as e:
        print(f"❌ Error parsing CRX file: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None


def batch_analyze_crx_files(directory: str, output_file: str = None):
    """
    Analyze multiple .crx files in a directory and optionally save results.
    
    Args:
        directory: Directory containing .crx files
        output_file: Optional file to save results in JSON format
    """
    crx_dir = Path(directory)
    if not crx_dir.exists():
        print(f"❌ Directory not found: {directory}")
        return
    
    crx_files = list(crx_dir.glob("*.crx"))
    if not crx_files:
        print(f"❌ No .crx files found in: {directory}")
        return
    
    print(f"🔍 Found {len(crx_files)} .crx files to analyze")
    print("=" * 60)
    
    results = []
    parser = CRXParser()
    
    for i, crx_file in enumerate(crx_files, 1):
        print(f"\n[{i}/{len(crx_files)}] Processing: {crx_file.name}")
        
        try:
            result = parser.parse_file(str(crx_file))
            result['file_path'] = str(crx_file)
            result['file_name'] = crx_file.name
            results.append(result)
            
            # Print brief summary
            manifest = result['manifest']
            ext_name = manifest.get('name', 'Unknown') if manifest else 'Unknown'
            print(f"  ✅ {ext_name} - {result['metadata']['file_count']} files")
            
        except Exception as e:
            print(f"  ❌ Failed: {e}")
            continue
    
    print(f"\n✅ Successfully analyzed {len(results)} out of {len(crx_files)} files")
    
    # Save results if requested
    if output_file and results:
        try:
            with open(output_file, 'w') as f:
                # Convert bytes to hex strings for JSON serialization
                json_results = []
                for result in results:
                    json_result = result.copy()
                    # Convert binary data to hex strings
                    if 'header' in json_result:
                        header = json_result['header'].copy()
                        if 'public_key' in header:
                            header['public_key'] = header['public_key'].hex()
                        if 'signature' in header:
                            header['signature'] = header['signature'].hex()
                        json_result['header'] = header
                    json_results.append(json_result)
                
                json.dump(json_results, f, indent=2, default=str)
            print(f"💾 Results saved to: {output_file}")
        except Exception as e:
            print(f"❌ Failed to save results: {e}")
    
    return results


def extract_ml_features_dataset(crx_results: list) -> list:
    """
    Extract a clean dataset of ML features from CRX parsing results.
    
    Args:
        crx_results: List of CRX parsing results
        
    Returns:
        List of dictionaries containing ML features
    """
    dataset = []
    
    for result in crx_results:
        if 'features' not in result:
            continue
        
        features = result['features'].copy()
        
        # Add metadata
        features['file_name'] = result.get('file_name', '')
        
        # Add manifest fields if available
        manifest = result.get('manifest', {})
        features['extension_name'] = manifest.get('name', '')
        features['extension_version'] = manifest.get('version', '')
        features['extension_description'] = manifest.get('description', '')
        
        dataset.append(features)
    
    return dataset


def main():
    """Main function for example usage."""
    if len(sys.argv) < 2:
        print("CRX Parser Example Usage")
        print("=" * 30)
        print("Usage:")
        print("  python example_usage.py <crx_file>           # Analyze single file")
        print("  python example_usage.py <directory>         # Analyze directory")
        print("  python example_usage.py <directory> <output.json>  # Save results")
        print("\nExamples:")
        print("  python example_usage.py my_extension.crx")
        print("  python example_usage.py ./crx_files/")
        print("  python example_usage.py ./crx_files/ analysis_results.json")
        return
    
    input_path = sys.argv[1]
    path = Path(input_path)
    
    if path.is_file() and path.suffix.lower() == '.crx':
        # Analyze single file
        analyze_single_crx(str(path))
        
    elif path.is_dir():
        # Analyze directory
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        results = batch_analyze_crx_files(str(path), output_file)
        
        if results:
            print("\n📊 Creating ML Features Dataset...")
            ml_dataset = extract_ml_features_dataset(results)
            
            if len(sys.argv) > 2:
                # Save ML dataset separately
                ml_output = Path(sys.argv[2]).with_suffix('.ml_features.json')
                with open(ml_output, 'w') as f:
                    json.dump(ml_dataset, f, indent=2, default=str)
                print(f"🤖 ML features dataset saved to: {ml_output}")
    
    else:
        print(f"❌ Invalid input: {input_path}")
        print("Please provide a .crx file or directory containing .crx files")


if __name__ == "__main__":
    main()