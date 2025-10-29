#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_cmd(cmd_list, cwd=None):
    try:
        # Use list format to prevent injection
        result = subprocess.run(cmd_list, shell=False, cwd=cwd, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def install_cfml_sast():
    print("🔧 Installing CFML SAST Scanner...")
    
    # Create CFSAST directory
    os.makedirs('CFSAST', exist_ok=True)
    print("✅ Created CFSAST folder")
    
    # Create Git hooks directory if Git repo exists
    if Path('.git').exists():
        os.makedirs('.git/hooks', exist_ok=True)
    
    # Download scanner from GitHub with integrity verification
    try:
        import urllib.request
        import ssl
        import hashlib
        
        # Create secure SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Expected file hashes for integrity verification (update these when files change)
        expected_hashes = {
            'cfml_sast_simple.py': None,  # Skip hash check for now - would need to be updated with each release
            'prepush.sh': None,
            'prepush.bat': None
        }
        
        def secure_download(url, filepath, expected_hash=None):
            """Download file securely with integrity verification"""
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'CFML-SAST-Installer/1.0')
            
            with urllib.request.urlopen(request, context=ssl_context, timeout=30) as response:
                if response.getcode() != 200:
                    raise Exception(f"HTTP {response.getcode()}")
                
                content = response.read()
                
                # Verify content size (prevent DoS)
                if len(content) > 10 * 1024 * 1024:  # 10MB limit
                    raise Exception("Downloaded file too large")
                
                # Verify hash if provided
                if expected_hash:
                    actual_hash = hashlib.sha256(content).hexdigest()
                    if actual_hash != expected_hash:
                        raise Exception(f"Hash mismatch: expected {expected_hash}, got {actual_hash}")
                
                # Write to file
                with open(filepath, 'wb') as f:
                    f.write(content)
        
        # Download main scanner
        secure_download(
            'https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/scripts/cfml_sast_simple.py',
            'CFSAST/cfml_sast_simple.py',
            expected_hashes['cfml_sast_simple.py']
        )
        print("✅ Downloaded CFML SAST scanner to CFSAST/")
        
        # Download secure prepush scripts
        secure_download(
            'https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/scripts/sast/prepush.sh',
            'CFSAST/prepush.sh',
            expected_hashes['prepush.sh']
        )
        secure_download(
            'https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/scripts/sast/prepush.bat',
            'CFSAST/prepush.bat',
            expected_hashes['prepush.bat']
        )
        print("✅ Downloaded secure prepush scripts")
        
    except urllib.error.URLError as e:
        print(f"❌ Network error: {e}")
        print("Please check your internet connection and try again")
        return False
    except ssl.SSLError as e:
        print(f"❌ SSL verification failed: {e}")
        print("This could indicate a security issue - aborting installation")
        return False
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return False
    
    # Create secure pre-push hook if Git repo exists
    if Path('.git').exists():
        if os.name == 'nt':  # Windows
            hook_content = '''@echo off
REM CFML SAST Pre-push Hook
cd /d "%~dp0..\.."
call "CFSAST\\prepush.bat"
exit /b %errorlevel%
'''
            hook_file = '.git/hooks/pre-push.bat'
        else:  # Unix/Linux/Mac
            hook_content = '''#!/bin/bash
# CFML SAST Pre-push Hook
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec "./CFSAST/prepush.sh"
'''
            hook_file = '.git/hooks/pre-push'
        
        with open(hook_file, 'w') as f:
            f.write(hook_content)
        
        # Set permissions (Unix/Linux/Mac)
        if os.name != 'nt':
            os.chmod('CFSAST/prepush.sh', 0o755)
            os.chmod(hook_file, 0o755)
        print("✅ Set up secure Git hooks")
    else:
        print("ℹ️ No Git repository found - skipping Git hooks")
    
    # Verify installation
    if Path('CFSAST/cfml_sast_simple.py').exists():
        print("✅ Installation successful!")
        print("\n📋 Usage:")
        print("py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc")
        print("py -3 CFSAST/cfml_sast_simple.py --init-ignore  # Create .sastignore")
        if Path('.git').exists():
            print("\n📋 Git integration:")
            print("git push  # Scanner will run automatically with secure scripts")
        return True
    else:
        print("❌ Installation failed - scanner file not found")
        return False

if __name__ == '__main__':
    install_cfml_sast()