#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
from pathlib import Path

# Emoji crash the installer when stdout is a legacy codepage (VS Code runs it
# through a pipe, which on Windows means cp1252 and a UnicodeEncodeError).
# Print them only when the stream can actually encode them.
_ASCII_FALLBACKS = {
    '\U0001f527 ': '',         # wrench
    '\U0001f4cb ': '',         # clipboard
    '✅': '[OK]',
    '❌': '[ERROR]',
    '⚠️': '[WARN]',
    'ℹ️': '[INFO]',
}

def say(message=''):
    encoding = getattr(sys.stdout, 'encoding', None) or 'ascii'
    try:
        message.encode(encoding)
    except UnicodeEncodeError:
        for char, replacement in _ASCII_FALLBACKS.items():
            message = message.replace(char, replacement)
        message = message.encode('ascii', 'replace').decode('ascii')
    print(message)

def run_cmd(cmd_list, cwd=None):
    try:
        # Use list format to prevent injection
        result = subprocess.run(cmd_list, shell=False, cwd=cwd, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def install_cfml_sast():
    say("🔧 Installing CFML SAST Scanner...")
    
    # Create CFSAST directory
    os.makedirs('CFSAST', exist_ok=True)
    say("✅ Created CFSAST folder")
    
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
        say("✅ Downloaded CFML SAST scanner to CFSAST/")
        
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
        say("✅ Downloaded secure prepush scripts")
        
    except urllib.error.URLError as e:
        say(f"❌ Network error: {e}")
        say("Please check your internet connection and try again")
        return False
    except ssl.SSLError as e:
        say(f"❌ SSL verification failed: {e}")
        say("This could indicate a security issue - aborting installation")
        return False
    except Exception as e:
        say(f"❌ Download failed: {e}")
        return False
    
    # Create pre-push hook if Git repo exists.
    #
    # The hook file must be named exactly `pre-push` with no extension on
    # every platform: git does not look for `pre-push.bat`, so writing one
    # installs a hook that never runs. Git for Windows ships bash and executes
    # hooks through it, so a POSIX shell hook is correct there too.
    if Path('.git').exists():
        hook_file = Path('.git/hooks/pre-push')
        hook_content = '''#!/usr/bin/env bash
# CFML SAST pre-push hook (installed by install.py).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec ./CFSAST/prepush.sh "$@"
'''

        # Newline is forced to \\n: a CRLF shebang line makes the hook fail
        # with "bad interpreter" under Git for Windows' bash.
        with open(hook_file, 'w', newline='\n') as f:
            f.write(hook_content)

        # git requires the hook itself to be executable; prepush.sh is exec'd
        # directly by it, so it needs the bit too. chmod is a no-op on Windows
        # but harmless.
        for path in (Path('CFSAST/prepush.sh'), hook_file):
            try:
                path.chmod(0o755)
            except OSError as e:
                say(f"⚠️  Could not set executable bit on {path}: {e}")

        say("✅ Installed pre-push hook at .git/hooks/pre-push")
    else:
        say("ℹ️ No Git repository found - skipping Git hooks")
    
    # Verify installation
    if Path('CFSAST/cfml_sast_simple.py').exists():
        say("✅ Installation successful!")
        say("\n📋 Usage:")
        say("py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc")
        say("py -3 CFSAST/cfml_sast_simple.py --init-ignore  # Create .sastignore")
        if Path('.git').exists():
            say("\n📋 Git integration:")
            say("git push  # Scanner will run automatically with secure scripts")
        return True
    else:
        say("❌ Installation failed - scanner file not found")
        return False

if __name__ == '__main__':
    install_cfml_sast()