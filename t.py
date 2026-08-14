import runpy, sys
m = runpy.run_path(r"g:\CF-SAST\install.py")
say = m["say"]
say("\U0001f527 Installing CFML SAST Scanner...")
say("\u2705 Created CFSAST folder")
say("\u274c Download failed: boom")
say("\u26a0\ufe0f  Could not set executable bit")
say("\u2139\ufe0f No Git repository found - skipping Git hooks")
say("\n\U0001f4cb Usage:")
print("stdout encoding:", sys.stdout.encoding)
