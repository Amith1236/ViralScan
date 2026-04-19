import os

# Ensure required settings are present during tests.
# These are dummy values only for local and CI test collection.
os.environ.setdefault("VIRUSTOTAL_API_KEY", "test-virus-total-key")
os.environ.setdefault("GEMINI_API_KEY", "test-gemini-key")
