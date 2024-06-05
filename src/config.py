# config.py
# Author: Arturo 'Buanzo' Busleiman github.com/buanzo

time_window_minutes = 5  # Time window in minutes to consider for similar subjects
similarity_threshold = 0.8  # Threshold for string similarity (0 to 1)
comparison_method = "similarity"  # Options: "similarity", "exact"
trigger_for_same_recipient = True  # Only trigger for emails sent to the same recipient
sqlite_db_path = '/tmp/email_subjects.db'  # Path to SQLite database
server_port = 10669  # TCP port for the policy server
DEBUG = True  # Default debug mode

# Whitelists
from_address_whitelist = [
    "trusted@example.com",
    "noreply@trusted.com",
    "alerts@trusted.com"
]

rcpt_address_whitelist = [
    "vip@example.com",
    "admin@example.com"
]
