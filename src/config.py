# config.py
# Author: Arturo 'Buanzo' Busleiman github.com/buanzo

time_window_minutes = 5  # Time window in minutes to consider for similar subjects
similarity_threshold = 0.8  # Threshold for string similarity (0 to 1)
similarity_count = 5  # Number of similar subjects required to trigger rejection
comparison_method = "similarity"  # Options: "similarity", "exact"
trigger_for_same_recipient = True  # Only trigger for emails sent to the same recipient
sqlite_db_path = '/tmp/policyd_subject_ratelimit.db'  # Path to SQLite database
server_ip = '127.0.0.1'  # IP address for the policy server
server_port = 10669  # TCP port for the policy server
DEBUG = True  # Default debug mode

# Whitelists
from_address_whitelist = []
rcpt_address_whitelist = []
domain_whitelist = []
domain_whitelist_file = None

# Action to take when similar subjects are found
action = 'HOLD'  # Options: 'REJECT', 'HOLD', 'DEFER'