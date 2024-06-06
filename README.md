# postfix-policyd-python-subject-ratelimit

## BE ADVISED: This software is in development. 

Ok?

# Project: Postfix Policy Daemon for Subject Rate Limiting

## Description
This is a Milter using protocol version 6 that has been tested with Postfix
only.  It helps you limit the rate of emails based on their subject lines. 
It detects and handles emails with similar subjects being sent in a short
time frame, preventing potential spam or abuse.

## Features
- Rate limiting based on email subject similarity.
- Configurable time window and similarity threshold.
- Whitelisting for specific senders, recipients, and domains.
- SQLite database for storing and querying email subjects.
- Customizable actions for detected similar subjects (e.g., HOLD, REJECT, DEFER).
- Detailed logging for monitoring and debugging.

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/buanzo/postfix-policyd-subject-ratelimit.git
   cd postfix-policyd-subject-ratelimit
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure the policy daemon by editing `config.py` to match your environment.

4. Initialize the SQLite database by running the daemon, which will automatically create the necessary tables.

## Configuration
Edit the `config.py` file to set the parameters for your needs. Key parameters include:

- `time_window_minutes`: Time window in minutes to consider for similar subjects.
- `similarity_threshold`: Threshold for string similarity (0 to 1).
- `similarity_count`: Number of similar subjects required to trigger rejection.
- `comparison_method`: Method for comparing subjects (`similarity` or `exact`).
- `trigger_for_same_recipient`: Only trigger for emails sent to the same recipient.
- `sqlite_db_path`: Path to the SQLite database.
- `server_ip` and `server_port`: IP address and port for the policy server.
- `DEBUG`: Debug mode toggle.
- `from_address_whitelist`, `rcpt_address_whitelist`, `domain_whitelist`: Whitelists for addresses and domains.
- `action`: Action to take when similar subjects are found (`HOLD`, `REJECT`, `DEFER`).

## Postfix Configuration
Add the following to your Postfix `main.cf` to integrate the policy daemon:

```
smtpd_milters = inet:127.0.0.1:10669
milter_protocol = 6
milter_default_action = accept
```

Reload Postfix to apply the configuration:
```
sudo postfix reload
```

## Usage
Start the policy daemon:
```
python subject_ratelimit_policyd.py
```

To test the policy script with a given sender, recipient, and subject:
```
python subject_ratelimit_policyd.py --test "sender@example.com" "recipient@example.com" "Test Subject"
```

## Database Maintenance
Run the database maintenance script periodically (e.g., via cron) to delete old records:
```
python subject_ratelimit_db_maintenance.py
```

## Service Configuration
To run the policy daemon as a service, create a systemd service file (e.g., `policyd-subject-ratelimit.service`):

```
[Unit]
Description=Subject Rate Limit Policy Service
After=network.target

[Service]
Type=simple
User=policyd-subject-ratelimit
Group=policyd-subject-ratelimit
WorkingDirectory=/path/to/repository
ExecStart=/usr/bin/python3 /path/to/repository/subject_ratelimit_policyd.py

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```
sudo systemctl enable policyd-subject-ratelimit.service
sudo systemctl start policyd-subject-ratelimit.service
```

## Logging
Logs are stored in `/var/log/subject_ratelimit_maintenance.log` and can be configured in the script files.

## Contributing
Contributions are welcome! Please fork the repository and submit pull requests.

## License
This project is licensed under the MIT License.
