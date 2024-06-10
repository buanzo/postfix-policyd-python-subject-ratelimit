# postfix-policyd-python-subject-ratelimit

I created this milter to specifically address the challenges posed by
sophisticated spam campaigns that utilize different sender accounts and
avoid typical Bayesian content filters.  Such campaigns, especially those
with political inclinations, often employ a strategy of sending emails with
similar subjects to a targeted set of recipient accounts.  Traditional spam
filters may not effectively catch these emails due to the variability in
sender addresses and the lack of typical spam content.

This milter enhances our ability to detect and mitigate these spam campaigns
by focusing on the similarity of email subjects within a configurable time
window.  By analyzing subject lines and applying a string similarity
threshold, the milter can identify patterns that indicate a coordinated spam
effort.  This is particularly useful in politically inclined campaigns where
the same message is disseminated across various accounts to influence or
disrupt targeted recipients.  The ability to customize actions such as HOLD,
REJECT, or DEFER further ensures that we can respond appropriately to these
threats, maintaining the integrity and security of our email communications.

## BE ADVISED: This software is in development. 

Ok?  I will add a prometheus exporter so you can monitor how it works.  I
suggest you also use the maintenance script daily/hourly.

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

3. Configure the milter by copying `config.py.dist` to `config.py`, then edit it to match your environment.

4. Choose how to start it. We provide a sample systemd service unit. See below for more information.

## Configuration
Edit the newly created `config.py` file to set the parameters for your needs. Key parameters include:

- `time_window_minutes`: Time window in minutes to consider for similar subjects.
- `similarity_threshold`: Threshold for string similarity (0 to 1).
- `similarity_count`: Number of similar subjects required to trigger rejection.
- `comparison_method`: Method for comparing subjects (`similarity` or `exact`).
- `trigger_for_same_recipient`: Only trigger for emails sent to the same recipient.
- `sqlite_db_path`: Path to the SQLite database.
- `server_ip` and `server_port`: IP address and port for the policy server.
- `DEBUG`: Debug mode toggle.
- `from_address_whitelist`, `rcpt_address_whitelist`, `domain_whitelist`: Whitelists for addresses and domains.
- `action`: Action to take when similar subjects are found and no whitelisting is triggered. See below for details.
- `domain_whitelist_file`: Path to a file containing a list of whitelisted domains. If set to None, no additional domains are loaded from a file.
- `action_log_file_path`: Path to the log file for logging actions. If set to None, action logging is disabled.

## Available actions

When similar subjects are found, the action parameter determines how the
email is handled.  The valid options are:

- `ACCEPT` to accept the message without modifications
- `REJECT` to permanently reject the message
- `HOLD` or `QUARANTINE` to quarantine the message for further review
- `DISCARD` to accept the message but silently discard it
- `TEMPFAIL` to temporarily fail the message, requesting the sender to retry later.

When DEBUG is True, the action that would have been taken is logged appropriately, but the message is ACCEPT-ed.

## Postfix Configuration
Add the following to your Postfix `main.cf` to integrate the milter:

```
smtpd_milters = inet:127.0.0.1:10669
milter_protocol = 6
milter_default_action = accept
```

Reload Postfix to apply the configuration:
```
sudo postfix reload
```

## Testing
To test the policy script with a given sender, recipient, and subject:
```
python subject_ratelimit_policyd.py --test "sender@example.com" "recipient@example.com" "Test Subject"
```

## Database Maintenance
Run the database maintenance script periodically (e.g., via cron) to delete old records:
```
python3 subject_ratelimit_db_maintenance.py
```

The maintenance script reads the same config.py as the main milter daemon.

## Service Configuration
To run the milter as a service, create a systemd service file (e.g., `policyd-subject-ratelimit.service`):

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
sudo systemctl daemon-reload
sudo systemctl enable policyd-subject-ratelimit.service
sudo systemctl start policyd-subject-ratelimit.service
```

## Logging
The script uses the logging module, so if you use systemd journalctl is your friend. The maintenance script should be called from the same User via crontab.
Logs are stored in `/var/log/subject_ratelimit_maintenance.log`, so make sure to touch and chown appropriately.

## Contributing
Contributions are welcome! Please fork the repository and submit pull requests.

## License
This project is licensed under the GNU GPLv3 License

