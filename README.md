# postfix-policyd-python-subject-ratelimit

## BE ADVISED: This software is in development. 

Ok?

## Overview

The postfix-policyd-python-subject-ratelimit project is a custom Postfix policy daemon designed to control email subject rates within a specified time window. It aims to mitigate spam and coordinated email attacks by tracking and comparing email subjects. The daemon operates by listening on a TCP port, receiving email data from Postfix, and utilizing an SQLite database to store and analyze email subjects.

This policy daemon enhances email security by preventing repetitive spam emails and enabling fine-tuned control over email subject filtering. It is integrated as a systemd service to ensure seamless operation and easy management.

By default, the script operates in DEBUG mode, logging useful data for tuning and always returning DUNNO. Once tuned, you can set DEBUG=False in config.py to enforce the policy.

## Key Features

1. Configurable Time Window: Monitor email subjects over a specified period to detect spam bursts.
2. Similarity Threshold: Set the threshold for subject similarity to identify and block repetitive spam emails.
3. Similarity Count: Wait until n similar-subjects for the same recipient before deciding.
4. Flexible Comparison Methods: Choose between string similarity and exact match for subject comparison.
5. Recipient-Based Triggering: Optionally apply checks only to emails sent to the same recipient.
6. Whitelisting: Bypass checks for trusted sender and recipient addresses.
7. Systemd Integration: Managed as a systemd service for reliability and ease of use.

## Setup
1. **Clone the Repository**: Download to your server using git clone as typical.
2. **Configure**: Edit `config.py` and set the different parameters. Explanations included in config.py. Make sure to leave DEBUG=True until you figure out how it works for your particular environment.

You can start it however you want. I am not providing native docker support nor pyenv, etc: that's up to you. Contribute it if you want :) - However, I do include a systemd unit file that you can adapt
to your requirements. See next section.

## Create Systemd Unit File

Save the sample unit file present in src/ as /etc/systemd/system/policyd-subject-ratelimit.service or other suitable location

Now you can reload Systemd and Enable the Service:

```bash
 sudo systemctl daemon-reload
 sudo systemctl enable policyd-subject-ratelimit.service
 sudo systemctl start policyd-subject-ratelimit.service
```

## Configure Postfix

Configure main.cf to use the new policy.

```plaintext
smtpd_recipient_restrictions = ...
check_policy_service inet:127.0.0.1:10669,
...
```

Finally, reload/restart postfix.

## Test mode

The --test mode allows for you to try manually, without having to run it from postfix. The syntax is simple: 

```plaintext
--test "SOURCE_ADDRESS" "DESTINATION_ADDRESS" "Subject"
```

Of course, when running --test it does not honour DEBUG setting.

Remember, once you are happy, set DEBUG to False in config.py
