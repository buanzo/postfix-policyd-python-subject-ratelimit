#!/usr/bin/env python3
# Author: Arturo 'Buanzo' Busleiman github.com/buanzo
import sqlite3
import datetime
import difflib
import logging
import argparse
import Milter

from config import (
    time_window_minutes,
    similarity_threshold,
    similarity_count,
    comparison_method,
    trigger_for_same_recipient,
    sqlite_db_path,
    server_ip,
    server_port,
    from_address_whitelist,
    rcpt_address_whitelist,
    domain_whitelist,
    domain_whitelist_file,
    DEBUG,
    action,
    action_log_file_path,
    internal_domains,
    internal_domains_file,
    use_subject_similarity_for_replies
)

class CustomFormatter(logging.Formatter):
    def format(self, record):
        record.msg = f"[SubjectRateLimit] {record.msg}"
        return super().format(record)

# General logger configuration
logger = logging.getLogger('general')
handler = logging.StreamHandler()
formatter = CustomFormatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)

# Action logger configuration
action_logger = None
if action_log_file_path is not None:
    action_logger = logging.getLogger('actions')
    action_handler = logging.FileHandler(action_log_file_path)
    action_formatter = CustomFormatter('%(asctime)s %(levellevelname)s: %(message)s')
    action_handler.setFormatter(action_formatter)
    action_logger.addHandler(action_handler)
    action_logger.setLevel(logging.INFO)

def sanitize_subject(subject):
    try:
        return subject.encode('utf-8', 'replace').decode('utf-8')
    except UnicodeEncodeError:
        return subject.encode('utf-8', 'ignore').decode('utf-8')

def clean_address(address):
    if '<' in address and '>' in address:
        address = address.split('<')[1].split('>')[0].strip()
    return address.strip()

def create_db_connection():
    return sqlite3.connect(sqlite_db_path, check_same_thread=False)

def init_db():
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            recipient TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS outbound_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            recipient TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def store_subject(subject, recipient):
    # Ensure the subject and recipient are properly encoded and cleaned
    subject = sanitize_subject(subject)
    recipient = clean_address(recipient)

    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO email_subjects (subject, recipient) VALUES (?, ?)', (subject, recipient))
    conn.commit()
    conn.close()

def store_outbound_email(subject, recipient):
    # Ensure the subject and recipient are properly encoded and cleaned
    subject = sanitize_subject(subject)
    recipient = clean_address(recipient)

    logger.debug(f"Storing outbound email: subject='{subject}', recipient='{recipient}'")

    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO outbound_emails (subject, recipient, timestamp) VALUES (?, ?, ?)', (subject, recipient, datetime.datetime.now()))
    conn.commit()
    conn.close()

    logger.debug("Outbound email stored successfully")

def get_recent_subjects(recipient=None, window_minutes=5):
    conn = create_db_connection()
    cursor = conn.cursor()
    time_threshold = datetime.datetime.now() - datetime.timedelta(minutes=window_minutes)
    if recipient and trigger_for_same_recipient:
        recipient = clean_address(recipient)
        cursor.execute('SELECT subject FROM email_subjects WHERE timestamp > ? AND recipient = ?', (time_threshold, recipient))
    else:
        cursor.execute('SELECT subject FROM email_subjects WHERE timestamp > ?', (time_threshold,))
    subjects = [sanitize_subject(row[0]) for row in cursor.fetchall()]
    conn.close()
    return subjects

def is_similar(subject, recent_subjects, method="similarity", threshold=0.8, count=3):
    similar_count = 0
    for recent_subject in recent_subjects:
        if method == "similarity":
            similarity = difflib.SequenceMatcher(None, subject, recent_subject).ratio()
            if similarity > threshold:
                similar_count += 1
                if similar_count >= count:
                    return True
        elif method == "exact" and subject == recent_subject:
            similar_count += 1
            if similar_count >= count:
                return True
    return False

def read_domain_whitelist(file_path):
    if file_path is None:
        return []
    whitelist = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    whitelist.append(line)
    except FileNotFoundError:
        logger.error(f"Domain whitelist file {file_path} not found.")
    return whitelist

def read_internal_domains(file_path):
    if file_path is None:
        return []
    domains = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
    except FileNotFoundError:
        logger.error(f"Internal domains file {file_path} not found.")
    return domains

# Read domains from the file and merge with the domain_whitelist from config.py
combined_domain_whitelist = domain_whitelist[:]
if domain_whitelist_file:
    combined_domain_whitelist.extend(read_domain_whitelist(domain_whitelist_file))

# Merge internal domains from config and file
combined_internal_domains = internal_domains[:]
if internal_domains_file:
    combined_internal_domains.extend(read_internal_domains(internal_domains_file))

def is_whitelisted(address, address_whitelist, domain_whitelist):
    address = clean_address(address)
    domain = address.split('@')[-1]

    if address in [addr.lower() for addr in address_whitelist]:
        return True

    for dom in domain_whitelist:
        if dom.startswith('.'):
            # Check if the domain or any of its subdomains match
            if domain == dom[1:] or domain.endswith(dom):
                return True
        elif domain == dom.lower():
            return True

    return False

def is_reply(subject):
    return subject.lower().startswith('re:')

def is_reply_to_outbound_email(subject, sender):
    # Ensure the subject is properly encoded and the sender is cleaned
    subject = sanitize_subject(subject)
    sender = clean_address(sender)

    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT subject FROM outbound_emails WHERE recipient = ?', (sender,))
    outbound_subjects = [sanitize_subject(row[0]) for row in cursor.fetchall()]
    conn.close()

    if use_subject_similarity_for_replies:
        for outbound_subject in outbound_subjects:
            if difflib.SequenceMatcher(None, subject, outbound_subject).ratio() > similarity_threshold:
                return True
        return False
    else:
        return bool(outbound_subjects)

class SubjectFilterMilter(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        self.sender = None
        self.recipients = []
        self.subject = None
        self.queue_id = None
        self.processed = False  # Track if the email has already been processed

    def connect(self, IPname, family, hostaddr):
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *str):
        self.sender = clean_address(mailfrom.lower())
        self.queue_id = self.getsymval('i')
        logger.debug(f"sender is {self.sender}")
        self.processed = False  # Reset processed flag for new transaction
        return Milter.CONTINUE

    def envrcpt(self, recip, *str):
        self.recipients.append(clean_address(recip.lower()))
        logger.debug(f"adding recipient {recip}")
        return Milter.CONTINUE

    def header(self, name, value):
        if name.lower() == 'subject':
            self.subject = value.strip().replace('\n','')
            logger.debug(f"subject is '{self.subject}'")
        return Milter.CONTINUE

    def eoh(self):
        logger.debug(f"EOH : Processing email from {self.sender} -> {self.recipients} with subject: '{self.subject}'")

        if self.processed:
            logger.debug("Email already processed, skipping further checks.")
            return Milter.ACCEPT

        # Debug statement to check internal domains
        logger.debug(f"Combined internal domains: {combined_internal_domains}")

        if not self.subject:
            logger.debug(f"NO SUBJECT")
            return Milter.ACCEPT

        # Extract sender's domain
        try:
            sender_domain = self.sender.split('@')[-1]
            logger.debug(f"Extracted sender domain: {sender_domain}")
        except Exception as e:
            logger.error(f"Failed to extract sender domain from {self.sender}: {e}")
            return Milter.ACCEPT

        # Check if the sender is from an internal domain and store as outbound email if it's not a reply
        if sender_domain in combined_internal_domains:
            logger.debug(f"Sender {self.sender} is from an internal domain")
            if not is_reply(self.subject):
                logger.debug(f"Storing outbound email: subject='{self.subject}', recipient='{self.recipients[0]}'")
                store_outbound_email(self.subject, self.recipients[0])
                logger.debug(f"OUTBOUND EMAIL STORED: {self.subject} -> {self.recipients[0]}")

        # Check if the sender is whitelisted
        if is_whitelisted(self.sender, from_address_whitelist, combined_domain_whitelist):
            logger.debug(f"WHITELISTED SENDER: {self.sender}")
            self.processed = True  # Mark as processed
            return Milter.ACCEPT

        # Check if any recipient is whitelisted
        if any(is_whitelisted(recip, rcpt_address_whitelist, []) for recip in self.recipients):
            logger.debug(f"WHITELISTED RECIPIENT : Any of {self.recipients}")
            self.processed = True  # Mark as processed
            return Milter.ACCEPT

        if is_reply_to_outbound_email(self.subject, self.sender):
            logger.debug(f"REPLY DETECTED: {self.subject} from {self.sender}")
            self.processed = True  # Mark as processed
            return Milter.ACCEPT

        recent_subjects = get_recent_subjects(self.recipients[0] if trigger_for_same_recipient else None, window_minutes=time_window_minutes)
        if is_similar(self.subject, recent_subjects, method=comparison_method, threshold=similarity_threshold, count=similarity_count):
            logger.debug(f"SIMILARITY: Subject '{self.subject}' triggers similarity match")
            if DEBUG:
                logger.info(f"SIMILARITY: DEBUG ACTIVE: Will not reject by subject '{self.subject}': from {self.sender} to {self.recipients}")
                if action_logger:
                    action_logger.info(f"DEBUG: Would have rejected subject '{self.subject}' from {self.sender} to {self.recipients}")
                self.processed = True  # Mark as processed
                return Milter.ACCEPT
            action_to_take = {
                'REJECT': Milter.REJECT,
                'HOLD': Milter.TEMPFAIL,
                'DEFER': Milter.DEFER
            }.get(action, Milter.TEMPFAIL)
            logger.info(f"SIMILARITY: Returning {action} for sender {self.sender}")
            if action_logger:
                action_logger.info(f"{action}: Subject '{self.subject}' from {self.sender} to {self.recipients}")
            self.processed = True  # Mark as processed
            return action_to_take

        logger.debug(f"Storing subject '{self.subject}' for recipients {self.recipients}")
        for recip in self.recipients:
            store_subject(self.subject, recip)
        self.processed = True  # Mark as processed
        return Milter.ACCEPT

    def body(self, chunk):
        # Do nothing with the body
        return Milter.ACCEPT

    def eob(self):
        # End of body, already accepted in eoh
        return Milter.ACCEPT

    def close(self):
        return Milter.CONTINUE

    def abort(self):
        return Milter.CONTINUE

def main():
    init_db()
    parser = argparse.ArgumentParser(description='Subject Rate Limit Policy Daemon')
    parser.add_argument('--test', nargs=3, metavar=('SENDER', 'RECIPIENT', 'SUBJECT'), help='Test the policy script with given sender, recipient, and subject')
    args = parser.parse_args()

    if args.test:
        response = test_script(*args.test)
        print(response)
    else:
        Milter.factory = SubjectFilterMilter
        Milter.runmilter("subjectfilter", f"inet:{server_port}@{server_ip}")

if __name__ == '__main__':
    main()
