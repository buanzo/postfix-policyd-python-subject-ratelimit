#!/usr/bin/env python3
# Author: Arturo 'Buanzo' Busleiman github.com/buanzo
import re
import sqlite3
import datetime
import difflib
import logging
import argparse
import Milter
import traceback
from email.header import decode_header, make_header

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
    use_subject_similarity_for_replies,
    subject_substring_whitelist,
    scrub_subject_noise,
    subject_min_words
)

class CustomFormatter(logging.Formatter):
    def format(self, record):
        if hasattr(record, 'queue_id') and record.queue_id:
            record.msg = f"[queue_id: {record.queue_id}] [SubjectRateLimit] {record.msg}"
        else:
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
    action_formatter = CustomFormatter('%(asctime)s %(levelname)s: %(message)s')
    action_handler.setFormatter(action_formatter)
    action_logger.addHandler(action_handler)
    action_logger.setLevel(logging.INFO)

def count_words(string):
    # Use a regular expression to match words
    words = re.findall(r'\b\w+\b', string)
    return len(words)

def sanitize_subject(subject):
    try:
        return subject.encode('utf-8', 'replace').decode('utf-8')
    except UnicodeEncodeError:
        return subject.encode('utf-8', 'ignore').decode('utf-8')

def clean_address(address):
    if '<' in address and '>' in address:
        address = address.split('<')[1].split('>')[0].strip()
    return address.strip()

def log_debug_with_queue_id(logger, message, queue_id):
    if queue_id:
        extra = {'queue_id': queue_id}
        logger.debug(message, extra=extra)
    else:
        logger.debug(message)

def log_info_with_queue_id(logger, message, queue_id):
    if queue_id:
        extra = {'queue_id': queue_id}
        logger.info(message, extra=extra)
    else:
        logger.info(message)

def log_error_with_queue_id(logger, message, queue_id):
    if queue_id:
        extra = {'queue_id': queue_id}
        logger.error(message, extra=extra)
    else:
        logger.error(message)

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
    subject = subject
    recipient = clean_address(recipient)

    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO email_subjects (subject, recipient) VALUES (?, ?)', (subject, recipient))
    conn.commit()
    conn.close()

def store_outbound_email(subject, recipient):
    subject = subject
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
    subjects = [row[0] for row in cursor.fetchall()]
    conn.close()
    return subjects

def is_subject_whitelisted(subject, whitelist):
    """
    Check if the subject contains any whitelisted substring.
    """
    for substring in whitelist:
        if substring.lower() in subject:
            return True
    return False

def is_similar(subject, recent_subjects, method="similarity", threshold=0.8, count=3):
    try:
        if subject_min_words is not None and count_words(subject) < subject_min_words:
            return False
    except:
        return False
    similar_count = 0
    if scrub_subject_noise:
        subject = ''.join(filter(lambda x: x not in '0123456789 ', subject))
    for recent_subject in recent_subjects:
        if scrub_subject_noise:
            recent_subject = ''.join(filter(lambda x: x not in '0123456789 ', recent_subject))
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

combined_domain_whitelist = domain_whitelist[:]
if domain_whitelist_file:
    combined_domain_whitelist.extend(read_domain_whitelist(domain_whitelist_file))

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
            if domain == dom[1:] or domain.endswith(dom):
                return True
        elif domain == dom.lower():
            return True

    return False

def decode_subject(subject):
    try:
        decoded_header = decode_header(subject)
        return str(make_header(decoded_header))
    except Exception as e:
        logger.error(f"Failed to decode subject: {subject}. Error: {e}")
        return subject

def is_reply(subject):
    return subject.startswith('re:')

def is_reply_to_outbound_email(subject, sender):
    subject = subject
    sender = clean_address(sender)

    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT subject FROM outbound_emails WHERE recipient = ?', (sender,))
    outbound_subjects = [row[0] for row in cursor.fetchall()]
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
        self.headers_to_add = []  # Store headers to add
        self.action_reason = None  # Reason for action
        self.action_action = None  # Action to take
        self.is_similar = False

    def eoh(self):
        try:
            self.queue_id = self.getsymval('i')
            log_debug_with_queue_id(logger, f"EOH : Processing email from {self.sender} -> {self.recipients} with original subject: '{self.subject}'", self.queue_id)

            # Debug statement to check internal domains
            log_debug_with_queue_id(logger, f"Combined internal domains: {combined_internal_domains}", self.queue_id)

            if not self.subject:
                log_info_with_queue_id(logger, "NO SUBJECT. Accepting", self.queue_id)
                return Milter.ACCEPT

            # Check if the subject contains any whitelisted substring
            if is_subject_whitelisted(self.subject, subject_substring_whitelist):
                log_debug_with_queue_id(logger, f"WHITELISTED SUBJECT: {self.subject}", self.queue_id)
                # self.headers_to_add.append(('X-Subject-Ratelimit-Action', 'Whitelist_Substring_ACCEPT'))
                log_info_with_queue_id(action_logger, f"ACCEPT reason=subject_whitelist subject='{self.subject}'", self.queue_id)
                return Milter.ACCEPT

            # Extract sender's domain
            try:
                sender_domain = self.sender.split('@')[-1]
                log_debug_with_queue_id(logger, f"Extracted sender domain: {sender_domain}", self.queue_id)
            except Exception as e:
                log_debug_with_queue_id(logger, f"Failed to extract sender domain from {self.sender}: {e}", self.queue_id)
                return Milter.ACCEPT

            # Check if the sender is from an internal domain and store as outbound email if it's not a reply
            if sender_domain in combined_internal_domains:
                log_debug_with_queue_id(logger, f"Sender {self.sender} is from an internal domain", self.queue_id)
# TODO: FIX
#                if not is_reply(self.subject):
#                    log_debug_with_queue_id(logger, f"Storing outbound email: subject='{self.subject}', recipient='{self.recipients[0]}'", self.queue_id)
#                    store_outbound_email(self.subject, self.recipients[0])
#                    log_debug_with_queue_id(logger, f"OUTBOUND EMAIL STORED: {self.subject} -> {self.recipients[0]}", self.queue_id)

            # Check if the sender is whitelisted
            if is_whitelisted(self.sender, from_address_whitelist, combined_domain_whitelist):
                log_debug_with_queue_id(logger, f"WHITELISTED SENDER: {self.sender}", self.queue_id)
                # self.headers_to_add.append(('X-Subject-Ratelimit-Action', 'Whitelist_Sender_ACCEPT'))
                log_info_with_queue_id(action_logger, f"ACCEPT reason=sender_whitelist sender={self.sender} subject='{self.subject}' recipients='{self.recipients}'", self.queue_id)
                return Milter.ACCEPT

            # Check if any recipient is whitelisted
            if any(is_whitelisted(recip, rcpt_address_whitelist, []) for recip in self.recipients):
                log_debug_with_queue_id(logger, f"WHITELISTED RECIPIENT: Any of {self.recipients}", self.queue_id)
                log_info_with_queue_id(action_logger, f"ACCEPT reason=rcpt_whitelist sender={self.sender} subject='{self.subject}' recipients={self.recipients}", self.queue_id)
                # self.headers_to_add.append(('X-Subject-Ratelimit-Action', 'Whitelist_Rcpt_ACCEPT'))
                return Milter.ACCEPT

#TODO: FIX
#            if is_reply_to_outbound_email(self.subject, self.sender):
#                log_debug_with_queue_id(logger, f"REPLY DETECTED: {self.subject} from {self.sender}", self.queue_id)
#                # self.headers_to_add.append(('X-Subject-Ratelimit-Action', 'Whitelist_Reply_ACCEPT'))
#                log_info_with_queue_id(action_logger, "ACCEPT reason=reply_whitelist", self.queue_id)
#                return Milter.ACCEPT

            recent_subjects = get_recent_subjects(self.recipients[0] if trigger_for_same_recipient else None, window_minutes=time_window_minutes)
            self.is_similar = is_similar(self.subject, recent_subjects, method=comparison_method, threshold=similarity_threshold, count=similarity_count)
            if self.is_similar == True:
                log_info_with_queue_id(logger, f"SIMILARITY: Subject '{self.subject}' triggers similarity match. sender={self.sender} subject='{self.subject}'", self.queue_id)
                # When DEBUG==True we only log what we would have done, but not actually do anything but ACCEPT
                if DEBUG:
                    logger.info(f"SIMILARITY: DEBUG ACTIVE: Will not action='{action}' by subject='{self.subject}': from={self.sender} rcpts={self.recipients}")
                    if action_logger:
                        action_logger.info(f"DEBUG: Would have applied action='{action}' for subject='{self.subject}' from={self.sender} rcpts={self.recipients}")
                    self.headers_to_add.append(('X-Subject-Ratelimit-Action', f'DEBUG_{action}'))
                    return Milter.CONTINUE  # Because we have headers to add, if not we could use Milter.ACCEPT


                # When not debugging, we set action_action and action_reason to be used later, in eom()
                logger.info(f"SIMILARITY: Will {action} sender {self.sender} subject='{self.subject}' rcpts={self.recipients}")
                if action_logger:
                    log_info_with_queue_id(action_logger, f"{action} reason=similarity subject='{self.subject}' sender='{self.sender}' recipients='{self.recipients}", self.queue_id)
                self.headers_to_add.append(('X-Subject-Ratelimit-Action', f'{action}'))
                self.action_reason = "Please try later - error code ss01rl04"
                self.action_action = action
                return Milter.CONTINUE
            elif self.is_similar == False:
                log_debug_with_queue_id(logger, f"Storing subject '{self.subject}' for recipients {self.recipients}", self.queue_id)
                for recip in self.recipients:
                    store_subject(self.subject, recip)
                return Milter.ACCEPT # Nothing else to do, no headers to add, so we can ACCEPT

        except Exception as e:
            log_error_with_queue_id(logger, f"Unhandled exception: {e}\n{traceback.format_exc()}", self.queue_id)
            return Milter.TEMPFAIL

    def eom(self):
        # If no Milter.ACCEPT/TEMPFAIL happened in eoh() then we have something to do
        # Like adding headers, which can only be done, apparently, in eom()
        # And of course, take the similarity-triggered action
        try:
            # First we add any headers we might need to add
            for header, value in self.headers_to_add:
                try:
                    self.addheader(header, value)
                    # log_debug_with_queue_id(logger, f"Added header {header}: {value}", self.queue_id)
                except Exception as e:
                    log_error_with_queue_id(logger, f"Failed to add header {header}: {e}", self.queue_id)

            # Now we check for quarantine/hold actions first so we can call quarantine(): 
            # https://pythonhosted.org/pymilter/classMilter_1_1Base.html#a4f9e59479fe677ebe425128a37db67b0
            if self.action_action is not None and self.action_action in ("QUARANTINE", "HOLD") and self.is_similar:
                self.quarantine("Quarantined by subject similarity ratelimit")
                log_info_with_queue_id(action_logger, f"Similarity triggered quarantine action_action={self.action_action} action_reason='{self.action_reason}' sender={self.sender} subject='{self.subject}' recipients='{self.recipients}'", self.queue_id)
                return Milter.ACCEPT  # actual quarantine requires self.quarantine(reason) then return Milter.ACCEPT and not Milter.QUARANTINE
            elif self.is_similar:  # Check for other actions that dont require specific methods
                action_to_take = {
                    'ACCEPT': Milter.ACCEPT,
                    'REJECT': Milter.REJECT,
                    'DISCARD': Milter.DISCARD,
                    'TEMPFAIL': Milter.TEMPFAIL
                }.get(action, Milter.TEMPFAIL)  # Default action is TEMPFAIL if the provided action is not recognized
                log_info_with_queue_id(action_logger, f"Similarity triggered action={action} is_similar={self.is_similar} action_action={self.action_action} action_reason='{self.action_reason}' sender={self.sender} subject='{self.subject}' recipients='{self.recipients}'", self.queue_id)
                return action_to_take
            elif self.is_similar == False: # This should never happen
                log_info__with_queue_id(action_logger, f"NOSIMILARITY is_similar={self.is_similar} action_action={self.action_action} action_reason='{self.action_reason}' sender={self.sender} subject='{self.subject}' recipients='{self.recipients}'", self.queue_id)
                
        except Exception as e:
            log_error_with_queue_id(logger, f"Unhandled exception in eom: {e}\n{traceback.format_exc()}", self.queue_id)
            return Milter.TEMPFAIL

    def envfrom(self, mailfrom, *str):
        self.sender = clean_address(mailfrom.lower())
        self.queue_id = self.getsymval('i')
        # log_debug_with_queue_id(logger, f"sender is {self.sender}", self.queue_id)
        # log_debug_with_queue_id(logger, f"self: {vars(self)}", self.queue_id)
        return Milter.CONTINUE

    def envrcpt(self, recip, *str):
        self.queue_id = self.getsymval('i')
        self.recipients.append(clean_address(recip.lower()))
        log_debug_with_queue_id(logger, f"adding recipient {recip} queue_id={self.queue_id}", self.queue_id)
        return Milter.CONTINUE

    def header(self, name, value):
        self.queue_id = self.getsymval('i')
        if name.lower() == 'subject':
            self.subject = sanitize_subject(decode_subject(value)).strip().replace('\n','')
            log_debug_with_queue_id(logger, f"subject is '{self.subject}'", self.queue_id)
        return Milter.CONTINUE

def test_script(sender, recipient, subject):
    subject = subject.strip().replace('\n', '')

    logger.debug(f"Testing with sender: {sender}, recipient: {recipient}, subject: {subject}")

    sender_domain = sender.split('@')[-1]

    if sender_domain in combined_internal_domains:
        if not is_reply(subject):
            store_outbound_email(subject, recipient)

    if is_whitelisted(sender, from_address_whitelist, combined_domain_whitelist):
        return "ACCEPT"

    if is_whitelisted(recipient, rcpt_address_whitelist, []):
        return "ACCEPT"

    if is_reply_to_outbound_email(subject, sender):
        return "ACCEPT"

    recent_subjects = get_recent_subjects(recipient if trigger_for_same_recipient else None, window_minutes=time_window_minutes)
    if is_similar(subject, recent_subjects, method=comparison_method, threshold=similarity_threshold, count=similarity_count):
        if DEBUG:
            logger.info(f"SIMILARITY: DEBUG ACTIVE: Will not reject by subject '{subject}': from {sender} to {recipient}")
            if action_logger:
                action_logger.info(f"DEBUG: Would have rejected subject '{subject}' from {sender} to {recipient}")
            return "ACCEPT"
        action_to_take = {
            'REJECT': "REJECT",
            'HOLD': "TEMPFAIL",
            'DEFER': "DEFER"
        }.get(action, "TEMPFAIL")
        return action_to_take

    store_subject(subject, recipient)
    return "ACCEPT"

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
