# Author: Arturo 'Buanzo' Busleiman github.com/buanzo

import socket
import sqlite3
import datetime
import difflib
import logging
import argparse
from config import (
    time_window_minutes,
    similarity_threshold,
    similarity_count,
    comparison_method,
    trigger_for_same_recipient,
    sqlite_db_path,
    server_port,
    from_address_whitelist,
    rcpt_address_whitelist,
    DEBUG
)

# Logging configuration
logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(sqlite_db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            recipient TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    return conn

# Store the email subject in the database
def store_subject(conn, subject, recipient):
    cursor = conn.cursor()
    cursor.execute('INSERT INTO email_subjects (subject, recipient) VALUES (?, ?)', (subject, recipient))
    conn.commit()

# Retrieve recent subjects from the database
def get_recent_subjects(conn, recipient=None, window_minutes=5):
    cursor = conn.cursor()
    time_threshold = datetime.datetime.now() - datetime.timedelta(minutes=window_minutes)
    if recipient and trigger_for_same_recipient:
        cursor.execute('SELECT subject FROM email_subjects WHERE timestamp > ? AND recipient = ?', (time_threshold, recipient))
    else:
        cursor.execute('SELECT subject FROM email_subjects WHERE timestamp > ?', (time_threshold,))
    return [row[0] for row in cursor.fetchall()]

# Check similarity between subjects
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

# Check if address is whitelisted
def is_whitelisted(address, whitelist):
    return address.lower() in [addr.lower() for addr in whitelist]

# Handle incoming requests
def handle_request(conn, data, testing=False):
    request_data = dict(line.split('=', 1) for line in data.strip().split('\n') if line)
    subject = request_data.get('subject', '').strip()
    recipient = request_data.get('recipient', '').strip()
    sender = request_data.get('sender', '').strip()

    logging.debug(f"Processing email from {sender} to {recipient} with subject: {subject}")

    # Check if sender or recipient is whitelisted
    if is_whitelisted(sender, from_address_whitelist) or is_whitelisted(recipient, rcpt_address_whitelist):
        logging.debug(f"Sender {sender} or recipient {recipient} is whitelisted.")
        return "action=DUNNO\n\n"

    if not subject:
        logging.debug("No subject found in email.")
        return "action=DUNNO\n\n"

    recent_subjects = get_recent_subjects(conn, recipient if trigger_for_same_recipient else None, window_minutes=time_window_minutes)
    if is_similar(subject, recent_subjects, method=comparison_method, threshold=similarity_threshold, count=similarity_count):
        logging.debug(f"Subject '{subject}' is similar to recent subjects: {recent_subjects}")
        if testing or not DEBUG:
            return "action=REJECT\n\n"

    store_subject(conn, subject, recipient)
    return "action=DUNNO\n\n"

# Start the policy server
def start_server(port):
    conn = init_db()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', port))
        s.listen()
        logging.info(f"Policy server listening on port {port}")
        while True:
            client_conn, _ = s.accept()
            with client_conn:
                data = client_conn.recv(4096).decode()
                response = handle_request(conn, data)
                client_conn.sendall(response.encode())

# Test the script without Postfix
def test_script(sender, recipient, subject):
    conn = init_db()
    data = f"sender={sender}\nrecipient={recipient}\nsubject={subject}\n"
    response = handle_request(conn, data, testing=True)
    print(response)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Subject Rate Limit Policy Daemon')
    parser.add_argument('--test', nargs=3, metavar=('SENDER', 'RECIPIENT', 'SUBJECT'), help='Test the policy script with given sender, recipient, and subject')
    args = parser.parse_args()

    if args.test:
        test_script(*args.test)
    else:
        start_server(server_port)
