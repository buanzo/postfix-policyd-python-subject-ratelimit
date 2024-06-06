#!/usr/bin/env python3
# Autor: Buanzo
import sqlite3
import datetime
import logging
from config import sqlite_db_path, time_window_minutes, DEBUG

class CustomFormatter(logging.Formatter):
    def format(self, record):
        record.msg = f"[SubjectRateLimitMaintenance] {record.msg}"
        return super().format(record)

# Configure logging
logger = logging.getLogger()
handler = logging.FileHandler('/var/log/subject_ratelimit_maintenance.log')
formatter = CustomFormatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)

def create_db_connection():
    return sqlite3.connect(sqlite_db_path, check_same_thread=False)

def delete_old_records():
    try:
        conn = create_db_connection()
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - datetime.timedelta(minutes=time_window_minutes)
        logger.debug(f"Deleting records older than {time_threshold}")
        cursor.execute('DELETE FROM email_subjects WHERE timestamp < ?', (time_threshold,))
        conn.commit()
        logger.info(f"Deleted {cursor.rowcount} old records from the database")
        conn.close()
    except sqlite3.OperationalError as e:
        logger.error(f"SQLite operational error: {e}")

def main():
    delete_old_records()

if __name__ == '__main__':
    main()
