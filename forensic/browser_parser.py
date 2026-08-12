import sqlite3
import datetime
from pathlib import Path

# Chrome timestamp offset: microseconds from 1601-01-01 to 1970-01-01
CHROME_EPOCH_OFFSET = 11644473600000000

class ForensicBrowserParser:
    @staticmethod
    def chrome_time_to_iso(chrome_time):
        """Converts Chrome WebKit timestamp (microseconds since Jan 1, 1601) to ISO datetime string."""
        if not chrome_time or chrome_time == 0:
            return None
        try:
            microseconds = chrome_time - CHROME_EPOCH_OFFSET
            seconds = microseconds / 1000000.0
            dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
            return dt.isoformat()
        except Exception:
            return None

    @staticmethod
    def prtime_to_iso(pr_time):
        """Converts Firefox PRTime (microseconds since Jan 1, 1970) to ISO datetime string."""
        if not pr_time or pr_time == 0:
            return None
        try:
            seconds = pr_time / 1000000.0
            dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
            return dt.isoformat()
        except Exception:
            return None

    @staticmethod
    def parse_browser_database(db_path):
        """
        Detects database type (Chrome/Edge vs Firefox) and extracts history & downloads.
        Returns dict with history, downloads, status, and browser type.
        """
        p = Path(db_path)
        if not p.exists():
            return {'supported': False, 'message': 'Database file not found', 'artifacts': []}

        # Open in URI read-only mode to guarantee zero modification
        uri_path = f"file:{p.resolve().as_posix()}?mode=ro"
        
        try:
            conn = sqlite3.connect(uri_path, uri=True)
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            
            artifacts = []
            browser_type = "Unknown"
            
            # Check for Chrome / Edge schema (urls, visits, downloads)
            if 'urls' in tables:
                browser_type = "Chromium Based (Chrome / Edge / Brave)"
                
                # Extract URL visits
                query_urls = """
                SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.last_visit_time
                FROM urls
                ORDER BY urls.last_visit_time DESC
                LIMIT 500
                """
                cursor.execute(query_urls)
                for row in cursor.fetchall():
                    last_visit_iso = ForensicBrowserParser.chrome_time_to_iso(row[4])
                    artifacts.append({
                        'artifact_type': 'browser_history',
                        'browser': browser_type,
                        'url': row[1],
                        'title': row[2] if row[2] else row[1],
                        'visit_count': row[3],
                        'timestamp': last_visit_iso,
                        'activity': 'History Visit',
                        'source': 'urls'
                    })
                    
                # Extract Downloads if present
                if 'downloads' in tables:
                    try:
                        cursor.execute("PRAGMA table_info(downloads)")
                        cols = [c[1] for c in cursor.fetchall()]
                        if 'target_path' in cols:
                            query_dl = "SELECT target_path, start_time, total_bytes, tab_url FROM downloads"
                        else:
                            query_dl = "SELECT current_path, start_time, total_bytes, tab_url FROM downloads"
                        cursor.execute(query_dl)
                        for row in cursor.fetchall():
                            dl_time_iso = ForensicBrowserParser.chrome_time_to_iso(row[1])
                            artifacts.append({
                                'artifact_type': 'browser_download',
                                'browser': browser_type,
                                'url': row[3] if len(row) > 3 else 'Unknown',
                                'title': f"Downloaded: {Path(row[0]).name if row[0] else 'File'}",
                                'visit_count': 1,
                                'timestamp': dl_time_iso,
                                'activity': 'Download',
                                'target_path': row[0],
                                'file_size': row[2] if len(row) > 2 else 0,
                                'source': 'downloads'
                            })
                    except Exception:
                        pass
                        
                conn.close()
                return {
                    'supported': True,
                    'browser': browser_type,
                    'count': len(artifacts),
                    'artifacts': artifacts
                }

            # Check for Firefox schema (moz_places, moz_historyvisits)
            elif 'moz_places' in tables:
                browser_type = "Mozilla Firefox"
                query_ff = """
                SELECT moz_places.url, moz_places.title, moz_places.visit_count, moz_historyvisits.visit_date
                FROM moz_places
                JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
                ORDER BY moz_historyvisits.visit_date DESC
                LIMIT 500
                """
                cursor.execute(query_ff)
                for row in cursor.fetchall():
                    visit_iso = ForensicBrowserParser.prtime_to_iso(row[3])
                    artifacts.append({
                        'artifact_type': 'browser_history',
                        'browser': browser_type,
                        'url': row[0],
                        'title': row[1] if row[1] else row[0],
                        'visit_count': row[2],
                        'timestamp': visit_iso,
                        'activity': 'History Visit',
                        'source': 'moz_places'
                    })
                conn.close()
                return {
                    'supported': True,
                    'browser': browser_type,
                    'count': len(artifacts),
                    'artifacts': artifacts
                }
            else:
                conn.close()
                return {
                    'supported': False,
                    'message': 'Artifact format not currently supported. SQLite database does not match known Chrome or Firefox schemas.',
                    'artifacts': []
                }
        except Exception as e:
            return {
                'supported': False,
                'message': f'Failed to parse SQLite database: {str(e)}',
                'artifacts': []
            }
