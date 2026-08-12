import re
import html
from pathlib import Path

class ForensicKeywordSearch:
    @staticmethod
    def search_text_content(content, query, is_regex=False, case_sensitive=False, context_chars=60):
        """
        Searches text string for a query/regex.
        Returns list of match context snippets.
        """
        if not query or not content:
            return []
            
        flags = 0 if case_sensitive else re.IGNORECASE
        
        if is_regex:
            try:
                pattern = re.compile(query, flags)
            except re.error:
                return []
        else:
            escaped = re.escape(query)
            pattern = re.compile(escaped, flags)

        results = []
        for match in pattern.finditer(content):
            start = max(0, match.start() - context_chars)
            end = min(len(content), match.end() + context_chars)
            
            snippet_before = content[start:match.start()]
            matched_text = match.group(0)
            snippet_after = content[match.end():end]
            
            # Escape HTML to prevent XSS vulnerability
            snippet_before_esc = html.escape(snippet_before)
            matched_text_esc = html.escape(matched_text)
            snippet_after_esc = html.escape(snippet_after)
            
            highlighted = f"{snippet_before_esc}<mark class='bg-warning text-dark font-weight-bold'>{matched_text_esc}</mark>{snippet_after_esc}"
            
            results.append({
                'match': matched_text,
                'position': match.start(),
                'snippet': highlighted
            })
            if len(results) >= 50: # Limit snippet matches per item to prevent UI flood
                break
                
        return results

    @staticmethod
    def search_file(file_path, query, is_regex=False, case_sensitive=False):
        """Safely searches a single file on disk."""
        p = Path(file_path)
        if not p.exists():
            return []
            
        try:
            # Read first 1MB of file as text safely
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)
                return ForensicKeywordSearch.search_text_content(
                    content, query, is_regex=is_regex, case_sensitive=case_sensitive
                )
        except Exception:
            return []
