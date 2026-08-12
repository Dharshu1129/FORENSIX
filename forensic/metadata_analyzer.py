import os
import stat
import datetime
from pathlib import Path
from PIL import Image, ExifTags

# Known magic byte signatures for safe forensic identification
KNOWN_MAGIC_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 'PNG Image file'),
    (b'\xff\xd8\xff', 'JPEG Image file'),
    (b'GIF87a', 'GIF Image file'),
    (b'GIF89a', 'GIF Image file'),
    (b'%PDF', 'PDF Document'),
    (b'PK\x03\x04', 'ZIP Archive / Office Open XML Document'),
    (b'SQLite format 3\x00', 'SQLite 3 Database'),
    (b'MZ', 'Windows Executable / DLL (PE)'),
    (b'\x7fELF', 'Linux Executable (ELF)'),
    (b'\x1f\x8b', 'GZIP Compressed Archive'),
    (b'BZh', 'BZIP2 Compressed Archive'),
    (b'\x37\x7a\xbc\xaf\x27\x1c', '7-Zip Archive'),
    (b'Rar!\x1a\x07\x00', 'RAR Archive (v4)'),
    (b'Rar!\x1a\x07\x01\x00', 'RAR Archive (v5)'),
]

class ForensicMetadataAnalyzer:
    @staticmethod
    def get_magic_signature(file_path):
        """Reads file magic bytes to determine actual file signature."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)
            for magic, desc in KNOWN_MAGIC_SIGNATURES:
                if header.startswith(magic):
                    return {
                        'signature_bytes': header[:len(magic)].hex().upper(),
                        'description': desc,
                        'matched': True
                    }
            return {
                'signature_bytes': header[:8].hex().upper() if header else 'N/A',
                'description': 'Unknown / Data File',
                'matched': False
            }
        except Exception as e:
            return {
                'signature_bytes': 'ERROR',
                'description': f'Error reading signature: {str(e)}',
                'matched': False
            }

    @staticmethod
    def extract_file_metadata(file_path):
        """Extracts complete file system metadata."""
        p = Path(file_path)
        if not p.exists():
            return {'error': 'File not found'}
            
        try:
            file_stat = p.stat()
            created_ts = datetime.datetime.fromtimestamp(file_stat.st_ctime, tz=datetime.timezone.utc)
            modified_ts = datetime.datetime.fromtimestamp(file_stat.st_mtime, tz=datetime.timezone.utc)
            accessed_ts = datetime.datetime.fromtimestamp(file_stat.st_atime, tz=datetime.timezone.utc)
            
            # File permission mode
            mode = oct(file_stat.st_mode)[-4:]
            
            # Hidden attribute detection
            is_hidden = False
            if p.name.startswith('.'):
                is_hidden = True
            elif os.name == 'nt':
                try:
                    import ctypes
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(str(p))
                    if attrs != -1 and (attrs & 2): # FILE_ATTRIBUTE_HIDDEN
                        is_hidden = True
                except Exception:
                    pass
                    
            magic_info = ForensicMetadataAnalyzer.get_magic_signature(p)
            
            metadata = {
                'filename': p.name,
                'extension': p.suffix.lower() if p.suffix else 'None',
                'file_size': file_stat.st_size,
                'created_timestamp': created_ts.isoformat(),
                'modified_timestamp': modified_ts.isoformat(),
                'accessed_timestamp': accessed_ts.isoformat(),
                'permissions': mode,
                'is_hidden': is_hidden,
                'magic_signature': magic_info['signature_bytes'],
                'magic_description': magic_info['description'],
                'exif': None
            }
            
            # Extract EXIF if it is an image
            if p.suffix.lower() in ['.jpg', '.jpeg', '.png', '.tiff', '.webp']:
                exif_data = ForensicMetadataAnalyzer.extract_exif_metadata(p)
                if exif_data:
                    metadata['exif'] = exif_data
                    
            return metadata
        except Exception as e:
            return {'error': f'Failed to extract metadata: {str(e)}'}

    @staticmethod
    def extract_exif_metadata(file_path):
        """Extracts EXIF metadata from image files using Pillow."""
        try:
            with Image.open(file_path) as img:
                exif = img.getexif()
                if not exif:
                    return None
                
                exif_data = {}
                for tag_id, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                    # Convert bytes to string if necessary
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = str(value)
                    elif isinstance(value, (datetime.date, datetime.datetime)):
                        value = value.isoformat()
                    exif_data[str(tag_name)] = str(value)
                    
                # Format common EXIF fields
                formatted_exif = {
                    'make': exif_data.get('Make', 'N/A'),
                    'model': exif_data.get('Model', 'N/A'),
                    'software': exif_data.get('Software', 'N/A'),
                    'date_time_original': exif_data.get('DateTimeOriginal', exif_data.get('DateTime', 'N/A')),
                    'orientation': exif_data.get('Orientation', 'N/A'),
                    'raw_tags': exif_data
                }
                return formatted_exif
        except Exception:
            return None
