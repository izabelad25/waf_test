import regex

CTRL_CHARACTERS = regex.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
KEYWORDS_SQL = regex.compile(r'(?i)\b(SELECT|UNION|DROP|DELETE|INSERT|WHERE|TRUNCATE|EXEC|UPDATE|OR)\b')
 
def sanitize_ip(ip: str) -> str:
    """192.168.1.1 -> 192[.]168[.]1[.]1"""
    ip = CTRL_CHARACTERS.sub('', str(ip))
    return ip.replace('.', '[.]')[:64]

def sanitize_path(path: str) -> str:
    """
    /api/search?q=<script> -> /api/search?q=[<]script[>]
    http://site.com        -> hxxp://site[.]com
    /api/DELETE WHERE 1=1  -> /api/[DELETE] [WHERE] 1[=]1
    """
    path = CTRL_CHARACTERS.sub('', str(path))
    path = regex.sub(r'(?i)https://', 'hxxps://', path)
    path = regex.sub(r'(?i)http://',  'hxxp://',  path)
    path = path.replace('<', '[<]').replace('>', '[>]')
    path = path.replace('(', '[(]').replace(')', '[)]')
    path = path.replace('=', '[=]')
    path = KEYWORDS_SQL.sub(r'[\1]', path)
    return path[:1024]