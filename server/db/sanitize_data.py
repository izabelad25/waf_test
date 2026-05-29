import regex


CTRL_CHARACTERS = regex.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
 
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
    path = path.replace('SELECT', '[SELECT]').replace('UNION', '[UNION]').replace('DROP', '[DROP]')
    path = path.replace('DELETE', '[DELETE]').replace('OR', '[OR]').replace('INSERT', '[INSERT]').replace('WHERE', '[WHERE]')
    path = path.replace('TRUNCATE', '[TRUNCATE]').replace('EXEC', '[EXEC]').replace('UPDATE', '[UPDATE]')
    return path[:1024]