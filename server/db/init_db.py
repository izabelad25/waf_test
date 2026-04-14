import duckdb
import regex 


print("Initializing DuckBD...")

db = duckdb.connect('waf_database.duckdb')


db.execute("""
    CREATE TABLE IF NOT EXISTS rules (
        rule_id INTEGER PRIMARY KEY,
        name VARCHAR NOT NULL,
        rule_type VARCHAR NOT NULL,     
        target_zone VARCHAR NOT NULL,   
        match_pattern VARCHAR NOT NULL, 
        action VARCHAR DEFAULT 'BLOCK', 
        is_active BOOLEAN DEFAULT TRUE,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")


db.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        log_id VARCHAR PRIMARY KEY,     
        timestamp TIMESTAMP NOT NULL,
        client_ip VARCHAR NOT NULL,
        http_method VARCHAR NOT NULL,
        request_path VARCHAR NOT NULL,
        status_code INTEGER,
        user_agent VARCHAR,
        response_time_ms DOUBLE
    )
""")


db.execute("""
    CREATE TABLE IF NOT EXISTS firewall_actions (
        action_id VARCHAR PRIMARY KEY,
        timestamp TIMESTAMP NOT NULL,
        activity_log_id VARCHAR,
        rule_id INTEGER,
        action_taken VARCHAR NOT NULL,
        trigger VARCHAR  
    )
""")

#DEFAULT RULES 

default_rules = [
    #Path traversal 
    (1, 'Block DIRECTORY Traversal', 'REGEX_MATCH', 'PATH', r'(?i)(?:\.\.(?:;|%00)*[/\\]|%u002e|%uff0e|%c0%ae|%c0%2e|%e0%40%ae|%252e|\.\.;/)', 'BLOCK'),
    
    (2, 'Block DIRECTORY Traversal to Sensitive Files', 'REGEX_MATCH', 'PATH', r'(?i)(?:^|/)(?:\.env|etc/(?:passwd|shadow|group|hosts|mysql)|windows/win\.ini|wp-config\.php|proc/self/environ|run/secrets/kubernetes)', 'BLOCK'),
    
    (3, 'Block DIRECTORY Traversal (query)', 'REGEX_MATCH', 'QUERY_STRING', r'(?i)(?:\.\.(?:;|%00)*[/\\]|%u002e|%uff0e|%c0%ae|%c0%2e|%e0%40%ae|%252e|\.\.;/)', 'BLOCK'),
    
    (4, 'Block DIRECTORY Absolute Traversal (Linux+Kubernetes)', 'REGEX_MATCH', 'QUERY_STRING', r'(?i)(?:^|[?&=])\s*[/\\](?:etc|proc|var|run|home)[/\\]', 'BLOCK'),
    
    (5, 'Block DIRECTORY Absolute Traversal (Windows)', 'REGEX_MATCH', 'QUERY_STRING', r'(?i)(?:c:[/\\](?:windows|inetpub|sysprep|system32)|\\\\(?:localhost|[\w.-]+)\\[a-z$])', 'BLOCK'),
    
    (6, 'Block Traversal (Headers)', 'REGEX_MATCH', 'HEADERS', r'(?i)(?:\.\.(?:;|%00)*[/\\]|%u002e|%uff0e|%c0%ae|%c0%2e|%e0%40%ae|%252e|\.\.;/)', 'BLOCK'),
   
    (7, 'Block OS Command Injection', 'REGEX_MATCH', 'BODY', r'(?i)(;\s*cat\s+\/etc\/|\|\s*bash|wget\s+http)', 'BLOCK'),

    #null byte injection
    (8, 'Block Null Byte Injection', 'REGEX_MATCH', 'QUERY_STRING', r'%00', 'BLOCK'),
    #IIS win short name 
    (9, 'Block IIS Short Name Scan', 'REGEX_MATCH', 'PATH', r'(?i)::(?:\$INDEX_ALLOCATION|\$DATA)', 'BLOCK'),
    
    #SQL injection rules
    (10, 'Block SQLi Auth Bypass', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)(?:'\s*(?:or|and)\s*'?\w|'\s*(?:or|and)\s*'[^']*'='|--(?:\s|$)|;\s*--)", 'BLOCK'),
    
    (11, 'Block SQLi Auth Bypass (Body)', 'REGEX_MATCH', 'BODY', r"(?i)(?:'\s*(?:or|and)\s*'?\w|'\s*(?:or|and)\s*'[^']*'='|--(?:\s|$)|;\s*--)", 'BLOCK'),
    
    (12, 'Block SQLi UNION SELECT', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)union[\s\/*\/!+#-]*(?:all[\s\/*\/!+#-]*)?select", 'BLOCK'),

    (13, 'Block SQLi UNION SELECT (Body)', 'REGEX_MATCH', 'BODY', r"(?i)union[\s\/*\/!+#-]*(?:all[\s\/*\/!+#-]*)?select", 'BLOCK'),

    ##########risk for false blocking 14-16######################
    (14, 'LOG SQLi Comment Obfuscation', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)(?:/\*.*?\*/|/\*![\d]*\s|--[^\r\n]*|#[^\r\n]*)", 'LOG'),

    (15, 'LOG SQLi Dangerous Keywords', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)\b(?:select|insert|update|delete|drop|truncate|exec(?:ute)?|xp_|sp_|information_schema|sysobjects|syscolumns|waitfor[\s+]delay|benchmark\s*\(|sleep\s*\()\b", 'LOG'),

    (16, 'LOG SQLi Dangerous Keywords (Body)', 'REGEX_MATCH', 'BODY', r"(?i)\b(?:select|insert|update|delete|drop|truncate|exec(?:ute)?|xp_|sp_|information_schema|sysobjects|syscolumns|waitfor[\s+]delay|benchmark\s*\(|sleep\s*\()\b", 'LOG'),
    
    (17, 'LOG SQLi Boolean Blind', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)(?:\d+\s*[<=>]=?\s*\d+|'\s*=\s*'|and\s+\d+\s*[<=>]=?\s*\d+|or\s+\d+\s*[<=>]=?\s*\d+|1\s*=\s*1|0\s*=\s*0)", 'LOG'),
    ##########################################################
    
    (18, 'Block SQLi in Headers (Cookie)', 'REGEX_MATCH', 'HEADERS', r"(?i)(?:union[\s\/\*]+select|'\s*(?:or|and)\s*'|--[^\r\n]*|/\*.*?\*/|waitfor[\s+]delay|benchmark\s*\()", 'BLOCK'),
    
    #cross site scripting rules XSS
    (20, 'Block XSS Script Tags', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)(?:<\s*script[\s>\/]|%3c\s*script)", 'BLOCK'),

    (21, 'Block XSS Script Tags (Body)', 'REGEX_MATCH', 'BODY', r"(?i)<\s*script[\s>\/]", 'BLOCK'),

    (22, 'Block XSS Event Handlers', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)\bon(?:error|load|click|mouseover|mouseout|focus|blur|change|submit|keydown|keyup|keypress|input|select|dblclick|contextmenu|drag|drop|copy|paste|cut|scroll|resize|abort|canplay|ended|pause|play|seeking|stalled|suspend|volumechange|waiting|message|open|close|beforeunload|hashchange|popstate|storage|online|offline|animationstart|animationend|transitionend)\s*=", 'BLOCK'),

    (23, 'Block XSS Event Handlers (Body)', 'REGEX_MATCH', 'BODY', r"(?i)\bon(?:error|load|click|mouseover|mouseout|focus|blur|change|submit|keydown|keyup|keypress|input|select|dblclick|contextmenu|drag|drop|copy|paste|cut|scroll|resize|abort|canplay|ended|pause|play|seeking|stalled|suspend|volumechange|waiting|message|open|close|beforeunload|hashchange|popstate|storage|online|offline|animationstart|animationend|transitionend)\s*=", 'BLOCK'),

    (24, 'Block XSS Javascript URI', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)(?:javascript|vbscript)\s*:|data:(?:text/html|application/[a-z+]+|image/svg)", 'BLOCK'),

    (25, 'Block XSS Javascript URI (Body)', 'REGEX_MATCH', 'BODY', r"(?i)(?:javascript|vbscript)\s*:|data:(?:text/html|application/[a-z+]+|image/svg)", 'BLOCK'),

    (26, 'Block XSS Dangerous HTML Tags', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)<\s*(?:iframe|object|embed|applet|form|base|link|meta|svg|img\s[^>]*src\s*=\s*[\"']?(?:javascript|data))[^>]*>", 'BLOCK'),

    (27, 'Block XSS Dangerous HTML Tags (Body)', 'REGEX_MATCH', 'BODY', r"(?i)<\s*(?:iframe|object|embed|applet|form|base|link|meta|svg|img\s[^>]*src\s*=\s*[\"']?(?:javascript|data))[^>]*>", 'BLOCK'),

    (28, 'Block XSS HTML Entity Encoded JS', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)&#(?:x0*[4-9a-f][0-9a-f]|0*(?:[4-9]\d|1[01]\d));?", 'BLOCK'),

    (29, 'Block XSS in Headers', 'REGEX_MATCH', 'HEADERS', r"(?i)(?:<\s*script|on\w+\s*=|javascript\s*:|vbscript\s*:|data\s*:text\/html)", 'BLOCK'),

    #URI/URL structure check
    (30, 'Block Null Bytes in URI', 'REGEX_MATCH', 'PATH', r'%00', 'BLOCK'),

    (31, 'Block Null Bytes in Query', 'REGEX_MATCH', 'QUERY_STRING', r'%00', 'BLOCK'),

    (32, 'Block Double URL Encoding', 'REGEX_MATCH', 'PATH', r"(?i)%25(?:2e|2f|5c|00|3c|3e|27|22)", 'BLOCK'),

    (33, 'Block Double URL Encoding (Query)', 'REGEX_MATCH', 'QUERY_STRING', r"(?i)%25(?:2e|2f|5c|00|3c|3e|27|22)", 'BLOCK'),

    (34, 'Block Malformed URI Characters', 'REGEX_MATCH', 'PATH', r"(?:%(?![0-9a-fA-F]{2})|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f])", 'BLOCK'),

    (35, 'Block Non-Printable Characters in Query', 'REGEX_MATCH', 'QUERY_STRING', r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", 'BLOCK'),

    (36, 'Block Backslash in URI Path', 'REGEX_MATCH', 'PATH', r"\\", 'BLOCK'),

    #RCE remote code exec
    (37, 'Block Command Injection', 'REGEX_MATCH', 'QUERY_STRING', r'(?i)(?:[;&|`$%](?:7[Cc]|26)?\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b'
     r'|%7[Cc]\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b'
     r'|%26\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b'
     r'|\|\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b'
     r'|&\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b'
     r'|\$\(|\$\{IFS\})', 'BLOCK'),

    (38, 'Block Command Injection (BODY)', 'REGEX_MATCH', 'BODY', r'(?i)(?:[;&|`$]\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b|\$\(|\$\{IFS\})', 'BLOCK'),


    #SERVER-SIDE REQUEST FORGERY
    (39, 'Block SSRF - Internal IP Ranges', 'REGEX_MATCH', 'QUERY_STRING', r'(?i)(?:169\.254\.169\.254|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|127\.0\.0\.\d+|localhost)', 'BLOCK'),
    (40, 'Block SSRF - File/Dict Protocol', 'REGEX_MATCH', 'QUERY_STRING', r'(?i)(?:^|\b)(?:file|dict|gopher|ftp):\/\/', 'BLOCK')

    
]

for rule in default_rules:
    db.execute(
        "INSERT OR REPLACE INTO rules "
        "(rule_id, name, rule_type, target_zone, match_pattern, action, is_active, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP)",
        rule
    )
 
print("WAF rules inserted.")


# IN-MEMORY CACHE

# O(1) set for blocked IP addresses
CACHE_IPS: set = set()
 
# Compiled regex rules grouped by the proxy zone they target
CACHE_REGEX: dict = {
    'PATH': [],
    'QUERY_STRING': [],
    'HEADERS': [],
    'BODY': [],
}
 
 
def reload_cache():
    global CACHE_IPS, CACHE_REGEX
 
    print("Loading rules into memory...")
 
    CACHE_IPS.clear()
    for key in CACHE_REGEX:
        CACHE_REGEX[key].clear()
 
    active_rules = db.execute(
        "SELECT rule_id, rule_type, target_zone, match_pattern, action "
        "FROM rules WHERE is_active = TRUE"
    ).fetchall()
 
    for rule in active_rules:
        r_id, r_type, target_zone, pattern, action = rule
 
        if r_type == 'IP_MATCH':
            CACHE_IPS.add(pattern)
 
        elif r_type == 'REGEX_MATCH':
            if target_zone not in CACHE_REGEX:
                print(f"  [WARNING]  Rule {r_id} has unknown target_zone '{target_zone}' => skipped")
                continue
            try:
                compiled = regex.compile(pattern)
                CACHE_REGEX[target_zone].append({
                    'rule_id': r_id,
                    'pattern': compiled,
                    'action':  action,
                })
            except Exception as e:
                print(f"  [ERROR!]   Failed to compile regex for rule {r_id}: {e}")
 
    ip_count = len(CACHE_IPS)
    regex_count = sum(len(v) for v in CACHE_REGEX.values())
    print(f"  [SUCCESS]   Loaded {ip_count} IP rules and {regex_count} REGEX rules into memory.")
    for zone, rules in CACHE_REGEX.items():
        print(f"  {zone}: {len(rules)} rules")
 
 
reload_cache()

#operations for analyzer
def add_new_rule(name: str, rule_type: str, target_zone: str, match_pattern: str, action: str = 'BLOCK'):
    valid_zones = {'PATH', 'BODY', 'QUERY_STRING', 'HEADERS', 'IP'}
    if target_zone not in valid_zones and rule_type != 'IP_MATCH':
        print(f"Invalid rule insertion == cancelled")
    
    try:
        cursor = db.cursor()

        #max id
        cursor.execute("SELECT MAX(rule_id) FROM rules")
        result = cursor.fetchone()[0]
        next_id = 1 if result is None else result + 1

        cursor.execute(
            """
            INSERT INTO rules 
            (rule_id, name, rule_type, target_zone, match_pattern, action, is_active, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP)
            """,
            (next_id, name, rule_type, target_zone, match_pattern, action)
        )
        
        print(f"[SUCCES] added rule '{name}' with ID {next_id}")

        reload_cache()

        return next_id
    except Exception as e:
        print(f" [ERR] to add rule: {e}")
        return None
    finally:
        cursor.close()