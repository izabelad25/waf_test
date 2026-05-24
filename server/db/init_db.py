import duckdb
import regex 
import os
import sys

_BASE   = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(os.path.dirname(_BASE), "fireball.db")


print("Initializing DuckBD...")

db = duckdb.connect(DB_PATH)


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
    (1, 'Block DIRECTORY Traversal', 'REGEX_MATCH', 'PATH', 
     r'(?i)(?:\.\.(?:;|%00)*[/\\]|%u002e|%uff0e|%c0%ae|%c0%2e|%e0%40%ae|%252e)', 'BLOCK'),
    
    (2, 'Block DIRECTORY Traversal to Sensitive Files', 'REGEX_MATCH', 'PATH', 
     r'(?i)(?:^|/)(?:\.env|etc/(?:passwd|shadow|group|hosts|mysql)|windows/win\.ini|proc/self/environ|run/secrets/kubernetes)', 
     'BLOCK'),

    (3, 'Block DIRECTORY Absolute Traversal (Linux, Kubernetes)', 'REGEX_MATCH', 'QUERY_STRING', 
     r'(?i)\s*[/\\](?:etc|proc|var|run|home)[/\\]', 'BLOCK'),

    (4, 'Block DIRECTORY Absolute Traversal (Windows)', 'REGEX_MATCH', 'PATH', 
     r'(?i)(?:c:[/\\](?:windows|inetpub|sysprep|system32)|\\\\(?:localhost|[\w.-]+)\\[a-z$])', 'BLOCK'),
    
    (5, 'Block DIRECTORY Traversal (query)', 'REGEX_MATCH', 'QUERY_STRING', 
     r'(?i)(?:\.\.(?:;|%00)*[/\\]|%u002e|%uff0e|%c0%ae|%c0%2e|%e0%40%ae|%252e)', 'BLOCK'),

    (6, 'Block DIRECTORY Traversal to Sensitive Files (query)', 'REGEX_MATCH', 'QUERY_STRING', 
     r'(?i)(?:^|/)(?:\.env|etc/(?:passwd|shadow|group|hosts|mysql)|windows/win\.ini|proc/self/environ|run/secrets/kubernetes)', 
     'BLOCK'),
    
    
    (7, 'Block DIRECTORY Absolute Traversal (Windows) (query)', 'REGEX_MATCH', 'QUERY_STRING', 
     r'(?i)(?:c:[/\\](?:windows|inetpub|sysprep|system32)|\\\\(?:localhost|[\w.-]+)\\[a-z$])', 'BLOCK'),
    
    (8, 'Block DIRECTORY Traversal (Headers)', 'REGEX_MATCH', 'HEADERS', 
     r'(?i)(?:\.\.(?:;|%00)*[/\\]|%u002e|%uff0e|%c0%ae|%c0%2e|%e0%40%ae|%252e)', 'BLOCK'),
    
    (9, 'Block DIRECTORY Traversal to Sensitive Files (Headers)', 'REGEX_MATCH', 'HEADERS', 
     r'(?i)(?:^|/)(?:\.env|etc/(?:passwd|shadow|group|hosts|mysql)|windows/win\.ini|proc/self/environ|run/secrets/kubernetes)', 
     'BLOCK'),

    (10, 'Block DIRECTORY Absolute Traversal (Windows) (Headers)', 'REGEX_MATCH', 'HEADERS', 
     r'(?i)(?:c:[/\\](?:windows|inetpub|sysprep|system32)|\\\\(?:localhost|[\w.-]+)\\[a-z$])', 'BLOCK'),
   
    
    
    #SQL injection rules

    (11, 'Block SQLi Auth Bypass', 'REGEX_MATCH', 'QUERY_STRING', 
     r"(?i)(?:'\s*(?:or|and)\s*'?\w|'\s*(?:or|and)\s*'[^']*'='|--(?:\s|$)|;\s*--)", 'BLOCK'),
    
    (12, 'Block SQLi Auth Bypass (Body)', 'REGEX_MATCH', 'BODY', 
     r"(?i)(?:'\s*(?:or|and)\s*'?\w|'\s*(?:or|and)\s*'[^']*'='|--(?:\s|$)|;\s*--)", 'BLOCK'),
    
    (13, 'Block SQLi UNION SELECT', 'REGEX_MATCH', 'QUERY_STRING', 
     r"(?i)union[\s\/*\/!+#-]*(?:all[\s\/*\/!+#-]*)?select", 'BLOCK'),

    (14, 'Block SQLi UNION SELECT (Body)', 'REGEX_MATCH', 'BODY', 
     r"(?i)union[\s\/*\/!+#-]*(?:all[\s\/*\/!+#-]*)?select", 'BLOCK'),

    ##########risk for false blocking 15-17######################

    (15, 'LOG SQLi Comment Obfuscation', 'REGEX_MATCH', 'QUERY_STRING', 
     r"(?i)(?:/\*.*?\*/|/\*![\d]*\s|--[^\r\n]*|#[^\r\n]*)", 'LOG'),

    (16, 'LOG SQLi Keywords', 'REGEX_MATCH', 'QUERY_STRING', 
     r"(?i)\b(?:select|insert|update|delete|drop|truncate|exec(?:ute)?|"
     r"xp_|sp_|information_schema|sysobjects|syscolumns|waitfor[\s+]delay|"
     r"benchmark\s*\(|sleep\s*\()\b", 'LOG'),

    (17, 'LOG SQLi Keywords (Body)', 'REGEX_MATCH', 'BODY', 
     r"(?i)\b(?:select|insert|update|delete|drop|truncate|exec(?:ute)?|"
     r"xp_|sp_|information_schema|sysobjects|syscolumns|waitfor[\s+]delay|"
     r"benchmark\s*\(|sleep\s*\()\b", 'LOG'),
    
    
    (18, 'Block SQLi in Headers', 'REGEX_MATCH', 'HEADERS', 
     r"(?i)(?:union[\s\/\*]+select|'\s*(?:or|and)\s*'|--[^\r\n]*|/\*.*?\*/|waitfor[\s+]delay|benchmark\s*\()", 
    'BLOCK'),
    
    #cross site scripting rules XSS
    (19, 'Block XSS Script Tags', 'REGEX_MATCH', 'QUERY_STRING', 
     r"(?i)<\s*script[\s>\/]", 'BLOCK'),

    (20, 'Block XSS Script Tags (Body)', 'REGEX_MATCH', 'BODY', 
     r"(?i)<\s*script[\s>\/]", 'BLOCK'),

    (21, 'Block XSS Event Handlers', 'REGEX_MATCH', 'QUERY_STRING', 
     r"(?i)\bon(?:error|load|click|mouseover|mouseout|focus|blur|change|submit|"
     r"keydown|keyup|keypress|input|select|dblclick|contextmenu|drag|drop|copy|"
     r"paste|cut|scroll|resize|abort|canplay|ended|pause|play|seeking|stalled|"
     r"suspend|volumechange|waiting|message|open|close|beforeunload|hashchange|"
     r"popstate|storage|online|offline|animationstart|animationend|transitionend)\s*=", 'BLOCK'),

    (22, 'Block XSS Event Handlers (Body)', 'REGEX_MATCH', 'BODY', 
     r"(?i)\bon(?:error|load|click|mouseover|mouseout|focus|blur|change|submit|"
     r"keydown|keyup|keypress|input|select|dblclick|contextmenu|drag|drop|copy|"
     r"paste|cut|scroll|resize|abort|canplay|ended|pause|play|seeking|stalled|"
     r"suspend|volumechange|waiting|message|open|close|beforeunload|hashchange|"
     r"popstate|storage|online|offline|animationstart|animationend|transitionend)\s*=", 'BLOCK'),

    (23, 'Block XSS Javascript URI', 'REGEX_MATCH', 'QUERY_STRING', 
     r"(?i)(?:javascript|vbscript)\s*:|data:(?:text/html|application/[a-z+]+|image/svg)", 'BLOCK'),

    (24, 'Block XSS Javascript URI (Body)', 'REGEX_MATCH', 'BODY', 
     r"(?i)(?:javascript|vbscript)\s*:|data:(?:text/html|application/[a-z+]+|image/svg)", 'BLOCK'),

   
    (25, 'Block XSS in Headers', 'REGEX_MATCH', 'HEADERS', 
     r"(?i)(?:<\s*script|javascript\s*:|vbscript\s*:|data\s*:text\/html|"
     r"\bon(?:error|load|click|mouseover|mouseout|focus|blur|change|submit|"
     r"keydown|keyup|keypress|input|select|dblclick|contextmenu|drag|drop|copy|"
     r"paste|cut|scroll|resize|abort|canplay|ended|pause|play|seeking|stalled|"
     r"suspend|volumechange|waiting|message|open|close|beforeunload|hashchange|"
     r"popstate|storage|online|offline|animationstart|animationend|transitionend)\s*=)", 'BLOCK'),

    (26, 'Block OS Command Injection', 'REGEX_MATCH', 'QUERY_STRING', 
      r'(?i)(?:[;&|`$]\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b|\$\(|\$\{IFS\})', 'BLOCK'),

    (27, 'Block Command Injection (BODY)', 'REGEX_MATCH', 'BODY', 
     r'(?i)(?:[;&|`$]\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b|\$\(|\$\{IFS\})', 'BLOCK'),

    #null byte injection

    (28, 'Block Null Bytes (path)', 'REGEX_MATCH', 'PATH', r'%00', 'BLOCK'),

    (29, 'Block Null Bytes (query)', 'REGEX_MATCH', 'QUERY_STRING', r'%00', 'BLOCK')
    
    
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