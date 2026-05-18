from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from db.init_db import db, CACHE_IPS, CACHE_REGEX, reload_cache
from typing import Optional
import regex

rule_router = APIRouter()

#default rules IDs (19 lipseste)
DEFAULT_RULE_IDS: frozenset[int] = frozenset([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40
])

#protected fields
protected_fields = {"name", "rule_type", "target_zone", "match_pattern"}

#using base models for automatic validation + type casting 

class RuleCreate(BaseModel):
    name: str
    rule_type: str       # 'IP_MATCH' sau 'REGEX_MATCH'
    target_zone: str     # 'CLIENT_IP', 'PATH', 'HEADERS', 'QUERY_STRING', 'BODY'
    match_pattern: str
    action: str = "BLOCK" #default action

class RuleUpdate(BaseModel):
    name:          Optional[str]  = None
    rule_type:     Optional[str]  = None
    target_zone:   Optional[str]  = None
    match_pattern: Optional[str]  = None
    action:        Optional[str]  = None
    is_active:     Optional[bool] = None

#functions for VALIDATING NEW RULES / UPDATED RULES
def validate_regex(pattern: str) -> None:
    #checking if the pattern added compiles
    try:
        regex.compile(pattern)
    except Exception as e:
        raise HTTPException(status_code=422, 
                            detail=f"Invalid regex pattern --> {e}")

def check_conflicts(
      zone: str,
    pattern: str,
    action: str,
    exclude_id: Optional[int] = None  
) -> list[dict]:
    #checks for conflicts with the existent rules
        #DUPLICATE
        
    rows = db.execute(
        "SELECT rule_id, name, match_pattern, action "
        "FROM rules "
        "WHERE target_zone = ? AND is_active = TRUE",
        (zone,)
    ).fetchall()

    conflicts = []

    for r_id, r_name, r_pattern, r_actions in rows:
        if exclude_id is not None and r_id == exclude_id:
            continue

        #DUPLICATE check
        if r_pattern == pattern:
            conflicts.append({
                "type":        "DUPLICATE",
                "rule_id":     r_id,
                "rule_name":   r_name,
                "description": (
                    f"Duplicate -> Rule #{r_id} '{r_name}' has the exact same pattern "
                    f"in zone '{zone}'."
                )
            })
    return conflicts


#READ all rules
@rule_router.get("/waf/rules")
async def get_all_rules():
    rows = db.execute("SELECT * FROM rules").fetchall()

    rules_list = []
    for row in rows:
        rules_list.append({
            "id": row[0], 
            "name": row[1],
            "rule_type": row[2],
            "target_zone": row[3],
            "match_pattern": row[4],
            "action": row[5],
            "is_active": row[6],
            "updated_at": row[7],
            "is_default": row[0] in DEFAULT_RULE_IDS,
        })
    return {"rules": rules_list}

#CREATE new rule
@rule_router.post("/waf/rules")
async def create_rule(rule: RuleCreate):
    #validate regex -- compiles?
    validate_regex(rule.match_pattern)

    #check conflict -- duplicate?
    conflicts = check_conflicts(rule.target_zone, rule.match_pattern, rule.action)

    if conflicts:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Rule cannot be added because it conflicts with existing rules!",
                "conflicts": conflicts
            }
        )
    #autoincrement pt next id
    next_id = db.execute("SELECT COALESCE(MAX(rule_id), 0) + 1 FROM rules").fetchone()[0]

    db.execute("INSERT INTO rules (rule_id, name, rule_type, target_zone, match_pattern, action, is_active)" \
    "VALUES (?, ?, ?, ?, ?, ?, ?)", (next_id, rule.name, rule.rule_type, rule.target_zone, rule.match_pattern, rule.action, True))

    reload_cache()
    return {"status": "success", "message": f"Rule '{rule.name}' created", "id": next_id}

#UPDATE rule
@rule_router.put("/waf/rules/{rule_id}")
async def update_rule(rule_id: int, updates: RuleUpdate):
    exists = db.execute("SELECT rule_type, target_zone, match_pattern FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()

    if not exists:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    current_type, current_zone, current_pattern = exists
    
    #default rule protection
    if rule_id in DEFAULT_RULE_IDS:
        protected_f = {
            f for f in protected_fields
            if getattr(updates, f, None) is not None
        }
        if protected_f:
            raise HTTPException(
                status_code=403,
                detail={
                    "message": (
                        f"Rule #{rule_id} is a default WAF rule. "
                        f"Fields {sorted(protected_f)} cannot be modified. "
                        "Only 'action' and 'is_active' are editable on default rules."
                    ),
                    "editable_fields": ["action", "is_active"]
                }
            )

    #for checks (new values for update or the current ones)   
    effective_zone    = updates.target_zone   or current_zone
    effective_pattern = updates.match_pattern or current_pattern
    
    #if pattern or zone is changing == compile regex check + conflict check
    pattern_changing = (
        updates.match_pattern is not None and updates.match_pattern != current_pattern
    )
    zone_changing = (
        updates.target_zone is not None and updates.target_zone != current_zone
    )

    if pattern_changing or zone_changing:
        validate_regex(effective_pattern)
        conflicts = check_conflicts(effective_zone, effective_pattern, updates.action or "BLOCK", exclude_id=rule_id)

        if conflicts:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "Updated pattern conflicts with existing rules! Cannot be updated!",
                    "conflicts": conflicts
                }
            )

    
    updatable = {
        "name":          updates.name,
        "rule_type":     updates.rule_type,
        "target_zone":   updates.target_zone,
        "match_pattern": updates.match_pattern,
        "action":        updates.action,
        "is_active":     updates.is_active,
    }
    for col, val in updatable.items():
        if val is not None:
            db.execute(
                f"UPDATE rules SET {col} = ? WHERE rule_id = ?", (val, rule_id)
            )
    
    db.execute("UPDATE rules SET updated_at = CURRENT_TIMESTAMP WHERE rule_id = ?", (rule_id,))

    reload_cache()
    return {"status": "success", "message": f"Rule {rule_id} updated"}

#DELETE
@rule_router.delete("/waf/rules/{rule_id}")
async def delete_rule(rule_id: int):
    #protection for default rules
    if rule_id in DEFAULT_RULE_IDS:
        raise HTTPException(
            status_code=403,
            detail={
                "message": (f"Rule {rule_id} is a default rule and cannot be deleted.")
            }
        )
    
    exists = db.execute("SELECT 1 FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()

    if not exists:
        raise HTTPException(status_code=404, detail="Rule not found!")
    

    db.execute("DELETE FROM rules WHERE rule_id = ?", (rule_id,))
    reload_cache()

    return {"status": "success", "message": f"Rule {rule_id} deleted"}

