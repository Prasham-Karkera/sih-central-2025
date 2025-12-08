from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from pathlib import Path
import os
import yaml

router = APIRouter(prefix="/api/sigma", tags=["sigma"])

SIGMA_RULES_DIR = Path("./Sigma_Rules")

class RuleContent(BaseModel):
    path: str
    content: str

@router.get("/folders")
async def get_sigma_folders():
    """List available Sigma rule folders."""
    if not SIGMA_RULES_DIR.exists():
        return {"folders": []}
    
    folders = [
        d.name for d in SIGMA_RULES_DIR.iterdir() 
        if d.is_dir() and not d.name.startswith('.')
    ]
    return {"folders": sorted(folders)}

@router.get("/rules")
async def list_rules(folder: str):
    """List rules in a specific folder."""
    folder_path = SIGMA_RULES_DIR / folder
    if not folder_path.exists() or not folder_path.is_dir():
        raise HTTPException(status_code=404, detail="Folder not found")
    
    rules = []
    for f in folder_path.glob("*.yml"):
        rules.append({
            "name": f.name,
            "path": f"{folder}/{f.name}",
            "size": f.stat().st_size
        })
    
    return {"rules": sorted(rules, key=lambda x: x['name'])}

@router.get("/rule")
async def get_rule_content(path: str):
    """Get content of a specific rule."""
    # Security check: prevent directory traversal
    if ".." in path or path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")
        
    file_path = SIGMA_RULES_DIR / path
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Rule not found")
    
    try:
        content = file_path.read_text(encoding="utf-8")
        return {"content": content, "path": path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/tree")
async def get_sigma_tree():
    """Get the full file tree of Sigma rules."""
    def build_tree(path: Path):
        tree = []
        try:
            # Sort: Directories first, then files
            items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            
            for item in items:
                if item.name.startswith('.'):
                    continue
                    
                node = {
                    "name": item.name,
                    "path": str(item.relative_to(SIGMA_RULES_DIR)),
                    "type": "directory" if item.is_dir() else "file"
                }
                
                if item.is_dir():
                    node["children"] = build_tree(item)
                
                tree.append(node)
        except Exception:
            pass
        return tree

    if not SIGMA_RULES_DIR.exists():
        return []
        
    return build_tree(SIGMA_RULES_DIR)

@router.post("/rule")
async def save_rule_content(rule: RuleContent):
    """Save content of a specific rule. Creates file if it doesn't exist."""
    # Security check
    if ".." in rule.path or rule.path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")
    
    file_path = SIGMA_RULES_DIR / rule.path
    
    try:
        # Validate YAML before saving
        try:
            yaml.safe_load(rule.content)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)}")
            
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_path.write_text(rule.content, encoding="utf-8")
        return {"status": "success", "message": "Rule saved successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
