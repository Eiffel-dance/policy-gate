import fnmatch
class PolicyGate:
    def __init__(self,rules):
        self.rules=[]
        for i,r in enumerate(rules):
            if r.get("effect") not in ("allow","deny"): raise ValueError("invalid effect")
            self.rules.append({"id":r.get("id",str(i)),"effect":r["effect"],"subject":r.get("subject","*"),"action":r.get("action","*"),"resource":r.get("resource","*"),"tags":r.get("tags",{})})
    def decide(self,subject,action,resource,tags=None):
        tags=tags or {}; matches=[r for r in self.rules if all(fnmatch.fnmatchcase(x,y) for x,y in ((subject,r["subject"]),(action,r["action"]),(resource,r["resource"]))) and all(tags.get(k)==v for k,v in r["tags"].items())]
        matches.sort(key=lambda r:(r["effect"]!="deny",self.rules.index(r))); hit=matches[0] if matches else None
        return {"effect":hit["effect"] if hit else "deny","rule":hit["id"] if hit else None,"reason":"matched rule" if hit else "default deny"}
