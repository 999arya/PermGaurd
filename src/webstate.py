"""Browser-carried, signed state and per-browser history for Vercel workers."""
import base64
from itsdangerous import URLSafeSerializer, BadSignature
from .models import ScanResult


def encode(value):
    if isinstance(value, ScanResult):
        return {'__scan__': value.model_dump(mode='json')}
    if isinstance(value, bytes):
        return {'__bytes__': base64.b64encode(value).decode()}
    if isinstance(value, dict):
        return {k:encode(v) for k,v in value.items() if k != '_uploads'}
    if isinstance(value,(list,tuple)):
        return [encode(v) for v in value]
    return value


def decode(value):
    if isinstance(value,dict):
        if set(value)=={'__scan__'}:return ScanResult.model_validate(value['__scan__'])
        if set(value)=={'__bytes__'}:return base64.b64decode(value['__bytes__'])
        return {k:decode(v) for k,v in value.items()}
    if isinstance(value,list):return [decode(v) for v in value]
    return value


def dump_state(state,secret,identity):
    return URLSafeSerializer(secret,salt='permguard-dashboard:'+identity).dumps(encode(state))


def load_state(token,secret,identity):
    value=URLSafeSerializer(secret,salt='permguard-dashboard:'+identity).loads(token)
    if not isinstance(value,dict):raise BadSignature('Invalid dashboard state')
    return decode(value)


class BrowserStore:
    def __init__(self,state):self.rows=state.setdefault('_history',{})
    def save(self,result,keep_full=False):
        r=result
        self.rows[r.scan_id]={'scan_id':r.scan_id,'scanned_at':r.scan_finished_at,
            'filename':r.metadata.filename,'package_name':r.metadata.package_name,
            'app_label':r.metadata.app_label,'category':r.purpose.category if r.purpose else None,
            'input_type':r.metadata.input_type,'scan_mode':r.scan_mode,'scan_depth':r.scan_depth_used,
            'risk_score':r.risk.score,'risk_level':r.risk.level.value,
            'permission_count':len(r.metadata.permissions),'finding_count':len(r.findings),
            'critical_count':r.severity_counts.get('CRITICAL',0),'high_count':r.severity_counts.get('HIGH',0)}
        while len(self.rows)>200:del self.rows[next(iter(self.rows))]
    def list_scans(self,limit=200):return sorted(self.rows.values(),key=lambda x:x['risk_score'],reverse=True)[:limit]
    def count(self):return len(self.rows)
    def get(self,key):return self.rows.get(key)
    def delete(self,key):return self.rows.pop(key,None) is not None
    def delete_all(self):
        count=len(self.rows)
        self.rows.clear()
        return count


class BrowserCache:
    def __init__(self,state):self.rows=state.setdefault('_scan_cache',{})
    def _key(self,*args):return '|'.join(str(x or '') for x in args)
    def get(self,*args):
        result=self.rows.get(self._key(*args))
        return result.model_copy(deep=True) if result else None
    def put(self,result,*args):
        self.rows[self._key(*args)]=result.model_copy(deep=True)
        # Keep signed responses small enough for serverless request limits.
        while len(self.rows)>6:del self.rows[next(iter(self.rows))]
