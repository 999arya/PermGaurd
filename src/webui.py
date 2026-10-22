"""Flask renderer for the dashboard's existing declarative UI calls.

The analysis and presentation code lives unchanged in dashboard.py. This module
only supplies widgets, layout, state and events; it does not implement analysis.
"""
from __future__ import annotations
import base64
import hashlib
import html
import io
import json
import re
from contextvars import ContextVar
from markdown_it import MarkdownIt

_active = ContextVar('dashboard_renderer')
_md = MarkdownIt('commonmark', {'html': False})
_cache = {}

class State(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError as exc:
            raise AttributeError(key) from exc
    def __setattr__(self, key, value):
        self[key] = value

class Rerun(BaseException):
    pass

class Upload(io.BytesIO):
    def __init__(self, data, name):
        super().__init__(data)
        self.name = name

class Block:
    def __init__(self, renderer, opening='', closing='', parent=None):
        self.renderer = renderer
        self.opening, self.closing, self.children = opening, closing, []
        if parent is not None:
            parent.children.append(self)
    def __enter__(self):
        self.renderer.stack.append(self)
        return self
    def __exit__(self, *args):
        self.renderer.stack.pop()
    def __getattr__(self, name):
        def call(*args, **kwargs):
            with self:
                return getattr(self.renderer, name)(*args, **kwargs)
        return call
    def render(self):
        return self.opening + ''.join(x.render() if isinstance(x, Block) else x for x in self.children) + self.closing

class Renderer:
    def __init__(self, state, values=None, uploads=None, event='', testing=False):
        self.session_state = state
        self.values = values or {}
        self.uploads = uploads or {}
        self.event = event
        self.root = Block(self)
        self.stack = [self.root]
        self.sidebar = Block(self, '<aside data-testid="stSidebar" aria-label="Sidebar">', '</aside>')
        self.counter = 0
        self.form_depth = 0
        self.title = 'PermGuard'
    def emit(self, value):
        self.stack[-1].children.append(value)
    def block(self, opening, closing='</div>'):
        return Block(self, opening, closing, self.stack[-1])
    def widget_id(self, label, key=None):
        return str(key) if key is not None else 'w_' + hashlib.sha256(str(label).encode()).hexdigest()[:16]
    def set_page_config(self, **kwargs):
        self.title = kwargs.get('page_title', self.title)
    def markdown(self, body, unsafe_allow_html=False, **kwargs):
        content = str(body) if unsafe_allow_html else _md.render(str(body))
        self.emit('<div data-testid="stMarkdown" class="stMarkdown"><div>' + content + '</div></div>')
    def caption(self, body, **kwargs):
        self.emit('<div data-testid="stCaptionContainer">' + _md.render(str(body)) + '</div>')
    def subheader(self, body, **kwargs):
        self.emit('<h3>'+html.escape(str(body))+'</h3>')
    def divider(self):
        self.emit('<hr>')
    def code(self, body, **kwargs):
        self.emit('<pre>'+html.escape(str(body))+'</pre>')
    def metric(self, label, value, **kwargs):
        self.emit('<div data-testid="stMetric"><label>'+html.escape(str(label))+'</label><div data-testid="stMetricValue">'+html.escape(str(value))+'</div></div>')
    def columns(self, spec, **kwargs):
        weights = [1]*spec if isinstance(spec, int) else spec
        row = self.block('<div data-testid="stHorizontalBlock" class="ui-columns">')
        return [Block(self, f'<div data-testid="stColumn" style="flex:{w};min-width:0">', '</div>', row) for w in weights]
    def container(self, border=False, **kwargs):
        return self.block('<div data-testid="stVerticalBlock" class="ui-stack'+(' ui-bordered' if border else '')+'">')
    def expander(self, label, expanded=False, **kwargs):
        return self.block('<details data-testid="stExpander"'+(' open' if expanded else '')+'><summary>'+html.escape(str(label))+'</summary><div data-testid="stExpanderDetails" class="ui-stack">', '</div></details>')
    def tabs(self, labels):
        self.counter += 1
        uid='tabs'+str(self.counter)
        row = self.block('<div data-testid="stTabs" data-tabs="'+uid+'">')
        row.children.append('<div role="tablist">'+''.join('<button type="button" role="tab" data-tab="'+str(i)+'" aria-selected="'+('true' if i==0 else 'false')+'">'+html.escape(str(label))+'</button>' for i,label in enumerate(labels))+'</div>')
        return [Block(self, '<div role="tabpanel" data-baseweb="tab-panel" class="ui-stack"'+(' hidden' if i else '')+'>', '</div>', row) for i in range(len(labels))]
    def form(self, key, **kwargs):
        return self.block('<div data-testid="stForm" data-form="'+html.escape(key)+'" class="ui-stack">')
    def _value(self, label, default, key):
        uid = self.widget_id(label,key)
        value = self.values.get(uid, self.session_state.get('_widgets',{}).get(uid, default))
        self.session_state.setdefault('_widgets',{})[uid] = value
        return uid, value
    def _label(self, label, uid, visibility='visible', help=None):
        return '<label for="'+html.escape(uid)+'"'+(' class="ui-hidden-label"' if visibility!='visible' else '')+'>'+html.escape(str(label))+(' <span title="'+html.escape(help,quote=True)+'">ⓘ</span>' if help else '')+'</label>'
    def text_input(self, label, value='', key=None, type='default', placeholder='', label_visibility='visible', help=None, **kwargs):
        uid,value=self._value(label,value,key)
        self.emit('<div data-testid="stTextInput">'+self._label(label,uid,label_visibility,help)+'<input id="'+html.escape(uid)+'" name="'+html.escape(uid)+'" type="'+('password' if type=='password' else 'text')+'" value="'+html.escape(str(value),quote=True)+'" placeholder="'+html.escape(placeholder,quote=True)+'"></div>')
        return value
    def text_area(self,label,value='',height=120,key=None,**kwargs):
        uid,value=self._value(label,value,key)
        self.emit('<div data-testid="stTextArea">'+self._label(label,uid)+'<textarea id="'+uid+'" name="'+uid+'" style="height:'+str(height)+'px">'+html.escape(str(value))+'</textarea></div>')
        return value
    def selectbox(self,label,options,index=0,key=None,format_func=str,label_visibility='visible',help=None,**kwargs):
        choices=list(options)
        uid,value=self._value(label,choices[index] if choices else None,key)
        value=next((x for x in choices if str(x)==str(value)),choices[index] if choices else None)
        self.emit('<div data-testid="stSelectbox">'+self._label(label,uid,label_visibility,help)+'<div data-baseweb="select"><select id="'+uid+'" name="'+uid+'">'+''.join('<option value="'+html.escape(str(x),quote=True)+'"'+(' selected' if x==value else '')+'>'+html.escape(str(format_func(x)))+'</option>' for x in choices)+'</select></div></div>')
        return value
    def multiselect(self,label,options,default=None,key=None,**kwargs):
        uid,value=self._value(label,default or [],key)
        if not isinstance(value,list): value=[value] if value else []
        value=[x for x in value if x in options]
        self.emit('<div data-testid="stMultiSelect">'+self._label(label,uid)+'<select multiple id="'+uid+'" name="'+uid+'">'+''.join('<option'+(' selected' if x in value else '')+'>'+html.escape(str(x))+'</option>' for x in options)+'</select></div>')
        return value
    def checkbox(self,label,value=False,key=None,help=None,**kwargs):
        uid,value=self._value(label,value,key)
        value=value in [True,'true','on',1]
        self.emit('<div data-testid="stCheckbox"><label><input type="checkbox" name="'+uid+'"'+(' checked' if value else '')+'>'+html.escape(label)+'</label></div>')
        return value
    def radio(self,label,options,index=0,key=None,**kwargs):
        uid,value=self._value(label,options[index],key)
        self.emit('<fieldset><legend>'+html.escape(label)+'</legend>'+''.join('<label><input type="radio" name="'+uid+'" value="'+html.escape(str(x),quote=True)+'"'+(' checked' if x==value else '')+'>'+html.escape(str(x))+'</label>' for x in options)+'</fieldset>')
        return value
    def slider(self,label,min_value,max_value,value,key=None,**kwargs):
        uid,value=self._value(label,value,key)
        value=max(min_value,min(max_value,int(value)))
        self.emit('<label>'+html.escape(label)+'<input type="range" name="'+uid+'" min="'+str(min_value)+'" max="'+str(max_value)+'" value="'+str(value)+'"><output>'+str(value)+'</output></label>')
        return value
    def file_uploader(self,label,type=None,key=None,accept_multiple_files=False,label_visibility='visible',help=None,**kwargs):
        uid=self.widget_id(label,key)
        saved=self.session_state.setdefault('_uploads',{})
        if uid in self.uploads:
            saved[uid]=self.uploads[uid]
        uploads=saved.get(uid,[])
        accept=','.join('.'+x for x in type or [])
        self.emit('<div data-testid="stFileUploader">'+self._label(label,uid,label_visibility,help)+'<section><label class="ui-upload" for="'+uid+'">Upload</label><input class="ui-upload-input" type="file" id="'+uid+'" name="'+uid+'" accept="'+accept+'"'+(' multiple' if accept_multiple_files else '')+'><span>200MB per file • '+', '.join(x.upper() for x in type or [])+'</span></section>'+''.join('<div class="ui-file">'+html.escape(x[0])+'<button type="button" data-clear-upload="'+uid+'" aria-label="Remove uploaded file">×</button></div>' for x in uploads)+'</div>')
        files=[Upload(data,name) for name,data in uploads]
        return files if accept_multiple_files and files else files[0] if files else None
    def button(self,label,key=None,type='secondary',**kwargs):
        uid=self.widget_id(label,key)
        self.emit('<div data-testid="stButton"><button type="button" data-event="'+uid+'" data-testid="stBaseButton-'+type+'">'+html.escape(str(label))+'</button></div>')
        return self.event==uid
    def form_submit_button(self,label,**kwargs):
        return self.button(label,**kwargs)
    def download_button(self,label,data,file_name='report',mime='application/octet-stream',**kwargs):
        if isinstance(data,str):data=data.encode()
        if hasattr(data,'read'):data=data.read()
        href='data:'+mime+';base64,'+base64.b64encode(data).decode()
        self.emit('<div data-testid="stDownloadButton"><a class="ui-button" download="'+html.escape(file_name,quote=True)+'" href="'+href+'">'+html.escape(re.sub(r':material/[^:]+:', '↓', label))+'</a></div>')
        return False
    def link_button(self,label,url,**kwargs):
        if not str(url).startswith(('http://','https://','#')):return
        self.emit('<a class="ui-button" href="'+html.escape(url,quote=True)+'" target="_blank" rel="noopener noreferrer">'+html.escape(label)+'</a>')
    def dataframe(self,data,height=None,**kwargs):
        if hasattr(data,'to_dict'):data=data.to_dict('records')
        rows=list(data)
        if not rows:return
        keys=list(rows[0])
        self.emit('<div data-testid="stDataFrame" class="ui-table"'+(' style="max-height:'+str(height)+'px"' if height else '')+'><table><thead><tr>'+''.join('<th>'+html.escape(str(k))+'</th>' for k in keys)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+html.escape(str(row.get(k,'')))+'</td>' for k in keys)+'</tr>' for row in rows)+'</tbody></table></div>')
    def plotly_chart(self,figure,**kwargs):
        self.emit('<div data-testid="stPlotlyChart" class="ui-chart" data-plot="'+html.escape(figure.to_json(),quote=True)+'"></div>')
    def bar_chart(self,data,**kwargs):
        import plotly.graph_objects as go
        fig=go.Figure(go.Bar(x=list(data),y=list(data.values())))
        fig.update_layout(template='plotly_dark',height=300)
        self.plotly_chart(fig)
    def info(self,body,**kwargs):self._alert(body,'info')
    def warning(self,body,**kwargs):self._alert(body,'warning')
    def error(self,body,**kwargs):self._alert(body,'error')
    def success(self,body,**kwargs):self._alert(body,'success')
    def _alert(self,body,kind):self.emit('<div role="status" class="ui-alert '+kind+'">'+_md.render(str(body))+'</div>')
    def spinner(self,label,**kwargs):return Block(self)
    def status(self,label,**kwargs):return Block(self)
    def progress(self,value,**kwargs):return Block(self)
    def empty(self):return self.block('<div>')
    def write(self,body,**kwargs):self.caption(body)
    def update(self,**kwargs):pass
    def rerun(self):raise Rerun()
    def cache_resource(self,**kwargs):
        def decorate(fn):
            def cached(*args):
                from flask import current_app
                if fn.__name__ in ('_store','_scan_cache'):
                    if current_app.config['HOSTED']:
                        from .webstate import BrowserStore, BrowserCache
                        return (BrowserStore if fn.__name__=='_store' else BrowserCache)(self.session_state)
                    if fn.__name__=='_store':
                        from .storage import ScanStore
                        return ScanStore(current_app.config['DATABASE'])
                    from .scancache import ScanCache
                    return ScanCache(current_app.config['CACHE_DIR'])
                key=(fn.__name__,args)
                if key not in _cache:_cache[key]=fn(*args)
                return _cache[key]
            return cached
        return decorate


def __getattr__(name):
    if name.startswith('__'):
        raise AttributeError(name)
    return getattr(_active.get(),name)
