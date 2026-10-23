let pending=false;
const tabState={};
const retainedFiles=new Map();
function initialize(){
  document.querySelectorAll('[data-tabs]').forEach(group=>{
    const key=group.dataset.tabs,buttons=[...group.querySelector(':scope > [role=tablist]').children],panels=[...group.querySelectorAll(':scope > [role=tabpanel]')];
    const activate=index=>{tabState[key]=index;buttons.forEach((b,i)=>b.setAttribute('aria-selected',String(i===index)));panels.forEach((p,i)=>p.hidden=i!==index);drawCharts();};
    buttons.forEach((b,i)=>b.onclick=()=>activate(i));activate(Math.min(tabState[key]||0,buttons.length-1));
  });
  document.querySelectorAll('[data-event]').forEach(b=>b.onclick=()=>submit(b.dataset.event));
  document.querySelectorAll('[data-clear-upload]').forEach(b=>b.onclick=()=>submit('',b.dataset.clearUpload));
  document.querySelectorAll('input[name],select[name],textarea[name]').forEach(input=>input.onchange=()=>{if(!input.closest('[data-form]'))submit();});
  initializeUploads();
  document.querySelector('#dashboard').onsubmit=e=>e.preventDefault();
  document.querySelector('#sidebar-toggle').onclick=()=>document.body.classList.toggle('sidebar-open');
  drawCharts();
}
function initializeUploads(){
  document.querySelectorAll('[data-testid=stFileUploader]').forEach(uploader=>{
    const input=uploader.querySelector('input[type=file]');
    const prompt=uploader.previousElementSibling?.querySelector('.pg-drop-prompt');
    if(prompt){
      prompt.setAttribute('role','button');
      prompt.tabIndex=0;
      prompt.setAttribute('aria-label','Choose APK or report files');
      prompt.onclick=()=>{if(!pending)input.click();};
      prompt.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();prompt.click();}};
    }
    [prompt,uploader.querySelector('section')].filter(Boolean).forEach(zone=>{
      zone.ondragover=e=>{e.preventDefault();e.dataTransfer.dropEffect='copy';};
      zone.ondrop=e=>{
        e.preventDefault();
        if(pending||!e.dataTransfer.files.length)return;
        const files=[...e.dataTransfer.files];
        const extensions=input.accept.toLowerCase().split(',').filter(Boolean);
        if(files.some(file=>extensions.length&&!extensions.some(ext=>file.name.toLowerCase().endsWith(ext)))){
          showUploadError('Unsupported file type. Choose '+input.accept+' files.');return;
        }
        const transfer=new DataTransfer();
        (input.multiple?files:files.slice(0,1)).forEach(file=>transfer.items.add(file));
        input.files=transfer.files;
        input.dispatchEvent(new Event('change',{bubbles:true}));
      };
    });
  });
}
function showUploadError(message){
  let notice=document.querySelector('#upload-error');
  if(!notice){notice=document.createElement('div');notice.id='upload-error';notice.className='ui-alert error';notice.setAttribute('role','alert');(document.querySelector('[data-testid=stFileUploader]')||document.querySelector('#dashboard')).append(notice);}
  notice.textContent=message;
}
function drawCharts(){document.querySelectorAll('[data-plot]').forEach(el=>{if(el.closest('[hidden]')||el.dataset.drawn)return;const plot=JSON.parse(el.dataset.plot);Plotly.newPlot(el,plot.data,plot.layout,{responsive:true,displayModeBar:false});el.dataset.drawn='true';});}
async function submit(event='',clear=''){
  if(pending)return;pending=true;const form=document.querySelector('#dashboard'),payload=new FormData(),values={};
  form.querySelectorAll('input[name],select[name],textarea[name]').forEach(input=>{
    const key=input.name;if(input.type==='file'){if(input.files.length)retainedFiles.set(key,[...input.files]);if(clear===key)retainedFiles.delete(key);for(const file of retainedFiles.get(key)||[])payload.append(key,file);}
    else if(input.type==='checkbox')values[key]=input.checked;
    else if(input.type==='radio'){if(input.checked)values[key]=input.value;}
    else if(input.multiple)values[key]=[...input.selectedOptions].map(o=>o.value);
    else values[key]=input.value;
  });
  payload.append('_snapshot',document.querySelector('#snapshot').value);
  payload.append('_values',JSON.stringify(values));payload.append('_event',event);payload.append('_csrf',document.querySelector('#csrf').value);if(clear)payload.append('_clear_upload',clear);
  document.querySelector('#upload-error')?.remove();
  if(form.dataset.hosted==='true'&&[...payload.values()].reduce((total,value)=>total+(value instanceof Blob?value.size:new Blob([value]).size),0)>=4_000_000){
    pending=false;
    showUploadError('Upload is too large for this hosted app (4 MB total request limit, including dashboard state). Use the local app for larger APKs, or remove files and choose a smaller upload.');
    return;
  }
  const y=window.scrollY,sidebar=document.body.classList.contains('sidebar-open'),open=[...document.querySelectorAll('details[open]')].map(d=>d.querySelector('summary')?.textContent);
  document.querySelector('#busy').hidden=false;
  try{const response=await fetch('/',{method:'POST',body:payload});if(!response.ok)throw new Error(`Request failed (${response.status}).`);const doc=new DOMParser().parseFromString(await response.text(),'text/html');document.querySelector('#dashboard').replaceWith(doc.querySelector('#dashboard'));document.body.classList.toggle('sidebar-open',sidebar);document.querySelectorAll('details').forEach(d=>d.open=open.includes(d.querySelector('summary')?.textContent));initialize();window.scrollTo({top:y,behavior:'instant'});}catch(error){alert(error.message);}finally{pending=false;document.querySelector('#busy').hidden=true;}
}
initialize();
