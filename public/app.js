const $ = (id) => document.getElementById(id);
let currentFile, currentQuery, currentResult;
const status = (message) => { $('status').textContent = message; };
function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function render(result) {
  $('app-name').textContent = result.metadata.app_label || result.metadata.package_name || 'Permission report';
  $('score').textContent = `${result.risk.score}/100 · ${result.risk.level} risk`;
  $('score').dataset.level = result.risk.level;
  $('explanation').textContent = result.risk.explanation;
  $('disclaimer').textContent = result.disclaimer;
  $('findings').replaceChildren();
  const rank = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
  [...result.findings].sort((a,b) => rank[a.severity]-rank[b.severity]).forEach(finding => {
    const article = document.createElement('article');
    for (const [tag, value, cls] of [ ['span',`${finding.severity} · ${finding.assessment_status}`,'badge'], ['h4',finding.title], ['p',finding.description], ['p',`Evidence: ${finding.evidence}`], ['p',`Action: ${finding.recommended_action}`], ['p',`Limitations: ${finding.limitations}`] ]) {
      const node = document.createElement(tag); node.textContent = value; if(cls) node.className = cls; article.append(node);
    }
    $('findings').append(article);
  });
  $('results').hidden = false;
}
async function scan(file, format = 'json', query = null) {
  if (!file || !file.size || file.size > 4000000) throw new Error('Choose a non-empty file no larger than 4 MB.');
  const params = new URLSearchParams(query || {filename:file.name,category:$('category').value,mode:$('mode').value});
  params.set('format', format);
  const response = await fetch(`/api/scan?${params}`, {method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || `Request failed (${response.status}). Try a smaller file or run locally.`);
  }
  return format === 'json' ? response.json() : response.blob();
}
async function run(file) {
  document.querySelectorAll('button').forEach(b => b.disabled = true);
  $('results').hidden = true; status('Analyzing permissions…');
  try {
    const query = {filename:file.name,category:$('category').value,mode:$('mode').value};
    const result = await scan(file, 'json', query);
    currentFile = file; currentQuery = query; currentResult = result;
    render(result); status('Analysis complete.');
  } catch(error) { status(error.message); }
  finally { document.querySelectorAll('button').forEach(b => b.disabled = false); }
}
$('scan-form').addEventListener('submit', event => {event.preventDefault(); run($('file').files[0]);});
$('demo').addEventListener('click', async () => {
  try {
    const response = await fetch('/api/demo'); if(!response.ok) throw new Error('Demo unavailable.');
    $('category').value = 'flashlight';
    await run(new File([await response.blob()], 'flashlight_mobsf.json', {type:'application/json'}));
  } catch(error) {status(error.message);}
});
$('json').addEventListener('click', () => download(new Blob([JSON.stringify(currentResult,null,2)],{type:'application/json'}),'permguard-report.json'));
for (const format of ['csv','pdf']) $(format).addEventListener('click', async () => {
  $(format).disabled = true; status(`Preparing ${format.toUpperCase()} report…`);
  try {download(await scan(currentFile,format,currentQuery),`permguard-report.${format}`);status('Report downloaded.');}
  catch(error) {status(error.message);} finally {$(format).disabled = false;}
});
fetch('/api/categories').then(response => {if(!response.ok) throw new Error(); return response.json();}).then(data => {
  for(const category of data.categories) {const option = document.createElement('option'); option.value = category; option.textContent = category.replaceAll('_',' '); $('category').append(option);}
}).catch(() => status('Could not load categories. Automatic inference remains available.'));
