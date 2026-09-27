//! The webmail single-page app: built files from the static directory, or a
//! small embedded fallback page when none are installed.

use std::path::Path;

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::api::APP_CSP;

/// Serve `path` from `static_dir`, falling back to `index.html` for client
/// routes and to the embedded page when the frontend is not installed.
pub(crate) fn spa(static_dir: &Path, path: &str) -> Response {
    if static_dir.is_dir() {
        let relative = if path == "/" {
            "index.html"
        } else {
            path.trim_start_matches('/')
        };
        let safe = !relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..");
        if safe {
            let file = static_dir.join(relative);
            if file.is_file()
                && let Ok(body) = std::fs::read(&file)
            {
                return file_response(content_type(&file), body);
            }
        }
        let index = static_dir.join("index.html");
        if index.is_file()
            && let Ok(body) = std::fs::read(index)
        {
            return file_response("text/html; charset=utf-8", body);
        }
    }
    embedded()
}

fn file_response(content_type: &'static str, body: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "html" => "text/html; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn embedded() -> Response {
    let mut response = file_response("text/html; charset=utf-8", EMBEDDED_SPA.as_bytes().to_vec());
    // The built-in fallback page carries its script inline.
    let policy = APP_CSP.replacen(
        "default-src 'self'",
        "default-src 'self'; script-src 'self' 'unsafe-inline'",
        1,
    );
    if let Ok(value) = HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

const EMBEDDED_SPA: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>rMail Webmail</title>
    <style>
      html,body,#root{height:100%}body{margin:0;overflow:hidden;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7f8;color:#222831}
      button,input{font:inherit}button{cursor:pointer}.login{min-height:100vh;display:grid;place-items:center;background:#edf3f2}
      form{width:min(360px,calc(100vw - 32px));display:grid;gap:12px;padding:24px;background:#fff;border:1px solid #d8dee2;border-radius:8px}
      input{border:1px solid #cfd7dc;border-radius:6px;padding:10px 12px}form button,.bar button{border:0;border-radius:6px;padding:10px 14px;background:#276ef1;color:#fff}
      .app{height:100vh;min-height:0;display:grid;grid-template-columns:220px minmax(340px,.95fr) minmax(380px,1.15fr);overflow:hidden}.folders{background:#24313a;color:#eef5f6;padding:14px 10px;overflow:auto}
      .folders button{width:100%;display:flex;justify-content:space-between;border:0;background:transparent;color:inherit;border-radius:6px;padding:9px 10px}.folders .active,.folders button:hover{background:#38505c}
      .list{display:grid;grid-template-rows:58px minmax(0,1fr);border-right:1px solid #d8dee2;min-width:0;min-height:0;background:#fff}.bar{display:flex;gap:8px;align-items:center;padding:8px 12px;border-bottom:1px solid #d8dee2}.bar input{flex:1;min-width:0;background:#f3f6f7}
      .list>div{min-height:0;overflow:auto}.msg{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;width:100%;border:0;border-bottom:1px solid #e3e8eb;background:#fff;text-align:left;padding:12px}.msg.unread{font-weight:700}.msg small{grid-column:2;color:#667780;font-weight:400;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
      .reader{min-height:0;background:#fff;padding:24px;overflow:hidden;display:flex;flex-direction:column}.reader-actions{display:flex;gap:8px;margin-bottom:18px}.reader pre{flex:1 1 auto;min-height:0;overflow:auto;white-space:pre-wrap;font-family:inherit;line-height:1.5}.html-message{flex:1 1 auto;min-height:0;width:100%;height:100%;border:0;background:#fff}.muted{color:#667780}
      @media(max-width:820px){.app{display:block}.folders,.list,.reader{height:auto;min-height:33vh}.msg{grid-template-columns:1fr}.msg small{grid-column:1}}
    </style>
  </head>
  <body><div id="root" class="login"></div><script>
    const root=document.getElementById('root');let folder='INBOX',q='';
    async function api(url,options={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json','X-Rmail-Webmail':'1'},...options});if(!r.ok)throw new Error(await r.text()||r.statusText);return r.status===204?null:r.json()}
    function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
    async function load(){try{const s=await api('/api/session'),folders=await api('/api/folders'),msgs=await api('/api/folders/'+encodeURIComponent(folder)+'/messages?limit=100&q='+encodeURIComponent(q));root.className='app';root.innerHTML='<aside class="folders"><p class="muted">'+esc(s.address)+'</p>'+folders.map(f=>'<button class="'+(f.name===folder?'active':'')+'" data-folder="'+esc(f.name)+'"><span>'+esc(f.name)+'</span><small>'+(f.unread||f.messages)+'</small></button>').join('')+'</aside><main class="list"><div class="bar"><input id="q" placeholder="Search mail" value="'+esc(q)+'"><button id="refresh">Refresh</button></div><div>'+msgs.map(m=>'<button class="msg '+(m.flags.some(f=>f.toLowerCase()==='\\\\seen')?'':'unread')+'" data-uid="'+m.uid+'"><span>'+esc(m.from||'(unknown)')+'</span><span>'+esc(m.subject||'(no subject)')+'</span><small>'+esc(m.snippet)+'</small></button>').join('')+'</div></main><article class="reader" id="reader">Select a message</article>';document.querySelector('.folders').onclick=e=>{const b=e.target.closest('button[data-folder]');if(b){folder=b.dataset.folder;load()}};document.getElementById('refresh').onclick=()=>{q=document.getElementById('q').value;load()};document.getElementById('q').onkeydown=e=>{if(e.key==='Enter'){q=e.target.value;load()}};document.querySelector('.list').onclick=async e=>{const b=e.target.closest('button[data-uid]');if(!b)return;const m=await api('/api/folders/'+encodeURIComponent(folder)+'/messages/'+b.dataset.uid);const body=m.html_body?'<iframe class="html-message" sandbox="allow-popups allow-popups-to-escape-sandbox"></iframe>':'<pre>'+esc(m.text_body)+'</pre>';document.getElementById('reader').innerHTML='<div class="reader-actions"><button id="archive">Archive</button><button id="delete">Delete</button></div><h2>'+esc(m.subject||'(no subject)')+'</h2><p class="muted">From '+esc(m.from||'(unknown)')+' to '+esc(m.to||s.address)+'</p>'+body;if(m.html_body){document.querySelector('.html-message').srcdoc=m.html_body}window.currentUid=Number(b.dataset.uid);document.getElementById('archive').onclick=()=>bulk('archive');document.getElementById('delete').onclick=()=>bulk('delete')}}catch{login()}}
    async function bulk(action){if(!window.currentUid)return;await api('/api/folders/'+encodeURIComponent(folder)+'/messages/bulk',{method:'POST',body:JSON.stringify({action,uids:[window.currentUid]})});window.currentUid=null;load()}
    function login(){root.className='login';root.innerHTML='<form id="login"><h1>rMail</h1><input name="address" placeholder="Mailbox" autocomplete="username"><input name="password" placeholder="Password" type="password" autocomplete="current-password"><button>Sign in</button><p id="err"></p></form>';document.getElementById('login').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);try{await api('/api/login',{method:'POST',body:JSON.stringify({address:fd.get('address'),password:fd.get('password')})});load()}catch{document.getElementById('err').textContent='Invalid mailbox or password'}}}
    load();
  </script></body>
</html>"#;
