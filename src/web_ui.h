#pragma once
#include <Arduino.h>

static const char LOGIN_HTML[] PROGMEM = R"HTML(<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>OPi Console — вход</title>
<style>
body{margin:0;height:100vh;display:grid;place-items:center;background:#10141a;color:#d6e0ea;font:15px system-ui,sans-serif}
form{background:#1a212b;padding:24px;border-radius:10px;width:min(320px,90vw);display:flex;flex-direction:column;gap:10px}
input,button{font:inherit;padding:9px;border-radius:6px;border:1px solid #2c3744;background:#0c1117;color:#d6e0ea}
button{background:#3b9cff;border-color:#3b9cff;color:#fff;cursor:pointer}#e{color:#e5484d;min-height:1.2em}
</style></head><body>
<form id="f"><h3 style="margin:0">OPi Console</h3>
<input id="u" placeholder="Логин" autocomplete="username" autofocus>
<input id="p" type="password" placeholder="Пароль" autocomplete="current-password">
<button>Войти</button><div id="e"></div></form>
<script>
document.getElementById('f').onsubmit=async e=>{e.preventDefault();
const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
body:new URLSearchParams({user:u.value,pass:p.value})});let j={};try{j=await r.json()}catch(_){}
if(r.ok)location.reload();else document.getElementById('e').textContent=
j.error=='locked'?'Слишком много попыток, подождите '+j.wait+' с':'Неверный логин или пароль';};
</script></body></html>)HTML";

static const char APP_HTML[] PROGMEM = R"HTML(<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>OPi Console</title>
<link rel="stylesheet" href="/assets/xterm.css">
<style>
:root{--bg:#10141a;--fg:#d6e0ea;--mut:#7d8b99;--acc:#3b9cff;--bad:#e5484d;--ok:#3fb950;--card:#1a212b;--br:#2c3744}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif;display:flex;flex-direction:column}
header{display:flex;gap:6px;align-items:center;padding:8px;background:var(--card);flex-wrap:wrap}
header .sp{flex:1}
button,input,select,textarea{font:inherit;color:var(--fg);background:#0c1117;border:1px solid var(--br);border-radius:6px;padding:7px}
button{cursor:pointer;background:var(--card)}button.on,button.p{background:var(--acc);border-color:var(--acc);color:#fff}
button.d{border-color:var(--bad);color:var(--bad)}
#dot{width:10px;height:10px;border-radius:50%;background:var(--bad)}#dot.ok{background:var(--ok)}
#st{font-size:12px;color:var(--mut);padding:4px 8px}
main{flex:1;min-height:0;display:flex;flex-direction:column;padding:8px;gap:8px}
.term{flex:1;min-height:0;min-width:0;overflow:hidden;background:#000;border-radius:6px}
.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
#keys{display:flex;gap:4px;flex-wrap:wrap;align-items:center}
#keys button{min-width:36px;padding:7px 10px}
#txst{color:var(--mut);font-size:12px}
#adm{overflow:auto;flex:1}.card{background:var(--card);border-radius:8px;padding:10px;margin-bottom:10px}
.admin-page{max-width:980px;width:100%;margin:0 auto;padding:10px}
.admin-card{background:var(--card);border:1px solid var(--br);border-radius:10px;padding:16px;margin-bottom:12px}
.admin-card h2{font-size:17px;margin:0 0 5px}.admin-card p,.hint{color:var(--mut);margin:4px 0 12px}
.admin-card input,.admin-card select{max-width:100%}.profile-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:10px}
.profile-row{border:1px solid var(--br);border-radius:8px;padding:10px;display:grid;grid-template-columns:1fr 1fr;gap:8px}
.profile-row label{font-size:12px;color:var(--mut)}.profile-row input[type=text],.profile-row input[type=password]{width:100%;margin-top:4px}
.measurement-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.measurement{border:1px solid var(--br);border-radius:8px;padding:10px;color:var(--mut)}
.measurement strong{display:block;color:var(--fg);font-size:20px;margin-top:3px}
.profile-row .open{grid-column:1/-1;color:var(--mut);font-size:12px}.admin-table{overflow:auto}
.admin-table table{min-width:500px}.admin-table td{padding:5px;border-bottom:1px solid var(--br)}
.admin-card .msg{margin-top:8px}.msg.good{color:var(--ok)}
textarea{width:100%;height:150px;font-family:monospace}table{width:100%;border-collapse:collapse}td{padding:4px}
.ov{position:fixed;inset:0;background:#000c;display:none;place-items:center}.ov.s{display:grid}
.ov .card{width:min(340px,92vw);display:flex;flex-direction:column;gap:8px}.msg{color:var(--bad);min-height:1.2em}
</style></head><body>
<header>
<button class="tab on" id="b0">Pi #1</button><button class="tab" id="b1">Pi #2</button>
<button id="ba" style="display:none">Админ</button><span id="dot"></span><span class="sp"></span>
<span id="who" style="color:var(--mut)"></span><button id="bp">Пароль</button><button id="bo">Выход</button>
</header><div id="st"></div>
<main>
<div class="term" id="t0" aria-label="Терминал Pi #1"></div><div class="term" id="t1" style="display:none" aria-label="Терминал Pi #2"></div>
<div id="adm" style="display:none"></div>
<div id="ctl">
<div class="row" id="pw"><span style="color:var(--mut)">Питание:</span>
<button id="r_on">Вкл</button><button id="r_off">Выкл</button><button id="r_cy">Перезапуск</button><span id="rs"></span></div>
<div class="row" style="margin-top:6px"><div id="keys" aria-label="Клавиши терминала">
<button data-key="esc">Esc</button><button data-key="tab">Tab</button><button data-key="ctrl-c">Ctrl-C</button>
<button data-key="ctrl-d">Ctrl-D</button><button data-key="ctrl-z">Ctrl-Z</button>
<button data-key="enter">Enter</button><button data-key="backspace">⌫</button>
<button data-key="up" aria-label="Стрелка вверх">↑</button>
<button data-key="down" aria-label="Стрелка вниз">↓</button><button data-key="left" aria-label="Стрелка влево">←</button>
<button data-key="right" aria-label="Стрелка вправо">→</button>
<button data-key="pageup">PgUp</button><button data-key="pagedown">PgDn</button></div>
<span id="txst" role="status" aria-live="polite"></span></div></div>
</main>
<div class="ov" id="ovp"><form class="card" id="fp"><b id="pt">Смена пароля</b>
<input id="po" type="password" placeholder="Текущий пароль" autocomplete="current-password">
<input id="pn" type="password" placeholder="Новый пароль (мин. 5)" autocomplete="new-password">
<input id="pn2" type="password" placeholder="Повторите" autocomplete="new-password">
<div class="msg" id="pm"></div><div class="row"><button class="p">Сменить</button><button type="button" id="pc">Отмена</button></div></form></div>
<script src="/assets/xterm.js"></script>
<script src="/assets/addon-fit.js"></script>
<script>
const $=s=>document.querySelector(s);let me=null,cur=0,view='t',online=[false,false],rxSeq=[null,null],pollBusy=[false,false],rel=[1,1],terminalNames=['Pi #1','Pi #2'],voltageTimer=null;
const T=[null,null],txPending=['',''],txBusy=[false,false];
async function api(u,d){let r;try{r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(d||{})})}
catch(e){return{ok:false,j:{error:'Сетевая ошибка: '+e.message}}}
let j={};try{j=await r.json()}catch(_){}if(r.status==401)location.reload();return{ok:r.ok,j}}
const keySeq={esc:'\x1b',tab:'\t','ctrl-c':'\x03','ctrl-d':'\x04','ctrl-z':'\x1a',enter:'\r',
backspace:'\x7f',up:'\x1b[A',down:'\x1b[B',left:'\x1b[D',right:'\x1b[C',
pageup:'\x1b[5~',pagedown:'\x1b[6~'};
function initTerminal(i,readOnly){const term=new Terminal({scrollback:2000,cursorBlink:true,disableStdin:readOnly,
fontFamily:'ui-monospace,Menlo,Consolas,monospace',fontSize:13,theme:{background:'#000000',foreground:'#cfe8e8'}});
const fit=new FitAddon.FitAddon();term.loadAddon(fit);term.open($('#t'+i));fit.fit();
term.onData(data=>sendInput(i,data));T[i]=term;T[i].fit=fit}
function applyTerminalNames(names){if(!Array.isArray(names)||names.length!=2)return;
terminalNames=names.map((n,i)=>String(n||('Pi #'+(i+1))));
for(let i=0;i<2;i++){$('#b'+i).textContent=terminalNames[i];$('#t'+i).setAttribute('aria-label','Терминал '+terminalNames[i])}
if(view=='t'&&!online[cur])$('#txst').textContent='Нет соединения с '+terminalNames[cur]}
function fitTerminal(i){if(T[i]&&$('#t'+i).clientWidth>0){T[i].fit.fit();T[i].focus()}}
function ind(){const ok=online[cur];$('#dot').className=ok?'ok':''}
function updateLink(i){online[i]=true;if(i==cur){ind();const s=$('#txst').textContent;
if(s.startsWith('Нет соединения')||s.startsWith('Ошибка связи:'))$('#txst').textContent=''}}
async function poll(i){if(pollBusy[i])return;pollBusy[i]=true;
try{const u='/api/uart/read?idx='+i+(rxSeq[i]===null?'':'&since='+encodeURIComponent(rxSeq[i]));
const r=await fetch(u,{cache:'no-store'});if(r.status==401){location.reload();return}
if(!r.ok)throw Error('HTTP '+r.status);const j=await r.json();rxSeq[i]=j.seq;updateLink(i);
if(j.data&&T[i]){const b=new Uint8Array(j.data.length/2);for(let n=0;n<b.length;n++)b[n]=parseInt(j.data.slice(n*2,n*2+2),16);T[i].write(b)}
}catch(e){online[i]=false;if(i==cur){ind();$('#txst').textContent='Ошибка связи: '+e.message}}
finally{pollBusy[i]=false}}
async function postInput(i,data){const r=await fetch('/api/uart/send',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
body:new URLSearchParams({idx:i,data})});if(r.status==401){location.reload();throw Error('Сессия истекла')}
const j=await r.json();if(!r.ok)throw Error(j.error||('HTTP '+r.status))}
function sendInput(i,data){txPending[i]+=data;if(!txBusy[i]){txBusy[i]=true;setTimeout(()=>flushInput(i),15)}}
async function flushInput(i){const pending=txPending[i];if(!pending){txBusy[i]=false;return}
let batch='',bytes=0;for(const char of pending){const size=new TextEncoder().encode(char).length;
if(bytes+size>200)break;batch+=char;bytes+=size}
txPending[i]=pending.slice(batch.length);
try{await postInput(i,batch)}catch(e){if(i==cur)$('#txst').textContent='Ошибка отправки: '+e.message}
if(txPending[i])setTimeout(()=>flushInput(i),0);else txBusy[i]=false}
function show(v,i){view=v;if(i!==undefined)cur=i;
for(let k=0;k<2;k++)$('#t'+k).style.display=(v=='t'&&cur==k)?'':'none';
$('#adm').style.display=v=='a'?'':'none';$('#ctl').style.display=v=='t'?'':'none';
$('#b0').className='tab'+(v=='t'&&cur==0?' on':'');$('#b1').className='tab'+(v=='t'&&cur==1?' on':'');
$('#ba').className=v=='a'?'on':'';fitTerminal(cur);ind();relUi();
if(v=='t'&&!online[cur])$('#txst').textContent='Нет соединения с '+terminalNames[cur];
else $('#txst').textContent='';
if(v=='a')admin()}
function relUi(){$('#rs').textContent=rel[cur]?'● включено':'○ выключено';$('#rs').style.color=rel[cur]?'var(--ok)':'var(--mut)'}
async function stat(){try{const j=await (await fetch('/api/status')).json();rel=j.relays;
applyTerminalNames(j.terminals);
$('#st').textContent=j.ip+' · '+j.mode+(j.mode=='STA'?' '+j.rssi+' dBm':'')+' · VPN: '+j.vpn+(j.vpnIp?' '+j.vpnIp:'')+' · сессий: '+j.sessions;relUi()}catch(_){}}
function pwdlg(must){$('#ovp').classList.add('s');$('#pc').style.display=must?'none':'';$('#pm').textContent='';
$('#pt').textContent=must?'Необходимо сменить пароль':'Смена пароля'}
$('#fp').onsubmit=async e=>{e.preventDefault();if($('#pn').value!=$('#pn2').value){$('#pm').textContent='Пароли не совпадают';return}
const r=await api('/api/passwd',{old:$('#po').value,new:$('#pn').value});
if(r.ok)location.reload();else $('#pm').textContent=r.j.error||'Ошибка'};
$('#pc').onclick=()=>$('#ovp').classList.remove('s');$('#bp').onclick=()=>pwdlg(false);
$('#bo').onclick=async()=>{await api('/api/logout');location.reload()};
$('#b0').onclick=()=>show('t',0);$('#b1').onclick=()=>show('t',1);$('#ba').onclick=()=>show('a');
$('#keys').onclick=e=>{const key=e.target.closest('button[data-key]');if(key)sendInput(cur,keySeq[key.dataset.key])};
window.addEventListener('resize',()=>fitTerminal(cur));
for(const [id,a] of [['r_on','on'],['r_off','off'],['r_cy','cycle']])$('#'+id).onclick=async()=>{
if(a!='on'&&!confirm('Изменить питание '+terminalNames[cur]+'?'))return;await api('/api/relay',{idx:cur,act:a});stat()};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function admin(){
if(voltageTimer){clearInterval(voltageTimer);voltageTimer=null}
const a=$('#adm');a.innerHTML='<div class="admin-page"><p>Загрузка настроек…</p></div>';
try{
const responses=await Promise.all(['/api/users','/api/vpn','/api/wifi/profiles','/api/uart','/api/terminals'].map(u=>fetch(u)));
if(responses.some(r=>!r.ok))throw new Error('Не удалось загрузить настройки (HTTP '+responses.find(r=>!r.ok).status+')');
const [us,v,wifi,uart,terminals]=await Promise.all(responses.map(r=>r.json()));
applyTerminalNames(terminals.names);
let h='<div class="admin-page"><h1 style="font-size:21px;margin:4px 0 12px">Управление устройством</h1>';
h+='<section class="admin-card"><h2>Напряжение и ток</h2><p>Текущие измерения ADC, обновляются каждую секунду.</p><div class="measurement-grid">'+
'<div class="measurement">Напряжение 1<strong id="voltage-v1">—</strong></div>'+
'<div class="measurement">Напряжение 2<strong id="voltage-v2">—</strong></div>'+
'<div class="measurement">Ток<strong id="voltage-current">—</strong></div>'+
'</div><div class="hint" id="voltage-status" role="status">Загрузка измерений…</div></section>';
h+='<section class="admin-card"><h2>Пользователи</h2><p>Роли и пароли учётных записей веб-консоли.</p><div class="admin-table"><table>';
for(const u of us)h+=`<tr data-n="${esc(u.name)}"><td>${esc(u.name)}</td><td><select>${['ro','rw','admin'].map(r=>`<option${r==u.role?' selected':''}>${r}</option>`).join('')}</select></td>
<td><input placeholder="Новый пароль" type="password" autocomplete="new-password" style="width:150px"></td><td><button class="sv">Сохранить</button> <button class="d dl">Удалить</button></td></tr>`;
h+=`</table></div><div class="row" style="margin-top:10px"><input id="nn" placeholder="Логин" maxlength="16"><input id="np" type="password" placeholder="Пароль" autocomplete="new-password">
<select id="nr"><option>ro</option><option selected>rw</option><option>admin</option></select><button id="na">Добавить</button></div><div class="msg" id="um" role="status"></div></section>`;
h+=`<section class="admin-card"><h2>Имена терминалов</h2><p>Задайте имена, которые будут показаны на вкладках, в OLED и в сообщениях веб-консоли.</p>
<div class="profile-list"><label>${esc(terminalNames[0])}<input id="term-name-0" type="text" maxlength="24" value="${esc(terminalNames[0])}"></label>
<label>${esc(terminalNames[1])}<input id="term-name-1" type="text" maxlength="24" value="${esc(terminalNames[1])}"></label></div>
<div class="row" style="margin-top:10px"><button class="p" id="term-names-save">Сохранить имена</button></div>
<div class="msg" id="term-names-msg" role="status"></div></section>`;
h+=`<section class="admin-card"><h2>UART</h2><p>Настройки последовательного порта задаются отдельно для каждой платы. После сохранения устройство перезагрузится.</p><div class="profile-list">`;
for(let i=0;i<2;i++){const s=uart[i]||{baud:115200,bits:8,parity:'N',stop:1};
h+=`<div class="profile-row uart-row" data-idx="${i}"><strong>Pi #${i+1}</strong><span></span>
<label>Скорость (бод)<input class="uart-baud" type="number" min="300" max="2000000" step="1" value="${s.baud}"></label>
<label>Биты данных<select class="uart-bits">${[5,6,7,8].map(n=>`<option value="${n}"${n==s.bits?' selected':''}>${n}</option>`).join('')}</select></label>
<label>Чётность<select class="uart-parity">${[['N','Нет'],['E','Чётная'],['O','Нечётная']].map(([v,n])=>`<option value="${v}"${v==s.parity?' selected':''}>${n}</option>`).join('')}</select></label>
<label>Стоп-биты<select class="uart-stop">${[1,2].map(n=>`<option value="${n}"${n==s.stop?' selected':''}>${n}</option>`).join('')}</select></label>
<div class="row"><button class="p uart-save" data-idx="${i}">Сохранить UART Pi #${i+1}</button></div>
<div class="msg uart-msg" data-idx="${i}" role="status"></div></div>`}
h+=`</div></section>`;
h+=`<section class="admin-card"><h2>Wi-Fi</h2><p>Устройство перебирает сохранённые сети по порядку. Можно указать до пяти; пустые строки будут удалены. Пароль не показывается: пустое поле сохраняет прежний пароль для той же сети.</p>
<div class="profile-list wifi-list">`;
for(let i=0;i<5;i++){const p=wifi[i]||{ssid:'',hasPassword:false};const has=!!p.hasPassword;
h+=`<div class="profile-row"><label>Сеть ${i+1}<input class="ssid" type="text" maxlength="32" value="${esc(p.ssid)}" autocomplete="off"></label>
<label>Пароль<input class="password" type="password" maxlength="63" autocomplete="new-password" placeholder="${has?'Пусто — оставить сохранённый':'Пароль сети'}"></label>
<label class="open"><input class="is-open" type="checkbox"${!has&&p.ssid?' checked':''}> Открытая сеть (без пароля)</label></div>`}
h+=`</div><div class="row" style="margin-top:12px"><button class="p" id="wsv">Сохранить Wi-Fi</button></div><div class="msg" id="wmsg" role="status"></div></section>`;
h+=`<section class="admin-card"><h2>WireGuard — до 3 отдельных туннелей</h2><p>Загрузите отдельный wg.conf для каждого соединения. PresharedKey поддерживается. Маршруты берутся из AllowedIPs; используется самый специфичный маршрут, остальной трафик идёт через обычный Wi-Fi-шлюз. Не указывайте один и тот же маршрут в нескольких туннелях.</p>`;
const tunnels=v.tunnels||[];
for(let i=0;i<3;i++){const t=tunnels[i]||{configured:false,state:'off'};
h+=`<div class="admin-card" style="margin-top:10px"><h3 style="margin:0 0 8px">Туннель ${i+1}</h3>
<p>${t.configured?`Состояние: ${esc(t.state)}${t.ip?' ('+esc(t.ip)+')':''}<br>Адрес: ${esc(t.address)} · Endpoint: ${esc(t.endpoint)}<br>AllowedIPs: ${esc(t.allowed)} · Keepalive: ${t.keepalive} с<br>Peer PublicKey: ${esc(t.publicKey)}<br>PresharedKey: ${t.hasPresharedKey?'задан (не показывается)':'не задан'}`:'Конфигурация отсутствует'}</p>
<textarea class="wg-config" data-idx="${i}" placeholder="Вставьте wg-quick конфигурацию…" spellcheck="false"></textarea>
<div class="row"><input type="file" class="wg-file" data-idx="${i}" accept=".conf,text/plain"><button class="p wg-save" data-idx="${i}">Сохранить и подключить</button>
<button class="d wg-delete" data-idx="${i}"${t.configured?'':' disabled'}>Удалить туннель</button></div>
<div class="msg wg-msg" data-idx="${i}" role="status"></div></div>`}
h+='</section></div>';
a.innerHTML=h;
const refreshVoltage=async()=>{
try{
const response=await fetch('/api/voltage',{cache:'no-store'});
if(!response.ok)throw new Error('HTTP '+response.status);
const data=await response.json();
const v1=data.channels[0],v2=data.channels[1],current=data.shunt;
$('#voltage-v1').textContent=v1.valid?Number(v1.voltage).toFixed(3)+' В':'—';
$('#voltage-v2').textContent=v2.valid?Number(v2.voltage).toFixed(3)+' В':'—';
$('#voltage-current').textContent=current.valid?Number(current.current_amps).toFixed(3)+' А':'—';
$('#voltage-status').textContent=[v1.valid,v2.valid,current.valid].every(Boolean)
?'Усреднение: 64 отсчёта на канал.'
:'Ожидание первых 64 отсчётов измерения.';
}catch(e){$('#voltage-status').textContent='Ошибка чтения измерений: '+e.message}
};
refreshVoltage();voltageTimer=setInterval(()=>{if(view=='a')refreshVoltage()},1000);
a.querySelectorAll('tr[data-n]').forEach(tr=>{const n=tr.dataset.n;
tr.querySelector('.sv').onclick=async()=>{const r=await api('/api/users/set',{name:n,role:tr.querySelector('select').value,pass:tr.querySelector('input').value});$('#um').textContent=r.ok?'Сохранено':(r.j.error||'Ошибка сохранения');$('#um').className='msg'+(r.ok?' good':'');if(r.ok)admin()};
tr.querySelector('.dl').onclick=async()=>{if(!confirm('Удалить пользователя '+n+'?'))return;const r=await api('/api/users/del',{name:n});if(r.ok)admin();else $('#um').textContent=r.j.error||'Ошибка удаления'}});
$('#na').onclick=async()=>{const r=await api('/api/users/add',{name:$('#nn').value,pass:$('#np').value,role:$('#nr').value});if(r.ok)admin();else $('#um').textContent=r.j.error||'Ошибка добавления'};
$('#term-names-save').onclick=async()=>{
const button=$('#term-names-save'),msg=$('#term-names-msg');button.disabled=true;
const r=await api('/api/terminals',{name0:$('#term-name-0').value,name1:$('#term-name-1').value});
msg.textContent=r.ok?'Имена сохранены.':(r.j.error||'Не удалось сохранить имена');
msg.className='msg'+(r.ok?' good':'');
if(r.ok)applyTerminalNames(r.j.names);
button.disabled=false};
a.querySelectorAll('.wifi-list .profile-row').forEach(row=>{const open=row.querySelector('.is-open'),pass=row.querySelector('.password');
open.onchange=()=>{if(open.checked)pass.value='';pass.disabled=open.checked}});
a.querySelectorAll('.wifi-list .is-open').forEach(c=>{if(c.checked)c.closest('.profile-row').querySelector('.password').disabled=true});
a.querySelectorAll('.uart-save').forEach(button=>button.onclick=async()=>{
const idx=button.dataset.idx,row=a.querySelector(`.uart-row[data-idx="${idx}"]`),msg=a.querySelector(`.uart-msg[data-idx="${idx}"]`);
const baud=row.querySelector('.uart-baud').value;
if(!baud||Number(baud)<300||Number(baud)>2000000){msg.textContent='Скорость должна быть от 300 до 2000000 бод';msg.className='msg';return}
button.disabled=true;
const r=await api('/api/uart',{idx,baud,bits:row.querySelector('.uart-bits').value,
parity:row.querySelector('.uart-parity').value,stop:row.querySelector('.uart-stop').value});
msg.textContent=r.ok?'Сохранено. Устройство перезагрузится для применения настроек.':(r.j.error||'Ошибка сохранения');
msg.className='msg'+(r.ok?' good':'');button.disabled=false});
$('#wsv').onclick=async()=>{const data={};a.querySelectorAll('.wifi-list .profile-row').forEach((row,i)=>{data['ssid'+i]=row.querySelector('.ssid').value;data['password'+i]=row.querySelector('.password').value;if(row.querySelector('.is-open').checked)data['open'+i]='1'});
const btn=$('#wsv'),msg=$('#wmsg');btn.disabled=true;
try{const r=await api('/api/wifi/profiles',data);msg.textContent=r.ok?'Сохранено. Устройство перезагрузится и подключится по списку сетей.':(r.j.error||'Ошибка сохранения');msg.className='msg'+(r.ok?' good':'')}
catch(e){msg.textContent='Ошибка сохранения: '+e.message;msg.className='msg'}finally{btn.disabled=false}};
a.querySelectorAll('.wg-file').forEach(input=>input.onchange=async e=>{const file=e.target.files[0];if(!file)return;
const idx=e.target.dataset.idx;a.querySelector(`.wg-config[data-idx="${idx}"]`).value=await file.text()});
a.querySelectorAll('.wg-save').forEach(button=>button.onclick=async()=>{const idx=button.dataset.idx,textarea=a.querySelector(`.wg-config[data-idx="${idx}"]`),msg=a.querySelector(`.wg-msg[data-idx="${idx}"]`);
button.disabled=true;let response,json={};try{response=await fetch('/api/vpn?idx='+idx,{method:'POST',headers:{'Content-Type':'text/plain'},body:textarea.value});try{json=await response.json()}catch(_){}}
catch(e){msg.textContent='Ошибка сети: '+e.message;msg.className='msg';button.disabled=false;return}
msg.textContent=response.ok?'Сохранено. Туннель подключается; состояние обновится после повторной загрузки админки.':(json.error||'Ошибка сохранения');
msg.className='msg'+(response.ok?' good':'');button.disabled=false;
if(response.ok)a.querySelector(`.wg-delete[data-idx="${idx}"]`).disabled=false});
a.querySelectorAll('.wg-delete').forEach(button=>button.onclick=async()=>{const idx=button.dataset.idx;
if(!confirm('Остановить и удалить туннель '+(Number(idx)+1)+'?'))return;
const msg=a.querySelector(`.wg-msg[data-idx="${idx}"]`);button.disabled=true;
const r=await api('/api/vpn/delete',{idx});
msg.textContent=r.ok?'Туннель остановлен, конфигурация удалена.':(r.j.error||'Не удалось удалить туннель');
msg.className='msg'+(r.ok?' good':'');
if(r.ok)setTimeout(()=>admin(),1000);else button.disabled=false});
}catch(e){a.innerHTML='<div class="admin-page"><div class="admin-card"><h2>Ошибка загрузки</h2><p>'+esc(e.message||'Не удалось загрузить настройки')+'</p><button onclick="admin()">Повторить</button></div></div>'}
}
(async()=>{const r=await fetch('/api/me');if(!r.ok){location.reload();return}me=await r.json();
$('#who').textContent=me.user+' ('+me.role+')';if(me.role=='admin')$('#ba').style.display='';
if(me.role=='ro'){$('#keys').style.display='none';$('#pw').style.display='none'}
if(me.must){pwdlg(true);return}
initTerminal(0,me.role=='ro');initTerminal(1,me.role=='ro');show('t',0);poll(0);poll(1);stat();setInterval(()=>{poll(0);poll(1)},150);setInterval(stat,3000)})();
</script></body></html>)HTML";
