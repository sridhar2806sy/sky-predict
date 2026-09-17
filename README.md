# sky-predict
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const port = Number(process.env.PORT || 3000);
const root = path.join(__dirname, 'public');
const dataDir = path.join(__dirname, 'data');
const usersPath = path.join(dataDir, 'users.json');
const sessions = new Map();
fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(usersPath)) fs.writeFileSync(usersPath, '[]', { mode: 0o600 });

function users() { return JSON.parse(fs.readFileSync(usersPath, 'utf8')); }
function saveUsers(value) { fs.writeFileSync(usersPath, JSON.stringify(value, null, 2), { mode: 0o600 }); }
function hash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function safeEqual(a, b) { return a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(x => { const i = x.indexOf('='); return [x.slice(0, i).trim(), decodeURIComponent(x.slice(i + 1))]; }));
}
function session(req) { const id = parseCookies(req).sp_session; return id && sessions.get(id); }
function json(res, status, body, headers = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers }); res.end(JSON.stringify(body)); }
function body(req) { return new Promise((resolve, reject) => { let raw = ''; req.on('data', d => raw += d); req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { reject(Error('Invalid request')); } }); }); }
function newSession(res, user) {
  const id = crypto.randomBytes(32).toString('base64url');
  sessions.set(id, { email: user.email, createdAt: Date.now() });
  res.setHeader('Set-Cookie', `sp_session=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`);
}
function requireUser(req, res) { const user = session(req); if (!user) { json(res, 401, { error: 'Please sign in.' }); return null; } return user; }
function dateInRange(date) {
  const day = new Date(`${date}T00:00:00Z`).getTime();
  const today = new Date(); today.setUTCHours(0, 0, 0, 0);
  return Number.isFinite(day) && day >= today.getTime() && day <= today.getTime() + 16 * 86400000;
}

async function weather(req, res, url) {
  if (!requireUser(req, res)) return;
  const place = (url.searchParams.get('place') || '').trim();
  const date = url.searchParams.get('date');
  if (place.length < 2 || !dateInRange(date)) return json(res, 400, { error: 'Choose an Indian location and a date within the next 16 days.' });
  const geo = await fetch(`https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(place)}&count=20&language=en&format=json`);
  const locations = (await geo.json()).results || [];
  const location = locations.find(x => x.country_code === 'IN');
  if (!location) return json(res, 404, { error: 'No Indian district or town matched that search.' });
  const q = new URLSearchParams({ latitude: location.latitude, longitude: location.longitude, timezone: 'Asia/Kolkata', start_date: date, end_date: date, hourly: 'temperature_2m,relative_humidity_2m,precipitation_probability,precipitation,weather_code,wind_speed_10m' });
  const forecast = await fetch(`https://api.open-meteo.com/v1/forecast?${q}`);
  const data = await forecast.json();
  if (!data.hourly) return json(res, 502, { error: 'Weather provider returned no hourly forecast.' });
  json(res, 200, { location: { name: location.name, state: location.admin1 || '', district: location.admin2 || '' }, hourly: data.hourly });
}

async function locations(req, res, url) {
  if (!requireUser(req, res)) return;
  const query = (url.searchParams.get('q') || '').trim();
  if (query.length < 1) return json(res, 200, { results: [] });
  const response = await fetch(`https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(query)}&count=100&language=en&format=json`);
  const results = ((await response.json()).results || []).filter(x => x.country_code === 'IN').slice(0, 100)
    .map(x => ({ label: `${x.name}${x.admin1 ? `, ${x.admin1}` : ''}${x.admin2 ? ` · ${x.admin2}` : ''}`, value: `${x.name}${x.admin1 ? `, ${x.admin1}` : ''}` }));
  json(res, 200, { results });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === 'POST' && (url.pathname === '/api/auth/signup' || url.pathname === '/api/auth/signin')) {
      const { email = '', password = '' } = await body(req);
      const normalized = String(email).trim().toLowerCase();
      if (!/^\S+@\S+\.\S+$/.test(normalized) || String(password).length < 8) return json(res, 400, { error: 'Use a valid email and a password of at least 8 characters.' });
      const list = users(); let user = list.find(u => u.email === normalized);
      if (url.pathname.endsWith('signup')) {
        if (user) return json(res, 409, { error: 'An account already exists for this email.' });
        user = { email: normalized, ...hash(String(password)), createdAt: new Date().toISOString() };
        list.push(user); saveUsers(list);
      } else if (!user || !safeEqual(hash(String(password), user.salt).hash, user.hash)) return json(res, 401, { error: 'Email or password is incorrect.' });
      newSession(res, user); return json(res, 200, { email: user.email });
    }
    if (req.method === 'POST' && url.pathname === '/api/auth/logout') { const id = parseCookies(req).sp_session; sessions.delete(id); return json(res, 200, { ok: true }, { 'Set-Cookie': 'sp_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' }); }
    if (req.method === 'GET' && url.pathname === '/api/auth/me') { const user = session(req); return user ? json(res, 200, user) : json(res, 401, { error: 'Not signed in' }); }
    if (req.method === 'GET' && url.pathname === '/api/weather') return await weather(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/locations') return await locations(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/auth/google') return json(res, 501, { error: 'Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, then add the OAuth callback route.' });
    const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const resolved = path.resolve(root, file);
    if (!resolved.startsWith(root) || !fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html; charset=utf-8', 'x-content-type-options': 'nosniff' });
    fs.createReadStream(resolved).pipe(res);
  } catch (error) { console.error(error); json(res, 500, { error: 'Server error. Try again.' }); }
});
server.listen(port, () => console.log(`Sky Predict is running at http://localhost:${port}`));
{
  "name": "sky-predict",
  "version": "1.0.0",
  "private": true,
  "description": "India district weather dashboard",
  "engines": {
    "node": ">=20"
  },
  "scripts": {
    "start": "node server.js"
  }
}
services:
  - type: web
    name: sky-predict
    runtime: node
    buildCommand: npm install
    startCommand: npm start
    healthCheckPath: /
    envVars:
      - key: NODE_VERSION
        value: 20
# Sky Predict

## Run locally

Run `npm start`, then open `http://localhost:3000`.

## Publish to the web

1. Create a GitHub repository and upload this `sky-predict` folder.
2. In Render, create a new **Blueprint** from that repository. It will use `render.yaml`.
3. After deployment, use Render's public HTTPS address.

## Important security notes

The website has server-side password hashing and HTTP-only session cookies. Before public launch, replace the local `data/users.json` file with a persistent database, add rate limiting, email verification, CSRF protection, password reset, and a managed authentication service.

Google sign-in needs a Google OAuth client ID and secret registered for the final public HTTPS domain. The project intentionally includes no fake credentials.
data/users.json
.env
node_modules/
const $=id=>document.getElementById(id),codes={0:['Clear sky','☀️'],1:['Mainly clear','🌤️'],2:['Partly cloudy','⛅'],3:['Overcast','☁️'],45:['Fog','🌫️'],51:['Drizzle','🌦️'],61:['Light rain','🌦️'],63:['Rain','🌧️'],65:['Heavy rain','🌧️'],71:['Snow','❄️'],80:['Showers','🌧️'],81:['Showers','🌧️'],82:['Heavy showers','⛈️'],95:['Thunderstorm','⛈️']};let signup=false,timer;const condition=x=>codes[x]||['Changing conditions','🌡️'];
function date(){return `${$('year').value}-${String(+$('month').value+1).padStart(2,'0')}-${String($('day').value).padStart(2,'0')}`}function calendar(){let now=new Date();for(let x=1;x<=31;x++)$('day').add(new Option(x,x));for(let x=0;x<12;x++)$('month').add(new Option(new Date(2026,x,1).toLocaleString('en',{month:'short'}),x));for(let x=2026;x<=2075;x++)$('year').add(new Option(x,x));$('day').value=now.getDate();$('month').value=now.getMonth();$('year').value=Math.max(2026,now.getFullYear())}calendar();
function graph(h){let s=$('graph'),w=640,H=190,left=42,right=18,top=28,bottom=34,t=h.temperature_2m,r=h.precipitation_probability,min=Math.floor(Math.min(...t)-2),max=Math.ceil(Math.max(...t)+2),x=i=>left+i*(w-left-right)/23,y=v=>H-bottom-(v-min)*(H-top-bottom)/(max-min||1),points=t.map((v,i)=>`${x(i)},${y(v)}`).join(' '),area=`${left},${H-bottom} ${points} ${x(23)},${H-bottom}`,grid=[0,.25,.5,.75,1].map(q=>{let yy=top+q*(H-top-bottom),value=Math.round(max-q*(max-min));return `<line x1="${left}" y1="${yy}" x2="${w-right}" y2="${yy}" stroke="#e1eaf2"/><text x="${left-9}" y="${yy+4}" text-anchor="end" fill="#66788d" font-size="11">${value}°</text>`}).join(''),bars=r.map((v,i)=>{let bh=v*.42;return `<rect x="${x(i)-4}" y="${H-bottom-bh}" width="8" height="${bh}" rx="3" fill="#1976c7" opacity=".20"/>`}).join(''),dots=t.map((v,i)=>i%3===0?`<circle cx="${x(i)}" cy="${y(v)}" r="3.5" fill="#fff" stroke="#e87a2b" stroke-width="2"/>`:'' ).join(''),labels=[0,6,12,18,23].map(i=>`<text x="${x(i)}" y="${H-10}" text-anchor="middle" fill="#66788d" font-size="11">${String(i).padStart(2,'0')}:00</text>`).join('');s.setAttribute('viewBox',`0 0 ${w} ${H}`);s.innerHTML=`<defs><linearGradient id="tempFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#e87a2b" stop-opacity=".24"/><stop offset="1" stop-color="#e87a2b" stop-opacity="0"/></linearGradient></defs><text x="${left}" y="14" fill="#66788d" font-size="11">Temperature</text><text x="${w-right}" y="14" text-anchor="end" fill="#66788d" font-size="11">Rain probability</text>${grid}${bars}<polygon points="${area}" fill="url(#tempFill)"/><polyline points="${points}" fill="none" stroke="#e87a2b" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>${dots}<line x1="${left}" y1="${H-bottom}" x2="${w-right}" y2="${H-bottom}" stroke="#c9d8e5"/>${labels}`}
async function suggestions(){let q=$('place').value.trim();if(!q)return;try{let r=await fetch('https://geocoding-api.open-meteo.com/v1/search?name='+encodeURIComponent(q)+'&count=100&language=en&format=json'),j=await r.json(),results=(j.results||[]).filter(x=>x.country_code==='IN').slice(0,100),list=$('districts');list.innerHTML='';results.forEach(x=>{let o=document.createElement('option');o.value=x.name+(x.admin1?', '+x.admin1:'');o.label=o.value+(x.admin2?' · '+x.admin2:'');list.append(o)});$('status').textContent=results.length?`${results.length} India locations match “${q}”. Select one or keep typing.`:'No India locations match that search.'}catch{$('status').textContent='District suggestions need an internet connection.'}}
async function report(){let place=$('place').value.trim(),chosen=date(),today=new Date();today.setHours(0,0,0,0);let target=new Date(chosen+'T00:00:00');if(target<today||target-today>16*864e5){$('status').textContent='Daily weather forecasts are only available for today through the next 16 days. A date such as 2050 or 2075 needs climate-projection data, not a daily forecast.';return}if(!place)return;$('status').textContent='Loading live weather report…';try{let r=await fetch(`/api/weather?place=${encodeURIComponent(place)}&date=${chosen}`),j=await r.json();if(!r.ok)throw Error(j.error);let h=j.hourly,i=chosen===new Date().toISOString().slice(0,10)?new Date().getHours():12,c=condition(h.weather_code[i]);$('location').textContent=j.location.name+(j.location.state?' · '+j.location.state:'');$('temp').textContent=Math.round(h.temperature_2m[i])+'°C';$('condition').textContent=c[1]+' '+c[0];$('rain').textContent=h.precipitation_probability[i]+'%';$('wind').textContent=Math.round(h.wind_speed_10m[i])+' km/h';$('humidity').textContent=h.relative_humidity_2m[i]+'%';$('hours').innerHTML='';h.time.forEach((_,k)=>{let c=condition(h.weather_code[k]),e=document.createElement('div');e.className='hour '+(h.precipitation_probability[k]>=35?'rain':'');e.innerHTML=`<time>${String(k).padStart(2,'0')}:00</time><b>${c[1]} ${Math.round(h.temperature_2m[k])}°</b><span>${h.precipitation_probability[k]}% rain</span>`;$('hours').append(e)});graph(h);$('status').textContent='Updated live forecast for '+$('location').textContent}catch(e){$('status').textContent=e.message}}
function enter(user){$('user').textContent=user.email;$('auth').classList.add('hidden');$('app').classList.remove('hidden');report()}async function auth(){let r=await fetch('/api/auth/'+(signup?'signup':'signin'),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:$('email').value,password:$('password').value})}),j=await r.json();if(!r.ok)return $('authMsg').textContent=j.error;enter(j)}function toggle(){signup=!signup;$('title').textContent=signup?'Create secure account':'Sign in securely';$('submit').textContent=signup?'Create account':'Sign in';$('switch').innerHTML=signup?'Already have an account? <button class="link" id="toggle">Sign in</button>':'New here? <button class="link" id="toggle">Create account</button>';$('toggle').onclick=toggle}$('place').oninput=()=>{clearTimeout(timer);timer=setTimeout(suggestions,250)};$('submit').onclick=auth;$('toggle').onclick=toggle;$('google').onclick=async()=>{let r=await fetch('/api/auth/google'),j=await r.json();$('authMsg').textContent=j.error};$('load').onclick=report;$('logout').onclick=async()=>{await fetch('/api/auth/logout',{method:'POST'});location.reload()};fetch('/api/auth/me').then(r=>r.ok?r.json():null).then(x=>x&&enter(x));
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sky Predict</title><style>
:root{--n:#0b2946;--b:#1976c7;--bg:#f4f8fb;--p:#fff;--i:#122740;--m:#66788d;--l:#dae3ec;--o:#e87a2b}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--i);font:15px/1.45 system-ui}.hidden{display:none!important}.auth{min-height:100vh;display:grid;place-items:center;padding:20px;background:linear-gradient(135deg,#092845,#1a70b7)}.box{width:min(430px,100%);background:#fff;padding:32px;border-radius:18px;box-shadow:0 25px 65px #00172d90}.logo{font-weight:850;font-size:23px;color:var(--n)}.logo span{color:var(--b)}h1{font-size:29px;line-height:1.14;margin:23px 0 8px}.muted{color:var(--m)}label{display:block;font-size:12px;font-weight:750;margin:17px 0 6px}input,select,button{font:inherit}input,select{width:100%;padding:11px;border:1px solid var(--l);border-radius:8px}button{cursor:pointer;border:0;border-radius:8px;padding:11px 14px;font-weight:750}.primary{width:100%;margin-top:21px;background:var(--b);color:#fff}.google{width:100%;margin-top:9px;background:#fff;border:1px solid var(--l);color:var(--i)}.switch{text-align:center;font-size:13px}.link{background:none;color:var(--b);padding:0}.notice{background:#eaf5ff;border-radius:8px;padding:10px;font-size:12px;margin-top:15px}.nav{background:var(--n);color:#fff;padding:15px max(20px,calc((100vw - 1160px)/2));display:flex;justify-content:space-between}.nav .logo{color:#fff}.nav .logo span{color:#9ed8ff}.nav button{background:#ffffff20;color:#fff;padding:7px 11px}.shell{max-width:1200px;margin:auto;padding:25px 20px 45px}.heading h1{margin:0}.lookup,.card{background:var(--p);border:1px solid var(--l);border-radius:14px}.lookup{padding:17px;display:grid;grid-template-columns:2fr 1.25fr auto;gap:12px;align-items:end;margin-top:19px}.date{display:grid;grid-template-columns:1fr 1.25fr 1fr;gap:5px}.hint,.status{font-size:13px;color:var(--m);margin:8px 2px}.search{background:var(--b);color:#fff}.grid{display:grid;grid-template-columns:1fr 2fr;gap:16px}.card{padding:19px}.eyebrow{color:var(--m);font-size:12px;font-weight:750;text-transform:uppercase;letter-spacing:.08em}.temp{font-size:48px;font-weight:850;letter-spacing:-2px}.condition{font-weight:750;font-size:17px}.facts{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:16px}.fact{background:#edf6fd;padding:9px;border-radius:8px}.fact small{display:block;color:var(--m)}.hours{display:grid;grid-template-columns:repeat(6,1fr);gap:7px;margin-top:14px}.hour{padding:7px;border-left:3px solid var(--b);background:#f7fafc;font-size:12px}.hour.rain{border-color:var(--o)}.hour b,.hour time{display:block}.hour time{color:var(--m)}svg{width:100%;height:145px;margin-top:13px}@media(max-width:760px){.lookup,.grid{grid-template-columns:1fr}.hours{grid-template-columns:repeat(3,1fr)}}
</style><body><section class="auth" id="auth"><div class="box"><div class="logo">Sky<span>Predict</span></div><h1 id="title">Sign in securely</h1><p class="muted">Your district research dashboard.</p><label>Email</label><input id="email" type="email" autocomplete="email" placeholder="you@example.com"><label>Password</label><input id="password" type="password" autocomplete="current-password" placeholder="At least 8 characters"><button class="primary" id="submit">Sign in</button><button class="google" id="google">Continue with Google</button><p class="switch" id="switch">New here? <button class="link" id="toggle">Create account</button></p><p class="notice">🔒 Passwords are sent only to this local server and stored as salted hashes. Google sign-in needs your OAuth credentials.</p><p class="muted" id="authMsg"></p></div></section><main class="hidden" id="app"><header class="nav"><div class="logo">Sky<span>Predict</span></div><div><span id="user"></span> <button id="logout">Sign out</button></div></header><div class="shell"><section class="heading"><h1>India daily weather report</h1><p class="muted">24-hour conditions for Indian districts and towns.</p></section><section class="lookup"><div><label>District / location</label><input id="place" list="districts" value="Bengaluru, India" autocomplete="off" placeholder="Type even one letter, e.g. T"><datalist id="districts"></datalist><p class="hint">Start typing to view India-only matches.</p></div><div><label>Report date</label><div class="date"><select id="day" aria-label="Day"></select><select id="month" aria-label="Month"></select><select id="year" aria-label="Year"></select></div></div><button class="search" id="load">Get report</button></section><p class="status" id="status">Search a district to see suggestions.</p><section class="grid"><article class="card"><div class="eyebrow" id="location">Today’s conditions</div><div class="temp" id="temp">—</div><div class="condition" id="condition">—</div><div class="facts"><div class="fact"><small>Rain chance</small><b id="rain">—</b></div><div class="fact"><small>Wind</small><b id="wind">—</b></div><div class="fact"><small>Humidity</small><b id="humidity">—</b></div><div class="fact"><small>Data</small><b>Live model</b></div></div></article><article class="card"><div class="eyebrow">24-hour outlook</div><div class="hours" id="hours"></div><svg id="graph" role="img" aria-label="Temperature line and rain probability bars"></svg></article></section></div></main><script src="app.js"></script></body></html>
