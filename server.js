const http = require('http');
const fs = require('fs');
const path = require('path');
const port = Number(process.env.PORT || 3000);
const root = path.join(__dirname, 'public');
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); };
async function weather(url, res) {
  const place = (url.searchParams.get('place') || '').trim();
  const date = url.searchParams.get('date');
  const geo = await fetch('https://geocoding-api.open-meteo.com/v1/search?name=' + encodeURIComponent(place) + '&count=20&language=en&format=json');
  const location = ((await geo.json()).results || []).find(x => x.country_code === 'IN');
  if (!location) return json(res, 404, { error: 'No Indian district or town matched that search.' });
  const params = new URLSearchParams({ latitude: location.latitude, longitude: location.longitude, timezone: 'Asia/Kolkata', start_date: date, end_date: date, hourly: 'temperature_2m,relative_humidity_2m,precipitation_probability,weather_code,wind_speed_10m' });
  const data = await (await fetch('https://api.open-meteo.com/v1/forecast?' + params)).json();
  json(res, 200, { location: { name: location.name, state: location.admin1 || '' }, hourly: data.hourly });
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + req.headers.host);
  try {
    if (url.pathname === '/api/auth/me') return json(res, 200, { email: 'Guest access' });
    if (url.pathname === '/api/auth/logout') return json(res, 200, { ok: true });
    if (url.pathname === '/api/weather') return await weather(url, res);
    const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const resolved = path.resolve(root, file);
    if (!resolved.startsWith(root) || !fs.existsSync(resolved)) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : 'text/html; charset=utf-8' });
    fs.createReadStream(resolved).pipe(res);
  } catch (error) { console.error(error); json(res, 500, { error: 'Server error' }); }
});
server.listen(port, () => console.log('Sky Predict running on port ' + port));
