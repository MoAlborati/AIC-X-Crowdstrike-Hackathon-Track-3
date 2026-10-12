// SPIKE — stand-in "attacker" collector. Logs every arrival with a timestamp.
import http from 'node:http';
http.createServer((req, res) => {
  console.log(JSON.stringify({ at: new Date().toISOString(), kind: 'CANARY_HIT', method: req.method, url: req.url }));
  res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
}).listen(8080, () => console.log('canary listening :8080'));
