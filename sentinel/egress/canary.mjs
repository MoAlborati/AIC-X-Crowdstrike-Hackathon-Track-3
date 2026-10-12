// T12 — stand-in attacker collector ("attacker server"). Ground truth for egress scoring: a line here
// means bytes LANDED. Listens on the `outside` network only; DVAA can reach it solely via the inspector.
import http from 'node:http';
http.createServer((req, res) => {
  let n = 0;
  req.on('data', (c) => { n += c.length; });
  req.on('end', () => {
    console.log(JSON.stringify({ at: new Date().toISOString(), kind: 'CANARY_HIT', method: req.method, url: req.url, body_bytes: n }));
    res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
  });
}).listen(8080, () => console.log('canary listening :8080'));
