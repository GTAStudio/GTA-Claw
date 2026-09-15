param(
    [Parameter(Mandatory = $true)]
    [string]$NodePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$NodePath = (Resolve-Path -LiteralPath $NodePath).Path
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
  $major = & $NodePath -p 'parseInt(process.versions.node)'
    if ($LASTEXITCODE -ne 0 -or [int]$major -lt 26) {
        throw 'The retained Node service requires Node 26 or newer.'
    }
    & $NodePath node_modules/typescript/bin/tsc
    if ($LASTEXITCODE -ne 0) { throw 'Legacy TypeScript compilation failed.' }
    @'
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { createServer as createHttp2Server, connect } from 'node:http2';
import { createServer } from './dist/server.js';

const deadline = setTimeout(() => {
  console.error('Isolated legacy dependency regression exceeded 30 seconds');
  process.exit(1);
}, 30000);
deadline.unref();
const require = createRequire(import.meta.url);
const csv = require('csv');
const uuid = require('uuid');
const findMyWay = require('find-my-way');
const axios = require('axios');
let assertions = 0;
function equal(actual, expected) {
  assert.deepEqual(actual, expected);
  assertions += 1;
}

const injected = { securityProbe: true };
const rows = await new Promise((resolve, reject) => {
  csv.parse('injected,ordinary', {
    columns: ['__proto__', 'name'],
    cast(value, context) {
      return context.index === 0 ? injected : value;
    },
  }, (error, records) => error ? reject(error) : resolve(records));
});
equal(rows[0].name, 'ordinary');
equal(rows[0].securityProbe, undefined);
assert.notEqual(Object.getPrototypeOf(rows[0]), injected);
assertions += 1;
equal(uuid.validate(uuid.v4()), true);
for (const generate of [uuid.v3, uuid.v5]) {
  assert.throws(() => generate('security-probe', uuid.DNS, new Uint8Array(4)));
  assertions += 1;
}

let reloads = 0;
let chats = 0;
let ready = false;
const adminToken = randomUUID();
const service = createServer({
  bot: {},
  config: {
    ENABLE_TEAMS: false,
    ENABLE_TELEGRAM: false,
    ENABLE_DISCORD: false,
    ENABLE_WHATSAPP: false,
    DEVICE_FLOW_ENABLED: false,
    RATE_LIMIT_PER_MIN: 60,
    TRUST_PROXY: false,
    ADMIN_TOKEN: adminToken,
    COPILOT_MODEL: 'isolated-fixture',
  },
  getEngine: () => ready ? {
    sessionCount: 0,
    async chat(conversation, message) {
      chats += 1;
      return `${conversation}:${message}`;
    },
  } : null,
  getRuntimeStatus: () => ({ skillCount: 0, activeModel: 'isolated-fixture' }),
  async reloadFn() {
    reloads += 1;
    return { skillCount: 2, roleModel: 'isolated-fixture' };
  },
});
service.get('/security/route/:id', (request, response, next) => {
  response.send(200, { id: request.params.id, query: request.query, uuid: request.id() });
  next();
});
service.post('/security/csv', (request, response, next) => {
  response.send(200, request.body);
  next();
});
service.listen(0, '127.0.0.1');
await once(service, 'listening');
const origin = `http://127.0.0.1:${service.address().port}`;
try {
  const health = await axios.get(`${origin}/health`, { proxy: false, timeout: 5000 });
  equal(health.status, 200);
  equal(health.data.authenticated, false);
  const request = async (path, options = {}) => fetch(`${origin}${path}`, {
    signal: AbortSignal.timeout(5000), ...options,
  });
  const post = (path, body, token) => request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  equal((await request('/auth/device')).status, 400);
  equal((await post('/chat', {})).status, 400);
  equal((await post('/chat', { message: 'hello' })).status, 401);
  equal((await post('/admin/reload', {})).status, 403);
  equal((await post('/admin/reload', {}, 'incorrect-fixture-token')).status, 403);
  equal(reloads, 0);
  equal(chats, 0);
  equal((await post('/admin/reload', {}, adminToken)).status, 200);
  equal(reloads, 1);
  ready = true;
  equal(await (await post('/chat', { message: 'hello', conversation_id: 'fixture' })).json(), { reply: 'fixture:hello' });
  equal(chats, 1);
  const routed = await (await request('/security/route/value?name=hello&__proto__[securityProbe]=true')).json();
  equal(routed.id, 'value');
  equal(routed.query.name, 'hello');
  equal(routed.query.securityProbe, undefined);
  equal(uuid.validate(routed.uuid), true);
  equal((await request('/does-not-exist')).status, 404);
  equal((await request('/health', { method: 'DELETE' })).status, 405);
  const parsed = await request('/security/csv', {
    method: 'POST', headers: { 'content-type': 'text/csv' }, body: 'name,count\nfixture,2',
  });
  equal(parsed.status, 200);
  equal(await parsed.json(), [{ name: 'fixture', count: '2', index: 0 }]);
} finally {
  await new Promise((resolve, reject) => service.close(error => error ? reject(error) : resolve()));
}

const router = findMyWay({
  defaultRoute(request, response) {
    response.statusCode = 404;
    response.end('missing');
  },
});
router.on('GET', '/probe', (request, response) => response.end('ok'));
const http2 = createHttp2Server(router.lookup.bind(router));
http2.listen(0, '127.0.0.1');
await once(http2, 'listening');
const session = connect(`http://127.0.0.1:${http2.address().port}`);
try {
  for (const method of ['GET', 'constructor', 'toString', '__proto__']) {
    const status = await new Promise((resolve, reject) => {
      const stream = session.request({ ':method': method, ':path': '/probe' });
      let responseStatus;
      stream.on('response', headers => { responseStatus = headers[':status']; });
      stream.on('data', () => {});
      stream.on('end', () => resolve(responseStatus));
      stream.on('error', reject);
      stream.end();
    });
    equal(status, method === 'GET' ? 200 : 404);
  }
} finally {
  session.close();
  await once(session, 'close');
  await new Promise((resolve, reject) => http2.close(error => error ? reject(error) : resolve()));
}
clearTimeout(deadline);
console.log(JSON.stringify({ status: 'PASS', assertions, node: process.version, liveAccounts: false }));
'@ | & $NodePath --no-node-snapshot --input-type=module -
    if ($LASTEXITCODE -ne 0) { throw 'Legacy dependency runtime regression failed.' }
} finally {
    Pop-Location
}