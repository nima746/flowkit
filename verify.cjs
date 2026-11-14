const assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');global.crypto=webcrypto;
const {tools,execute,detect}=require('./dist/core.js');
(async()=>{
 const original='中文與 emoji 🌱';assert.equal(tools.decode.run(tools.encode.run(original)),original);
 const safe=JSON.parse((await execute('{"nested":{"password":"secret"},"items":[{"email":"a@b"}],"ok":1}',['pretty','mask'])).value);assert.equal(safe.nested.password,'[REDACTED]');assert.equal(safe.items[0].email,'[REDACTED]');assert.equal(safe.ok,1);
 assert.equal((await execute(' b \na\nb\n\n',['trim','unique','sort'])).value,'a\nb');
 assert.equal(tools.urlDecode.run(tools.urlEncode.run(original)),original);
 assert.equal((await execute('abc',['hash'])).value,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
 assert.equal(detect('{}').tool,'pretty');assert.equal(detect('%E4%B8%AD').tool,'urlDecode');
 await assert.rejects(execute('invalid',['pretty']),/第 1 步/);
 const out=await execute(tools.encode.run('{"x":1}'),['decode','pretty']);assert.equal(out.trace.length,2);assert.equal(JSON.parse(out.value).x,1);
 console.log('PASS: Unicode roundtrip, nested redaction, cleanup pipeline, URL roundtrip, SHA-256, detection, error reporting, intermediate results');
})().catch(e=>{console.error(e);process.exitCode=1;});
