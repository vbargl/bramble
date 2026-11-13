import { strict as assert } from "node:assert";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { generatedPolicy, scriptHashes } from "./security-headers.mjs";
const dist = resolve(import.meta.dirname,"../dist");
test("deployed CSP authorizes every generated script without authorizing arbitrary inline code",async()=>{
 const headers=await readFile(resolve(dist,"_headers"),"utf8");
 assert.equal(headers,await generatedPolicy(dist));
 const policy=headers.split("\n").find(x=>x.trim().startsWith("Content-Security-Policy:"));
 assert.ok(policy);
 assert.doesNotMatch(policy,/script-src[^;]*unsafe-inline/);
 assert.doesNotMatch(policy,/script-src[^;]*(unsafe-eval|https:|\*)/);
 assert.match(policy,/frame-ancestors 'none'/);
 assert.match(headers,/X-Frame-Options: DENY/);
 assert.match(headers,/Strict-Transport-Security: max-age=31536000\s*\n/);
 assert.doesNotMatch(headers,/includeSubDomains|preload/);
 assert.match(headers,/\/\.well-known\/matrix\/\*[\s\S]*Access-Control-Allow-Origin: \*/);
 assert.match(headers,/\/desktop\/\*[\s\S]*Cache-Control: public, max-age=300/);
 let checked=0;
 for(const file of await readdir(dist,{recursive:true})) if(file.endsWith(".html")) {
  for(const hash of scriptHashes(await readFile(resolve(dist,file),"utf8"))) {
   assert.ok(policy.includes(hash),`${file}: missing ${hash}`);checked++;
  }
 }
 assert.ok(checked>0,"test must check actual generated scripts");
 const [injected]=scriptHashes('<script>alert("untrusted injection")</script>');
 assert.ok(!policy.includes(injected));
});
