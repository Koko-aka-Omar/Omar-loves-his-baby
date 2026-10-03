'use strict';
const fs = require('node:fs');
const path = require('node:path');
// Only the loopback preview uses local files. Deployed sessions and limits
// use shared Redis so worker restarts cannot reset them.
class LocalStore {
  constructor(file, now = Date.now) {
    this.file=file;this.now=now;this.entries={};
    fs.mkdirSync(path.dirname(file),{recursive:true});
    if (fs.existsSync(file)) this.entries=JSON.parse(fs.readFileSync(file,'utf8'));
  }
  prune() { for (const [key,record] of Object.entries(this.entries)) if (record.expiresAt <= this.now()) delete this.entries[key]; }
  persist() {
    this.prune();fs.writeFileSync(this.file+'.tmp',JSON.stringify(this.entries),{mode:0o600});fs.renameSync(this.file+'.tmp',this.file);
  }
  async get(key) { const r=this.entries[key];return r && r.expiresAt>this.now() ? r.value : null; }
  async set(key,value,ttl) { this.entries[key]={value,expiresAt:this.now()+ttl*1000};this.persist(); }
  async del(...keys) { keys.forEach(key=>delete this.entries[key]);this.persist(); }
  async takeAttempt(key,limit,seconds) {
    let r=this.entries[key];
    if (!r || r.expiresAt<=this.now()) r=this.entries[key]={value:0,expiresAt:this.now()+seconds*1000};
    if (r.value>=limit) return Math.max(1,Math.ceil((r.expiresAt-this.now())/1000));
    r.value++;this.persist();return 0;
  }
}
class RedisStore {
  constructor(url,token) {
    const parsed=new URL(url);
    if (parsed.protocol!=='https:' || !token) throw new Error('Invalid private store settings');
    this.url=parsed.href;this.token=token;
  }
  async command(args) {
    const response=await fetch(this.url,{method:'POST',headers:{Authorization:'Bearer '+this.token,'Content-Type':'application/json'},body:JSON.stringify(args),signal:AbortSignal.timeout(5000)});
    if (!response.ok) throw new Error('Private store unavailable');
    const result=await response.json();if (result.error) throw new Error('Private store failed');return result.result;
  }
  get(key) { return this.command(['GET',key]); }
  set(key,value,ttl) { return this.command(['SET',key,value,'EX',String(ttl)]); }
  del(...keys) { return this.command(['DEL',...keys]); }
  async takeAttempt(key,limit,seconds) {
    const lua="local n=tonumber(redis.call('GET',KEYS[1]) or '0'); if n>=tonumber(ARGV[1]) then return math.max(1,redis.call('TTL',KEYS[1])) end; n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[2]) end; return 0";
    return Number(await this.command(['EVAL',lua,'1',key,String(limit),String(seconds)]));
  }
}
module.exports={LocalStore,RedisStore};
