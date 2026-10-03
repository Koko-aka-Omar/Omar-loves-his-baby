'use strict';
const crypto=require('node:crypto');
const {verifyPassword,validHash,unseal,fingerprint}=require('./crypto.cjs');
const {LocalStore,RedisStore}=require('./store.cjs');
const sealed=require('./sealed.cjs');
const publicEntrance=require('./login.cjs');
const SITE_SECONDS=6*60*60, DIARY_SECONDS=2*60*60, ATTEMPT_WINDOW=15*60, ATTEMPT_LIMIT=8;
const pagePaths=new Set(['/', '/index.html', '/games', '/notes', '/quiz', '/catch-hearts', '/find-karamella', '/catch-battle', '/scratcher', '/kitchen', '/sit-with-me', '/tiny-bakery', '/notes/the-night', '/notes/arabic-yap', '/notes/rabena-ye5aleke-leya', '/notes/the-first-paragraph', '/notes/the-first-loving-paragraph', '/notes/bus-yap']);
function environmentConfig() {
  const production=process.env.VERCEL==='1' || process.env.VERCEL==='true' || process.env.NODE_ENV==='production';
  const key=process.env.KARMEL_CONTENT_KEY,siteHash=process.env.KARMEL_SITE_PASSWORD_HASH,diaryHash=process.env.KARMEL_DIARY_PASSWORD_HASH;
  if (!/^[\w-]{43}$/.test(key||'') || !validHash(siteHash) || !validHash(diaryHash)) throw new Error('Private settings missing');
  const origin=new URL(process.env.KARMEL_ORIGIN);
  if (origin.pathname!=='/' || origin.search || origin.hash || origin.username || origin.password) throw new Error('Invalid private origin');
  if (production && origin.protocol!=='https:') throw new Error('HTTPS required');
  if (!production && !['http://127.0.0.1:4173','http://localhost:4173'].includes(origin.origin)) throw new Error('Local preview must use loopback');
  const store=production ? new RedisStore(process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN) : new LocalStore(process.env.KARMEL_LOCAL_STORE);
  const origins=new Set([origin.origin]);
  if(production && /^[a-z0-9.-]+$/i.test(process.env.VERCEL_URL || '')) origins.add('https://'+process.env.VERCEL_URL);
  return {key,siteHash,diaryHash,production,origin:origin.origin,origins,store};
}
function cookies(req) {
  const parsed={};for (const pair of (req.headers.cookie||'').split(';')) {const index=pair.indexOf('=');if(index>0) parsed[pair.slice(0,index).trim()]=pair.slice(index+1).trim();}return parsed;
}
function createHandler(configProvider=environmentConfig) {
  let config,cachedApp,cachedDiary,cachedHints,hashQueue=Promise.resolve();
  const now=()=>config.now ? config.now() : Date.now();
  const name=scope=>(config.production?'__Host-':'')+'karmel-'+scope;
  const prefix=()=>'karmel:private:v1:'+fingerprint(config.key).slice(0,16)+':';
  const sessionKey=(scope,token)=>prefix()+'session:'+scope+':'+fingerprint(token);
  const json=(res,code,data)=>{res.statusCode=code;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(data));};
  function cookie(scope,token,seconds) {return name(scope)+'='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age='+seconds+(config.production?'; Secure':'');}
  async function session(req,scope,parent) {
    const token=cookies(req)[name(scope)];if(!/^[\w-]{43}$/.test(token||'')) return null;
    const raw=await config.store.get(sessionKey(scope,token));if(!raw) return null;
    const record=JSON.parse(raw);
    if(record.expiresAt<=now() || record.scope!==scope || (scope==='diary' && record.parent!==parent?.id)) return null;
    return record;
  }
  async function issue(scope,parent) {
    const token=crypto.randomBytes(32).toString('base64url');
    const seconds=scope==='site'?SITE_SECONDS:Math.min(DIARY_SECONDS,Math.floor((parent.expiresAt-now())/1000));
    const record={scope,id:fingerprint(token),expiresAt:now()+seconds*1000};if(parent) record.parent=parent.id;
    await config.store.set(sessionKey(scope,token),JSON.stringify(record),seconds);return {cookie:cookie(scope,token,seconds),record};
  }
  async function revoke(req,scope) {const token=cookies(req)[name(scope)];if(/^[\w-]{43}$/.test(token||'')) await config.store.del(sessionKey(scope,token));}
  async function body(req) {
    if((req.headers['content-type']||'').split(';')[0]!=='application/json') throw {status:415};
    if(Number(req.headers['content-length'])>4096) throw {status:413};
    let buffer='';for await(const chunk of req) {buffer+=chunk.toString('utf8');if(Buffer.byteLength(buffer)>4096) throw {status:413};}
    try {const data=JSON.parse(buffer);if(!data || typeof data!=='object' || Array.isArray(data)) throw 0;return data;} catch(_) {throw {status:400};}
  }
  async function matches(password,hash) {
    // Serialize scrypt within each worker to bound memory consumption.
    const task=hashQueue.then(()=>verifyPassword(password,hash));hashQueue=task.catch(()=>false);return task;
  }
  return async function handler(req,res) {
    res.setHeader('Cache-Control','private, no-store, max-age=0');res.setHeader('CDN-Cache-Control','no-store');res.setHeader('Vercel-CDN-Cache-Control','no-store');
    res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Security-Policy',"frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'");res.setHeader('X-Robots-Tag','noindex, nofollow, noarchive');
    try {
      config ||= configProvider();if(config.production) res.setHeader('Strict-Transport-Security','max-age=31536000');
      const path=new URL(req.url,config.origin).pathname.replace(/\/$/,'')||'/';
      if(path==='/favicon.ico') {res.statusCode=204;return res.end();}
      if(path==='/_vercel/insights/script.js' || path==='/_vercel/speed-insights/script.js') {res.setHeader('Content-Type','application/javascript');return res.end('');}
      if(!['GET','HEAD','POST'].includes(req.method)) {res.setHeader('Allow','GET, HEAD, POST');return json(res,405,{error:'Method not allowed'});}
      if(req.method==='POST') {
        if(!(config.origins || new Set([config.origin])).has(req.headers.origin) || req.headers['sec-fetch-site']==='cross-site') return json(res,403,{error:'Request denied'});
        if(path!=='/api/access') return json(res,405,{error:'Method not allowed'});
        const data=await body(req);
        if(data.action==='logout') {await revoke(req,'site');await revoke(req,'diary');res.setHeader('Set-Cookie',[cookie('site','',0),cookie('diary','',0)]);return json(res,200,{site:false,diary:false});}
        if(data.action!=='login' && data.action!=='diary') return json(res,400,{error:'Invalid action'});
        const parent=data.action==='diary'?await session(req,'site'):null;
        if(data.action==='diary' && !parent) return json(res,401,{error:'Entrance password required'});
        const scope=data.action==='login'?'site':'diary';
        const attemptKey=prefix()+'attempt:'+scope+(parent?':'+parent.id:'');
        const retryAfter=await config.store.takeAttempt(attemptKey,ATTEMPT_LIMIT,ATTEMPT_WINDOW);
        if(retryAfter) {res.setHeader('Retry-After',String(retryAfter));return json(res,429,{error:'Too many attempts',retryAfter});}
        if(typeof data.password!=='string' || !data.password || data.password.length>128) return json(res,400,{error:'Invalid password'});
        const candidate=scope==='diary'?data.password.trim().replace(/\s+/g,' ').toLowerCase():data.password;
        if(!await matches(candidate,scope==='site'?config.siteHash:config.diaryHash)) return json(res,401,{error:'Password not accepted'});
        await config.store.del(attemptKey);await revoke(req,scope);if(scope==='site') await revoke(req,'diary');
        const issued=await issue(scope,parent);res.setHeader('Set-Cookie',scope==='site'?[issued.cookie,cookie('diary','',0)]:issued.cookie);
        return json(res,200,{[scope]:true,expiresAt:issued.record.expiresAt});
      }
      if(path==='/api/access') {const site=await session(req,'site');const diary=site?await session(req,'diary',site):null;return json(res,200,{site:!!site,diary:!!diary,siteExpiresAt:site?.expiresAt||0,diaryExpiresAt:diary?.expiresAt||0});}
      if(path==='/api/diary-hints') {
        const site=await session(req,'site');if(!site) return json(res,401,{error:'Entrance password required'});
        if(!await session(req,'diary',site)) return json(res,403,{error:'Diary password required'});
        cachedHints ||= JSON.parse(unseal(sealed.hints,config.key,'hints'));
        const serverNow=now();
        const hints=cachedHints.map(h=>({key:h.key,revealsAt:Date.parse(h.revealsAt),hint:serverNow>=Date.parse(h.revealsAt)?h.hint:null}));
        return json(res,200,{serverNow,hints});
      }
      if(path==='/api/diary') {
        const site=await session(req,'site');if(!site) return json(res,401,{error:'Entrance password required'});
        if(!await session(req,'diary',site)) return json(res,403,{error:'Diary password required'});
        // Browser keys are saved game progress; only the server session grants
        // access. The letter never appears in the delivered application HTML.
        cachedDiary ||= unseal(sealed.diary,config.key,'diary');return json(res,200,{text:cachedDiary});
      }
      if(!pagePaths.has(path)) return json(res,404,{error:'Page not found'});
      const site=await session(req,'site');res.setHeader('Content-Type','text/html; charset=utf-8');
      if(site) {cachedApp ||= unseal(sealed.app,config.key,'app');return res.end(req.method==='HEAD'?'':cachedApp);}
      res.setHeader('Set-Cookie',[cookie('site','',0),cookie('diary','',0)]);return res.end(req.method==='HEAD'?'':publicEntrance);
    } catch(error) {
      // Underlying exceptions can contain credentials or private paths.
      if(!res.headersSent) return json(res,error.status||503,{error:'Our little place is unavailable. Try again soon.'});res.end();
    }
  };
}
module.exports={createHandler,environmentConfig};
