// Candidate only. No request logs. v2 tables are separate from every pre-existing table.
// HYBRID_DB is the dedicated feedback D1; secrets: BOT_TOKEN, CHAT_ID,
// HYBRID_PEPPER, HYBRID_VAULT_KEY (distinct, stable); HYBRID_OWNER_TOKEN
// is an optional legacy recovery credential.
const enc=new TextEncoder(), dec=new TextDecoder();
const ID=/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const ISSUE=/^[a-f0-9]{32}$/;
const KEY=/^[A-Za-z0-9_.-]{8,128}$/;
const NONCE=/^[a-f0-9]{32}$/;
const json=(x,s=200)=>Response.json(x,{status:s,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const goodSecret=x=>typeof x==='string'&&x.length>=32&&x.length<=256&&!/[\x00-\x1f\x7f]/.test(x);
const hwidOK=x=>typeof x==='string'&&x.length>0&&x.length<=256&&!/[\x00-\x1f\x7f]/.test(x)&&!/^(unknown_device|unknown|none|null|n\/a|0+)$/i.test(x.replace(/\s/g,''));
const hex=x=>Array.from(new Uint8Array(x),n=>n.toString(16).padStart(2,'0')).join('');
async function hash(x){return new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(x)));}
async function equal(a,b){if(typeof a!=='string'||typeof b!=='string')return false;let x=await hash(a),y=await hash(b),d=0;for(let i=0;i<x.length;i++)d|=x[i]^y[i];return d===0;}
async function mac(s,x){let k=await crypto.subtle.importKey('raw',enc.encode(s),{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(await crypto.subtle.sign('HMAC',k,enc.encode(x)));}
function b64(x){let s='';for(let n of new Uint8Array(x))s+=String.fromCharCode(n);return btoa(s);}
function unb64(x){let s=atob(x);return Uint8Array.from(s,c=>c.charCodeAt(0));}
async function vaultKey(s){let raw=await hash('SKUY-VAULT-V2\n'+s);return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);}
async function seal(secret,aad,plain){let iv=crypto.getRandomValues(new Uint8Array(12)),key=await vaultKey(secret);let data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(aad)},key,enc.encode(plain));return b64(iv)+'.'+b64(data);}
async function open(secret,aad,blob){let p=blob.split('.');if(p.length!==2)throw Error('cipher');let key=await vaultKey(secret);return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(p[0]),additionalData:enc.encode(aad)},key,unb64(p[1])));}
async function validStoredKey(env,r,k){return KEY.test(k)&&await equal(r.key_tag,await mac(env.HYBRID_PEPPER,'key\n'+r.issuance_id+'\n'+r.file_id+'\n'+k))&&await equal(r.key_search_tag,await mac(env.HYBRID_PEPPER,'search\n'+k));}
const ready=env=>!!env.HYBRID_DB&&goodSecret(env.HYBRID_PEPPER)&&goodSecret(env.HYBRID_VAULT_KEY)&&env.HYBRID_PEPPER!==env.HYBRID_VAULT_KEY&&(!env.HYBRID_OWNER_TOKEN||(goodSecret(env.HYBRID_OWNER_TOKEN)&&env.HYBRID_OWNER_TOKEN!==env.HYBRID_PEPPER&&env.HYBRID_OWNER_TOKEN!==env.HYBRID_VAULT_KEY));
const validReg=d=>d&&typeof d.issuance_id==='string'&&ISSUE.test(d.issuance_id)&&typeof d.file_id==='string'&&ID.test(d.file_id)&&(d.mode==='customer'||d.mode==='shared')&&typeof d.key==='string'&&KEY.test(d.key)&&Number.isSafeInteger(d.expiry)&&d.expiry>0&&d.expiry<=4102444800&&Number.isInteger(d.max_devices)&&d.max_devices>=0&&d.max_devices<=1000&&(d.mode!=='customer'||d.max_devices>=1);
async function limitedBody(req,max){let len=req.headers.get('content-length');if(len&&(!/^\d+$/.test(len)||Number(len)>max))throw Error('too large');if(!req.body)return new Uint8Array();let reader=req.body.getReader(),parts=[],n=0;try{while(true){let r=await reader.read();if(r.done)break;n+=r.value.byteLength;if(n>max){await reader.cancel();throw Error('too large');}parts.push(r.value);}}finally{reader.releaseLock();}let out=new Uint8Array(n),at=0;for(let p of parts){out.set(p,at);at+=p.byteLength;}return out;}
async function receive(req){let s=dec.decode(await limitedBody(req,8192));let d=JSON.parse(s);if(!d||typeof d!=='object'||Array.isArray(d))throw Error('request');return d;}
async function owner(req,env){
 if(!ready(env))return false;
 let auth=req.headers.get('authorization')||'';
 if(env.HYBRID_OWNER_TOKEN&&await equal(auth,'Bearer '+env.HYBRID_OWNER_TOKEN))return true;
 let m=/^Bearer ([a-f0-9]{64})$/.exec(auth);if(!m)return false;
 try {let r=await env.HYBRID_DB.prepare('SELECT token_hash FROM skuy_hybrid_owner_v3 WHERE id=1').first();return !!r&&await equal(r.token_hash,hex(await hash(m[1])));}catch(_){return false;}
}
async function register(req,env){
 if(!ready(env))return json({ok:false,error:'unavailable'},503);
 if(!await owner(req,env))return json({ok:false,error:'unauthorized'},401);
 let d;try{d=await receive(req);}catch(_){return json({ok:false,error:'invalid'},400);}
 if(!validReg(d))return json({ok:false,error:'invalid'},400);
 try{
  const tag=await mac(env.HYBRID_PEPPER,'key\n'+d.issuance_id+'\n'+d.file_id+'\n'+d.key);
  const search=await mac(env.HYBRID_PEPPER,'search\n'+d.key);
  const cipher=await seal(env.HYBRID_VAULT_KEY,'key\n'+d.issuance_id,d.key);
  await env.HYBRID_DB.prepare('INSERT INTO skuy_hybrid_issuances_v2 (issuance_id,file_id,mode,key_tag,key_search_tag,key_cipher,expiry,max_devices,created_at) SELECT ?,?,?,?,?,?,?,?,unixepoch() WHERE ?>unixepoch() AND NOT EXISTS (SELECT 1 FROM skuy_hybrid_deleted_v2 WHERE issuance_id=?) ON CONFLICT DO NOTHING').bind(d.issuance_id,d.file_id,d.mode,tag,search,cipher,d.expiry,d.max_devices,d.expiry,d.issuance_id).run();
  const r=await env.HYBRID_DB.prepare('SELECT file_id,mode,key_tag,key_search_tag,key_cipher,expiry,max_devices,server_state,unixepoch() AS db_now FROM skuy_hybrid_issuances_v2 WHERE issuance_id=?').bind(d.issuance_id).first();
  if(!r||r.file_id!==d.file_id||r.mode!==d.mode||r.expiry!==d.expiry||r.max_devices!==d.max_devices||!await equal(r.key_tag,tag)||!await equal(r.key_search_tag,search))return json({ok:false,error:'issuance conflict'},409);
  if(r.server_state!=='active'||r.expiry<=r.db_now)return json({ok:false,error:'issuance inactive or expired'},409);
  let actual=await open(env.HYBRID_VAULT_KEY,'key\n'+d.issuance_id,r.key_cipher);
  if(!await equal(actual,d.key))return json({ok:false,error:'issuance conflict'},409);
  // Re-check state and expiry after decryption, at the final database read.
  let current=await env.HYBRID_DB.prepare("SELECT 1 AS valid FROM skuy_hybrid_issuances_v2 WHERE issuance_id=? AND server_state='active' AND expiry>unixepoch()").bind(d.issuance_id).first();
  if(!current)return json({ok:false,error:'issuance inactive or expired'},409);
  return json({ok:true,version:2,issuance_id:d.issuance_id,file_id:d.file_id,max_devices:d.max_devices});
 }catch(_){return json({ok:false,error:'unavailable'},503);}
}
// Each insertion is a single SQLite statement: capacity and block checks are
// evaluated inside that same write, not in a race-prone SELECT/INSERT pair.
async function license(d,env,allowBind=true){
 const reply=status=>({version:2,issuance_id:d.issuance_id,file_id:d.file_id,nonce:d.nonce,status});
 if(!ready(env))return reply('unavailable');
 try{
  let tag=await mac(env.HYBRID_PEPPER,'key\n'+d.issuance_id+'\n'+d.file_id+'\n'+d.key), dev=await mac(env.HYBRID_PEPPER,'device\n'+d.issuance_id+'\n'+d.hwid);
  let cipher=await seal(env.HYBRID_VAULT_KEY,'device\n'+d.issuance_id+'\n'+dev,d.hwid);
  if(allowBind) await env.HYBRID_DB.prepare("INSERT INTO skuy_hybrid_devices_v2 (issuance_id,device_tag,hwid_cipher,state,updated_at) SELECT i.issuance_id,?,?,'active',unixepoch() FROM skuy_hybrid_issuances_v2 i WHERE i.issuance_id=? AND i.file_id=? AND i.key_tag=? AND i.expiry>unixepoch() AND i.server_state='active' AND NOT EXISTS (SELECT 1 FROM skuy_hybrid_devices_v2 b WHERE b.issuance_id=i.issuance_id AND b.device_tag=? AND b.state='blocked') AND (EXISTS (SELECT 1 FROM skuy_hybrid_devices_v2 a WHERE a.issuance_id=i.issuance_id AND a.device_tag=? AND a.state='active') OR i.max_devices=0 OR (SELECT COUNT(*) FROM skuy_hybrid_devices_v2 a WHERE a.issuance_id=i.issuance_id AND a.state='active')<i.max_devices) ON CONFLICT(issuance_id,device_tag) DO UPDATE SET updated_at=excluded.updated_at WHERE skuy_hybrid_devices_v2.state='active' RETURNING state").bind(dev,cipher,d.issuance_id,d.file_id,tag,dev,dev).first();
  // Single SQL snapshot at verdict time: never return an earlier write result.
  let r=await env.HYBRID_DB.prepare("SELECT i.expiry,unixepoch() AS db_now,i.max_devices,i.server_state,(SELECT state FROM skuy_hybrid_devices_v2 WHERE issuance_id=i.issuance_id AND device_tag=?) AS device_state,(SELECT COUNT(*) FROM skuy_hybrid_devices_v2 WHERE issuance_id=i.issuance_id AND state='active') AS n FROM skuy_hybrid_issuances_v2 i WHERE i.issuance_id=? AND i.file_id=? AND i.key_tag=?").bind(dev,d.issuance_id,d.file_id,tag).first();
  if(!r)return reply('invalid');
  if(r.expiry<=r.db_now)return reply('expired');
  if(r.server_state!=='active')return reply('disabled');
  if(r.device_state==='blocked')return reply('blocked');
  if(r.device_state==='active' && (r.max_devices===0 || r.n<=r.max_devices))return reply('accepted');
  if(r.max_devices>0 && r.n>=r.max_devices)return reply('mismatch');
  return reply('unavailable');
 }catch(_){return reply('unavailable');}
}
const validMeta=d=>typeof d.issuance_id==='string'&&ISSUE.test(d.issuance_id)&&typeof d.file_id==='string'&&ID.test(d.file_id)&&typeof d.key==='string'&&KEY.test(d.key)&&typeof d.nonce==='string'&&NONCE.test(d.nonce)&&hwidOK(d.hwid);
async function feedback(req,env){
 let f;try{let body=await limitedBody(req,12*1024*1024);f=await new Request(req.url,{method:'POST',headers:req.headers,body}).formData();}catch(_){return json({ok:false,status:false,error:'Invalid form'},400);}
 let image=f.get('base64_image');if(typeof image!=='string'||!image)return json({ok:false,status:false,error:'Missing base64_image'},400);
 if(image.length>10*1024*1024)return json({ok:false,status:false,error:'Image too large'},413);
 let clean=image;if(clean.startsWith('data:image/')){let i=clean.indexOf(',');if(i>=0)clean=clean.slice(i+1);}
 let bytes;try{let s=atob(clean.replace(/\s+/g,''));if(!s.length)throw Error();bytes=Uint8Array.from(s,c=>c.charCodeAt(0));}catch(_){return json({ok:false,status:false,error:'Invalid base64 image'},400);}
 let names=['issuance_id','file_id','key','hwid','nonce'],has=names.some(k=>f.has(k)),d=Object.fromEntries(names.map(k=>[k,f.get(k)]));
 let caption=String(f.get('caption')||'').slice(0,1024);for(let v of [d.key,d.hwid])if(typeof v==='string'&&v)caption=caption.split(v).join('[redacted]');
 let sent=false,tgError='Telegram unavailable',tgCode;
 if(env.BOT_TOKEN&&env.CHAT_ID){
  try{
   let t=new FormData();t.append('chat_id',env.CHAT_ID);t.append('caption',caption);t.append('photo',new Blob([bytes],{type:'image/jpeg'}),'feedback.jpg');
   let res=await fetch('https://api.telegram.org/bot'+env.BOT_TOKEN+'/sendPhoto',{method:'POST',body:t}),result=await res.json();
   sent=res.ok&&result.ok===true;
   if(!sent){tgError='Telegram rejected the request';if(Number.isInteger(result?.error_code))tgCode=result.error_code;}
  }catch(_){}
 }else tgError='Missing BOT_TOKEN or CHAT_ID';
 // A failed Telegram send may READ an existing verdict but never creates a binding.
 let lic=has?(validMeta(d)?await license(d,env,sent):{version:2,status:'invalid_request'}):undefined;
 if(sent)return json({ok:true,status:true,message:'Feedback sent to Telegram',...(lic?{license:lic}:{})});
 let body={ok:false,status:false,error:tgError,...(tgCode?{telegram:{ok:false,error_code:tgCode}}:{}),...(lic?{license:lic}:{})};
 // Hybrid requests need the verdict body even on Telegram failure; preserve
 // legacy error status on requests that do not carry hybrid metadata.
 return json(body,has?200:(tgError==='Missing BOT_TOKEN or CHAT_ID'?500:502));
}
async function admin(req,env,operation){
 if(!ready(env))return json({ok:false,error:'unavailable'},503);
 if(!await owner(req,env))return json({ok:false,error:'unauthorized'},401);
 let d;try{d=await receive(req);}catch(_){return json({ok:false,error:'invalid'},400);}
 try{
  if(operation==='list'){
   let limit=d.limit===undefined?10:d.limit,after=d.after||'';
   if(!Number.isInteger(limit)||limit<1||limit>25||(after!==''&&!ISSUE.test(after)))return json({ok:false,error:'invalid'},400);
   if(d.file_id!==undefined&&!ID.test(d.file_id))return json({ok:false,error:'invalid'},400);
   if(d.key!==undefined&&!KEY.test(d.key))return json({ok:false,error:'invalid'},400);
   let sql='SELECT issuance_id,file_id,mode,key_tag,key_search_tag,key_cipher,expiry,max_devices,created_at,server_state FROM skuy_hybrid_issuances_v2 WHERE issuance_id>?',args=[after];
   if(d.file_id!==undefined){sql+=' AND file_id=?';args.push(d.file_id);}
   if(d.key!==undefined){sql+=' AND key_search_tag=?';args.push(await mac(env.HYBRID_PEPPER,'search\n'+d.key));}
   sql+=' ORDER BY issuance_id LIMIT ?';args.push(limit+1);
   let q=await env.HYBRID_DB.prepare(sql).bind(...args).all(),rows=q.results||[],more=rows.length>limit;rows=rows.slice(0,limit);
   let result=[];for(let r of rows){let k=await open(env.HYBRID_VAULT_KEY,'key\n'+r.issuance_id,r.key_cipher);if(!await validStoredKey(env,r,k))throw Error('cipher mismatch');let count=await env.HYBRID_DB.prepare("SELECT COUNT(*) AS n FROM skuy_hybrid_devices_v2 WHERE issuance_id=? AND state='active'").bind(r.issuance_id).first();result.push({issuance_id:r.issuance_id,file_id:r.file_id,mode:r.mode,key:k,expiry:r.expiry,max_devices:r.max_devices,active_devices:count?.n??0,created_at:r.created_at,server_state:r.server_state});}
   return json({ok:true,items:result,next:more?rows[rows.length-1].issuance_id:null});
  }
  if(operation==='item'){
   if(typeof d.issuance_id!=='string'||!ISSUE.test(d.issuance_id))return json({ok:false,error:'invalid'},400);
   let r=await env.HYBRID_DB.prepare('SELECT issuance_id,file_id,mode,key_tag,key_search_tag,key_cipher,expiry,max_devices,created_at,server_state FROM skuy_hybrid_issuances_v2 WHERE issuance_id=?').bind(d.issuance_id).first();
   if(!r)return json({ok:false,error:'not found'},404);
   let key=await open(env.HYBRID_VAULT_KEY,'key\n'+r.issuance_id,r.key_cipher);
   if(!await validStoredKey(env,r,key))throw Error('cipher mismatch');
   let count=await env.HYBRID_DB.prepare("SELECT COUNT(*) AS n FROM skuy_hybrid_devices_v2 WHERE issuance_id=? AND state='active'").bind(r.issuance_id).first();
   return json({ok:true,item:{issuance_id:r.issuance_id,file_id:r.file_id,mode:r.mode,key,expiry:r.expiry,max_devices:r.max_devices,active_devices:count?.n??0,created_at:r.created_at,server_state:r.server_state}});
  }
  if(operation==='devices'){
   if(!ISSUE.test(d.issuance_id||''))return json({ok:false,error:'invalid'},400);
   let limit=d.limit===undefined?10:d.limit,after=d.after||'';
   if(!Number.isInteger(limit)||limit<1||limit>25||(after!==''&&!/^[a-f0-9]{64}$/.test(after)))return json({ok:false,error:'invalid'},400);
   let q=await env.HYBRID_DB.prepare('SELECT device_tag,hwid_cipher,state,updated_at FROM skuy_hybrid_devices_v2 WHERE issuance_id=? AND device_tag>? ORDER BY device_tag LIMIT ?').bind(d.issuance_id,after,limit+1).all(),rows=q.results||[],more=rows.length>limit;rows=rows.slice(0,limit);
   let items=[];for(let r of rows)items.push({device_tag:r.device_tag,hwid:await open(env.HYBRID_VAULT_KEY,'device\n'+d.issuance_id+'\n'+r.device_tag,r.hwid_cipher),state:r.state,updated_at:r.updated_at});
   return json({ok:true,items,next:more?rows[rows.length-1].device_tag:null});
  }
  if(operation==='delete-key'){
   if(typeof d.issuance_id!=='string'||!ISSUE.test(d.issuance_id)||d.confirm!==true)return json({ok:false,error:'invalid'},400);
   // D1 batch is one transaction. Mark first, then remove only this issuance's
   // device records and issuance (including tags/cipher). Register's INSERT
   // checks the marker inside its own write. No FK cascade is assumed.
   const db=env.HYBRID_DB, id=d.issuance_id;
   const results=await db.batch([
    db.prepare('INSERT INTO skuy_hybrid_deleted_v2 (issuance_id) SELECT issuance_id FROM skuy_hybrid_issuances_v2 WHERE issuance_id=? ON CONFLICT DO NOTHING').bind(id),
    db.prepare('DELETE FROM skuy_hybrid_devices_v2 WHERE issuance_id=? AND EXISTS (SELECT 1 FROM skuy_hybrid_deleted_v2 WHERE issuance_id=?)').bind(id,id),
    db.prepare('DELETE FROM skuy_hybrid_issuances_v2 WHERE issuance_id=? AND EXISTS (SELECT 1 FROM skuy_hybrid_deleted_v2 WHERE issuance_id=?)').bind(id,id)
   ]);
   if(!Array.isArray(results)||results.some(x=>!x.success))throw Error('batch');
   let marker=await db.prepare('SELECT issuance_id FROM skuy_hybrid_deleted_v2 WHERE issuance_id=?').bind(id).first();
   return marker?json({ok:true,issuance_id:id,deleted:true}):json({ok:false,error:'not found'},404);
  }
  if(operation==='issuance'){
   if(!ISSUE.test(d.issuance_id||'')||!['disable','enable'].includes(d.action)||d.confirm!==true)return json({ok:false,error:'invalid'},400);
   const expected=d.action==='disable'?'active':'disabled',target=d.action==='disable'?'disabled':'active';
   const row=await env.HYBRID_DB.prepare('UPDATE skuy_hybrid_issuances_v2 SET server_state=? WHERE issuance_id=? AND server_state=? RETURNING server_state').bind(target,d.issuance_id,expected).first();
   return row?json({ok:true,server_state:row.server_state}):json({ok:false,error:'issuance not found or state changed'},409);
  }
  if(operation==='device'){
   if(!ISSUE.test(d.issuance_id||'')||!['reset','block','unblock'].includes(d.action)||!(/^[a-f0-9]{64}$/).test(d.device_tag||'')||d.confirm!==true)return json({ok:false,error:'invalid'},400);
   let now=Math.floor(Date.now()/1000),r;
   if(d.action==='reset')r=await env.HYBRID_DB.prepare("DELETE FROM skuy_hybrid_devices_v2 WHERE issuance_id=? AND device_tag=? AND state='active' RETURNING state").bind(d.issuance_id,d.device_tag).first();
   if(d.action==='block')r=await env.HYBRID_DB.prepare("UPDATE skuy_hybrid_devices_v2 SET state='blocked',updated_at=? WHERE issuance_id=? AND device_tag=? AND state='active' RETURNING state").bind(now,d.issuance_id,d.device_tag).first();
   if(d.action==='unblock')r=await env.HYBRID_DB.prepare("DELETE FROM skuy_hybrid_devices_v2 WHERE issuance_id=? AND device_tag=? AND state='blocked' RETURNING state").bind(d.issuance_id,d.device_tag).first();
   return r?json({ok:true,action:d.action}):json({ok:false,error:'device not found or state changed'},409);
  }
  return json({ok:false,error:'not found'},404);
 }catch(_){return json({ok:false,error:'unavailable'},503);}
}
// Tool pertama menautkan token lokal; pemilik pertama menang.
async function ownerInit(req,env,u){
 if(u.protocol!=='https:'||req.method!=='POST')return json({ok:false,error:'invalid'},400);
 if(!ready(env))return json({ok:false,error:'unavailable'},503);
 const auth=req.headers.get('authorization')||'';
 const m=/^Bearer ([a-f0-9]{64})$/.exec(auth);
 if(!m)return json({ok:false,error:'unauthorized'},401);
 try{
  const digest=hex(await hash(m[1]));
  await env.HYBRID_DB.prepare('INSERT INTO skuy_hybrid_owner_v3 (id,token_hash,linked_at) VALUES (1,?,unixepoch()) ON CONFLICT(id) DO NOTHING').bind(digest).run();
  const row=await env.HYBRID_DB.prepare('SELECT token_hash FROM skuy_hybrid_owner_v3 WHERE id=1').first();
  return row&&await equal(row.token_hash,digest)?json({ok:true,status:'linked'}):json({ok:false,error:'already linked'},409);
 }catch(_){return json({ok:false,error:'unavailable'},503);}
}

export default {async fetch(req,env){
 try{
  const u=new URL(req.url);if(req.method==='POST'&&u.protocol!=='https:')return json({ok:false,status:false,error:'HTTPS required'},400);
  if(u.pathname==='/skuy/v3/owner/init')return await ownerInit(req,env,u);
  if(u.pathname.startsWith('/skuy/v3/'))return json({ok:false,error:'not found'},404);
  if(u.pathname==='/skuy/v2/register')return req.method==='POST'?await register(req,env):json({ok:false,error:'POST only'},405);
  if(u.pathname.startsWith('/skuy/v2/admin/'))return req.method==='POST'?await admin(req,env,u.pathname.slice('/skuy/v2/admin/'.length)):json({ok:false,error:'POST only'},405);
  if(req.method==='GET')return json({ok:true,status:true,service:'autofbskuy',message:'Auto Feedback Worker is running'});
  if(req.method!=='POST')return json({ok:false,status:false,error:'POST only'},405);
  return await feedback(req,env);
 }catch(_){return json({ok:false,status:false,error:'unavailable'},503);}
}};

