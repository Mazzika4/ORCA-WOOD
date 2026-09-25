'use strict';
// ORCA - سيرفر متابعة العملاء (بدون أي مكتبات خارجية، يحتاج Node 18+)
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),{promisify}=require('util');
const scrypt=promisify(crypto.scrypt);
const PORT=+process.env.PORT||3000,DATA=process.env.DATA_DIR||path.join(__dirname,'data'),CODE=process.env.SIGNUP_CODE||'';
fs.mkdirSync(path.join(DATA,'files'),{recursive:true});fs.mkdirSync(path.join(DATA,'backups'),{recursive:true});
const DBF=path.join(DATA,'db.json');
let db={cv:1,users:{},sessions:{},clients:{},files:{}};
try{db=Object.assign(db,JSON.parse(fs.readFileSync(DBF,'utf8')))}catch(e){if(e.code!=='ENOENT'){console.error('ملف db.json تالف، لن يبدأ السيرفر حتى لا تضيع البيانات:',e.message);process.exit(1)}}
function persist(){const t=DBF+'.tmp';fs.writeFileSync(t,JSON.stringify(db));fs.renameSync(t,DBF)}
function backup(){try{if(!fs.existsSync(DBF))return;const d=new Date().toISOString().slice(0,10);fs.copyFileSync(DBF,path.join(DATA,'backups','db-'+d+'.json'));
const l=fs.readdirSync(path.join(DATA,'backups')).sort();l.slice(0,Math.max(0,l.length-30)).forEach(f=>fs.unlinkSync(path.join(DATA,'backups',f)))}catch(e){console.error('backup',e.message)}}
backup();setInterval(backup,6*3600e3).unref();

const F=['client','address','design','type','phone','cdate','ddate','mfg','pur','eng','notes','mdate','ms','sdate','ss','idate','is','p2date','p2s','p2amt','p3date','p3s','p3amt'];
const TYPES={'application/pdf':'%PDF','image/png':'\x89PNG','image/jpeg':'\xFF\xD8','image/gif':'GIF8','image/webp':'RIFF'};
const H=s=>crypto.createHash('sha256').update(s).digest('hex');
const eq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const send=(res,c,o,h)=>{res.writeHead(c,Object.assign({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'},h));res.end(JSON.stringify(o))};
const fail=(c,e)=>({c,e});
function body(req,max){return new Promise((ok,no)=>{let n=0;const c=[];req.on('data',d=>{n+=d.length;if(n>max){no(fail(413,'الحجم أكبر من المسموح'));req.destroy()}else c.push(d)});
req.on('end',()=>{try{ok(JSON.parse(Buffer.concat(c).toString()||'{}'))}catch(e){no(fail(400,'بيانات غير صحيحة'))}});req.on('error',()=>no(fail(400,'خطأ في الطلب')))})}
function who(req){const m=/(?:^|; )sid=([^;]+)/.exec(req.headers.cookie||'');if(!m)return null;const s=db.sessions[H(m[1])];return s&&s.exp>Date.now()?db.users[s.email]||null:null}
const hits=new Map();
function limited(req){const ip=(process.env.TRUST_PROXY?String(req.headers['x-forwarded-for']||'').split(',')[0].trim():'')||req.socket.remoteAddress,now=Date.now();let h=hits.get(ip);if(!h||now-h.t>9e5)h={n:0,t:now};h.n++;hits.set(ip,h);return h.n>10}
async function mkpw(p){const salt=crypto.randomBytes(16);return{salt:salt.toString('hex'),hash:(await scrypt(p,salt,64)).toString('hex')}}
function login(req,res,email,u){const tok=crypto.randomBytes(32).toString('base64url'),now=Date.now();
for(const k in db.sessions)if(db.sessions[k].exp<now)delete db.sessions[k];
db.sessions[H(tok)]={email,exp:now+30*864e5};persist();
const sec=(req.headers['x-forwarded-proto']==='https'||req.socket.encrypted)?'; Secure':'';
send(res,200,{name:u.name,email},{'Set-Cookie':'sid='+tok+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000'+sec})}
function pick(b,partial){const o={};for(const k of F.concat(['mfid','mfname'])){if(b[k]===undefined){if(!partial)o[k]='';continue}
let v=b[k];if(typeof v==='number')v=String(v);if(typeof v!=='string'||v.length>2000)throw fail(400,'قيمة غير صحيحة في '+k);o[k]=v}
if(o.mfid&&!(/^s:[a-f0-9]{32}$/.test(o.mfid)&&db.files[o.mfid.slice(2)]))throw fail(400,'ملف غير موجود');return o}

async function api(req,res,url){
 const m=req.method,p=url.pathname;
 if(m!=='GET'&&!/^application\/json/.test(req.headers['content-type']||''))throw fail(415,'نوع الطلب غير مدعوم');
 if(p==='/api/signup'&&m==='POST'){if(limited(req))throw fail(429,'محاولات كثيرة، جرّب بعد شوية');
  const b=await body(req,1e4),email=String(b.email||'').trim().toLowerCase(),name=String(b.name||'').trim(),pw=String(b.password||'');
  const first=!Object.keys(db.users).length;
  if(CODE){if(!eq(b.code||'',CODE))throw fail(403,'كود التسجيل غير صحيح')}else if(!first)throw fail(403,'التسجيل مقفول. اطلب من المسؤول تفعيل كود التسجيل');
  if(!name||name.length>60)throw fail(400,'اكتب اسمك');if(!/^\S+@\S+\.\S+$/.test(email)||email.length>120)throw fail(400,'البريد الإلكتروني غير صحيح');
  if(pw.length<8||pw.length>200)throw fail(400,'كلمة المرور لازم تكون 8 حروف على الأقل');if(db.users[email])throw fail(409,'الحساب ده موجود بالفعل');
  const u=Object.assign({name,admin:first,at:Date.now()},await mkpw(pw));db.users[email]=u;return login(req,res,email,u)}
 if(p==='/api/login'&&m==='POST'){if(limited(req))throw fail(429,'محاولات كثيرة، جرّب بعد شوية');
  const b=await body(req,1e4),email=String(b.email||'').trim().toLowerCase(),u=db.users[email],bad=fail(401,'البريد أو كلمة المرور غير صحيحة');
  const h=(await scrypt(String(b.password||''),Buffer.from(u?u.salt:'00'.repeat(16),'hex'),64)).toString('hex');
  if(!u||!eq(h,u.hash))throw bad;return login(req,res,email,u)}
 if(p==='/api/logout'&&m==='POST'){const c=/(?:^|; )sid=([^;]+)/.exec(req.headers.cookie||'');if(c){delete db.sessions[H(c[1])];persist()}
  return send(res,200,{ok:1},{'Set-Cookie':'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'})}
 const u=who(req);if(!u)throw fail(401,'سجّل دخول الأول');
 if(p==='/api/me'&&m==='GET')return send(res,200,{name:u.name});
 if(p==='/api/clients'&&m==='GET')return send(res,200,url.searchParams.get('v')==db.cv?{same:true}:{v:db.cv,rows:Object.values(db.clients)});
 let x=/^\/api\/clients\/(\d{1,16})$/.exec(p);
 if(x){const id=x[1],old=db.clients[id];
  if(m==='PUT'){db.clients[id]=Object.assign(pick(await body(req,2e5)),{id:+id,by:u.name,at:Date.now()})}
  else if(m==='PATCH'){if(!old)throw fail(404,'العميل غير موجود');Object.assign(old,pick(await body(req,2e5),true),{by:u.name,at:Date.now()})}
  else if(m==='DELETE'){delete db.clients[id]}else throw fail(405,'غير مسموح');
  db.cv++;persist();return send(res,200,{ok:1})}
 if(p==='/api/files'&&m==='POST'){const b=await body(req,15e6),sig=TYPES[b.type];if(!sig)throw fail(400,'الملفات المسموحة: PDF أو صورة (png/jpg/gif/webp)');
  const buf=Buffer.from(String(b.data||''),'base64');if(!buf.length||buf.length>10e6)throw fail(400,'حجم الملف لازم يكون أقل من 10MB');
  if(buf.subarray(0,sig.length).toString('latin1')!==sig)throw fail(400,'الملف تالف أو نوعه غير مطابق');
  const id=crypto.randomBytes(16).toString('hex');fs.writeFileSync(path.join(DATA,'files',id),buf);
  db.files[id]={name:String(b.name||'file').slice(0,150),type:b.type,by:u.name,at:Date.now()};persist();return send(res,200,{id})}
 x=/^\/api\/files\/([a-f0-9]{32})$/.exec(p);
 if(x&&m==='GET'){const f=db.files[x[1]];if(!f)throw fail(404,'الملف غير موجود');
  res.writeHead(200,{'Content-Type':f.type,'Content-Disposition':"inline; filename*=UTF-8''"+encodeURIComponent(f.name),'X-Content-Type-Options':'nosniff','Cache-Control':'private, max-age=3600'});
  return fs.createReadStream(path.join(DATA,'files',x[1])).pipe(res)}
 throw fail(404,'غير موجود')}

const PAGE=path.join(__dirname,'public','index.html');
http.createServer((req,res)=>{
 const url=new URL(req.url,'http://x');
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');
 if(url.pathname.startsWith('/api/'))return api(req,res,url).catch(e=>{if(!res.headersSent)e&&e.c?send(res,e.c,{error:e.e}):(console.error(e),send(res,500,{error:'خطأ في السيرفر'}))});
 if((url.pathname==='/'||url.pathname==='/index.html')&&req.method==='GET'){
  res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache',
  'Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"});
  return fs.createReadStream(PAGE).pipe(res)}
 res.writeHead(404,{'Content-Type':'text/plain'});res.end('Not found')
}).listen(PORT,()=>console.log('ORCA شغال على http://localhost:'+PORT));
