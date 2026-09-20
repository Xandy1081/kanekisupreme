require('dotenv').config();
const express=require('express'),session=require('express-session'),passport=require('passport'),GoogleStrategy=require('passport-google-oauth20').Strategy,path=require('path'),fs=require('fs');
const app=express(),PORT=process.env.PORT||3000;
const OWNER=(process.env.ALLOWED_GOOGLE_EMAIL||'dina184513@gmail.com').trim().toLowerCase();
const PERM_FILE=path.join(__dirname,'permissions.json');
function loadPerms(){try{return JSON.parse(fs.readFileSync(PERM_FILE,'utf8')).map(x=>String(x).trim().toLowerCase()).filter(Boolean)}catch{return []}}
function savePerms(list){fs.writeFileSync(PERM_FILE,JSON.stringify([...new Set(list.map(x=>x.toLowerCase()))],null,2))}
if(!fs.existsSync(PERM_FILE))savePerms([]);
function isAuthorized(email){email=(email||'').toLowerCase();return email===OWNER||loadPerms().includes(email)}
function requireAuth(req,res,next){if(!req.user)return res.status(401).json({error:'Faça login com Google.'});if(!isAuthorized(req.user.email))return res.status(403).json({error:'Esta conta Google não tem permissão para acessar o Kaneki Store.'});next()}
function requireOwner(req,res,next){if(!req.user)return res.status(401).json({error:'Faça login com Google.'});if(req.user.email!==OWNER)return res.status(403).json({error:'Somente a conta proprietária pode conceder permissões.'});next()}
app.use(express.json());app.use(session({secret:process.env.SESSION_SECRET||'change-me',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production'}}));app.use(passport.initialize());app.use(passport.session());
passport.serializeUser((u,d)=>d(null,u));passport.deserializeUser((u,d)=>d(null,u));
if(process.env.GOOGLE_CLIENT_ID&&process.env.GOOGLE_CLIENT_SECRET)passport.use(new GoogleStrategy({clientID:process.env.GOOGLE_CLIENT_ID,clientSecret:process.env.GOOGLE_CLIENT_SECRET,callbackURL:process.env.GOOGLE_CALLBACK_URL||'http://localhost:3000/auth/google/callback'},(at,rt,p,done)=>{const email=(p.emails?.[0]?.value||'').toLowerCase();done(null,{id:p.id,email,name:p.displayName,photo:p.photos?.[0]?.value||'',isOwner:email===OWNER});}));
app.get('/auth/google',(req,res,next)=>{if(!passport._strategy('google'))return res.status(503).send('Configure o Google OAuth no .env.');const hint=String(req.query.email||'').trim().toLowerCase();passport.authenticate('google',{scope:['profile','email'],prompt:'select_account',loginHint:hint||undefined})(req,res,next)});
app.get('/auth/google/callback',passport.authenticate('google',{failureRedirect:'/?login=failed'}),(req,res)=>{if(!isAuthorized(req.user.email)){return req.logout(()=>res.status(403).send('Acesso negado. Esta conta Google não foi autorizada pelo proprietário.'))}res.redirect('/');});
app.post('/api/auth/logout',(req,res)=>req.logout(()=>res.json({ok:true})));
app.get('/api/me',requireAuth,(req,res)=>res.json({loggedIn:true,user:{...req.user,isOwner:req.user.email===OWNER}}));
app.get('/api/withdraw-access',requireAuth,(req,res)=>res.json({allowed:true,email:req.user.email}));
app.post('/api/withdraw',requireAuth,(req,res)=>{const amount=Number(req.body.amount);if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'Valor inválido.'});res.status(501).json({error:'Gateway de saque ainda não conectado.',authorizedEmail:req.user.email});});
app.get('/api/permissions',requireOwner,(req,res)=>res.json({owner:OWNER,authorized:[OWNER,...loadPerms().filter(e=>e!==OWNER)]}));
app.post('/api/permissions',requireOwner,(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase();if(!/^[^\s@]+@gmail\.com$/i.test(email))return res.status(400).json({error:'Informe um Gmail válido.'});if(email===OWNER)return res.json({ok:true,authorized:[OWNER,...loadPerms().filter(e=>e!==OWNER)]});const list=loadPerms();if(!list.includes(email))list.push(email);savePerms(list);res.json({ok:true,authorized:[OWNER,...loadPerms().filter(e=>e!==OWNER)]});});
app.delete('/api/permissions/:email',requireOwner,(req,res)=>{const email=decodeURIComponent(req.params.email).toLowerCase();savePerms(loadPerms().filter(e=>e!==email));res.json({ok:true,authorized:[OWNER,...loadPerms().filter(e=>e!==OWNER)]});});
app.get('/api/private',requireAuth,(req,res)=>res.json({ok:true,message:'Área privada autorizada'}));
app.use((req,res,next)=>{if(req.path.startsWith('/auth/')||req.path.startsWith('/api/'))return next();if(!req.user)return res.redirect('/auth/google');if(!isAuthorized(req.user.email))return res.status(403).send('Acesso negado.');next()});
app.use(express.static(path.join(__dirname,'public')));app.listen(PORT,()=>console.log(`http://localhost:${PORT}`));
