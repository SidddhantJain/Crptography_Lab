// Minimal client-side demo: salted SHA-256 + lockout
const U = {}; const MAX = 3, LOCK = 30_000;
const q = id => document.getElementById(id);
const salt = (n=16)=>{
  const c="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";let s="";
  for(let i=0;i<n;i++)
    s+=c[Math.random()*c.length|0];
  return s;};
const sha = async (t)=>{const b=new TextEncoder().encode(t);
  const d=await crypto.subtle.digest("SHA-256",b);
  return Array.from(new Uint8Array(d)).map(x=>x.toString(16).padStart(2,"0")).join("");};
const strong = pw => /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(pw);
async function signUp(){
  const u=q("signupUser").value.trim(), p=q("signupPass").value.trim(), m=q("signupMsg");
  if(!u||!p) return m.textContent="Enter username and password.", m.style.color="red";
  if(U[u]) return m.textContent="User already exists.", m.style.color="red";
  if(!strong(p)) return m.textContent="Use 8+ chars with letters & numbers.", m.style.color="red";
  const s=salt(), h=await sha(p+s); U[u]={h,s,a:0,t:0};
  m.textContent="Signup successful. You can login now."; m.style.color="green";
}
async function login(){
  const u=q("loginUser").value.trim(), p=q("loginPass").value.trim(), m=q("loginMsg"), r=U[u];
  if(!r) return m.textContent="User not found.", m.style.color="red";
  const now=Date.now(); if(r.t&&now<r.t){m.textContent=`Locked. Try in ${Math.ceil((r.t-now)/1000)}s.`; m.style.color="red"; return;}
  if(await sha(p+r.s)===r.h){ r.a=0; r.t=0; m.textContent="Login successful."; m.style.color="green"; }
  else { r.a=(r.a||0)+1; if(r.a>=MAX){ r.t=Date.now()+LOCK; m.textContent=`Too many attempts. Locked for ${LOCK/1000}s.`; }
         else { m.textContent=`Wrong password. Attempts: ${r.a}/${MAX}`; } m.style.color="red"; }
}
