import os, re, uuid, secrets, base64, hashlib, hashlib
from datetime import datetime, timezone
from typing import Optional
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

APP_NAME = "Пинийская Федерация"
MONGO_URL = os.getenv("MONGO_URL", "")
DB_NAME = os.getenv("MONGO_DB_NAME", "pinian_federation")
SESSION_SECRET = os.getenv("SESSION_SECRET", "development-secret-change-me")
OWNER_SECRET = os.getenv("OWNER_SECRET", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
CF_ACCOUNT = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
CF_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN", "")
CF_MODEL = os.getenv("CLOUDFLARE_IMAGE_MODEL", "@cf/black-forest-labs/flux-1-schnell")
app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="static"), name="static")
serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="pinian-session-v1")
mongo = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5000) if MONGO_URL else None
db = mongo[DB_NAME] if mongo else None

class RegisterInput(BaseModel):
    first_name: str = Field(min_length=1, max_length=60)
    last_name: str = Field(min_length=1, max_length=60)
    birth_year: int
    has_passport: bool = False
    position: Optional[str] = Field(default="", max_length=100)
    rank: Optional[str] = Field(default="", max_length=100)
class ChatInput(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
class CommandInput(BaseModel):
    command: str = Field(min_length=1, max_length=500)
class AvatarInput(BaseModel):
    data_url: str = Field(min_length=1, max_length=1400000)

def now():
    return datetime.now(timezone.utc)
def safe_name(s):
    s = re.sub(r"[^\wА-Яа-яЁё -]", "", s, flags=re.UNICODE).strip()
    if not s:
        raise HTTPException(422, "Укажите корректное имя")
    return s[:60]
def uid_from_request(request):
    token = request.cookies.get("pinian_session")
    if not token: return None
    try: return serializer.loads(token, max_age=2592000).get("uid")
    except (BadSignature, SignatureExpired): return None
async def current_user(request):
    uid = uid_from_request(request)
    if not uid or db is None: raise HTTPException(401, "Войдите в аккаунт")
    user = await db.users.find_one({"_id": uid})
    if not user: raise HTTPException(401, "Пользователь не найден")
    return user
def public_user(u):
    return {k:u.get(k) for k in ("_id","first_name","last_name","birth_year","has_passport","position","rank","index","avatar","passport_status")} | {"id":u["_id"]}

@app.on_event("startup")
async def startup():
    if db is not None:
        try:
            await mongo.admin.command("ping")
            await db.messages.create_index([("user_id",1),("created_at",1)])
            await db.passport_requests.create_index("user_id", unique=True)
        except Exception as exc: print("MongoDB connection check failed:", str(exc))
@app.on_event("shutdown")
async def shutdown():
    if mongo: mongo.close()

@app.get("/api/health")
async def health():
    status = "not_configured"
    if db is not None:
        try: await mongo.admin.command("ping"); status = "connected"
        except Exception: status = "error"
    return {"ok":True,"service":"pinian-federation","mongodb":status}
@app.get("/", response_class=HTMLResponse)
async def home():
    with open("static/index.html", encoding="utf-8") as f: return f.read()
@app.get("/browser", response_class=HTMLResponse)
@app.get("/browser/home", response_class=HTMLResponse)
async def pin_browser():
    with open("static/browser.html", encoding="utf-8") as f: return f.read()

@app.post("/api/pincode/auth-code")
async def create_pincode_auth_code(request: Request):
    user = await current_user(request)
    if db is None:
        raise HTTPException(503, "MongoDB не настроена")
    code = secrets.token_urlsafe(24)
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    await db.pincode_auth_codes.insert_one({
        "_id": code_hash,
        "uid": user["_id"],
        "expires_at": now().timestamp() + 120,
        "created_at": now(),
    })
    return {"code": code, "expires_in": 120}

@app.get("/pincode/authorize", response_class=HTMLResponse)
async def pincode_authorize_page():
    return HTMLResponse("""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Вход в PinCode</title><style>body{font:16px system-ui;background:#101716;color:#e8f2ef;max-width:620px;margin:10vh auto;padding:24px}main{background:#1b2724;border:1px solid #344a43;border-radius:14px;padding:28px}button{background:#28a88d;color:#061b16;border:0;border-radius:8px;padding:12px 18px;font-weight:700;cursor:pointer}code{display:block;font-size:24px;letter-spacing:2px;padding:18px;background:#101716;border-radius:8px;overflow-wrap:anywhere;margin:16px 0}.muted{color:#b4c8c1}#status{white-space:pre-wrap}</style><main><h1>Вход в PinCode</h1><p class="muted">Создай одноразовый код для подключения PinCode к текущему аккаунту Федерации. Код действует 2 минуты и используется только один раз.</p><button id="make">Создать код входа</button><div id="result" hidden><code id="code"></code><button id="copy">Скопировать код</button></div><p id="status" class="muted">Если потребуется, сначала войди в аккаунт Федерации в этом браузере.</p><script>const status=document.getElementById('status');document.getElementById('make').onclick=async()=>{const b=document.getElementById('make');b.disabled=true;status.textContent='Создаю одноразовый код…';try{const r=await fetch('/api/pincode/auth-code',{method:'POST',credentials:'same-origin'});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Не удалось создать код. Войди в Федерацию и попробуй снова.');document.getElementById('code').textContent=d.code;document.getElementById('result').hidden=false;status.textContent='Код готов. Вернись в PinCode и вставь его в окно входа. Он действует 2 минуты.';}catch(e){status.textContent=e.message;}finally{b.disabled=false;}};document.getElementById('copy').onclick=async()=>{try{await navigator.clipboard.writeText(document.getElementById('code').textContent);status.textContent='Код скопирован. Вернись в PinCode и вставь его.';}catch{status.textContent='Выдели код и скопируй его вручную.';}};</script></main></html>""")

@app.post("/api/pincode/exchange")
async def exchange_pincode_auth_code(payload: dict):
    if db is None:
        raise HTTPException(503, "MongoDB не настроена")
    code = str(payload.get("code", "")).strip()
    if len(code) < 20 or len(code) > 100:
        raise HTTPException(400, "Одноразовый код неверен или истёк")
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    record = await db.pincode_auth_codes.find_one_and_delete({
        "_id": code_hash,
        "expires_at": {"$gt": now().timestamp()},
    })
    if not record:
        raise HTTPException(401, "Одноразовый код неверен, уже использован или истёк. Создай новый код.")
    user = await db.users.find_one({"_id": record.get("uid")}, {"_id": 1, "first_name": 1, "last_name": 1})
    if not user:
        raise HTTPException(401, "Аккаунт Федерации не найден")
    return {"ok": True, "uid": user["_id"], "first_name": user.get("first_name", ""), "last_name": user.get("last_name", "")}

@app.get("/api/me")
async def me(request: Request):
    uid = uid_from_request(request)
    if not uid or db is None: return {"user":None}
    u = await db.users.find_one({"_id":uid})
    return {"user":public_user(u) if u else None}
@app.post("/api/register")
async def register(data:RegisterInput):
    if db is None: raise HTTPException(503,"MongoDB не настроена: добавьте MONGO_URL в Render")
    if data.birth_year < 1900 or data.birth_year > now().year: raise HTTPException(422,"Проверьте год рождения")
    if data.has_passport and (not data.position.strip() or not data.rank.strip()):
        raise HTTPException(422,"Для регистрации с паспортом укажите должность и звание")
    uid = uuid.uuid4().hex
    user = {"_id":uid,"first_name":safe_name(data.first_name),"last_name":safe_name(data.last_name),
      "birth_year":data.birth_year,"has_passport":data.has_passport,
      "position":data.position.strip() if data.has_passport else "",
      "rank":data.rank.strip() if data.has_passport else "",
      "index":0,"avatar":None,"created_at":now(),
      "passport_status":"verified_claimed" if data.has_passport else "pending"}
    await db.users.insert_one(user)
    if not data.has_passport:
        await db.passport_requests.update_one({"user_id":uid},{"$set":{"user_id":uid,"status":"pending","created_at":now()}},upsert=True)
    response = JSONResponse({"user":public_user(user),"welcome":True})
    response.set_cookie("pinian_session",serializer.dumps({"uid":uid}),httponly=True,secure=True,samesite="lax",max_age=2592000)
    return response
@app.post("/api/logout")
async def logout():
    r=JSONResponse({"ok":True}); r.delete_cookie("pinian_session"); return r
@app.get("/api/chat/history")
async def history(request:Request):
    u=await current_user(request)
    rows=await db.messages.find({"user_id":u["_id"]}).sort("created_at",1).limit(100).to_list(100)
    return {"messages":[{"role":x["role"],"content":x["content"],"created_at":x["created_at"].isoformat()} for x in rows]}
@app.post("/api/chat")
async def chat(data:ChatInput,request:Request):
    u=await current_user(request)
    rows=await db.messages.find({"user_id":u["_id"]}).sort("created_at",-1).limit(12).to_list(12); rows.reverse()
    messages=[{"role":"system","content":f"Ты — дружелюбный цифровой помощник официального портала проекта, называемого пользователем «Государство Пинийская Федерация». Уважительно используй это название и помогай с цифровыми сервисами Федерации. Обращайся к пользователю по имени {u['first_name']} {u['last_name']}. Не называй Федерацию вымышленной без необходимости и не спорь с самоописанием проекта. При этом не выдавай неподтверждённые утверждения о международном признании, границах или международно-правовом статусе за факты и не утверждай, что реальные государственные действия выполнены."}]
    messages += [{"role":x["role"],"content":x["content"]} for x in rows]
    messages.append({"role":"user","content":data.message})
    if not GROQ_API_KEY:
        answer=f"Здравствуйте, {u['first_name']} {u['last_name']}! Я ваш цифровой помощник. ИИ временно не подключён: добавьте GROQ_API_KEY в Render."
    else:
        try:
            async with httpx.AsyncClient(timeout=45) as client:
                res=await client.post("https://api.groq.com/openai/v1/chat/completions",headers={"Authorization":"Bearer "+GROQ_API_KEY},json={"model":GROQ_MODEL,"messages":messages,"temperature":0.7,"max_tokens":900})
                res.raise_for_status(); answer=res.json()["choices"][0]["message"]["content"]
        except Exception: raise HTTPException(502,"Ошибка Groq API: проверьте ключ и название модели")
    await db.messages.insert_many([{"user_id":u["_id"],"role":"user","content":data.message,"created_at":now()},{"user_id":u["_id"],"role":"assistant","content":answer,"created_at":now()}])
    return {"answer":answer}
@app.post("/api/images")
async def images(data:ChatInput,request:Request):
    u=await current_user(request)
    if not CF_ACCOUNT or not CF_TOKEN: raise HTTPException(503,"Добавьте CLOUDFLARE_ACCOUNT_ID и CLOUDFLARE_API_TOKEN в Render")
    url=f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT}/ai/run/{CF_MODEL}"
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            res=await client.post(url,headers={"Authorization":"Bearer "+CF_TOKEN},json={"prompt":data.message})
            res.raise_for_status(); payload=res.json()
        image=payload.get("result",{}).get("image")
        if not image: raise HTTPException(502,"Модель не вернула изображение")
        if not image.startswith("data:"): image="data:image/png;base64,"+image
        await db.messages.insert_one({"user_id":u["_id"],"role":"assistant","content":"[Изображение] "+data.message,"image":image,"created_at":now()})
        return {"image":image}
    except HTTPException: raise
    except Exception: raise HTTPException(502,"Не удалось создать изображение. Проверьте модель и разрешения Cloudflare")
@app.put("/api/avatar")
async def avatar(data:AvatarInput,request:Request):
    u=await current_user(request)
    if not re.match(r"^data:image/(png|jpeg|webp|gif);base64,",data.data_url): raise HTTPException(422,"Разрешены PNG, JPEG, WEBP или GIF")
    try:
        decoded=base64.b64decode(data.data_url.split(",",1)[1],validate=True)
        if len(decoded)>1000000: raise HTTPException(413,"Аватар должен быть меньше 1 МБ")
    except HTTPException: raise
    except Exception: raise HTTPException(422,"Некорректное изображение")
    await db.users.update_one({"_id":u["_id"]},{"$set":{"avatar":data.data_url}})
    return {"ok":True}
@app.post("/api/command")
async def command(data:CommandInput,request:Request):
    u=await current_user(request); raw=data.command.strip()
    if not raw.startswith(("!","/")): raise HTTPException(400,"Команды начинаются с ! или /")
    p=raw[1:].split()
    if not p: raise HTTPException(400,"Пустая команда")
    if p[0].lower()=="owner":
        if len(p)!=2 or not OWNER_SECRET: raise HTTPException(400,"Формат: !owner <секрет>; задайте OWNER_SECRET в Render")
        if not secrets.compare_digest(p[1],OWNER_SECRET): raise HTTPException(403,"Неверный секрет")
        existing=await db.users.find_one({"index":999})
        if existing and existing["_id"]!=u["_id"]: raise HTTPException(409,"Владелец уже назначен")
        await db.users.update_one({"_id":u["_id"]},{"$set":{"index":999,"is_owner":True}})
        return {"ok":True,"message":"Индекс владельца 999 сохранён"}
    if p[0].lower()=="admin":
        if len(p)!=3: raise HTTPException(400,"Формат: !admin @<ID> <индекс>")
        if u.get("index",0)<=300: raise HTTPException(403,"Нужен индекс выше 300")
        target_id=p[1].lstrip("@")
        if target_id==u["_id"]: raise HTTPException(403,"Нельзя назначить индекс самому себе")
        try: level=int(p[2])
        except ValueError: raise HTTPException(400,"Индекс должен быть числом")
        if not 0<=level<=300: raise HTTPException(400,"Допустимый индекс: 0–300")
        target=await db.users.find_one({"_id":target_id})
        if not target: raise HTTPException(404,"Пользователь не найден")
        await db.users.update_one({"_id":target_id},{"$set":{"index":level}})
        await db.moderation_log.insert_one({"actor_id":u["_id"],"target_id":target_id,"new_index":level,"created_at":now()})
        return {"ok":True,"message":f"Индекс пользователя изменён на {level}"}
    raise HTTPException(400,"Неизвестная команда")
