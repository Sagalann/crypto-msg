import os, json, time, base64, secrets, string, hashlib, math, threading
import requests
from flask import Flask, request, jsonify, render_template
from crypto import *

app = Flask(__name__)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "сюда_вставь_ключ")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"
BOT_ID       = "Crypto_Assistor"
SYSTEM_PROMPT = (
    "Ты Crypto Assistant — помощник по криптографии и кибербезопасности. "
    "Отвечай кратко. Используй HTML: <b>жирный</b>, <code>код</code>, <br>. "
    "Не используй markdown."
)

users      = {}
messages   = {}   # { recipient_id: [ {from, ciphertext, timestamp} ] }
profiles   = {}
user_keys  = {}
passwords  = {}   # { user_id: sha256_hex }
chat_msgs  = {}   # { "user1:user2": [ {from, text, ts} ] }  — открытый текст для истории

bot_priv, bot_pub = generate_identity_keypair()
users[BOT_ID]    = b64_encode_key(bot_pub)
messages[BOT_ID] = []
profiles[BOT_ID] = {"display_name":"Crypto Assistant","avatar":"🤖","status":"E2EE · всегда онлайн","theme":"dark"}

@app.route('/')
def index():
    return render_template('chat.html')

def chat_key(a, b):
    return ':'.join(sorted([a, b]))

@app.post('/login')
def login():
    data     = request.json
    uid      = data.get('user_id', '').strip()
    password = data.get('password', '').strip()
    if not uid or not password:
        return jsonify({"status":"error","message":"Введите ник и пароль"}), 400

    pwd_hash = hashlib.sha256(password.encode()).hexdigest()

    # Новый пользователь — регистрируем
    if uid not in passwords:
        passwords[uid] = pwd_hash
        priv, pub = generate_identity_keypair()
        user_keys[uid] = b64_encode_key(priv)
        users[uid]     = b64_encode_key(pub)
        if uid not in messages:  messages[uid] = []
        if uid not in profiles:  profiles[uid] = {"display_name":uid,"avatar":"🙂","status":"","theme":"dark"}
        return jsonify({"status":"ok","user_id":uid,"new":True})

    # Существующий — проверяем пароль
    if passwords[uid] != pwd_hash:
        return jsonify({"status":"error","message":"Неверный пароль"}), 401

    if uid not in messages:  messages[uid] = []
    if uid not in profiles:  profiles[uid] = {"display_name":uid,"avatar":"🙂","status":"","theme":"dark"}
    return jsonify({"status":"ok","user_id":uid,"new":False})

@app.post('/register')
def register():
    data = request.json
    uid  = data['user_id']
    users[uid] = data['identity_key']
    if uid not in messages: messages[uid] = []
    if uid not in profiles: profiles[uid] = {"display_name":uid,"avatar":"🙂","status":"","theme":"dark"}
    return jsonify({"status":"ok"})

@app.get('/users')
def list_users():
    return jsonify(list(users.keys()))

@app.get('/public_key/<user_id>')
def get_key(user_id):
    return jsonify({"public_key": users.get(user_id)})

@app.post('/send')
def send():
    data   = request.json
    to     = data['to']
    sender = data['from']
    if to not in messages: messages[to] = []

    if 'message' in data:
        # Сохраняем в открытую историю чата
        ck = chat_key(sender, to)
        if ck not in chat_msgs: chat_msgs[ck] = []
        chat_msgs[ck].append({"from": sender, "text": data['message'], "ts": time.time()})

        # Шифруем для E2EE доставки
        if sender in user_keys and to in users:
            try:
                priv          = b64_decode_private_key(user_keys[sender])
                recipient_pub = b64_decode_public_key(users[to])
                ct            = encrypt_message(priv, recipient_pub, data['message'])
                messages[to].append({"from":sender,"ciphertext":ct,"timestamp":time.time()})
            except Exception as e:
                print(f"Encrypt error: {e}")
        else:
            messages[to].append({"from":sender,"ciphertext":data['message'],"timestamp":time.time()})
    elif 'ciphertext' in data:
        messages[to].append({"from":sender,"ciphertext":data['ciphertext'],"timestamp":time.time()})

    return jsonify({"status":"sent"})

@app.get('/messages/<user_id>')
def get_msgs(user_id):
    msgs = messages.get(user_id,[]).copy()
    messages[user_id] = []
    return jsonify(msgs)
@app.get('/chat_history')
def chat_history_route():
    uid   = request.args.get('user_id', '')
    other = request.args.get('other', '')
    if not uid or not other or uid not in user_keys:
        return jsonify([])
    ck = ':'.join(sorted([uid, other]))
    return jsonify(chat_msgs.get(ck, []))


@app.get('/get_messages')
def get_messages_route():
    uid = request.args.get('user_id','')
    if not uid or uid not in user_keys: return jsonify([])
    raw = messages.get(uid,[]).copy()
    messages[uid] = []
    priv   = b64_decode_private_key(user_keys[uid])
    result = []
    for m in raw:
        try:
            sender_pub = b64_decode_public_key(users[m['from']])
            text = decrypt_message(priv, sender_pub, m['ciphertext'])
            result.append({"from":m['from'],"text":text})
        except Exception as e:
            print(f"Decrypt error: {e}")
    return jsonify(result)

@app.get('/profile/<user_id>')
def get_profile(user_id):
    p = profiles.get(user_id)
    if not p: return jsonify({"error":"not found"}), 404
    return jsonify(p)

@app.post('/profile/<user_id>')
def set_profile(user_id):
    if user_id not in profiles:
        profiles[user_id] = {"display_name":user_id,"avatar":"🙂","status":"","theme":"dark"}
    data = request.json
    for key in ["display_name","avatar","status","theme"]:
        if key in data: profiles[user_id][key] = data[key]
    return jsonify({"status":"ok","profile":profiles[user_id]})

@app.get('/profiles')
def get_all_profiles():
    return jsonify({uid:{"display_name":p["display_name"],"avatar":p["avatar"],"status":p["status"]} for uid,p in profiles.items()})

def groq_request(history):
    resp = requests.post(GROQ_URL,
        headers={"Authorization":f"Bearer {GROQ_API_KEY}","Content-Type":"application/json"},
        json={"model":GROQ_MODEL,"messages":history,"max_tokens":1024},timeout=20)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]

chat_history = {}

def menu():
    return ("<b>🤖 Crypto Assistant v4.6</b><br><br><div class='bot-menu'>"
        "<button class='menu-btn' onclick='fillCmd(\"hash \")'>#️⃣ Hash</button>"
        "<button class='menu-btn' onclick='sendCmd(\"pass\")'>🔐 Pass</button>"
        "<button class='menu-btn' onclick='fillCmd(\"stego hide \")'>📦 Hide</button>"
        "<button class='menu-btn' onclick='fillCmd(\"stego reveal \")'>🔓 Reveal</button>"
        "<button class='menu-btn' onclick='fillCmd(\"encrypt \")'>📥 Enc</button>"
        "<button class='menu-btn' onclick='fillCmd(\"decrypt \")'>📤 Dec</button>"
        "<button class='menu-btn' onclick='fillCmd(\"entropy \")'>📊 Entropy</button>"
        "<button class='menu-btn' onclick='fillCmd(\"caesar enc 3 \")'>🔤 Caesar</button>"
        "<button class='menu-btn' onclick='sendCmd(\"keygen\")'>🗝️ Keygen</button>"
        "<button class='menu-btn full' onclick='sendCmd(\"info\")'>ℹ️ Info</button></div>")

def try_builtin(raw):
    t=raw.strip(); tl=t.lower()
    if tl in ["/help","help","❓","меню","/start"]: return menu()
    if tl=="info": return "🛡️ <b>Архитектура:</b><br>• E2EE<br>• Curve25519<br>• XSalsa20-Poly1305<br>• Стеганография<br>• AI: Llama 3.3 70B"
    if tl.startswith("hash "): return f"#️⃣ <b>SHA256:</b><br><code>{hashlib.sha256(t[5:].strip().encode()).hexdigest()}</code>"
    if tl.startswith("encrypt "): return f"📥 <b>Base64:</b><br><code>{base64.b64encode(t[8:].encode()).decode()}</code>"
    if tl.startswith("decrypt "):
        try: return f"📤 <b>Decoded:</b><br>{base64.b64decode(t[8:].encode()).decode()}"
        except: return "❌ Ошибка"
    if tl.startswith("entropy "):
        d=t[8:]; c=len(set(d)); e=len(d)*math.log2(c) if c>1 else len(d)
        return f"📊 <b>Энтропия:</b> {e:.2f} бит"
    if tl.startswith("stego hide "):
        s=t[11:]; b=''.join(format(ord(c),'08b') for c in s)
        return f"<b>Скрытое:</b><div class='stego-copy-box'>SAFE{''.join(chr(0x200b) if x=='0' else chr(0x200c) for x in b)}</div>"
    if tl.startswith("stego reveal "):
        bits="".join('0' if c=='\u200b' else '1' for c in t if c in['\u200b','\u200c'])
        try: return f"<b>Раскрыто:</b> <code>{''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8))}</code>"
        except: return "Скрытых данных не найдено"
    if tl.startswith("caesar enc "):
        try:
            p=t.split(" ",3); sh=int(p[2])
            return f"🔤 <code>{''.join(chr((ord(c)-65+sh)%26+65) if c.isupper() else chr((ord(c)-97+sh)%26+97) if c.islower() else c for c in p[3])}</code>"
        except: return "caesar enc 3 hello"
    if tl=="pass": return f"🔐 <code>{''.join(secrets.choice(string.ascii_letters+string.digits+'!@#$%') for _ in range(16))}</code>"
    if tl=="keygen": _,pb=generate_identity_keypair(); return f"🗝️ <code>{b64_encode_key(pb)}</code>"
    return None

def ask_ai(sender, message):
    if sender not in chat_history:
        chat_history[sender]=[{"role":"system","content":SYSTEM_PROMPT}]
    chat_history[sender].append({"role":"user","content":message})
    for attempt in range(3):
        try:
            reply=groq_request(chat_history[sender])
            chat_history[sender].append({"role":"assistant","content":reply})
            if len(chat_history[sender])>21:
                chat_history[sender]=[chat_history[sender][0]]+chat_history[sender][-20:]
            return reply
        except Exception as e:
            print(f"AI попытка {attempt+1}: {e}")
            if "429" in str(e): time.sleep(5)
            else: break
    chat_history[sender].pop()
    return "⚠️ AI перегружен, попробуй через 10 сек"

def bot_loop():
    print("🤖 Бот запущен")
    while True:
        try:
            pending=messages.get(BOT_ID,[]).copy()
            if pending:
                messages[BOT_ID]=[]
                for m in pending:
                    sender=m['from']
                    if sender not in users: continue
                    try:
                        sender_pub=b64_decode_public_key(users[sender])
                        income=decrypt_message(bot_priv,sender_pub,m['ciphertext'])
                        reply=try_builtin(income) or ask_ai(sender,income)
                        ct=encrypt_message(bot_priv,sender_pub,reply)
                        if sender not in messages: messages[sender]=[]
                        messages[sender].append({"from":BOT_ID,"ciphertext":ct,"timestamp":time.time()})
                    except Exception as e: print(f"Bot msg error: {e}")
        except Exception as e: print(f"Bot loop error: {e}")
        time.sleep(1)

threading.Thread(target=bot_loop,daemon=True).start()

if __name__=='__main__':
    port=int(os.environ.get("PORT",5000))
    app.run(host='0.0.0.0',port=port)
