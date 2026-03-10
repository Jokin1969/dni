from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Literal
import secrets
import time

app = FastAPI(title="DNI Match", docs_url=None, redoc_url=None)

ROOM_TTL_SECONDS = 6 * 60 * 60
rooms: dict[str, dict] = {}

HTML = r"""
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DNI Match</title>
  <style>
    :root {
      --bg: #0b1020;
      --card: #121932;
      --muted: #a7b1d1;
      --text: #eef2ff;
      --accent: #7c9cff;
      --border: #263155;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: linear-gradient(180deg, #0a0f1d, #10172e);
      color: var(--text);
    }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 24px; }
    h1, h2 { margin: 0 0 12px; }
    p { color: var(--muted); line-height: 1.5; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
      margin-top: 18px;
    }
    .card {
      background: rgba(18, 25, 50, 0.92);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.25);
    }
    label {
      display: block;
      margin: 12px 0 6px;
      font-size: 14px;
      color: #dbe4ff;
    }
    input, select, textarea {
      width: 100%;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: #0e1530;
      color: var(--text);
      outline: none;
    }
    textarea {
      min-height: 220px;
      resize: vertical;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    input[type="file"] {
      padding: 10px;
      background: transparent;
      border: 1px dashed var(--border);
    }
    button {
      border: 0;
      background: var(--accent);
      color: white;
      padding: 12px 16px;
      border-radius: 12px;
      cursor: pointer;
      font-weight: 600;
    }
    button.secondary { background: #253253; }
    button.ghost {
      background: transparent;
      border: 1px solid var(--border);
    }
    .row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 12px;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 8px 12px;
      color: #dbe4ff;
      font-size: 13px;
      background: rgba(14, 21, 48, 0.8);
    }
    .status {
      margin-top: 12px;
      padding: 12px 14px;
      border-radius: 12px;
      background: #0e1530;
      border: 1px solid var(--border);
      white-space: pre-wrap;
      color: #d9e3ff;
      min-height: 50px;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      word-break: break-all;
    }
    ul.matches {
      margin: 12px 0 0;
      padding-left: 18px;
    }
    .muted { color: var(--muted); }
    .small { font-size: 13px; }
    .hero { margin-bottom: 18px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>DNI Match</h1>
      <p>
        Sube dos listados y obtén solo las coincidencias. Los DNIs se tokenizan en tu navegador con HMAC-SHA-256 usando una clave compartida;
        el servidor recibe solo tokens y compara intersecciones.
      </p>
      <div class="row">
        <span class="pill">No sube DNIs en claro</span>
        <span class="pill">Cada lado solo ve sus coincidencias</span>
        <span class="pill">Usa una clave nueva en cada cruce</span>
      </div>
    </div>

    <div class="grid">
      <section class="card">
        <h2>1) Crear sala</h2>
        <p class="small">Crea una sala nueva y comparte con la otra parte el room id, su lado y su access code.</p>
        <div class="row">
          <button id="createRoomBtn">Crear sala</button>
        </div>
        <div id="createRoomOut" class="status">Todavía no has creado ninguna sala.</div>
      </section>

      <section class="card">
        <h2>2) Entrar y subir tu lista</h2>

        <label for="roomId">Room ID</label>
        <input id="roomId" placeholder="Ej. AbC123xyz" />

        <label for="side">Lado</label>
        <select id="side">
          <option value="A">A</option>
          <option value="B">B</option>
        </select>

        <label for="accessCode">Access code</label>
        <input id="accessCode" placeholder="Código de acceso de tu lado" />

        <label for="secret">Clave compartida</label>
        <input id="secret" placeholder="La misma para ambos lados en este cruce" />
        <div class="row">
          <button class="secondary" id="genSecretBtn" type="button">Generar clave aleatoria</button>
        </div>

        <label for="dniFile">Fichero .txt con un DNI por línea</label>
        <input id="dniFile" type="file" accept=".txt" />

        <label for="dniText">O pega aquí la lista</label>
        <textarea id="dniText" placeholder="12345678Z&#10;87654321X"></textarea>

        <div class="row">
          <button id="uploadBtn">Tokenizar y subir</button>
          <button class="secondary" id="statusBtn" type="button">Ver estado</button>
          <button class="ghost" id="clearLocalBtn" type="button">Borrar estado local</button>
        </div>

        <div id="uploadOut" class="status">Aquí verás el resultado de la subida.</div>
      </section>
    </div>

    <div class="grid">
      <section class="card">
        <h2>3) Obtener coincidencias</h2>
        <p class="small">Cuando ambos lados hayan subido sus tokens, pulsa este botón. El servidor devolverá solo los tokens que coinciden y tu navegador los traducirá a tus DNIs localmente.</p>
        <div class="row">
          <button id="matchesBtn">Ver mis coincidencias</button>
          <button class="secondary" id="downloadBtn" type="button">Descargar coincidencias.txt</button>
        </div>
        <div id="matchesOut" class="status">Aún no has pedido coincidencias.</div>
        <ul id="matchesList" class="matches"></ul>
      </section>

      <section class="card">
        <h2>Notas</h2>
        <p class="small">
          Esta demo valida DNIs españoles con 8 dígitos y letra. La letra se comprueba automáticamente.
          El servidor guarda los tokens en memoria durante 6 horas o hasta que reinicies la app.
        </p>
        <p class="small">
          Recomendaciones: usa una clave nueva en cada cruce, pásala por un canal distinto al room id, y no reutilices salas antiguas.
        </p>
        <div id="tips" class="status">Primero crea la sala. Luego cada lado entra con su access code, pega o sube su lista y pulsa “Tokenizar y subir”. Por último, cada uno pulsa “Ver mis coincidencias” y, si quiere, las descarga.</div>
      </section>
    </div>
  </div>

<script>
const LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";
let lastMatches = [];

function setStatus(id, msg) {
  document.getElementById(id).textContent = msg;
}

function storageKey(roomId, side) {
  return `dni-match:${roomId}:${side}`;
}

function normalizeDni(raw) {
  const dni = raw.trim().toUpperCase().replace(/[\s-]/g, "");
  if (!dni) return null;
  if (!/^\d{8}[A-Z]$/.test(dni)) throw new Error(`Formato inválido: ${raw}`);
  const num = parseInt(dni.slice(0, 8), 10);
  const letter = dni.slice(8);
  const expected = LETTERS[num % 23];
  if (letter !== expected) throw new Error(`Letra incorrecta en: ${raw}`);
  return dni;
}

function parseDniList(text) {
  const lines = text.split(/\r?\n/);
  const dnis = [];
  const errors = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const dni = normalizeDni(line);
      if (dni) dnis.push(dni);
    } catch (err) {
      errors.push(`Línea ${i + 1}: ${err.message}`);
    }
  }
  return { dnis: [...new Set(dnis)], errors };
}

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function hmacHex(key, message) {
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(sig);
}

async function tokenizeDnis(secret, dnis) {
  const key = await importHmacKey(secret);
  const tokenToDni = {};
  const tokens = [];
  for (const dni of dnis) {
    const token = await hmacHex(key, dni);
    tokenToDni[token] = dni;
    tokens.push(token);
  }
  return { tokens: [...new Set(tokens)].sort(), tokenToDni };
}

async function jsonFetch(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "Error de servidor");
  return data;
}

async function createRoom() {
  const data = await jsonFetch("/api/rooms", { method: "POST", body: "{}" });
  const msg = [
    `Room ID: ${data.room_id}`,
    `Lado A -> access code: ${data.access_a}`,
    `Lado B -> access code: ${data.access_b}`,
    "",
    "Comparte con la otra parte: room id + su lado + su access code."
  ].join("\n");
  setStatus("createRoomOut", msg);
  document.getElementById("roomId").value = data.room_id;
  document.getElementById("side").value = "A";
  document.getElementById("accessCode").value = data.access_a;
}

function getFormState() {
  return {
    roomId: document.getElementById("roomId").value.trim(),
    side: document.getElementById("side").value,
    accessCode: document.getElementById("accessCode").value.trim(),
    secret: document.getElementById("secret").value
  };
}

async function uploadList() {
  const { roomId, side, accessCode, secret } = getFormState();
  const text = document.getElementById("dniText").value;
  if (!roomId || !accessCode || !secret) throw new Error("Completa room id, access code y clave compartida.");

  const { dnis, errors } = parseDniList(text);
  if (errors.length) throw new Error(errors.slice(0, 8).join("\n"));
  if (!dnis.length) throw new Error("No hay DNIs válidos para subir.");

  setStatus("uploadOut", `Tokenizando ${dnis.length} DNIs en tu navegador...`);
  const { tokens, tokenToDni } = await tokenizeDnis(secret, dnis);
  localStorage.setItem(storageKey(roomId, side), JSON.stringify(tokenToDni));

  const data = await jsonFetch(`/api/rooms/${roomId}/upload`, {
    method: "POST",
    body: JSON.stringify({ side, access_code: accessCode, tokens })
  });

  setStatus(
    "uploadOut",
    [
      `Subidos ${tokens.length} tokens del lado ${side}.`,
      data.ready ? `Ambos lados listos. Coincidencias: ${data.match_count}` : "Esperando a que el otro lado suba su lista.",
      "Tus DNIs siguen solo en este navegador."
    ].join("\n")
  );
}

async function checkStatus() {
  const { roomId, side, accessCode } = getFormState();
  if (!roomId || !accessCode) throw new Error("Completa room id y access code.");

  const data = await jsonFetch(`/api/rooms/${roomId}/status`, {
    method: "POST",
    body: JSON.stringify({ side, access_code: accessCode })
  });

  setStatus(
    "uploadOut",
    [
      `Tu lado (${side}) ha subido: ${data.me_uploaded ? "sí" : "no"}`,
      `El otro lado ha subido: ${data.other_uploaded ? "sí" : "no"}`,
      data.ready ? `Coincidencias disponibles: ${data.match_count}` : "Aún no están ambos lados listos."
    ].join("\n")
  );
}

async function getMatches() {
  const { roomId, side, accessCode } = getFormState();
  if (!roomId || !accessCode) throw new Error("Completa room id y access code.");

  const data = await jsonFetch(`/api/rooms/${roomId}/matches`, {
    method: "POST",
    body: JSON.stringify({ side, access_code: accessCode })
  });

  if (!data.ready) {
    lastMatches = [];
    setStatus("matchesOut", "Todavía no están ambos lados listos.");
    document.getElementById("matchesList").innerHTML = "";
    return;
  }

  const mapRaw = localStorage.getItem(storageKey(roomId, side));
  if (!mapRaw) throw new Error("No encuentro tu mapa local. Sube tu lista desde este navegador antes de pedir coincidencias.");

  const tokenToDni = JSON.parse(mapRaw);
  const myDnis = data.matches.map(t => tokenToDni[t]).filter(Boolean).sort();
  lastMatches = myDnis;

  setStatus("matchesOut", `Coincidencias encontradas: ${myDnis.length}`);
  document.getElementById("matchesList").innerHTML = myDnis.length
    ? myDnis.map(dni => `<li><span class="mono">${dni}</span></li>`).join("")
    : "<li class='muted'>No hay coincidencias.</li>";
}

function downloadMatches() {
  if (!lastMatches.length) {
    setStatus("matchesOut", "No hay coincidencias cargadas para descargar.");
    return;
  }
  const blob = new Blob([lastMatches.join("\n") + "\n"], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "coincidencias.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function clearLocal() {
  const { roomId, side } = getFormState();
  if (roomId && side) localStorage.removeItem(storageKey(roomId, side));
  lastMatches = [];
  document.getElementById("dniText").value = "";
  document.getElementById("matchesList").innerHTML = "";
  setStatus("uploadOut", "Estado local borrado en este navegador.");
  setStatus("matchesOut", "Aún no has pedido coincidencias.");
}

function generateSecret() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  document.getElementById("secret").value = [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

document.getElementById("createRoomBtn").addEventListener("click", async () => {
  try { await createRoom(); } catch (err) { setStatus("createRoomOut", err.message || String(err)); }
});
document.getElementById("uploadBtn").addEventListener("click", async () => {
  try { await uploadList(); } catch (err) { setStatus("uploadOut", err.message || String(err)); }
});
document.getElementById("statusBtn").addEventListener("click", async () => {
  try { await checkStatus(); } catch (err) { setStatus("uploadOut", err.message || String(err)); }
});
document.getElementById("matchesBtn").addEventListener("click", async () => {
  try { await getMatches(); } catch (err) { setStatus("matchesOut", err.message || String(err)); }
});
document.getElementById("downloadBtn").addEventListener("click", downloadMatches);
document.getElementById("clearLocalBtn").addEventListener("click", clearLocal);
document.getElementById("genSecretBtn").addEventListener("click", generateSecret);
document.getElementById("dniFile").addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  document.getElementById("dniText").value = await file.text();
});
</script>
</body>
</html>
"""


class UploadPayload(BaseModel):
    side: Literal["A", "B"]
    access_code: str
    tokens: list[str]


class QueryPayload(BaseModel):
    side: Literal["A", "B"]
    access_code: str


def cleanup_rooms() -> None:
    now = time.time()
    expired = [room_id for room_id, room in rooms.items() if now - room["created_at"] > ROOM_TTL_SECONDS]
    for room_id in expired:
        rooms.pop(room_id, None)


def get_room(room_id: str) -> dict:
    cleanup_rooms()
    room = rooms.get(room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada o caducada")
    return room


def check_access(room: dict, side: str, access_code: str) -> None:
    if room[side]["access_code"] != access_code:
        raise HTTPException(status_code=403, detail="Access code incorrecto")


def other_side(side: str) -> str:
    return "B" if side == "A" else "A"


def validate_tokens(tokens: list[str]) -> list[str]:
    cleaned = []
    seen = set()
    for tok in tokens:
        tok = tok.strip().lower()
        if len(tok) != 64 or any(ch not in "0123456789abcdef" for ch in tok):
            raise HTTPException(status_code=400, detail="Hay tokens con formato inválido")
        if tok not in seen:
            seen.add(tok)
            cleaned.append(tok)
    return cleaned


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    cleanup_rooms()
    return HTML


@app.post("/api/rooms")
def create_room():
    cleanup_rooms()
    room_id = secrets.token_urlsafe(8)
    room = {
        "created_at": time.time(),
        "A": {"access_code": secrets.token_urlsafe(12), "tokens": None},
        "B": {"access_code": secrets.token_urlsafe(12), "tokens": None},
    }
    rooms[room_id] = room
    return {
        "room_id": room_id,
        "access_a": room["A"]["access_code"],
        "access_b": room["B"]["access_code"],
        "ttl_hours": ROOM_TTL_SECONDS // 3600,
    }


@app.post("/api/rooms/{room_id}/upload")
def upload_tokens(room_id: str, payload: UploadPayload):
    room = get_room(room_id)
    check_access(room, payload.side, payload.access_code)
    tokens = set(validate_tokens(payload.tokens))
    room[payload.side]["tokens"] = tokens

    a = room["A"]["tokens"]
    b = room["B"]["tokens"]
    ready = a is not None and b is not None
    match_count = len(a & b) if ready else 0
    return {"ok": True, "ready": ready, "match_count": match_count}


@app.post("/api/rooms/{room_id}/status")
def room_status(room_id: str, payload: QueryPayload):
    room = get_room(room_id)
    check_access(room, payload.side, payload.access_code)

    mine = room[payload.side]["tokens"]
    other = room[other_side(payload.side)]["tokens"]
    ready = mine is not None and other is not None
    match_count = len(mine & other) if ready else 0
    return {
        "me_uploaded": mine is not None,
        "other_uploaded": other is not None,
        "ready": ready,
        "match_count": match_count,
    }


@app.post("/api/rooms/{room_id}/matches")
def room_matches(room_id: str, payload: QueryPayload):
    room = get_room(room_id)
    check_access(room, payload.side, payload.access_code)

    mine = room[payload.side]["tokens"]
    other = room[other_side(payload.side)]["tokens"]
    if mine is None or other is None:
        return {"ready": False, "matches": []}

    matches = sorted(mine & other)
    return {"ready": True, "matches": matches, "match_count": len(matches)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
