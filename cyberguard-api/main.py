from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import hashlib, base64, re, math, secrets, string
import time, logging, json
from datetime import datetime
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.FileHandler("audit.log"), logging.StreamHandler()]
)
logger = logging.getLogger("CyberGuard")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="CyberGuard API",
    description="API de herramientas de ciberseguridad desarrollada con FastAPI. Incluye modulos para analisis de contrasenas, hashes, URLs, tokens JWT, entropia y direcciones IP.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 2)
    logger.info(f"{request.method} {request.url.path} | {response.status_code} | {duration}ms | IP:{request.client.host}")
    return response


class PasswordRequest(BaseModel):
    password: str = Field(..., min_length=1, example="MyP@ssw0rd123!")

class HashRequest(BaseModel):
    text: str = Field(..., example="Hello World")
    algorithm: str = Field("sha256", example="sha256")

class URLRequest(BaseModel):
    url: str = Field(..., example="https://example.com/login?token=abc123")

class JWTRequest(BaseModel):
    token: str = Field(..., example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

class TextRequest(BaseModel):
    text: str = Field(..., example="aGVsbG8gd29ybGQ=")

class IPRequest(BaseModel):
    ip: str = Field(..., example="8.8.8.8")

class PasswordGenRequest(BaseModel):
    length: int = Field(16, ge=8, le=128)
    use_symbols: bool = True
    use_numbers: bool = True
    use_uppercase: bool = True


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    n = len(text)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def estimate_crack_time(password: str) -> str:
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    combinations = charset ** len(password)
    seconds = combinations / 1_000_000_000
    if seconds < 1: return "Instantaneo"
    if seconds < 60: return f"{int(seconds)} segundos"
    if seconds < 3600: return f"{int(seconds/60)} minutos"
    if seconds < 86400: return f"{int(seconds/3600)} horas"
    if seconds < 31536000: return f"{int(seconds/86400)} dias"
    if seconds < 3153600000: return f"{int(seconds/31536000)} anos"
    return "Siglos (muy seguro)"


COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "abc123",
    "111111", "letmein", "welcome", "monkey", "dragon",
    "master", "admin", "login", "pass", "1234", "12345678"
}

SUSPICIOUS_URL_PATTERNS = [
    r'paypal.*login', r'bank.*secure', r'verify.*account',
    r'update.*payment', r'confirm.*identity', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'bit\.ly|tinyurl|goo\.gl|t\.co',
    r'secure.*-.*login', r'account.*-.*verify',
]

HASH_PATTERNS = {
    r'^[a-f0-9]{32}$': "MD5",
    r'^[a-f0-9]{40}$': "SHA-1",
    r'^[a-f0-9]{56}$': "SHA-224",
    r'^[a-f0-9]{64}$': "SHA-256",
    r'^[a-f0-9]{96}$': "SHA-384",
    r'^[a-f0-9]{128}$': "SHA-512",
    r'^\$2[ayb]\$.{56}$': "bcrypt",
    r'^\$argon2': "Argon2",
    r'^\$6\$': "SHA-512-crypt (Linux)",
    r'^\$1\$': "MD5-crypt",
}


@app.get("/", tags=["Info"])
async def root():
    return {
        "api": "CyberGuard API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "modules": [
            "/api/v1/password/analyze",
            "/api/v1/password/breach",
            "/api/v1/password/generate",
            "/api/v1/hash/identify",
            "/api/v1/hash/generate",
            "/api/v1/url/analyze",
            "/api/v1/jwt/decode",
            "/api/v1/text/entropy",
            "/api/v1/crypto/keygen",
            "/api/v1/ip/analyze",
        ],
        "docs": "/docs"
    }


@app.post("/api/v1/password/analyze", tags=["Password"])
@limiter.limit("30/minute")
async def analyze_password(req: PasswordRequest, request: Request):
    pwd = req.password
    score = 0
    issues = []
    suggestions = []

    has_lower = bool(re.search(r'[a-z]', pwd))
    has_upper = bool(re.search(r'[A-Z]', pwd))
    has_digit = bool(re.search(r'\d', pwd))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', pwd))
    is_common = pwd.lower() in COMMON_PASSWORDS

    if len(pwd) >= 8: score += 1
    if len(pwd) >= 12: score += 1
    if len(pwd) >= 16: score += 1
    if has_lower: score += 1
    if has_upper: score += 1
    if has_digit: score += 1
    if has_symbol: score += 2
    if is_common:
        score -= 4
        issues.append("Contrasena extremadamente comun")

    if len(pwd) < 8: suggestions.append("Usa al menos 8 caracteres")
    if not has_upper: suggestions.append("Agrega letras mayusculas")
    if not has_lower: suggestions.append("Agrega letras minusculas")
    if not has_digit: suggestions.append("Agrega numeros")
    if not has_symbol: suggestions.append("Agrega simbolos (!@#$%)")

    score = max(0, min(score, 10))
    strength_map = {
        (0, 2): "Muy Debil",
        (3, 4): "Debil",
        (5, 6): "Moderada",
        (7, 8): "Fuerte",
        (9, 10): "Muy Fuerte"
    }
    strength = next(v for k, v in strength_map.items() if k[0] <= score <= k[1])

    return {
        "password_length": len(pwd),
        "score": f"{score}/10",
        "strength": strength,
        "entropy_bits": shannon_entropy(pwd),
        "crack_time_estimate": estimate_crack_time(pwd),
        "checks": {
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "is_common_password": is_common,
            "length_ok": len(pwd) >= 8,
        },
        "issues": issues,
        "suggestions": suggestions,
        "analyzed_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/password/breach", tags=["Password"])
@limiter.limit("10/minute")
async def check_breach(req: PasswordRequest, request: Request):
    sha1_hash = hashlib.sha1(req.password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"}
            )
        hashes = {line.split(":")[0]: int(line.split(":")[1])
                  for line in resp.text.splitlines()}
        count = hashes.get(suffix, 0)
        breached = count > 0
    except Exception:
        return {"error": "No se pudo conectar a HaveIBeenPwned"}

    if count > 100:
        risk = "CRITICO - Cambia esta contrasena de inmediato"
    elif breached:
        risk = "ALTO - Contrasena comprometida"
    else:
        risk = "No encontrada en brechas conocidas"

    return {
        "breached": breached,
        "times_seen": count,
        "risk": risk,
        "sha1_prefix_used": prefix,
        "note": "Verificacion via HaveIBeenPwned usando protocolo k-anonymity. La contrasena nunca se transmite.",
        "checked_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/password/generate", tags=["Password"])
@limiter.limit("50/minute")
async def generate_password(req: PasswordGenRequest, request: Request):
    chars = string.ascii_lowercase
    if req.use_uppercase: chars += string.ascii_uppercase
    if req.use_numbers: chars += string.digits
    if req.use_symbols: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    password = ''.join(secrets.choice(chars) for _ in range(req.length))
    return {
        "password": password,
        "length": req.length,
        "entropy_bits": shannon_entropy(password),
        "crack_time": estimate_crack_time(password),
        "generated_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/hash/identify", tags=["Hash"])
async def identify_hash(data: dict):
    hash_value = data.get("hash", "").strip()
    if not hash_value:
        raise HTTPException(status_code=400, detail="Proporciona un valor 'hash'")

    detected = []
    for pattern, name in HASH_PATTERNS.items():
        if re.match(pattern, hash_value, re.IGNORECASE):
            detected.append(name)

    return {
        "hash": hash_value,
        "length": len(hash_value),
        "possible_types": detected if detected else ["Desconocido o formato invalido"],
        "is_hex": bool(re.match(r'^[a-f0-9]+$', hash_value, re.IGNORECASE)),
        "is_base64": bool(re.match(r'^[A-Za-z0-9+/=]+$', hash_value)),
    }


@app.post("/api/v1/hash/generate", tags=["Hash"])
async def generate_hash(req: HashRequest):
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "sha3_512": hashlib.sha3_512,
        "blake2b": hashlib.blake2b,
    }

    algo = req.algorithm.lower()
    if algo not in algorithms:
        raise HTTPException(status_code=400,
            detail=f"Algoritmo no soportado. Opciones disponibles: {', '.join(algorithms.keys())}")

    text_bytes = req.text.encode("utf-8")
    return {
        "input": req.text,
        "algorithm": algo.upper(),
        "hash": algorithms[algo](text_bytes).hexdigest(),
        "input_bytes": len(text_bytes),
        "all_hashes": {k: v(text_bytes).hexdigest() for k, v in algorithms.items()},
        "generated_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/url/analyze", tags=["URL"])
@limiter.limit("20/minute")
async def analyze_url(req: URLRequest, request: Request):
    url = req.url.lower()
    flags = []
    score = 0

    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            flags.append(f"Patron sospechoso detectado: {pattern}")
            score += 2

    has_https = url.startswith("https://")
    has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
    has_port = bool(re.search(r':\d{2,5}/', url))
    subdomain_count = len(url.split("//")[-1].split(".")) - 2
    has_suspicious_tld = any(url.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq'])
    long_url = len(url) > 100
    has_at = '@' in url
    double_slash = '//' in url[8:]

    if not has_https: score += 1; flags.append("No utiliza HTTPS")
    if has_ip: score += 3; flags.append("URL contiene direccion IP directa")
    if has_port: score += 1; flags.append("Puerto inusual en la URL")
    if subdomain_count > 3: score += 2; flags.append(f"Multiples subdominios ({subdomain_count})")
    if has_suspicious_tld: score += 3; flags.append("TLD sospechoso (.tk, .ml, etc)")
    if long_url: score += 1; flags.append(f"URL excesivamente larga ({len(req.url)} caracteres)")
    if has_at: score += 3; flags.append("Simbolo @ en la URL (tecnica de engano)")
    if double_slash: score += 2; flags.append("Doble barra fuera del protocolo")

    if score >= 6:
        risk_level = "ALTO RIESGO"
        recommendation = "No visites esta URL"
    elif score >= 3:
        risk_level = "SOSPECHOSO"
        recommendation = "Verifica la URL antes de continuar"
    else:
        risk_level = "PROBABLEMENTE SEGURO"
        recommendation = "Sin senales obvias de phishing"

    return {
        "url": req.url,
        "risk_score": f"{min(score, 10)}/10",
        "risk_level": risk_level,
        "has_https": has_https,
        "has_ip_address": has_ip,
        "url_length": len(req.url),
        "subdomain_count": max(0, subdomain_count),
        "suspicious_flags": flags,
        "recommendation": recommendation,
        "analyzed_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/jwt/decode", tags=["JWT"])
async def decode_jwt(req: JWTRequest):
    try:
        parts = req.token.split('.')
        if len(parts) != 3:
            raise HTTPException(status_code=400, detail="Formato JWT invalido (debe contener 3 partes)")

        def decode_part(part):
            padding = 4 - len(part) % 4
            if padding != 4:
                part += '=' * padding
            return json.loads(base64.urlsafe_b64decode(part))

        header = decode_part(parts[0])
        payload = decode_part(parts[1])

        warnings = []
        if header.get("alg") == "none":
            warnings.append("Algoritmo 'none' detectado - configuracion insegura")
        if header.get("alg") == "HS256":
            warnings.append("HS256: verificar que el secreto utilizado sea suficientemente fuerte")
        if "exp" not in payload:
            warnings.append("Token sin fecha de expiracion (exp) - vigencia indefinida")
        if "iat" in payload:
            issued = datetime.utcfromtimestamp(payload["iat"])
            warnings.append(f"Emitido el: {issued.isoformat()}")
        if "exp" in payload:
            expiry = datetime.utcfromtimestamp(payload["exp"])
            expired = expiry < datetime.utcnow()
            warnings.append(f"{'EXPIRADO' if expired else 'Valido hasta'}: {expiry.isoformat()}")

        return {
            "header": header,
            "payload": payload,
            "signature": parts[2][:20] + "...",
            "algorithm": header.get("alg", "unknown"),
            "security_analysis": warnings,
            "decoded_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al decodificar el token: {str(e)}")


@app.post("/api/v1/text/entropy", tags=["Entropia"])
async def analyze_entropy(req: TextRequest):
    text = req.text
    entropy = shannon_entropy(text)

    is_base64 = bool(re.match(r'^[A-Za-z0-9+/=]+$', text) and len(text) % 4 == 0)
    is_hex = bool(re.match(r'^[a-f0-9]+$', text, re.IGNORECASE))

    if entropy > 4.5:
        interpretation = "Muy alta - probable cifrado o compresion de datos"
    elif entropy > 3.5:
        interpretation = "Alta - posible codificacion (Base64, hexadecimal)"
    elif entropy > 2.5:
        interpretation = "Moderada - texto con cierta estructura"
    else:
        interpretation = "Baja - texto natural o con alta repeticion"

    char_freq = {}
    for c in text:
        char_freq[c] = char_freq.get(c, 0) + 1
    top_chars = sorted(char_freq.items(), key=lambda x: -x[1])[:5]

    return {
        "text_length": len(text),
        "entropy_bits": entropy,
        "interpretation": interpretation,
        "unique_characters": len(set(text)),
        "top_5_characters": [{"char": repr(c), "count": n} for c, n in top_chars],
        "detected_encoding": {
            "base64": is_base64,
            "hexadecimal": is_hex,
        },
        "analyzed_at": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/crypto/keygen", tags=["Crypto"])
@limiter.limit("20/minute")
async def generate_keys(request: Request, bits: int = 256):
    if bits not in [128, 192, 256, 512]:
        raise HTTPException(status_code=400, detail="El parametro bits debe ser: 128, 192, 256 o 512")

    raw_bytes = secrets.token_bytes(bits // 8)
    return {
        "bits": bits,
        "hex_key": raw_bytes.hex(),
        "base64_key": base64.b64encode(raw_bytes).decode(),
        "url_safe_token": secrets.token_urlsafe(bits // 8),
        "api_key_format": f"cgk_{secrets.token_hex(16)}",
        "uuid_v4_style": f"{secrets.token_hex(4)}-{secrets.token_hex(2)}-4{secrets.token_hex(1)[1:]}-{secrets.token_hex(2)}-{secrets.token_hex(6)}",
        "generated_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/ip/analyze", tags=["IP"])
@limiter.limit("15/minute")
async def analyze_ip(req: IPRequest, request: Request):
    ip = req.ip.strip()

    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        raise HTTPException(status_code=400, detail="Formato de direccion IP invalido")

    octets = list(map(int, ip.split('.')))
    if any(o > 255 for o in octets):
        raise HTTPException(status_code=400, detail="Octet fuera de rango valido (0-255)")

    is_private = (
        octets[0] == 10 or
        (octets[0] == 172 and 16 <= octets[1] <= 31) or
        (octets[0] == 192 and octets[1] == 168) or
        octets[0] == 127
    )
    is_loopback = octets[0] == 127
    is_multicast = 224 <= octets[0] <= 239
    is_reserved = octets[0] == 0 or octets[0] >= 240

    geo_info = {}
    if not is_private:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"https://ipapi.co/{ip}/json/")
                geo_info = resp.json()
        except Exception:
            geo_info = {"note": "Geolocalizacion no disponible"}

    return {
        "ip": ip,
        "classification": {
            "is_private": is_private,
            "is_loopback": is_loopback,
            "is_multicast": is_multicast,
            "is_reserved": is_reserved,
            "is_public": not (is_private or is_loopback or is_multicast or is_reserved),
        },
        "geolocation": {
            "country": geo_info.get("country_name", "N/A"),
            "city": geo_info.get("city", "N/A"),
            "region": geo_info.get("region", "N/A"),
            "org": geo_info.get("org", "N/A"),
            "latitude": geo_info.get("latitude", "N/A"),
            "longitude": geo_info.get("longitude", "N/A"),
            "timezone": geo_info.get("timezone", "N/A"),
        } if not is_private else {"note": "Direccion IP privada - geolocalizacion no aplicable"},
        "threat_indicators": {
            "is_tor_exit": False,
            "is_vpn": False,
            "note": "Para analisis avanzado de amenazas integrar con AbuseIPDB o Shodan"
        },
        "analyzed_at": datetime.utcnow().isoformat()
    }


@app.get("/health", tags=["Info"])
async def health():
    return {
        "status": "operational",
        "api": "CyberGuard",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)