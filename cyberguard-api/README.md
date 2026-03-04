# TRABAJO SEMANA 2 GRUPO 8 
# Integrantes: 
## Byron Velasco
## Edison Cofre 
## Jefferson Ramirez

# 🛡️ CyberGuard API
## Descripción general

CyberGuard API es una interfaz de programación de aplicaciones REST desarrollada con el framework **FastAPI** de Python. Su propósito es centralizar un conjunto de herramientas de ciberseguridad en un único servicio accesible mediante peticiones HTTP, aplicando buenas prácticas de desarrollo como versionamiento de endpoints, validación de datos con Pydantic, limitación de tasa de peticiones y registro de auditoría automático.

## Módulos implementados

| Módulo | Método | Endpoint | Función |
|---|---|---|---|
| 🔑 Análisis de contraseña | POST | `/api/v1/password/analyze` | Evalúa fortaleza, entropía de Shannon y tiempo estimado de crackeo |
| 💥 Verificación de brechas | POST | `/api/v1/password/breach` | Consulta HaveIBeenPwned usando protocolo k-anonymity |
| 🎲 Generador de contraseñas | POST | `/api/v1/password/generate` | Genera contraseñas criptográficamente seguras con `secrets` |
| 🔐 Identificador de hashes | POST | `/api/v1/hash/identify` | Detecta MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, entre otros |
| #️⃣ Generador de hashes | POST | `/api/v1/hash/generate` | Produce hashes con 9 algoritmos distintos |
| 🌐 Analizador de URLs | POST | `/api/v1/url/analyze` | Detecta patrones de phishing, TLDs sospechosos y técnicas de engaño |
| 🎫 Decodificador JWT | POST | `/api/v1/jwt/decode` | Decodifica y analiza tokens JWT sin verificar firma |
| 📊 Entropía de Shannon | POST | `/api/v1/text/entropy` | Calcula la entropía de un texto para detectar posible cifrado |
| 🔒 Generador de claves | GET | `/api/v1/crypto/keygen` | Produce claves hexadecimales, Base64 y tokens de API seguros |
| 🌍 Análisis de IP | POST | `/api/v1/ip/analyze` | Clasifica y geolocaliza direcciones IP públicas |

---

## Instalación y ejecución local

**Requisitos previos:** Python 3.11 o superior instalado en el sistema.

**Paso 1.** Clonar el repositorio:
```bash
git clone https://github.com/tu-usuario/cyberguard-api.git
cd cyberguard-api
```

**Paso 2.** Crear y activar un entorno virtual:
```bash
python -m venv venv

# En Windows:
venv\Scripts\activate

# En macOS/Linux:
source venv/bin/activate
```

**Paso 3.** Instalar las dependencias:
```bash
pip install -r requirements.txt
```

**Paso 4.** Iniciar el servidor:
```bash
python -m uvicorn main:app --reload
```

Una vez iniciado, la API queda disponible en `http://localhost:8000` y la documentación interactiva Swagger UI en `http://localhost:8000/docs`.

---

## Evidencia de funcionamiento local

### Swagger UI — API operativa

> Documentación interactiva generada automáticamente por FastAPI en `http://localhost:8000/docs`

![Swagger UI](docs/swagger_ui.png)

### Ejemplo 1 — Análisis de contraseña

Petición:
```json
POST /api/v1/password/analyze
{
  "password": "uide2025!"
}
```

Respuesta:
```json
{
  "password_length": 9,
  "score": "7/10",
  "strength": "🟢 Fuerte",
  "entropy_bits": 3.1699,
  "crack_time_estimate": "Días",
  "checks": {
    "has_lowercase": true,
    "has_uppercase": false,
    "has_digits": true,
    "has_symbols": true,
    "is_common_password": false,
    "length_ok": true
  },
  "suggestions": ["Agrega letras mayúsculas"]
}
```

### Ejemplo 2 — Detección de phishing en URL

Petición:
```json
POST /api/v1/url/analyze
{
  "url": "http://paypal-secure-login.tk/verify-account?id=12345"
}
```

Respuesta:
```json
{
  "risk_score": "8/10",
  "risk_level": "🔴 ALTO RIESGO",
  "suspicious_flags": [
    "No usa HTTPS",
    "Patrón sospechoso: paypal.*login",
    "TLD sospechoso (.tk, .ml, etc)",
    "Patrón sospechoso: verify.*account"
  ],
  "recommendation": "⛔ No visites esta URL"
}
```

### Ejemplo 3 — Generación de clave criptográfica

Petición:
```
GET /api/v1/crypto/keygen?bits=256
```

Respuesta:
```json
{
  "bits": 256,
  "hex_key": "a3f2d1e9c4b7...",
  "base64_key": "o/LR6cS3...",
  "url_safe_token": "A3kLm9...",
  "api_key_format": "cgk_a3f2d1e9c4b70823"
}
```

---

## Estructura del proyecto

```
cyberguard-api/
├── main.py
├── requirements.txt
├── audit.log
└── README.md
```

El archivo `main.py` concentra toda la lógica de la aplicación: configuración del servidor, middleware de auditoría, modelos de datos Pydantic y la definición de cada endpoint. El archivo `audit.log` se genera automáticamente al iniciar la API y registra cada petición recibida con su método, ruta, código de respuesta, tiempo de procesamiento y dirección IP del cliente.

---

## Características técnicas destacadas

**Rate Limiting** — Implementado con la librería `slowapi`, limita el número de peticiones por minuto por IP para proteger la API contra uso abusivo.

**Audit Logging** — Un middleware intercepta cada petición antes y después de procesarla, registrando automáticamente la actividad en un archivo de log persistente.

**k-Anonymity en verificación de brechas** — Al consultar HaveIBeenPwned, únicamente se envían los primeros 5 caracteres del hash SHA-1 de la contraseña. El hash completo nunca abandona el servidor, garantizando que la contraseña original no pueda ser reconstruida por el servicio externo.

**Validación automática con Pydantic** — Todos los modelos de entrada son validados antes de ejecutar la lógica del endpoint, retornando mensajes de error descriptivos ante datos malformados o incompletos.

**CORS habilitado** — La API acepta peticiones desde cualquier origen, permitiendo ser consumida directamente desde aplicaciones web o frontends.

---

## Integración con APIs externas

La API se integra con dos servicios externos:

- **HaveIBeenPwned** (`api.pwnedpasswords.com`) — Verifica si una contraseña fue comprometida en brechas de seguridad conocidas, usando el protocolo k-anonymity para preservar la privacidad.
- **ipapi.co** — Geolocaliza direcciones IP públicas, retornando país, ciudad, región, organización y zona horaria.

---

## Dependencias principales

| Librería | Versión | Uso |
|---|---|---|
| fastapi | 0.115.0 | Framework principal |
| uvicorn | 0.30.6 | Servidor ASGI |
| pydantic | 2.9.2 | Validación de datos |
| httpx | 0.27.2 | Cliente HTTP asíncrono |
| slowapi | 0.1.9 | Rate limiting |
| cryptography | 43.0.3 | Operaciones criptográficas |
| PyJWT | 2.9.0 | Manejo de tokens JWT |

---
# EVIDENCIA 
## EXTRACCIÓN DE DATOS 
https://github.com/Jefferson0210/Tratamiento_de_Datos_Grupo__/blob/main/cyberguard-api/extracci%C3%B3n1.jpeg

https://github.com/Jefferson0210/Tratamiento_de_Datos_Grupo__/blob/main/cyberguard-api/Extracci%C3%B3n%202.jpeg
## API FUNCIONAL LOCALMENTE
https://github.com/Jefferson0210/Tratamiento_de_Datos_Grupo__/blob/main/cyberguard-api/API%20funcional%201.jpeg

https://github.com/Jefferson0210/Tratamiento_de_Datos_Grupo__/blob/main/cyberguard-api/API%20funcional%202.jpeg

