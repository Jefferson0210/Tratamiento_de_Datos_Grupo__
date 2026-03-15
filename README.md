# Tratamiento_de_Datos_Grupo 8
## Objetivo

Diseñar, construir y desplegar un API funcional, aplicando buenas prácticas de desarrollo, versionamiento, pruebas y despliegue local usando FastAPI.

## Los archivos README se encuentran en cada Directorio con su respectiva explicación: 
cve-scraper

cyberguard-api

## RESPUESTAS A LAS CONSULTAS DE LA SEMANA 2 
# •	Sobre CyberGuard API:
Dado que varias funcionalidades implican análisis de información sensible (contraseñas, hashes, JWT, IPs), ¿qué medidas adicionales implementarían para evitar que la API sea mal utilizada (por ejemplo, registro avanzado de auditoría, detección de abuso, límites adaptativos, autenticación obligatoria o separación de endpoints públicos y privados)?

# Respuesta:
Para una API como CyberGuard API, que procesa información sensible (contraseñas, hashes, tokens JSON Web Token (JWT), direcciones IP, etc.), es fundamental implementar controles adicionales de seguridad que reduzcan el riesgo de abuso, enumeración de datos o uso malicioso. En la industria se aplican varias capas de protección.
1. Autenticación obligatoria y control de acceso
2. Separación de endpoints públicos y privados
3. Rate limiting y límites adaptativos
4. Registro avanzado de auditoría
5. Protección adicional a nivel de infraestructura
  API Gateway
  WAF (Web Application Firewall)
  cifrado obligatorio HTTPS/TLS
validación estricta de entradas (Pydantic en FastAPI).
## •	Sobre el scraper de vulnerabilidades:
¿Cómo podrían transformar este scraper en un sistema más orientado a monitoreo continuo y alerta temprana (por ejemplo, actualización incremental automática, base de datos histórica, notificaciones por severidad o dashboard de tendencias de vulnerabilidades)?
# Respuesta
Para evolucionar un scraper de vulnerabilidades hacia un sistema de monitoreo continuo y alerta temprana, es necesario transformarlo de una herramienta puntual de recolección de datos a una arquitectura automatizada, persistente y orientada a eventos.
1. Actualización incremental automática
2. Base de datos histórica
3. Sistema de alertas por severidad
4. Dashboard de monitoreo
5. Detección de tendencias y priorización
