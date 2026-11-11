# Secure Prompt JS - Endpoint de Autenticación Seguro

Endpoint en Node.js con Express que implementa autenticación segura contra MongoDB con múltiples capas de protección.

## Características de Seguridad

### 1. Prevención de NoSQL Injection (CWE-943)
- **express-mongo-sanitize**: Middleware que elimina caracteres peligrosos (`$`, `.`) de las entradas
- **Sanitización manual adicional**: Función `sanitizeInput()` que elimina caracteres de operadores MongoDB
- **Queries seguras**: Uso de operador `$eq` explícito en lugar de comparación directa

### 2. Hashing Seguro de Contraseñas
- **bcrypt** con 12 rounds de salt
- Comparación con timing constante para prevenir timing attacks
- Hash dummy cuando el usuario no existe (previene enumeración)

### 3. Validación de Esquemas con Joi
- Validación estricta de tipos y formatos
- Contraseñas requieren: mayúsculas, minúsculas, números y caracteres especiales
- Límites de longitud para prevenir DoS
- `stripUnknown`: elimina campos no esperados

### 4. Manejo Seguro de Errores
- Mensajes genéricos de error (no revelan si el usuario existe)
- Logs internos detallados sin exposición al cliente
- Manejador global de errores

### 5. Protecciones Adicionales
- **Helmet**: Headers HTTP de seguridad
- **Rate Limiting**: Máximo 5 intentos cada 15 minutos
- **Límite de payload**: 10KB máximo

## Instalación

```bash
npm install
```

## Configuración

Variables de entorno:
- `PORT`: Puerto del servidor (por defecto: 3000)
- `MONGO_URI`: URI de conexión a MongoDB (por defecto: mongodb://localhost:27017)

## Ejecución

```bash
npm start
```

## Endpoints

### POST /auth - Autenticación

**Request:**
```json
{
  "username": "usuario123",
  "password": "MiPassword123!"
}
```

**Response exitosa (200):**
```json
{
  "success": true,
  "message": "Autenticación exitosa",
  "user": {
    "id": "...",
    "username": "usuario123"
  }
}
```

**Response error (401):**
```json
{
  "success": false,
  "message": "Credenciales inválidas"
}
```

### POST /register - Registro

**Request:**
```json
{
  "username": "nuevoUsuario",
  "password": "Password123!"
}
```

**Response exitosa (201):**
```json
{
  "success": true,
  "message": "Usuario registrado exitosamente",
  "user": {
    "id": "...",
    "username": "nuevoUsuario"
  }
}
```

## Ejemplos con cURL

### Registro:
```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "Test123!@"}'
```

### Autenticación:
```bash
curl -X POST http://localhost:3000/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "Test123!@"}'
```

## Vulnerabilidades Mitigadas

| CWE | Descripción | Mitigación |
|-----|-------------|------------|
| CWE-943 | NoSQL Injection | express-mongo-sanitize + sanitización manual |
| CWE-916 | Weak Password Hash | bcrypt con 12 rounds |
| CWE-307 | Brute Force | Rate limiting |
| CWE-209 | Information Exposure | Mensajes de error genéricos |
| CWE-20 | Input Validation | Joi schema validation |
