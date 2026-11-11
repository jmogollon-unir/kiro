# Zero Shot JS - Endpoint de Autenticación

Endpoint en Node.js con Express que autentica usuarios contra una base de datos MongoDB.

## Instalación

```bash
npm install
```

## Configuración

Variables de entorno opcionales:
- `PORT`: Puerto del servidor (por defecto: 3000)
- `MONGO_URI`: URI de conexión a MongoDB (por defecto: mongodb://localhost:27017)

## Ejecución

```bash
npm start
```

O en modo desarrollo:

```bash
npm run dev
```

## Uso del Endpoint

### POST /auth

Autentica un usuario por su nombre de usuario.

**Request:**
```json
{
  "username": "nombreUsuario"
}
```

**Response exitosa (200):**
```json
{
  "success": true,
  "message": "Usuario autenticado correctamente",
  "user": {
    "id": "...",
    "username": "nombreUsuario"
  }
}
```

**Response error - Usuario no encontrado (401):**
```json
{
  "success": false,
  "message": "Usuario no encontrado"
}
```

**Response error - Campo requerido (400):**
```json
{
  "success": false,
  "message": "El campo username es requerido"
}
```

## Ejemplo con cURL

```bash
curl -X POST http://localhost:3000/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "admin"}'
```
