# API Segura de Usuarios - FastAPI + PostgreSQL

API REST segura para consulta de usuarios implementando mejores prácticas de seguridad.

## Características de Seguridad

### 1. Validación Explícita de Parámetros
- Validación a nivel de Path parameter con restricciones `gt=0` y `le=2147483647`
- Validador Pydantic adicional (`UserIdValidator`) con comprobaciones exhaustivas
- Rechazo de booleanos y decimales que podrían convertirse implícitamente

### 2. Prevención de SQL Injection (CWE-89)
- Uso exclusivo de **consultas parametrizadas** con asyncpg
- Los parámetros se pasan usando placeholders posicionales (`$1`)
- El valor nunca se concatena directamente en la consulta SQL

```python
# CORRECTO - Consulta parametrizada
await conn.fetchrow("SELECT * FROM usuarios WHERE id = $1", user_id)

# INCORRECTO - Vulnerable a SQL injection
await conn.fetchrow(f"SELECT * FROM usuarios WHERE id = {user_id}")
```

### 3. Manejo Seguro de Excepciones
- Los errores de base de datos se registran internamente pero no se exponen al cliente
- Mensajes de error genéricos para el usuario final
- Logging estructurado sin datos sensibles

## Estructura del Proyecto

```
secure-prompt-python/
├── main.py           # Aplicación FastAPI
├── requirements.txt  # Dependencias
└── README.md         # Este archivo
```

## Instalación

```bash
# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt
```

## Configuración

Modificar las credenciales en `DatabaseConfig` dentro de `main.py`:

```python
class DatabaseConfig:
    HOST: str = "localhost"
    PORT: int = 5432
    DATABASE: str = "mi_base_de_datos"
    USER: str = "usuario"
    PASSWORD: str = "password"
```

> **Nota de seguridad**: En producción, utilizar variables de entorno para las credenciales.

## Ejecución

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Uso

### Obtener usuario por ID

```bash
curl http://localhost:8000/usuarios/1
```

**Respuesta exitosa (200):**
```json
{
    "id": 1,
    "nombre": "Juan Pérez",
    "email": "juan@ejemplo.com",
    "activo": true
}
```

**Usuario no encontrado (404):**
```json
{
    "detail": "Usuario no encontrado"
}
```

**ID inválido (422):**
```json
{
    "detail": [
        {
            "type": "greater_than",
            "loc": ["path", "user_id"],
            "msg": "Input should be greater than 0"
        }
    ]
}
```

## Documentación API

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Esquema de Base de Datos

```sql
CREATE TABLE usuarios (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    activo BOOLEAN DEFAULT TRUE
);
```
