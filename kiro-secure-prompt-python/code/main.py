"""
API segura para consulta de usuarios en PostgreSQL.
Implementa validaciones explícitas, consultas parametrizadas y manejo seguro de errores.
"""
import logging
from contextlib import asynccontextmanager
from typing import Optional

import asyncpg
from fastapi import FastAPI, HTTPException, Path, Depends
from pydantic import BaseModel, Field, field_validator

# Configuración de logging seguro (sin datos sensibles)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# =============================================================================
# Configuración
# =============================================================================

class DatabaseConfig:
    """Configuración de la base de datos."""
    HOST: str = "localhost"
    PORT: int = 5432
    DATABASE: str = "mi_base_de_datos"
    USER: str = "usuario"
    PASSWORD: str = "password"  # En producción, usar variables de entorno
    MIN_CONNECTIONS: int = 2
    MAX_CONNECTIONS: int = 10

    @classmethod
    def get_dsn(cls) -> str:
        return f"postgresql://{cls.USER}:{cls.PASSWORD}@{cls.HOST}:{cls.PORT}/{cls.DATABASE}"


# =============================================================================
# Modelos Pydantic con validación estricta
# =============================================================================

class UserResponse(BaseModel):
    """Modelo de respuesta para datos de usuario."""
    id: int = Field(..., gt=0, description="ID único del usuario")
    nombre: str = Field(..., min_length=1, max_length=255)
    email: str = Field(..., max_length=255)
    activo: Optional[bool] = Field(default=True)

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": 1,
                "nombre": "Juan Pérez",
                "email": "juan@ejemplo.com",
                "activo": True
            }
        }
    }


class ErrorResponse(BaseModel):
    """Modelo estándar para respuestas de error."""
    detail: str = Field(..., description="Mensaje de error genérico")
    error_code: Optional[str] = Field(default=None, description="Código de error interno")


class UserIdValidator(BaseModel):
    """Validador explícito para user_id."""
    user_id: int = Field(..., gt=0, le=2147483647, description="ID de usuario (entero positivo)")

    @field_validator("user_id", mode="before")
    @classmethod
    def validate_positive_integer(cls, v):
        """Valida que el valor sea un entero positivo."""
        if isinstance(v, bool):
            raise ValueError("El ID de usuario debe ser un entero, no un booleano")
        if isinstance(v, float):
            if not v.is_integer():
                raise ValueError("El ID de usuario debe ser un entero, no un decimal")
            v = int(v)
        if not isinstance(v, int):
            raise ValueError("El ID de usuario debe ser un entero")
        if v <= 0:
            raise ValueError("El ID de usuario debe ser un entero positivo mayor que cero")
        if v > 2147483647:
            raise ValueError("El ID de usuario excede el valor máximo permitido")
        return v


# =============================================================================
# Gestión de conexiones a base de datos
# =============================================================================

class DatabasePool:
    """Gestor del pool de conexiones a PostgreSQL."""
    
    _pool: Optional[asyncpg.Pool] = None

    @classmethod
    async def create_pool(cls) -> asyncpg.Pool:
        """Crea el pool de conexiones."""
        try:
            cls._pool = await asyncpg.create_pool(
                dsn=DatabaseConfig.get_dsn(),
                min_size=DatabaseConfig.MIN_CONNECTIONS,
                max_size=DatabaseConfig.MAX_CONNECTIONS,
                command_timeout=30
            )
            logger.info("Pool de conexiones creado exitosamente")
            return cls._pool
        except Exception as e:
            # Log interno sin exponer detalles al cliente
            logger.error(f"Error al crear pool de conexiones: {type(e).__name__}")
            raise

    @classmethod
    async def close_pool(cls) -> None:
        """Cierra el pool de conexiones."""
        if cls._pool:
            await cls._pool.close()
            logger.info("Pool de conexiones cerrado")

    @classmethod
    def get_pool(cls) -> asyncpg.Pool:
        """Obtiene el pool de conexiones."""
        if cls._pool is None:
            raise RuntimeError("Pool de conexiones no inicializado")
        return cls._pool


# =============================================================================
# Aplicación FastAPI
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestión del ciclo de vida de la aplicación."""
    await DatabasePool.create_pool()
    yield
    await DatabasePool.close_pool()


app = FastAPI(
    title="API de Usuarios Segura",
    description="API con validaciones de seguridad para consulta de usuarios",
    version="1.0.0",
    lifespan=lifespan
)


# =============================================================================
# Dependencias
# =============================================================================

async def get_db_connection():
    """Dependencia para obtener una conexión del pool."""
    pool = DatabasePool.get_pool()
    async with pool.acquire() as connection:
        yield connection


def validate_user_id(
    user_id: int = Path(
        ...,
        gt=0,
        le=2147483647,
        description="ID único del usuario (entero positivo)",
        example=1
    )
) -> int:
    """
    Validación explícita del parámetro user_id.
    
    - Debe ser un entero positivo
    - Debe estar dentro del rango válido para PostgreSQL INTEGER
    """
    # Validación adicional usando el modelo Pydantic
    validated = UserIdValidator(user_id=user_id)
    return validated.user_id


# =============================================================================
# Repositorio de usuarios
# =============================================================================

class UserRepository:
    """Repositorio para operaciones de usuario en la base de datos."""

    # Consulta preparada con parámetro posicional ($1) - previene SQL injection
    QUERY_GET_USER_BY_ID = """
        SELECT id, nombre, email, activo 
        FROM usuarios 
        WHERE id = $1
    """

    @staticmethod
    async def get_by_id(conn: asyncpg.Connection, user_id: int) -> Optional[dict]:
        """
        Obtiene un usuario por su ID usando consulta parametrizada.
        
        La consulta usa $1 como placeholder, lo que garantiza que el valor
        sea tratado como dato y nunca como parte de la instrucción SQL,
        previniendo inyecciones SQL (CWE-89).
        """
        try:
            row = await conn.fetchrow(
                UserRepository.QUERY_GET_USER_BY_ID,
                user_id  # Parámetro pasado de forma segura
            )
            
            if row:
                return dict(row)
            return None
            
        except asyncpg.PostgresError as e:
            # Log del error real internamente
            logger.error(f"Error de base de datos al consultar usuario: {type(e).__name__}")
            # No exponer detalles del error
            raise DatabaseError("Error al consultar la base de datos")


class DatabaseError(Exception):
    """Excepción personalizada para errores de base de datos."""
    pass


# =============================================================================
# Endpoints
# =============================================================================

@app.get(
    "/usuarios/{user_id}",
    response_model=UserResponse,
    responses={
        200: {"description": "Usuario encontrado", "model": UserResponse},
        400: {"description": "ID de usuario inválido", "model": ErrorResponse},
        404: {"description": "Usuario no encontrado", "model": ErrorResponse},
        500: {"description": "Error interno del servidor", "model": ErrorResponse}
    },
    summary="Obtener usuario por ID",
    description="Consulta los detalles de un usuario específico por su ID"
)
async def obtener_usuario(
    user_id: int = Depends(validate_user_id),
    conn: asyncpg.Connection = Depends(get_db_connection)
) -> UserResponse:
    """
    Obtiene los detalles de un usuario por su ID.
    
    ## Validaciones de seguridad:
    - El user_id debe ser un entero positivo
    - Se utilizan consultas parametrizadas para prevenir SQL injection
    - Los errores internos no se exponen al cliente
    
    ## Parámetros:
    - **user_id**: ID único del usuario (entero positivo, máximo 2147483647)
    
    ## Respuestas:
    - **200**: Usuario encontrado
    - **400**: ID de usuario inválido
    - **404**: Usuario no encontrado
    - **500**: Error interno del servidor
    """
    try:
        usuario = await UserRepository.get_by_id(conn, user_id)
        
        if usuario is None:
            logger.info(f"Usuario no encontrado: id={user_id}")
            raise HTTPException(
                status_code=404,
                detail="Usuario no encontrado"
            )
        
        return UserResponse(**usuario)
        
    except HTTPException:
        # Re-lanzar excepciones HTTP sin modificar
        raise
        
    except DatabaseError:
        # Error de base de datos ya manejado
        raise HTTPException(
            status_code=500,
            detail="Error al procesar la solicitud"
        )
        
    except Exception as e:
        # Capturar cualquier error inesperado
        logger.error(f"Error inesperado en obtener_usuario: {type(e).__name__}")
        # Respuesta genérica sin exponer detalles internos
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor"
        )


@app.get("/health", include_in_schema=False)
async def health_check():
    """Endpoint de health check."""
    return {"status": "healthy"}
