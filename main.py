from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import asyncpg

app = FastAPI()

# Configuración de la base de datos
DATABASE_URL = "postgresql://usuario:password@localhost:5432/mi_base_de_datos"


class UserResponse(BaseModel):
    id: int
    nombre: str
    email: str
    activo: Optional[bool] = True


# Pool de conexiones
async def get_db_pool():
    return await asyncpg.create_pool(DATABASE_URL)


@app.on_event("startup")
async def startup():
    app.state.pool = await get_db_pool()


@app.on_event("shutdown")
async def shutdown():
    await app.state.pool.close()


async def get_connection():
    async with app.state.pool.acquire() as connection:
        yield connection


@app.get("/usuarios/{user_id}", response_model=UserResponse)
async def obtener_usuario(user_id: int, conn=Depends(get_connection)):
    """
    Obtiene los detalles de un usuario por su ID.
    
    - **user_id**: ID único del usuario en la base de datos
    """
    query = "SELECT id, nombre, email, activo FROM usuarios WHERE id = $1"
    
    row = await conn.fetchrow(query, user_id)
    
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Usuario con id {user_id} no encontrado"
        )
    
    return UserResponse(
        id=row["id"],
        nombre=row["nombre"],
        email=row["email"],
        activo=row["activo"]
    )
