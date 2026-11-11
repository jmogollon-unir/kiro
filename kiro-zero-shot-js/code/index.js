const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

// Configuración de MongoDB
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = 'auth_db';
const COLLECTION_NAME = 'users';

let db;

// Conexión a MongoDB
async function connectToMongo() {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    db = client.db(DB_NAME);
    console.log('Conectado a MongoDB');
}

// Endpoint POST /auth - Autenticación de usuario
app.post('/auth', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ 
                success: false, 
                message: 'El campo username es requerido' 
            });
        }

        // Consulta directa a MongoDB para buscar el usuario
        const user = await db.collection(COLLECTION_NAME).findOne({ username: username });

        if (user) {
            return res.status(200).json({
                success: true,
                message: 'Usuario autenticado correctamente',
                user: {
                    id: user._id,
                    username: user.username
                }
            });
        } else {
            return res.status(401).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }
    } catch (error) {
        console.error('Error en autenticación:', error);
        return res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
});

// Iniciar servidor
connectToMongo()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
        });
    })
    .catch(error => {
        console.error('Error al conectar a MongoDB:', error);
        process.exit(1);
    });
