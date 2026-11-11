const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;

// Configuración de MongoDB
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = 'auth_db';
const COLLECTION_NAME = 'users';

let db;

// ============================================
// MIDDLEWARES DE SEGURIDAD
// ============================================

// Headers de seguridad HTTP
app.use(helmet());

// Parsear JSON con límite de tamaño
app.use(express.json({ limit: '10kb' }));

// Sanitización contra NoSQL Injection (CWE-943)
// Elimina caracteres como $ y . de las entradas
app.use(mongoSanitize({
    replaceWith: '_',
    onSanitize: ({ req, key }) => {
        console.warn(`[SECURITY] Intento de NoSQL Injection detectado en ${key}`);
    }
}));

// Rate limiting para prevenir ataques de fuerza bruta
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 intentos por ventana
    message: {
        success: false,
        message: 'Demasiados intentos de autenticación. Intente más tarde.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

// ============================================
// VALIDACIÓN DE ESQUEMAS CON JOI
// ============================================

// Esquema de validación para autenticación
const authSchema = Joi.object({
    username: Joi.string()
        .alphanum()
        .min(3)
        .max(30)
        .required()
        .messages({
            'string.base': 'El username debe ser texto',
            'string.alphanum': 'El username solo puede contener caracteres alfanuméricos',
            'string.min': 'El username debe tener al menos 3 caracteres',
            'string.max': 'El username no puede exceder 30 caracteres',
            'any.required': 'El username es requerido'
        }),
    password: Joi.string()
        .min(8)
        .max(128)
        .required()
        .messages({
            'string.base': 'La contraseña debe ser texto',
            'string.min': 'La contraseña debe tener al menos 8 caracteres',
            'string.max': 'La contraseña no puede exceder 128 caracteres',
            'any.required': 'La contraseña es requerida'
        })
});

// Esquema de validación para registro
const registerSchema = Joi.object({
    username: Joi.string()
        .alphanum()
        .min(3)
        .max(30)
        .required()
        .messages({
            'string.base': 'El username debe ser texto',
            'string.alphanum': 'El username solo puede contener caracteres alfanuméricos',
            'string.min': 'El username debe tener al menos 3 caracteres',
            'string.max': 'El username no puede exceder 30 caracteres',
            'any.required': 'El username es requerido'
        }),
    password: Joi.string()
        .min(8)
        .max(128)
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
        .required()
        .messages({
            'string.base': 'La contraseña debe ser texto',
            'string.min': 'La contraseña debe tener al menos 8 caracteres',
            'string.max': 'La contraseña no puede exceder 128 caracteres',
            'string.pattern.base': 'La contraseña debe contener mayúsculas, minúsculas, números y caracteres especiales',
            'any.required': 'La contraseña es requerida'
        })
});

// Middleware de validación genérico
const validateRequest = (schema) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.body, { 
            abortEarly: false,
            stripUnknown: true // Elimina campos no definidos en el esquema
        });

        if (error) {
            const errorMessages = error.details.map(detail => detail.message);
            return res.status(400).json({
                success: false,
                message: 'Error de validación',
                errors: errorMessages
            });
        }

        // Reemplaza el body con los valores validados y sanitizados
        req.body = value;
        next();
    };
};

// ============================================
// FUNCIONES DE SEGURIDAD
// ============================================

// Sanitización adicional manual para prevenir NoSQL Injection
function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return input;
    }
    
    // Eliminar caracteres peligrosos para MongoDB
    const sanitized = input
        .replace(/\$/g, '')
        .replace(/\./g, '')
        .replace(/\{/g, '')
        .replace(/\}/g, '');
    
    return sanitized.trim();
}

// Hash seguro de contraseña con bcrypt
async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
}

// Verificación segura de contraseña con timing constante
async function verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}

// Mensaje genérico de error de autenticación (previene enumeración de usuarios)
function getAuthErrorResponse() {
    return {
        success: false,
        message: 'Credenciales inválidas'
    };
}

// ============================================
// CONEXIÓN A MONGODB
// ============================================

async function connectToMongo() {
    const client = new MongoClient(MONGO_URI, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000
    });
    await client.connect();
    db = client.db(DB_NAME);
    
    // Crear índice único para username
    await db.collection(COLLECTION_NAME).createIndex(
        { username: 1 }, 
        { unique: true }
    );
    
    console.log('Conectado a MongoDB de forma segura');
}

// ============================================
// ENDPOINTS
// ============================================

// POST /auth - Autenticación segura de usuario
app.post('/auth', authLimiter, validateRequest(authSchema), async (req, res) => {
    try {
        const { username, password } = req.body;

        // Sanitización adicional del username
        const sanitizedUsername = sanitizeInput(username);

        // Buscar usuario con query segura (sin interpolación directa)
        const user = await db.collection(COLLECTION_NAME).findOne(
            { username: { $eq: sanitizedUsername } },
            { projection: { username: 1, password: 1 } }
        );

        // Verificación de usuario y contraseña
        // Usamos el mismo mensaje de error para ambos casos (seguridad)
        if (!user) {
            // Ejecutar hash dummy para prevenir timing attacks
            await bcrypt.hash('dummy_password', SALT_ROUNDS);
            return res.status(401).json(getAuthErrorResponse());
        }

        const isPasswordValid = await verifyPassword(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json(getAuthErrorResponse());
        }

        // Autenticación exitosa
        return res.status(200).json({
            success: true,
            message: 'Autenticación exitosa',
            user: {
                id: user._id,
                username: user.username
            }
        });

    } catch (error) {
        // Log interno del error (no exponer detalles al cliente)
        console.error('[ERROR] Error en autenticación:', error.message);
        
        return res.status(500).json({
            success: false,
            message: 'Error en el servidor'
        });
    }
});

// POST /register - Registro seguro de usuario
app.post('/register', validateRequest(registerSchema), async (req, res) => {
    try {
        const { username, password } = req.body;

        // Sanitización adicional del username
        const sanitizedUsername = sanitizeInput(username);

        // Verificar si el usuario ya existe
        const existingUser = await db.collection(COLLECTION_NAME).findOne(
            { username: { $eq: sanitizedUsername } }
        );

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'El nombre de usuario ya está en uso'
            });
        }

        // Hash seguro de la contraseña
        const hashedPassword = await hashPassword(password);

        // Crear usuario con datos sanitizados
        const result = await db.collection(COLLECTION_NAME).insertOne({
            username: sanitizedUsername,
            password: hashedPassword,
            createdAt: new Date(),
            failedLoginAttempts: 0
        });

        return res.status(201).json({
            success: true,
            message: 'Usuario registrado exitosamente',
            user: {
                id: result.insertedId,
                username: sanitizedUsername
            }
        });

    } catch (error) {
        console.error('[ERROR] Error en registro:', error.message);

        // Manejar error de duplicado de MongoDB
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: 'El nombre de usuario ya está en uso'
            });
        }

        return res.status(500).json({
            success: false,
            message: 'Error en el servidor'
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Manejador de rutas no encontradas
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Recurso no encontrado'
    });
});

// Manejador global de errores
app.use((error, req, res, next) => {
    console.error('[ERROR] Error no manejado:', error.message);
    res.status(500).json({
        success: false,
        message: 'Error interno del servidor'
    });
});

// ============================================
// INICIAR SERVIDOR
// ============================================

connectToMongo()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Servidor seguro ejecutándose en http://localhost:${PORT}`);
        });
    })
    .catch(error => {
        console.error('Error al conectar a MongoDB:', error);
        process.exit(1);
    });

module.exports = app;
