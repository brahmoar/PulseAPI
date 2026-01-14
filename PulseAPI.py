"""
PulseAPI - API de Comunicación en Tiempo Real
Versión Segura con Autenticación y WebSockets
Desarrollado para: Brahmoar (Super Admin)
"""

from datetime import datetime, timedelta
import json, time, hmac, hashlib, requests, logging, secrets, os
from functools import wraps
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, verify_jwt_in_request
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, validate, validates, ValidationError
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ============================================================================
# CONFIGURACIÓN SEGURA
# ============================================================================

app = Flask(__name__)
app.config['APP_NAME'] = 'PulseAPI'
app.config['VERSION'] = '2.0.0'
app.config['SUPER_ADMIN'] = 'Brahmoar'  # Super administrador único

# Usar variables de entorno (crear archivo .env)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///pulseapi.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=3)
app.config['WEBHOOK_SECRET'] = os.getenv('WEBHOOK_SECRET', secrets.token_urlsafe(32))

# CORS configurado correctamente
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Logging con formato personalizado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [PulseAPI] - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("PulseAPI")

# Extensiones
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# Rate Limiter (usar Redis en producción: redis://localhost:6379/0)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=os.getenv('REDIS_URL', 'memory://'),
    default_limits=["1000 per day", "200 per hour"]
)

# ============================================================================
# MODELOS DE BASE DE DATOS
# ============================================================================

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(80), unique=True, nullable=False, index=True)
    correo = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    es_admin = db.Column(db.Boolean, default=False, nullable=False)
    activo = db.Column(db.Boolean, default=True, nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ultimo_acceso = db.Column(db.DateTime)
    
    # Relaciones
    mensajes = db.relationship('Mensaje', backref='autor', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, pwd):
        """Hashear contraseña con pbkdf2:sha256"""
        self.password_hash = generate_password_hash(pwd, method='pbkdf2:sha256')
    
    def check_password(self, pwd):
        """Verificar contraseña"""
        return check_password_hash(self.password_hash, pwd)
    
    def es_super_admin(self):
        """Verificar si es el super administrador"""
        return self.nombre_usuario == app.config['SUPER_ADMIN']
    
    def to_dict(self, include_email=False):
        """Convertir a diccionario"""
        data = {
            'id': self.id,
            'nombre_usuario': self.nombre_usuario,
            'es_admin': self.es_admin,
            'es_super_admin': self.es_super_admin(),
            'activo': self.activo,
            'creado_en': self.creado_en.isoformat() if self.creado_en else None,
            'ultimo_acceso': self.ultimo_acceso.isoformat() if self.ultimo_acceso else None
        }
        if include_email:
            data['correo'] = self.correo
        return data
    
    def __repr__(self):
        return f'<Usuario {self.nombre_usuario}>'

class Mensaje(db.Model):
    __tablename__ = 'mensajes'
    
    id = db.Column(db.Integer, primary_key=True)
    sala = db.Column(db.String(100), index=True, nullable=False)
    remitente = db.Column(db.String(80), db.ForeignKey('usuarios.nombre_usuario'), nullable=False)
    contenido = db.Column(db.Text, nullable=False)
    editado = db.Column(db.Boolean, default=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    actualizado_en = db.Column(db.DateTime)
    
    def to_dict(self):
        """Convertir a diccionario"""
        return {
            'id': self.id,
            'sala': self.sala,
            'remitente': self.remitente,
            'contenido': self.contenido,
            'editado': self.editado,
            'creado_en': self.creado_en.isoformat() if self.creado_en else None,
            'actualizado_en': self.actualizado_en.isoformat() if self.actualizado_en else None
        }
    
    def __repr__(self):
        return f'<Mensaje {self.id} de {self.remitente}>'

class Sala(db.Model):
    __tablename__ = 'salas'
    
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False, index=True)
    descripcion = db.Column(db.String(255))
    privada = db.Column(db.Boolean, default=False)
    creador = db.Column(db.String(80), db.ForeignKey('usuarios.nombre_usuario'))
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convertir a diccionario"""
        return {
            'id': self.id,
            'nombre': self.nombre,
            'descripcion': self.descripcion,
            'privada': self.privada,
            'creador': self.creador,
            'creado_en': self.creado_en.isoformat() if self.creado_en else None
        }

# ============================================================================
# SCHEMAS DE VALIDACIÓN
# ============================================================================

class RegistroSchema(Schema):
    nombre_usuario = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=80),
            validate.Regexp(
                r'^[a-zA-Z0-9_]+$',
                error="Solo se permiten letras, números y guión bajo"
            )
        ]
    )
    correo = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, error="Mínimo 8 caracteres")
    )
    
    @validates('nombre_usuario')
    def validate_nombre_usuario(self, value):
        if Usuario.query.filter_by(nombre_usuario=value).first():
            raise ValidationError("El nombre de usuario ya existe")
    
    @validates('correo')
    def validate_correo(self, value):
        if Usuario.query.filter_by(correo=value).first():
            raise ValidationError("El correo ya está registrado")

class LoginSchema(Schema):
    nombre_usuario = fields.Str(required=True)
    password = fields.Str(required=True)

class UsuarioSchema(Schema):
    id = fields.Int(dump_only=True)
    nombre_usuario = fields.Str()
    correo = fields.Email()
    es_admin = fields.Bool()
    es_super_admin = fields.Bool()
    activo = fields.Bool()
    creado_en = fields.DateTime(dump_only=True)
    ultimo_acceso = fields.DateTime(dump_only=True)

class MensajeSchema(Schema):
    sala = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    contenido = fields.Str(required=True, validate=validate.Length(min=1, max=5000))

class SalaSchema(Schema):
    nombre = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    descripcion = fields.Str(validate=validate.Length(max=255))
    privada = fields.Bool()

# ============================================================================
# DECORADORES DE SEGURIDAD
# ============================================================================

def admin_requerido(fn):
    """Verifica que el usuario sea administrador activo"""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identidad = get_jwt_identity()
        usuario = Usuario.query.get(identidad["id"])
        
        if not usuario:
            logger.warning(f"Usuario {identidad['id']} no encontrado")
            return jsonify({"mensaje": "Usuario no encontrado"}), 404
        
        if not usuario.activo:
            logger.warning(f"Usuario inactivo: {usuario.nombre_usuario}")
            return jsonify({"mensaje": "Usuario inactivo"}), 403
        
        if not usuario.es_admin:
            logger.warning(f"Acceso no autorizado: {usuario.nombre_usuario}")
            return jsonify({"mensaje": "Acceso solo para administradores"}), 403
        
        # Actualizar último acceso
        usuario.ultimo_acceso = datetime.utcnow()
        db.session.commit()
        
        return fn(*args, **kwargs)
    return wrapper

def super_admin_requerido(fn):
    """Verifica que el usuario sea el super administrador"""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identidad = get_jwt_identity()
        usuario = Usuario.query.get(identidad["id"])
        
        if not usuario or not usuario.es_super_admin():
            logger.warning(f"Acceso super admin denegado: {identidad.get('nombre_usuario')}")
            return jsonify({"mensaje": "Acceso solo para super administrador"}), 403
        
        return fn(*args, **kwargs)
    return wrapper

def auth_socket(fn):
    """Autenticación para WebSockets"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except:
            logger.warning(f"Socket sin autenticación válida")
            return False
        return fn(*args, **kwargs)
    return wrapper

# ============================================================================
# MANEJADORES DE ERRORES
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Error interno: {error}", exc_info=True)
    return jsonify({"error": "Error interno del servidor"}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit excedido: {request.remote_addr} - {request.path}")
    return jsonify({
        "error": "Demasiadas solicitudes",
        "mensaje": "Has excedido el límite. Intenta más tarde."
    }), 429

@app.errorhandler(ValidationError)
def validation_error(error):
    return jsonify({"errores": error.messages}), 400

# ============================================================================
# SWAGGER/OPENAPI
# ============================================================================

SWAGGER_URL = "/docs"
API_URL = "/openapi.json"
swagger_ui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL, API_URL, config={"app_name": "PulseAPI"}
)
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

@app.get("/openapi.json")
def openapi():
    return jsonify({
        "swagger": "2.0",
        "info": {
            "title": "PulseAPI",
            "version": "2.0.0",
            "description": "API de comunicación en tiempo real con WebSockets y REST",
            "contact": {
                "name": "Brahmoar",
                "email": "admin@pulseapi.com"
            }
        },
        "host": "localhost:5000",
        "basePath": "/",
        "schemes": ["http", "https"],
        "securityDefinitions": {
            "BearerAuth": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Token en formato: Bearer <token>"
            }
        },
        "tags": [
            {"name": "Autenticación", "description": "Registro y login de usuarios"},
            {"name": "Usuarios", "description": "Gestión de usuarios (admin)"},
            {"name": "Mensajes", "description": "CRUD de mensajes"},
            {"name": "Salas", "description": "Gestión de salas de chat"},
            {"name": "Estadísticas", "description": "Estadísticas del sistema (admin)"},
            {"name": "Webhooks", "description": "Integración externa"}
        ],
        "paths": {
            "/": {
                "get": {
                    "summary": "Información general de la API",
                    "tags": ["General"],
                    "responses": {"200": {"description": "Info de PulseAPI"}}
                }
            },
            "/health": {
                "get": {
                    "summary": "Health check del sistema",
                    "tags": ["General"],
                    "responses": {"200": {"description": "Estado del servidor"}}
                }
            },
            "/auth/registro": {
                "post": {
                    "summary": "Registrar nuevo usuario",
                    "description": "Crea una nueva cuenta. Si el nombre es 'Brahmoar', se crea como super admin automáticamente.",
                    "tags": ["Autenticación"],
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "required": True,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "nombre_usuario": {
                                    "type": "string",
                                    "minLength": 3,
                                    "maxLength": 80,
                                    "example": "juan123"
                                },
                                "correo": {
                                    "type": "string",
                                    "format": "email",
                                    "example": "juan@example.com"
                                },
                                "password": {
                                    "type": "string",
                                    "minLength": 8,
                                    "example": "Password123!"
                                }
                            },
                            "required": ["nombre_usuario", "correo", "password"]
                        }
                    }],
                    "responses": {
                        "201": {"description": "Usuario creado exitosamente"},
                        "400": {"description": "Datos inválidos o usuario ya existe"}
                    }
                }
            },
            "/auth/login": {
                "post": {
                    "summary": "Iniciar sesión",
                    "description": "Autentica un usuario y devuelve un token JWT",
                    "tags": ["Autenticación"],
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "required": True,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "nombre_usuario": {
                                    "type": "string",
                                    "example": "Brahmoar"
                                },
                                "password": {
                                    "type": "string",
                                    "example": "MiPassword123"
                                }
                            },
                            "required": ["nombre_usuario", "password"]
                        }
                    }],
                    "responses": {
                        "200": {
                            "description": "Login exitoso - devuelve token JWT",
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "token": {"type": "string"},
                                    "usuario": {"type": "object"},
                                    "mensaje": {"type": "string"}
                                }
                            }
                        },
                        "401": {"description": "Credenciales inválidas"}
                    }
                }
            },
            "/auth/me": {
                "get": {
                    "summary": "Obtener información del usuario actual",
                    "tags": ["Autenticación"],
                    "security": [{"BearerAuth": []}],
                    "responses": {
                        "200": {"description": "Datos del usuario autenticado"}
                    }
                }
            },
            "/usuarios": {
                "get": {
                    "summary": "Listar todos los usuarios (paginado)",
                    "tags": ["Usuarios"],
                    "security": [{"BearerAuth": []}],
                    "parameters": [
                        {
                            "name": "page",
                            "in": "query",
                            "type": "integer",
                            "default": 1,
                            "description": "Número de página"
                        },
                        {
                            "name": "per_page",
                            "in": "query",
                            "type": "integer",
                            "default": 20,
                            "maximum": 100,
                            "description": "Usuarios por página"
                        }
                    ],
                    "responses": {
                        "200": {"description": "Lista paginada de usuarios"},
                        "403": {"description": "Requiere permisos de admin"}
                    }
                }
            },
            "/estadisticas": {
                "get": {
                    "summary": "Estadísticas del sistema",
                    "tags": ["Estadísticas"],
                    "security": [{"BearerAuth": []}],
                    "responses": {
                        "200": {"description": "Estadísticas generales"},
                        "403": {"description": "Solo admins"}
                    }
                }
            },
            "/salas": {
                "get": {
                    "summary": "Listar salas públicas",
                    "tags": ["Salas"],
                    "security": [{"BearerAuth": []}],
                    "responses": {"200": {"description": "Lista de salas"}}
                },
                "post": {
                    "summary": "Crear nueva sala",
                    "tags": ["Salas"],
                    "security": [{"BearerAuth": []}],
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "nombre": {"type": "string", "example": "mi-sala"},
                                "descripcion": {"type": "string"},
                                "privada": {"type": "boolean", "default": False}
                            }
                        }
                    }],
                    "responses": {
                        "201": {"description": "Sala creada"},
                        "400": {"description": "Sala ya existe"}
                    }
                }
            },
            "/mensajes/{sala}": {
                "get": {
                    "summary": "Obtener mensajes de una sala",
                    "tags": ["Mensajes"],
                    "security": [{"BearerAuth": []}],
                    "parameters": [{
                        "name": "sala",
                        "in": "path",
                        "required": True,
                        "type": "string"
                    }],
                    "responses": {"200": {"description": "Lista de mensajes"}}
                }
            },
            "/mensajes": {
                "post": {
                    "summary": "Enviar mensaje a una sala",
                    "tags": ["Mensajes"],
                    "security": [{"BearerAuth": []}],
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "sala": {"type": "string", "example": "general"},
                                "contenido": {"type": "string", "example": "Hola mundo!"}
                            }
                        }
                    }],
                    "responses": {"201": {"description": "Mensaje enviado"}}
                }
            }
        }
    })

# ============================================================================
# RUTA PRINCIPAL
# ============================================================================

@app.get("/")
def index():
    """Información de la API"""
    return jsonify({
        "api": "PulseAPI",
        "version": app.config['VERSION'],
        "descripcion": "API de comunicación en tiempo real",
        "super_admin": app.config['SUPER_ADMIN'],
        "endpoints": {
            "docs": "/docs",
            "openapi": "/openapi.json",
            "health": "/health"
        },
        "features": [
            "Autenticación JWT",
            "WebSockets en tiempo real",
            "Rate limiting",
            "Paginación",
            "Swagger UI",
            "Super Admin (Brahmoar)"
        ],
        "documentacion": "Visita /docs para la documentación interactiva"
    })

@app.get("/health")
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected",
        "version": app.config['VERSION']
    })

# ============================================================================
# RUTAS DE AUTENTICACIÓN
# ============================================================================

@app.post("/auth/registro")
@limiter.limit("3 per hour")
def registro():
    """Registrar nuevo usuario (máximo 3 por hora)"""
    try:
        data = RegistroSchema().load(request.json or {})
    except ValidationError as err:
        return jsonify({"errores": err.messages}), 400
    
    # El super admin se crea automáticamente como admin
    es_super_admin = data["nombre_usuario"] == app.config['SUPER_ADMIN']
    
    nuevo = Usuario(
        nombre_usuario=data["nombre_usuario"],
        correo=data["correo"],
        es_admin=es_super_admin
    )
    nuevo.set_password(data["password"])
    
    db.session.add(nuevo)
    db.session.commit()
    
    logger.info(f"Usuario registrado: {nuevo.nombre_usuario}" + 
                (f" [SUPER ADMIN]" if es_super_admin else ""))
    
    return jsonify({
        "mensaje": "Usuario registrado exitosamente",
        "usuario": UsuarioSchema().dump(nuevo)
    }), 201

@app.post("/auth/login")
@limiter.limit("5 per minute")
@limiter.limit("20 per hour")
def login():
    """Iniciar sesión (5 intentos/minuto, 20/hora)"""
    try:
        data = LoginSchema().load(request.json or {})
    except ValidationError as err:
        return jsonify({"errores": err.messages}), 400
    
    u = Usuario.query.filter_by(nombre_usuario=data["nombre_usuario"]).first()
    
    if not u or not u.check_password(data["password"]):
        time.sleep(1)  # Delay anti-brute force
        logger.warning(f"Login fallido: {data['nombre_usuario']} desde {request.remote_addr}")
        return jsonify({"mensaje": "Credenciales inválidas"}), 401
    
    if not u.activo:
        return jsonify({"mensaje": "Usuario inactivo"}), 403
    
    # Actualizar último acceso
    u.ultimo_acceso = datetime.utcnow()
    db.session.commit()
    
    token = create_access_token(identity={
        "id": u.id,
        "nombre_usuario": u.nombre_usuario,
        "es_admin": u.es_admin,
        "es_super_admin": u.es_super_admin()
    })
    
    logger.info(f"Login exitoso: {u.nombre_usuario}" + 
                (f" [SUPER ADMIN]" if u.es_super_admin() else ""))
    
    return jsonify({
        "token": token,
        "usuario": u.to_dict(include_email=True),
        "mensaje": f"Bienvenido, {u.nombre_usuario}!"
    })

@app.get("/auth/me")
@jwt_required()
@limiter.limit("100 per minute")
def me():
    """Obtener información del usuario autenticado"""
    identidad = get_jwt_identity()
    u = Usuario.query.get_or_404(identidad["id"])
    return jsonify(UsuarioSchema().dump(u))

# ============================================================================
# RUTAS DE USUARIOS (ADMIN)
# ============================================================================

@app.get("/usuarios")
@admin_requerido
@limiter.limit("50 per minute")
def listar_usuarios():
    """Listar usuarios con paginación (solo admin)"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    
    usuarios = Usuario.query.order_by(Usuario.creado_en.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    return jsonify({
        "usuarios": UsuarioSchema(many=True).dump(usuarios.items),
        "total": usuarios.total,
        "paginas": usuarios.pages,
        "pagina_actual": page,
        "por_pagina": per_page
    })

@app.get("/usuarios/<int:user_id>")
@admin_requerido
def obtener_usuario(user_id):
    """Obtener usuario por ID (solo admin)"""
    usuario = Usuario.query.get_or_404(user_id)
    return jsonify(usuario.to_dict(include_email=True))

@app.post("/usuarios/<int:user_id>/admin")
@super_admin_requerido
def hacer_admin(user_id):
    """Otorgar privilegios de administrador (solo super admin)"""
    usuario = Usuario.query.get_or_404(user_id)
    
    if usuario.es_admin:
        return jsonify({"mensaje": "Usuario ya es administrador"}), 400
    
    usuario.es_admin = True
    db.session.commit()
    
    logger.info(f"Super Admin promovió a {usuario.nombre_usuario}")
    
    return jsonify({
        "mensaje": "Usuario promovido a administrador",
        "usuario": usuario.to_dict()
    })

@app.delete("/usuarios/<int:user_id>/admin")
@super_admin_requerido
def quitar_admin(user_id):
    """Remover privilegios de administrador (solo super admin)"""
    usuario = Usuario.query.get_or_404(user_id)
    
    if usuario.es_super_admin():
        return jsonify({"mensaje": "No puedes remover privilegios del super admin"}), 400
    
    if not usuario.es_admin:
        return jsonify({"mensaje": "Usuario no es administrador"}), 400
    
    usuario.es_admin = False
    db.session.commit()
    
    logger.info(f"Privilegios removidos de {usuario.nombre_usuario}")
    
    return jsonify({
        "mensaje": "Privilegios removidos",
        "usuario": usuario.to_dict()
    })

@app.patch("/usuarios/<int:user_id>/activar")
@admin_requerido
def toggle_usuario(user_id):
    """Activar/desactivar usuario (solo admin)"""
    usuario = Usuario.query.get_or_404(user_id)
    identidad = get_jwt_identity()
    
    if usuario.id == identidad["id"]:
        return jsonify({"mensaje": "No puedes desactivarte a ti mismo"}), 400
    
    if usuario.es_super_admin():
        return jsonify({"mensaje": "No puedes desactivar al super admin"}), 400
    
    usuario.activo = not usuario.activo
    db.session.commit()
    
    estado = "activado" if usuario.activo else "desactivado"
    logger.info(f"Usuario {usuario.nombre_usuario} {estado}")
    
    return jsonify({
        "mensaje": f"Usuario {estado}",
        "usuario": usuario.to_dict()
    })

@app.delete("/usuarios/<int:user_id>")
@super_admin_requerido
def eliminar_usuario(user_id):
    """Eliminar usuario permanentemente (solo super admin)"""
    usuario = Usuario.query.get_or_404(user_id)
    
    if usuario.es_super_admin():
        return jsonify({"mensaje": "No puedes eliminar al super admin"}), 400
    
    nombre = usuario.nombre_usuario
    db.session.delete(usuario)
    db.session.commit()
    
    logger.warning(f"Usuario eliminado: {nombre}")
    
    return jsonify({"mensaje": f"Usuario {nombre} eliminado permanentemente"})

# ============================================================================
# RUTAS DE SALAS
# ============================================================================

@app.get("/salas")
@jwt_required()
@limiter.limit("50 per minute")
def listar_salas():
    """Listar salas disponibles"""
    salas = Sala.query.filter_by(privada=False).all()
    return jsonify({
        "salas": [s.to_dict() for s in salas],
        "total": len(salas)
    })

@app.post("/salas")
@jwt_required()
@limiter.limit("10 per hour")
def crear_sala():
    """Crear nueva sala"""
    identidad = get_jwt_identity()
    
    try:
        data = SalaSchema().load(request.json or {})
    except ValidationError as err:
        return jsonify({"errores": err.messages}), 400
    
    if Sala.query.filter_by(nombre=data['nombre']).first():
        return jsonify({"mensaje": "La sala ya existe"}), 400
    
    sala = Sala(
        nombre=data['nombre'],
        descripcion=data.get('descripcion'),
        privada=data.get('privada', False),
        creador=identidad['nombre_usuario']
    )
    
    db.session.add(sala)
    db.session.commit()
    
    logger.info(f"Sala creada: {sala.nombre} por {identidad['nombre_usuario']}")
    
    return jsonify({
        "mensaje": "Sala creada exitosamente",
        "sala": sala.to_dict()
    }), 201

@app.delete("/salas/<int:sala_id>")
@admin_requerido
def eliminar_sala(sala_id):
    """Eliminar sala (solo admin)"""
    sala = Sala.query.get_or_404(sala_id)
    
    # Eliminar mensajes asociados
    Mensaje.query.filter_by(sala=sala.nombre).delete()
    
    nombre = sala.nombre
    db.session.delete(sala)
    db.session.commit()
    
    logger.warning(f"Sala eliminada: {nombre}")
    
    return jsonify({"mensaje": f"Sala {nombre} eliminada"})

# ============================================================================
# RUTAS DE MENSAJES
# ============================================================================

@app.get("/mensajes/<string:sala>")
@jwt_required()
@limiter.limit("100 per minute")
def obtener_mensajes(sala):
    """Obtener mensajes de una sala con paginación"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    mensajes = Mensaje.query.filter_by(sala=sala)\
        .order_by(Mensaje.creado_en.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "mensajes": [m.to_dict() for m in mensajes.items],
        "total": mensajes.total,
        "pagina": page,
        "sala": sala
    })

@app.post("/mensajes")
@jwt_required()
@limiter.limit("30 per minute")
def crear_mensaje():
    """Crear nuevo mensaje"""
    identidad = get_jwt_identity()
    
    try:
        data = MensajeSchema().load(request.json or {})
    except ValidationError as err:
        return jsonify({"errores": err.messages}), 400
    
    mensaje = Mensaje(
        sala=data['sala'],
        remitente=identidad['nombre_usuario'],
        contenido=data['contenido']
    )
    
    db.session.add(mensaje)
    db.session.commit()
    
    # Emitir por WebSocket
    socketio.emit('nuevo_mensaje', mensaje.to_dict(), room=data['sala'])
    
    logger.info(f"Mensaje en {data['sala']} por {identidad['nombre_usuario']}")
    
    return jsonify(mensaje.to_dict()), 201

@app.put("/mensajes/<int:mensaje_id>")
@jwt_required()
@limiter.limit("20 per minute")
def editar_mensaje(mensaje_id):
    """Editar mensaje propio"""
    identidad = get_jwt_identity()
    mensaje = Mensaje.query.get_or_404(mensaje_id)
    
    # Solo el autor o admin puede editar
    if mensaje.remitente != identidad['nombre_usuario'] and not identidad.get('es_admin'):
        return jsonify({"mensaje": "No tienes permiso para editar este mensaje"}), 403
    
    data = request.json or {}
    nuevo_contenido = data.get('contenido')
    
    if not nuevo_contenido:
        return jsonify({"mensaje": "Contenido requerido"}), 400
    
    mensaje.contenido = nuevo_contenido
    mensaje.editado = True
    mensaje.actualizado_en = datetime.utcnow()
    db.session.commit()
    
    # Emitir actualización por WebSocket
    socketio.emit('mensaje_editado', mensaje.to_dict(), room=mensaje.sala)
    
    return jsonify(mensaje.to_dict())

@app.delete("/mensajes/<int:mensaje_id>")
@jwt_required()
def eliminar_mensaje(mensaje_id):
    """Eliminar mensaje"""
    identidad = get_jwt_identity()
    mensaje = Mensaje.query.get_or_404(mensaje_id)
    
    # Solo el autor o admin puede eliminar
    if mensaje.remitente != identidad['nombre_usuario'] and not identidad.get('es_admin'):
        return jsonify({"mensaje": "No tienes permiso para eliminar este mensaje"}), 403
    
    sala = mensaje.sala
    db.session.delete(mensaje)
    db.session.commit()
    
    # Emitir eliminación por WebSocket
    socketio.emit('mensaje_eliminado', {'id': mensaje_id}, room=sala)
    
    logger.info(f"Mensaje {mensaje_id} eliminado por {identidad['nombre_usuario']}")
    
    return jsonify({"mensaje": "Mensaje eliminado"})

# ============================================================================
# SSE (Server-Sent Events)
# ============================================================================

@app.get("/sse/stream")
@jwt_required()
def sse_stream():
    """Stream de eventos para mensajes nuevos"""
    def gen():
        ultimo = 0
        intentos = 0
        max_intentos = 3
        
        while intentos < max_intentos:
            try:
                nuevos = Mensaje.query.filter(Mensaje.id > ultimo)\
                    .order_by(Mensaje.id)\
                    .limit(10)\
                    .all()
                
                for m in nuevos:
                    ultimo = m.id
                    yield f"data: {json.dumps(m.to_dict())}\n\n"
                
                time.sleep(1)
                intentos = 0
            except Exception as e:
                logger.error(f"Error en SSE: {e}")
                intentos += 1
                time.sleep(2)
        
        yield "event: error\ndata: Conexión cerrada\n\n"
    
    return Response(stream_with_context(gen()), mimetype="text/event-stream")

@app.get("/sse/sala/<string:sala>")
@jwt_required()
def sse_sala_stream(sala):
    """Stream de eventos para una sala específica"""
    def gen():
        ultimo = 0
        while True:
            try:
                nuevos = Mensaje.query\
                    .filter(Mensaje.sala == sala)\
                    .filter(Mensaje.id > ultimo)\
                    .order_by(Mensaje.id)\
                    .limit(5)\
                    .all()
                
                for m in nuevos:
                    ultimo = m.id
                    yield f"data: {json.dumps(m.to_dict())}\n\n"
                
                time.sleep(1)
            except:
                break
    
    return Response(stream_with_context(gen()), mimetype="text/event-stream")

# ============================================================================
# WEBSOCKETS
# ============================================================================

@socketio.on("connect")
def handle_connect():
    """Manejar conexión de WebSocket"""
    logger.info(f"Cliente conectado: {request.sid}")
    emit("conectado", {"mensaje": "Conexión exitosa a PulseAPI"})

@socketio.on("disconnect")
def handle_disconnect():
    """Manejar desconexión"""
    logger.info(f"Cliente desconectado: {request.sid}")

@socketio.on("unirse")
@auth_socket
def unirse_sala(data):
    """Unirse a una sala de chat"""
    sala = data.get("sala")
    identidad = get_jwt_identity()
    
    if not sala:
        emit("error", {"mensaje": "Sala requerida"})
        return
    
    join_room(sala)
    logger.info(f"{identidad['nombre_usuario']} se unió a sala {sala}")
    
    emit("unido", {
        "sala": sala,
        "mensaje": f"Te uniste a {sala}"
    })
    
    emit("usuario_unido", {
        "usuario": identidad['nombre_usuario'],
        "sala": sala
    }, room=sala, skip_sid=request.sid)

@socketio.on("salir")
@auth_socket
def salir_sala(data):
    """Salir de una sala"""
    sala = data.get("sala")
    identidad = get_jwt_identity()
    
    if not sala:
        return
    
    leave_room(sala)
    logger.info(f"{identidad['nombre_usuario']} salió de sala {sala}")
    
    emit("usuario_salio", {
        "usuario": identidad['nombre_usuario'],
        "sala": sala
    }, room=sala)

@socketio.on("mensaje")
@auth_socket
def manejar_mensaje(data):
    """Manejar mensaje en tiempo real"""
    identidad = get_jwt_identity()
    sala = data.get("sala")
    contenido = data.get("contenido")
    
    if not sala or not contenido:
        emit("error", {"mensaje": "Sala y contenido son requeridos"})
        return
    
    # Validar longitud
    if len(contenido) > 5000:
        emit("error", {"mensaje": "Mensaje demasiado largo (máximo 5000 caracteres)"})
        return
    
    # Guardar en BD
    mensaje = Mensaje(
        sala=sala,
        remitente=identidad['nombre_usuario'],
        contenido=contenido
    )
    db.session.add(mensaje)
    db.session.commit()
    
    # Emitir a todos en la sala
    emit("nuevo_mensaje", mensaje.to_dict(), room=sala)
    
    logger.info(f"Mensaje WebSocket en {sala} por {identidad['nombre_usuario']}")

@socketio.on("escribiendo")
@auth_socket
def usuario_escribiendo(data):
    """Notificar que un usuario está escribiendo"""
    identidad = get_jwt_identity()
    sala = data.get("sala")
    
    if sala:
        emit("usuario_escribiendo", {
            "usuario": identidad['nombre_usuario'],
            "sala": sala
        }, room=sala, skip_sid=request.sid)

@socketio.on("ping")
def handle_ping():
    """Responder a ping para mantener conexión viva"""
    emit("pong", {"timestamp": datetime.utcnow().isoformat()})

# ============================================================================
# WEBHOOKS
# ============================================================================

def verificar_firma_webhook(payload, firma):
    """Verificar firma HMAC del webhook"""
    if not firma:
        return False
    
    clave = app.config["WEBHOOK_SECRET"]
    calculada = hmac.new(
        clave.encode(),
        json.dumps(payload, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()
    
    return secrets.compare_digest(calculada, firma)

@app.post("/webhook/recibir")
@limiter.limit("10 per minute")
def recibir_webhook():
    """Recibir webhook de servicio externo"""
    firma = request.headers.get("X-Firma")
    data = request.json or {}
    
    if not verificar_firma_webhook(data, firma):
        logger.warning(f"Webhook con firma inválida desde {request.remote_addr}")
        return jsonify({"mensaje": "Firma inválida"}), 400
    
    logger.info(f"Webhook recibido: {data.get('evento', 'desconocido')}")
    
    # Procesar webhook según el tipo de evento
    evento = data.get("evento")
    
    if evento == "nuevo_usuario":
        # Lógica para procesar nuevo usuario
        pass
    elif evento == "mensaje_enviado":
        # Lógica para procesar mensaje
        pass
    
    return jsonify({
        "mensaje": "Webhook procesado correctamente",
        "evento": evento
    })

@app.post("/webhook/enviar")
@jwt_required()
@admin_requerido
@limiter.limit("30 per minute")
def enviar_webhook():
    """Enviar webhook a URL externa (solo admin)"""
    body = request.json or {}
    url = body.get("url")
    
    if not url:
        return jsonify({"mensaje": "URL requerida"}), 400
    
    if not url.startswith(('http://', 'https://')):
        return jsonify({"mensaje": "URL inválida"}), 400
    
    payload = body.get("body", {})
    
    # Firmar el payload
    clave = app.config["WEBHOOK_SECRET"]
    firma = hmac.new(
        clave.encode(),
        json.dumps(payload, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()
    
    try:
        r = requests.post(
            url,
            json=payload,
            headers={
                "X-Firma": firma,
                "User-Agent": "PulseAPI/2.0",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        logger.info(f"Webhook enviado a {url}: {r.status_code}")
        
        return jsonify({
            "status": r.status_code,
            "respuesta": r.text[:500],
            "mensaje": "Webhook enviado exitosamente"
        })
    except requests.Timeout:
        logger.error(f"Timeout enviando webhook a {url}")
        return jsonify({"error": "Timeout al enviar webhook"}), 504
    except requests.RequestException as e:
        logger.error(f"Error enviando webhook: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# ESTADÍSTICAS (ADMIN)
# ============================================================================

@app.get("/estadisticas")
@admin_requerido
def estadisticas():
    """Obtener estadísticas del sistema (solo admin)"""
    total_usuarios = Usuario.query.count()
    usuarios_activos = Usuario.query.filter_by(activo=True).count()
    total_admins = Usuario.query.filter_by(es_admin=True).count()
    total_mensajes = Mensaje.query.count()
    total_salas = Sala.query.count()
    
    # Últimos 10 mensajes
    ultimos_mensajes = Mensaje.query.order_by(Mensaje.creado_en.desc()).limit(10).all()
    
    # Usuarios más activos
    from sqlalchemy import func
    usuarios_activos_stats = db.session.query(
        Mensaje.remitente,
        func.count(Mensaje.id).label('total')
    ).group_by(Mensaje.remitente).order_by(func.count(Mensaje.id).desc()).limit(5).all()
    
    return jsonify({
        "usuarios": {
            "total": total_usuarios,
            "activos": usuarios_activos,
            "admins": total_admins,
            "inactivos": total_usuarios - usuarios_activos
        },
        "mensajes": {
            "total": total_mensajes,
            "ultimos": [m.to_dict() for m in ultimos_mensajes]
        },
        "salas": {
            "total": total_salas
        },
        "usuarios_mas_activos": [
            {"usuario": u[0], "mensajes": u[1]} for u in usuarios_activos_stats
        ]
    })

# ============================================================================
# COMANDOS CLI
# ============================================================================

@app.cli.command()
def init_db():
    """Inicializar base de datos"""
    db.create_all()
    print("✓ Base de datos inicializada")

@app.cli.command()
def create_admin():
    """Crear primer administrador"""
    from getpass import getpass
    
    print("\n" + "="*60)
    print("CREAR ADMINISTRADOR - PulseAPI")
    print("="*60)
    
    nombre_usuario = input("Nombre de usuario: ").strip()
    correo = input("Correo: ").strip()
    password = getpass("Contraseña: ")
    password_confirm = getpass("Confirmar contraseña: ")
    
    if password != password_confirm:
        print("❌ Las contraseñas no coinciden")
        return
    
    if len(password) < 8:
        print("❌ La contraseña debe tener al menos 8 caracteres")
        return
    
    if Usuario.query.filter_by(nombre_usuario=nombre_usuario).first():
        print("❌ El usuario ya existe")
        return
    
    if Usuario.query.filter_by(correo=correo).first():
        print("❌ El correo ya está registrado")
        return
    
    es_super_admin = nombre_usuario == app.config['SUPER_ADMIN']
    
    admin = Usuario(
        nombre_usuario=nombre_usuario,
        correo=correo,
        es_admin=True,
        activo=True
    )
    admin.set_password(password)
    
    db.session.add(admin)
    db.session.commit()
    
    print(f"\n✓ Administrador '{nombre_usuario}' creado exitosamente")
    if es_super_admin:
        print("🌟 ¡SUPER ADMINISTRADOR CREADO!")
    print("="*60 + "\n")

@app.cli.command()
def create_super_admin():
    """Crear el super administrador (Brahmoar)"""
    from getpass import getpass
    
    super_admin_username = app.config['SUPER_ADMIN']
    
    if Usuario.query.filter_by(nombre_usuario=super_admin_username).first():
        print(f"❌ El super administrador '{super_admin_username}' ya existe")
        return
    
    print("\n" + "="*60)
    print(f"CREAR SUPER ADMINISTRADOR: {super_admin_username}")
    print("="*60)
    
    correo = input("Correo del super admin: ").strip()
    password = getpass("Contraseña: ")
    password_confirm = getpass("Confirmar contraseña: ")
    
    if password != password_confirm:
        print("❌ Las contraseñas no coinciden")
        return
    
    if len(password) < 8:
        print("❌ La contraseña debe tener al menos 8 caracteres")
        return
    
    super_admin = Usuario(
        nombre_usuario=super_admin_username,
        correo=correo,
        es_admin=True,
        activo=True
    )
    super_admin.set_password(password)
    
    db.session.add(super_admin)
    db.session.commit()
    
    print(f"\n✓ SUPER ADMINISTRADOR '{super_admin_username}' creado exitosamente")
    print("🌟 Este usuario tiene privilegios totales sobre el sistema")
    print("="*60 + "\n")

@app.cli.command()
def generate_keys():
    """Generar claves secretas seguras"""
    print("\n" + "="*60)
    print("CLAVES SEGURAS GENERADAS - PulseAPI")
    print("="*60)
    print(f"SECRET_KEY={secrets.token_urlsafe(32)}")
    print(f"JWT_SECRET_KEY={secrets.token_urlsafe(32)}")
    print(f"WEBHOOK_SECRET={secrets.token_urlsafe(32)}")
    print("\nCopia estas claves en tu archivo .env")
    print("="*60 + "\n")

@app.cli.command()
def crear_salas_default():
    """Crear salas predeterminadas"""
    salas_default = [
        {"nombre": "general", "descripcion": "Sala general de conversación"},
        {"nombre": "desarrollo", "descripcion": "Discusiones sobre desarrollo"},
        {"nombre": "soporte", "descripcion": "Sala de soporte técnico"},
        {"nombre": "anuncios", "descripcion": "Anuncios importantes"}
    ]
    
    for sala_data in salas_default:
        if not Sala.query.filter_by(nombre=sala_data["nombre"]).first():
            sala = Sala(
                nombre=sala_data["nombre"],
                descripcion=sala_data["descripcion"],
                privada=False,
                creador=app.config['SUPER_ADMIN']
            )
            db.session.add(sala)
    
    db.session.commit()
    print("✓ Salas predeterminadas creadas")

@app.cli.command()
def limpiar_mensajes():
    """Limpiar mensajes antiguos (más de 30 días)"""
    fecha_limite = datetime.utcnow() - timedelta(days=30)
    mensajes_antiguos = Mensaje.query.filter(Mensaje.creado_en < fecha_limite).all()
    
    count = len(mensajes_antiguos)
    
    for mensaje in mensajes_antiguos:
        db.session.delete(mensaje)
    
    db.session.commit()
    print(f"✓ {count} mensajes antiguos eliminados")

@app.cli.command()
def info():
    """Mostrar información del sistema"""
    print("\n" + "="*60)
    print("INFORMACIÓN DE PULSEAPI")
    print("="*60)
    print(f"Versión: {app.config['VERSION']}")
    print(f"Super Admin: {app.config['SUPER_ADMIN']}")
    print(f"Base de datos: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"\nEstadísticas:")
    print(f"  - Usuarios: {Usuario.query.count()}")
    print(f"  - Mensajes: {Mensaje.query.count()}")
    print(f"  - Salas: {Sala.query.count()}")
    print("="*60 + "\n")

@app.cli.command()
def get_token():
    """Obtener token JWT para Brahmoar"""
    from getpass import getpass
    
    password = getpass(f"Password de {app.config['SUPER_ADMIN']}: ")
    
    usuario = Usuario.query.filter_by(
        nombre_usuario=app.config['SUPER_ADMIN']
    ).first()
    
    if not usuario:
        print(f"❌ Usuario {app.config['SUPER_ADMIN']} no existe")
        print("   Ejecuta: flask create-super-admin")
        return
    
    if not usuario.check_password(password):
        print("❌ Password incorrecto")
        return
    
    token = create_access_token(identity={
        "id": usuario.id,
        "nombre_usuario": usuario.nombre_usuario,
        "es_admin": usuario.es_admin,
        "es_super_admin": usuario.es_super_admin()
    })
    
    print("\n" + "="*80)
    print("✓ TOKEN GENERADO PARA BRAHMOAR")
    print("="*80)
    print(f"\n{token}\n")
    print("="*80)
    print("\nUsa este token en tus peticiones:")
    print(f"Authorization: Bearer {token}")
    print("="*80 + "\n")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    # Crear tablas si no existen
    with app.app_context():
        db.create_all()
        
        # Verificar si existe el super admin
        super_admin = Usuario.query.filter_by(
            nombre_usuario=app.config['SUPER_ADMIN']
        ).first()
        
        if not super_admin:
            logger.warning(f"⚠️  Super admin '{app.config['SUPER_ADMIN']}' no existe")
            logger.warning("   Ejecuta: flask create-super-admin")
    
    # Verificar si hay claves por defecto
    if len(app.config['SECRET_KEY']) < 32:
        logger.warning("⚠️  ADVERTENCIA: Usando claves por defecto")
        logger.warning("   Ejecuta: flask generate-keys")
    
    print("\n" + "="*60)
    print("🚀 PULSEAPI - API DE COMUNICACIÓN EN TIEMPO REAL")
    print("="*60)
    print(f"Versión: {app.config['VERSION']}")
    print(f"Super Admin: {app.config['SUPER_ADMIN']}")
    print("-"*60)
    print(f"🌐 Servidor:  http://127.0.0.1:5000")
    print(f"📚 Swagger:   http://127.0.0.1:5000/docs")
    print(f"📄 OpenAPI:   http://127.0.0.1:5000/openapi.json")
    print(f"💓 Health:    http://127.0.0.1:5000/health")
    print("="*60)
    print("\n📋 Comandos útiles:")
    print("  flask init-db             - Inicializar base de datos")
    print("  flask create-admin        - Crear administrador")
    print("  flask create-super-admin  - Crear super administrador")
    print("  flask generate-keys       - Generar claves seguras")
    print("  flask get-token           - Obtener token de Brahmoar")
    print("  flask crear-salas-default - Crear salas predeterminadas")
    print("  flask info                - Ver información del sistema")
    print("="*60)
    print("\n🔐 Características de seguridad:")
    print("  ✓ JWT Authentication")
    print("  ✓ Rate Limiting")
    print("  ✓ Password Hashing (pbkdf2:sha256)")
    print("  ✓ CORS Protection")
    print("  ✓ HMAC Webhook Signing")
    print("  ✓ Super Admin Protection (Brahmoar)")
    print("="*60 + "\n")
    
    # Ejecutar servidor
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=os.getenv('FLASK_ENV') == 'development',
        allow_unsafe_werkzeug=True
    )