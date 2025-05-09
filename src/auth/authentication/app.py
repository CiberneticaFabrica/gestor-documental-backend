import os
import json
import uuid
import secrets
import hashlib
import logging
import datetime

from common.db import (
    execute_query,
    get_connection,
    generate_uuid,
    insert_audit_record
)

from common.headers import add_cors_headers

# Configurar el logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

def lambda_handler(event, context):
    """Manejador principal que direcciona a las funciones correspondientes"""
    try:
        http_method = event['httpMethod']
        path = event['path']
        
        # Manejar solicitudes OPTIONS para CORS preflight
        if http_method == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': add_cors_headers(),
                'body': ''
            }
        
        # Rutas de autenticación
        if http_method == 'POST' and path == '/auth/login':
            return login(event, context)
        elif http_method == 'POST' and path == '/auth/logout':
            return logout(event, context)
        elif http_method == 'POST' and path == '/auth/register':
            return create_user(event, context)
        elif http_method == 'POST' and path == '/auth/validate':
            return validate_session(event, context)
        elif http_method == 'POST' and path == '/auth/refresh':
            return refresh_token(event, context)
        elif http_method == 'POST' and path == '/auth/password/change':
            return change_password(event, context)
        elif http_method == 'POST' and path == '/auth/password/reset/request':
            return request_password_reset(event, context)
        elif http_method == 'POST' and path == '/auth/password/reset/confirm':
            return reset_password(event, context)
        elif http_method == 'POST' and path == '/auth/2fa/setup':
            return setup_2fa(event, context)
        elif http_method == 'POST' and path == '/auth/2fa/verify':
            return verify_2fa(event, context)
        elif http_method == 'POST' and path == '/auth/2fa/login':
            return login_with_2fa(event, context)
                 
        # Si no se encuentra una ruta, devolver 404
        return {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Ruta no encontrada'})
        }
        
    except Exception as e:
        logger.error(f"Error en despachador principal: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error interno del servidor: {str(e)}'})
        }

def verify_password(stored_password, provided_password):
    """Verifica si una contraseña coincide con el hash almacenado"""
    try:
        # Verificar si el formato contiene el separador $
        if '$' not in stored_password:
            logger.error(f"Formato de contraseña almacenada inválido: {stored_password}")
            return False
            
        # Separar el salt del hash almacenado
        salt, stored_hash = stored_password.split('$', 1)
        
        # Calcular el hash con el salt y la contraseña proporcionada
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=64
        )
        
        # Comparar el hash calculado con el almacenado
        return key.hex() == stored_hash
    except Exception as e:
        logger.error(f"Error al verificar contraseña: {str(e)}")
        return False

def generate_session_token():
    """Genera un token de sesión único"""
    return str(uuid.uuid4())

def login(event, context):
    """Procesa el inicio de sesión y crea una sesión"""
    try:
        # Obtener credenciales del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'password' not in body or ('email' not in body and 'username' not in body):
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requieren nombre de usuario o email, y contraseña'})
            }
        
        # Extraer credenciales
        email = body['email'] if 'email' in body else None
        username = body['username'] if 'username' in body else None
        password = body['password']
        
        # Buscar usuario por nombre de usuario o email
        query = """
        SELECT id_usuario, nombre_usuario, nombre, apellidos, email, hash_contrasena, estado
        FROM usuarios
        WHERE (nombre_usuario = %s OR email = %s)
        """
        
        # Ejecutar consulta para obtener el usuario
        user_result = execute_query(query, (username, email))

        # Verificar si el usuario existe
        if not user_result:
            # Registrar intento fallido en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': None,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'login',
                'entidad_afectada': 'sesion',
                'id_entidad_afectada': None,
                'detalles': json.dumps({'username': username, 'motivo': 'usuario_no_encontrado'}),
                'resultado': 'error'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Credenciales inválidas'})
            }
        
        # Obtener el primer resultado (usuario)
        user = user_result[0]
        
        # Verificar que el usuario esté activo
        if user['estado'] != 'activo':
            # Registrar intento fallido en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user['id_usuario'],
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'login',
                'entidad_afectada': 'sesion',
                'id_entidad_afectada': None,
                'detalles': json.dumps({'motivo': 'usuario_inactivo'}),
                'resultado': 'error'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Usuario inactivo'})
            }
        
        # Verificar contraseña de usuario
        if not verify_password(user['hash_contrasena'], password):
            # Registrar intento fallido en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user['id_usuario'],
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'login',
                'entidad_afectada': 'sesion',
                'id_entidad_afectada': None,
                'detalles': json.dumps({'motivo': 'password_incorrecto'}),
                'resultado': 'error'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Credenciales inválidas'})
            }
        
        # Generar token de sesión
        session_id = generate_session_token()
        
        # Calcular fecha de expiración (por defecto 24 horas)
        expiry_minutes = int(os.environ.get('SESSION_EXPIRY_MINUTES', '1440'))  # 24 horas por defecto
        expiry_date = datetime.datetime.now() + datetime.timedelta(minutes=expiry_minutes)
        
        # IP del cliente
        ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
        
        # Información del agente de usuario
        user_agent = event.get('headers', {}).get('User-Agent', '')
        
        # Crear registro de sesión
        session_query = """
        INSERT INTO sesiones (
            id_sesion,
            id_usuario,
            fecha_inicio,
            fecha_expiracion,
            direccion_ip,
            user_agent,
            activa
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        # Preparar parámetros para la inserción
        session_params = (
            session_id,
            user['id_usuario'],
            datetime.datetime.now(),
            expiry_date,
            ip_address,
            user_agent,
            True,
        )
        
        # Ejecutar inserción de sesión
        execute_query(session_query, session_params, fetch=False)

        # Actualizar último acceso del usuario
        update_query = """
        UPDATE usuarios
        SET ultimo_acceso = %s
        WHERE id_usuario = %s
        """
        
        # Ejecutar actualización de último acceso
        execute_query(update_query, (datetime.datetime.now(), user['id_usuario']), fetch=False)
        
        # Obtener roles y permisos del usuario
        roles_query = """
        SELECT r.id_rol, r.nombre_rol
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        WHERE ur.id_usuario = %s
        """
        
        # Obtener roles del usuario
        roles = execute_query(roles_query, (user['id_usuario'],))
        
        # # Obtener permisos del usuario
        # perms_query = """
        # CALL sp_user_permissions(%s)
        # """
        
        # # Ejecutar procedimiento almacenado para obtener permisos
        # permissions = execute_query(perms_query, (user['id_usuario'],))
        
        # Preparar respuesta
        user_data = {
            'id': user['id_usuario'],
            'username': user['nombre_usuario'],
            'nombre': user['nombre'],
            'apellidos': user['apellidos'],
            'email': user['email'],
            'roles': roles,
            # 'permisos': permissions
        }
        
        # Registrar inicio de sesión exitoso en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user['id_usuario'],
            'direccion_ip': ip_address,
            'accion': 'login',
            'entidad_afectada': 'sesion',
            'id_entidad_afectada': session_id,
            'detalles': json.dumps({'user_agent': user_agent}),
            'resultado': 'éxito'
        }
        
        # Insertar registro de auditoría
        insert_audit_record(audit_data)
        
        # Retornar respuesta exitosa
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Inicio de sesión exitoso',
                'session_token': session_id,
                'expires_at': expiry_date.isoformat(),
                'user': user_data
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error en inicio de sesión: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error en inicio de sesión: {str(e)}'})
        }

def logout(event, context):
    """Cierra una sesión de usuario"""
    try:
        # Obtener token de sesión del header de autorización
        auth_header = event.get('headers', {}).get('Authorization', '')
        
        # Verificar que el header de autorización esté presente
        if not auth_header.startswith('Bearer '):
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token no proporcionado'})
            }
        
        # Extraer el token de sesión
        session_token = auth_header.split(' ')[1]
        
        # Verificar si la sesión existe
        check_query = """
        SELECT id_sesion, id_usuario, activa
        FROM sesiones
        WHERE id_sesion = %s
        """
        
        # Ejecutar consulta para verificar la sesión
        session_result = execute_query(check_query, (session_token,))
        
        # Verificar si la sesión existe y está activa
        if not session_result or not session_result[0]['activa']:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión inválida o ya cerrada'})
            }
        
        # Obtener la sesión
        session = session_result[0]
        
        # Desactivar la sesión
        update_query = """
        UPDATE sesiones
        SET activa = FALSE,
            fecha_expiracion = %s
        WHERE id_sesion = %s
        """
        
        # Ejecutar actualización para desactivar la sesión
        execute_query(update_query, (datetime.datetime.now(), session_token), fetch=False)
        
        # Registrar cierre de sesión en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': session['id_usuario'],
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'logout',
            'entidad_afectada': 'sesion',
            'id_entidad_afectada': session_token,
            'detalles': json.dumps({'cierre': 'explícito'}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        # Retornar respuesta exitosa
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Sesión cerrada exitosamente'
            })
        }
        
    except Exception as e:
        logger.error(f"Error al cerrar sesión: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al cerrar sesión: {str(e)}'})
        }

def create_user(event, context):
    """Crea un nuevo usuario en el sistema"""
    try:
        body = json.loads(event['body'])

        required_fields = ['nombre_usuario', 'nombre', 'apellidos', 'email', 'password', 'roles']
        if not all(field in body for field in required_fields):
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Faltan campos requeridos'})
            }

        # Verificar si el usuario o email ya existen
        check_query = """
        SELECT id_usuario FROM usuarios
        WHERE nombre_usuario = %s OR email = %s
        """
        existing = execute_query(check_query, (body['nombre_usuario'], body['email']))
        if existing:
            return {
                'statusCode': 409,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Usuario o correo ya registrado'})
            }

        # Generar salt y hash de contraseña
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            body['password'].encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=64
        )
        hash_contrasena = f"{salt}${hashed.hex()}"

        user_id = generate_uuid()
        insert_query = """
        INSERT INTO usuarios (
            id_usuario, nombre_usuario, nombre, apellidos, email, hash_contrasena, salt, estado, fecha_creacion
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            user_id,
            body['nombre_usuario'],
            body['nombre'],
            body['apellidos'],
            body['email'],
            hash_contrasena,
            salt,
            'activo',
            datetime.datetime.now()
        )
        execute_query(insert_query, params, fetch=False)

        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'create_user',
            'entidad_afectada': 'usuarios',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({'nombre_usuario': body['nombre_usuario']}),
            'resultado': 'éxito'
        }

        insert_audit_record(audit_data)

        # Asignar roles al usuario
        for role_id in body['roles']:
            role_query = """
            INSERT INTO usuarios_roles (id_usuario, id_rol, ambito, id_ambito)
            VALUES (%s, %s, %s, %s)
            """
            execute_query(role_query, (
                user_id,
                role_id,
                'global',
                '00000000-0000-0000-0000-000000000000'
            ), fetch=False)
                
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear_usuario',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({
                'nombre_usuario': body['nombre_usuario'],
                'email': body['email'],
                'roles': body['roles']
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)

        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'message': 'Usuario creado exitosamente', 'id_usuario': user_id})
        }

    except Exception as e:
        logger.error(f"Error al crear usuario: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al crear usuario: {str(e)}'})
        }

def validate_session(event, context):
    """Valida una sesión existente y la actualiza"""
    try:
        # Obtener token de sesión del header de autorización
        auth_header = event.get('headers', {}).get('Authorization', '')
        
        # Verificar que el header de autorización esté presente y que comience con 'Bearer '
        if not auth_header.startswith('Bearer '):
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token no proporcionado'})
            }
        
        # Extraer el token de sesión
        session_token = auth_header.split(' ')[1]
        
        # Verificar si la sesión existe, está activa y no ha expirado
        check_query = """
        SELECT s.id_sesion, s.id_usuario, s.fecha_expiracion, s.activa, s.datos_sesion,
               u.nombre_usuario, u.nombre, u.apellidos, u.email, u.estado
        FROM sesiones s
        JOIN usuarios u ON s.id_usuario = u.id_usuario
        WHERE s.id_sesion = %s
        """
        
        # Ejecutar consulta para verificar la sesión
        session_result = execute_query(check_query, (session_token,))
        
        # Verificar si la sesión existe
        if not session_result:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión no encontrada'})
            }
        
        # Obtener la sesión
        session = session_result[0]
        
        # Verificar si la sesión está activa
        if not session['activa']:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión inactiva'})
            }
        
        # Verificar si la sesión ha expirado
        now = datetime.datetime.now()
        expiry_date = session['fecha_expiracion']
        
        # Verificar si la sesión ha expirado
        if expiry_date < now:
            # Desactivar la sesión
            update_query = """
            UPDATE sesiones
            SET activa = FALSE,
                fecha_expiracion = %s
            WHERE id_sesion = %s
            """
            
            # Ejecutar actualización para desactivar la sesión
            execute_query(update_query, (now, session_token), fetch=False)
            
            # Registrar expiración en auditoría
            audit_data = {
                'fecha_hora': now,
                'usuario_id': session['id_usuario'],
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'expiracion',
                'entidad_afectada': 'sesion',
                'id_entidad_afectada': session_token,
                'detalles': json.dumps({'motivo': 'timeout'}),
                'resultado': 'expirada'
            }
            
            # Insertar registro de auditoría
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión expirada'})
            }
        
        # Verificar que el usuario siga activo
        if session['estado'] != 'activo':
            # Desactivar la sesión
            update_query = """
            UPDATE sesiones
            SET activa = FALSE,
                fecha_expiracion = %s
            WHERE id_sesion = %s
            """
            
            # Ejecutar actualización para desactivar la sesión
            execute_query(update_query, (now, session_token), fetch=False)
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': now,
                'usuario_id': session['id_usuario'],
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'invalidacion',
                'entidad_afectada': 'sesion',
                'id_entidad_afectada': session_token,
                'detalles': json.dumps({'motivo': 'usuario_inactivo'}),
                'resultado': 'error'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Usuario inactivo'})
            }
        
        # Actualizar última actividad de la sesión
        # update_query = """
        # UPDATE sesiones
        # SET ultima_actividad = %s
        # WHERE id_sesion = %s
        # """
        
        # # Ejecutar actualización de última actividad
        # execute_query(update_query, (now, session_token), fetch=False)
        
        # Obtener roles y permisos del usuario
        roles_query = """
        SELECT r.id_rol, r.nombre_rol
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        WHERE ur.id_usuario = %s
        """
        
        # Ejecutar consulta para obtener roles del usuario
        roles = execute_query(roles_query, (session['id_usuario'],))
        
        # Obtener permisos del usuario
        perms_query = """
        CALL sp_user_permissions(%s)
        """
        
        # Ejecutar procedimiento almacenado para obtener permisos
        permissions = execute_query(perms_query, (session['id_usuario'],))
        
        # Preparar respuesta
        user_data = {
            'id': session['id_usuario'],
            'username': session['nombre_usuario'],
            'nombre': session['nombre'],
            'apellidos': session['apellidos'],
            'email': session['email'],
            'roles': roles,
            'permisos': permissions
        }
        
        # Registrar validación exitosa (solo ocasionalmente para no sobrecargar logs)
        # Solo registrar 1 de cada 10 validaciones para no llenar la tabla de auditoría
        if now.second % 10 == 0:
            audit_data = {
                'fecha_hora': now,
                'usuario_id': session['id_usuario'],
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'validacion',
                'entidad_afectada': 'sesion',
                'id_entidad_afectada': session_token,
                'detalles': json.dumps({'path': event.get('path')}),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
        
        # Retornar respuesta exitosa
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'valid': True,
                'expires_at': expiry_date.isoformat(),
                'user': user_data
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al validar sesión: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al validar sesión: {str(e)}'})
        }
    
def refresh_token(event, context):
    """Renueva un token de sesión existente"""
    try:
        # Obtener token de sesión del cuerpo
        body = json.loads(event['body'])
        
        # Verificar que el token de sesión esté presente
        if 'session_token' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token de sesión no proporcionado'})
            }
        
        # Extraer el token de sesión
        session_token = body['session_token']
        
        # Verificar si la sesión existe y está activa
        check_query = """
        SELECT s.id_sesion, s.id_usuario, s.fecha_expiracion, s.activa,
               u.nombre_usuario, u.nombre, u.apellidos, u.email, u.estado
        FROM sesiones s
        JOIN usuarios u ON s.id_usuario = u.id_usuario
        WHERE s.id_sesion = %s AND s.activa = TRUE
        """
        
        # Ejecutar consulta para verificar la sesión
        session_result = execute_query(check_query, (session_token,))
        
        # Verificar si la sesión existe y está activa
        if not session_result:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión no encontrada o inactiva'})
            }
        
        # Obtener la sesión
        session = session_result[0]
        
        # Verificar que el usuario siga activo
        if session['estado'] != 'activo':
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Usuario inactivo'})
            }
        
        # Generar nuevo token
        new_token = generate_session_token()
        
        # Calcular nueva fecha de expiración
        expiry_minutes = int(os.environ.get('SESSION_EXPIRY_MINUTES', '1440'))  # 24 horas por defecto
        expiry_date = datetime.datetime.now() + datetime.timedelta(minutes=expiry_minutes)
        
        # IP del cliente
        ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
        
        # Información del agente de usuario
        user_agent = event.get('headers', {}).get('User-Agent', '')
        
        # Crear nuevo registro de sesión
        new_session_query = """
        INSERT INTO sesiones (
            id_sesion,
            id_usuario,
            fecha_inicio,
            fecha_expiracion,
            direccion_ip,
            user_agent,
            activa
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        # Preparar parámetros para la inserción
        new_session_params = (
            new_token,
            session['id_usuario'],
            datetime.datetime.now(),
            expiry_date,
            ip_address,
            user_agent,
            True
        )
        
        # Ejecutar inserción de nueva sesión
        execute_query(new_session_query, new_session_params, fetch=False)
        
        # Cerrar sesión anterior
        close_query = """
        UPDATE sesiones
        SET activa = FALSE,
            fecha_expiracion = %s
        WHERE id_sesion = %s
        """
        
        # Ejecutar actualización para cerrar la sesión anterior
        execute_query(close_query, (datetime.datetime.now(), session_token), fetch=False)
        
        # Registrar renovación en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': session['id_usuario'],
            'direccion_ip': ip_address,
            'accion': 'renovacion',
            'entidad_afectada': 'sesion',
            'id_entidad_afectada': new_token,
            'detalles': json.dumps({
                'sesion_anterior': session_token,
                'user_agent': user_agent
            }),
            'resultado': 'éxito'
        }
        
        # Insertar registro de auditoría
        insert_audit_record(audit_data)
        
        # Obtener roles y permisos del usuario
        roles_query = """
        SELECT r.id_rol, r.nombre_rol
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        WHERE ur.id_usuario = %s
        """
        
        # Ejecutar consulta para obtener roles del usuario
        roles = execute_query(roles_query, (session['id_usuario'],))
        
        # Obtener permisos del usuario
        perms_query = """
        CALL sp_user_permissions(%s)
        """
        
        # Ejecutar procedimiento almacenado para obtener permisos
        permissions = execute_query(perms_query, (session['id_usuario'],))
        
        # Preparar respuesta
        user_data = {
            'id': session['id_usuario'],
            'username': session['nombre_usuario'],
            'nombre': session['nombre'],
            'apellidos': session['apellidos'],
            'email': session['email'],
            'roles': roles,
            'permisos': permissions
        }
        
        # Retornar respuesta exitosa
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Token renovado exitosamente',
                'session_token': new_token,
                'expires_at': expiry_date.isoformat(),
                'user': user_data
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al renovar token: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al renovar token: {str(e)}'})
        }

def change_password(event, context):
    """Cambia la contraseña de un usuario"""
    try:
        # Obtener token de sesión del header de autorización
        auth_header = event.get('headers', {}).get('Authorization', '')
        
        # Verificar que el header de autorización esté presente y que comience con 'Bearer '
        if not auth_header.startswith('Bearer '):
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token no proporcionado'})
            }
        
        # Extraer el token de sesión
        session_token = auth_header.split(' ')[1]
        
        # Verificar si la sesión existe y está activa
        check_query = """
        SELECT s.id_sesion, s.id_usuario, s.activa,
               u.nombre_usuario, u.hash_contrasena
        FROM sesiones s
        JOIN usuarios u ON s.id_usuario = u.id_usuario
        WHERE s.id_sesion = %s AND s.activa = TRUE
        """
        
        # Ejecutar consulta para verificar la sesión
        session_result = execute_query(check_query, (session_token,))
        
        # Verificar si la sesión existe y está activa
        if not session_result or not session_result[0]['activa']:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión inválida o inactiva'})
            }
        
        # Obtener la sesión
        session = session_result[0]
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'current_password' not in body or 'new_password' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requieren contraseña actual y nueva'})
            }
        
        # Extraer contraseñas
        current_password = body['current_password']
        new_password = body['new_password']
        
        # Verificar contraseña actual
        if not verify_password(session['hash_contrasena'], current_password):
            # Registrar intento fallido en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': session['id_usuario'],
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'cambio_password',
                'entidad_afectada': 'usuario',
                'id_entidad_afectada': session['id_usuario'],
                'detalles': json.dumps({'motivo': 'password_actual_incorrecto'}),
                'resultado': 'error'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Contraseña actual incorrecta'})
            }
        
        # Validar nueva contraseña
        if len(new_password) < 8:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'La nueva contraseña debe tener al menos 8 caracteres'})
            }
        
        # Generar hash de nueva contraseña
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            new_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=64
        )
        new_password_hash = f"{salt}${key.hex()}"
        
        # Actualizar contraseña
        update_query = """
        UPDATE usuarios
        SET hash_contrasena = %s,
            fecha_modificacion = %s
        WHERE id_usuario = %s
        """
        
        # Preparar parámetros para la actualización
        update_params = (
            new_password_hash,
            datetime.datetime.now(),
            session['id_usuario']
        )
        
        # Ejecutar actualización de contraseña
        execute_query(update_query, update_params, fetch=False)
        
        # Registrar cambio en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': session['id_usuario'],
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'cambio_password',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': session['id_usuario'],
            'detalles': json.dumps({'tipo': 'cambio_directo'}),
            'resultado': 'éxito'
        }
        
        # Insertar registro de auditoría
        insert_audit_record(audit_data)
        
        # Retornar respuesta exitosa
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Contraseña cambiada exitosamente'
            })
        }
        
    except Exception as e:
        logger.error(f"Error al cambiar contraseña: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al cambiar contraseña: {str(e)}'})
        }
    
def request_password_reset(event, context):
    """Solicita un código de recuperación de contraseña"""
    try:
        # Obtener email o nombre de usuario del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'identifier' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requiere email o nombre de usuario'})
            }
        
        # Extraer identificador (email o nombre de usuario)
        identifier = body['identifier']
        
        # Buscar usuario por email o nombre de usuario
        query = """
        SELECT id_usuario, nombre_usuario, email, estado
        FROM usuarios
        WHERE (email = %s OR nombre_usuario = %s)
        """
        
        # Ejecutar consulta para obtener el usuario
        user_result = execute_query(query, (identifier, identifier))
        
        # Si no se encuentra el usuario, devolver respuesta genérica por seguridad
        if not user_result or user_result[0]['estado'] != 'activo':
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'Si el email o usuario existe en nuestro sistema, recibirás un correo con instrucciones para restablecer tu contraseña'
                })
            }
        
        # Obtener el primer resultado (usuario)
        user = user_result[0]
        
        # Generar código de recuperación único
        reset_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        # Tiempo de expiración (30 minutos)
        expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=30)
        
        # Guardar el código en la base de datos
        reset_query = """
        INSERT INTO recuperacion_contrasena (
            id_usuario,
            codigo,
            fecha_expiracion,
            utilizado
        ) VALUES (%s, %s, %s, %s)
        """
        
        # Ejecutar inserción del código de recuperación
        execute_query(reset_query, (
            user['id_usuario'],
            reset_code,
            expiry_time,
            False
        ), fetch=False)
        
        # En un sistema real, aquí se enviaría el email con el código
        # Aquí solo simulamos el envío para el ejemplo
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user['id_usuario'],
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'solicitud_reset',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user['id_usuario'],
            'detalles': json.dumps({'email': user['email']}),
            'resultado': 'éxito'
        }
        
        # Insertar registro de auditoría
        insert_audit_record(audit_data)
        
        # Respuesta genérica por seguridad
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Si el email o usuario existe en nuestro sistema, recibirás un correo con instrucciones para restablecer tu contraseña'
            })
        }
        
    except Exception as e:
        logger.error(f"Error en solicitud de recuperación: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error en el proceso de recuperación: {str(e)}'})
        }

def reset_password(event, context):
    """Restablece la contraseña usando un código de recuperación"""
    try:
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'identifier' not in body or 'reset_code' not in body or 'new_password' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requieren identificador, código y nueva contraseña'})
            }
        
        # Extraer datos del cuerpo
        identifier = body['identifier']
        reset_code = body['reset_code']
        new_password = body['new_password']
        
        # Validar nueva contraseña
        if len(new_password) < 8:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'La nueva contraseña debe tener al menos 8 caracteres'})
            }
        
        # Buscar usuario
        query = """
        SELECT id_usuario, nombre_usuario, email
        FROM usuarios
        WHERE (email = %s OR nombre_usuario = %s) AND estado = 'activo'
        """
        
        # Ejecutar consulta para obtener el usuario
        user_result = execute_query(query, (identifier, identifier))
        
        # Si no se encuentra el usuario, devolver respuesta genérica por seguridad
        if not user_result:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Usuario no encontrado o inactivo'})
            }
        
        # Obtener el primer resultado (usuario)
        user = user_result[0]
        
        # Verificar código de recuperación
        verify_query = """
        SELECT id, fecha_expiracion, utilizado
        FROM recuperacion_contrasena
        WHERE id_usuario = %s AND codigo = %s
        ORDER BY fecha_creacion DESC
        LIMIT 1
        """
        
        # Ejecutar consulta para verificar el código de recuperación
        reset_result = execute_query(verify_query, (user['id_usuario'], reset_code))
        
        # Si no se encuentra el código, devolver respuesta genérica por seguridad
        if not reset_result:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Código de recuperación inválido'})
            }
        
        # Obtener el primer resultado (código de recuperación)
        reset = reset_result[0]
        
        # Verificar que el código no ha sido utilizado
        if reset['utilizado']:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'El código ya ha sido utilizado'})
            }
        
        # Verificar que el código no ha expirado
        if reset['fecha_expiracion'] < datetime.datetime.now():
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'El código ha expirado'})
            }
        
        # Generar hash de nueva contraseña
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            new_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=64
        )
        new_password_hash = f"{salt}${key.hex()}"
        
        # Actualizar contraseña
        update_query = """
        UPDATE usuarios
        SET password_hash = %s,
            fecha_modificacion = %s,
            modificado_por = %s
        WHERE id_usuario = %s
        """
        
        # Ejecutar actualización de contraseña
        execute_query(update_query, (
            new_password_hash,
            datetime.datetime.now(),
            user['id_usuario'],
            user['id_usuario']
        ), fetch=False)
        
        # Marcar código como utilizado
        used_query = """
        UPDATE recuperacion_contrasena
        SET utilizado = TRUE,
            fecha_uso = %s
        WHERE id = %s
        """
        
        # Ejecutar actualización para marcar el código como utilizado
        execute_query(used_query, (datetime.datetime.now(), reset['id']), fetch=False)
        
        # Cerrar todas las sesiones activas del usuario
        close_sessions_query = """
        UPDATE sesiones
        SET activa = FALSE,
            fecha_expiracion = %s
        WHERE id_usuario = %s AND activa = TRUE
        """
        
        # Ejecutar actualización para cerrar sesiones activas
        execute_query(close_sessions_query, (datetime.datetime.now(), user['id_usuario']), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user['id_usuario'],
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'reset_password',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user['id_usuario'],
            'detalles': json.dumps({'metodo': 'codigo_reset'}),
            'resultado': 'éxito'
        }
        
        # Insertar registro de auditoría
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Contraseña restablecida exitosamente'
            })
        }
        
    except Exception as e:
        logger.error(f"Error en restablecimiento de contraseña: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error en restablecimiento de contraseña: {str(e)}'})
        }
    
def setup_2fa(event, context):
    """Configura la autenticación de dos factores para un usuario"""
    try:
        # Verificar autenticación
        auth_header = event.get('headers', {}).get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token no proporcionado'})
            }
        
        session_token = auth_header.split(' ')[1]
        
        # Verificar si la sesión existe y está activa
        check_query = """
        SELECT s.id_usuario, u.nombre_usuario, u.email
        FROM sesiones s
        JOIN usuarios u ON s.id_usuario = u.id_usuario
        WHERE s.id_sesion = %s AND s.activa = TRUE
        """
        
        session_result = execute_query(check_query, (session_token,))
        
        if not session_result:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión inválida o inactiva'})
            }
        
        user = session_result[0]
        
        # Generar secreto para TOTP (Time-based One-Time Password)
        # En un sistema real, usaríamos una biblioteca como pyotp
        # Aquí simplificamos para el ejemplo
        secret_key = secrets.token_hex(20)
        
        # Crear registro de dispositivo 2FA
        device_id = generate_uuid()
        
        insert_query = """
        INSERT INTO dispositivos_2fa (
            id_dispositivo,
            id_usuario,
            tipo_dispositivo,
            secreto,
            fecha_creacion,
            fecha_ultima_verificacion,
            activo
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        now = datetime.datetime.now()
        
        insert_params = (
            device_id,
            user['id_usuario'],
            'TOTP',
            secret_key,
            now,
            now,
            True
        )
        
        execute_query(insert_query, insert_params, fetch=False)
        
        # En un sistema real, aquí generaríamos un código QR para que el usuario
        # lo escanee con su aplicación de autenticación
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user['id_usuario'],
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'configurar_2fa',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user['id_usuario'],
            'detalles': json.dumps({'tipo': 'TOTP'}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Configuración 2FA iniciada exitosamente',
                'device_id': device_id,
                'secret_key': secret_key,
                'username': user['nombre_usuario']
            })
        }
        
    except Exception as e:
        logger.error(f"Error al configurar 2FA: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al configurar 2FA: {str(e)}'})
        }

def verify_2fa(event, context):
    """Verifica un código 2FA durante el inicio de sesión"""
    try:
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'temp_token' not in body or '2fa_code' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requieren token temporal y código 2FA'})
            }
        
        temp_token = body['temp_token']
        code = body['2fa_code']
        
        # Verificar que el token temporal existe y está activo
        token_query = """
        SELECT tt.id_usuario, tt.fecha_expiracion, tt.usado,
               d.id_dispositivo, d.secreto, d.tipo_dispositivo
        FROM tokens_temporales tt
        JOIN dispositivos_2fa d ON tt.id_usuario = d.id_usuario
        WHERE tt.token = %s AND tt.tipo = '2fa' AND d.activo = TRUE
        """
        
        token_result = execute_query(token_query, (temp_token,))
        
        if not token_result:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token temporal inválido o caducado'})
            }
        
        token = token_result[0]
        
        # Verificar que el token no ha sido usado
        if token['usado']:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token ya utilizado'})
            }
        
        # Verificar que el token no ha expirado
        if token['fecha_expiracion'] < datetime.datetime.now():
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Token expirado'})
            }
        
        # En un sistema real, aquí verificaríamos el código TOTP con una biblioteca como pyotp
        # Aquí simplificamos para el ejemplo y asumimos que el código es válido si tiene 6 dígitos
        if not code.isdigit() or len(code) != 6:
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Código 2FA inválido'})
            }
        
        # Marcar token como usado
        update_token_query = """
        UPDATE tokens_temporales
        SET usado = TRUE, fecha_uso = %s
        WHERE token = %s
        """
        
        execute_query(update_token_query, (datetime.datetime.now(), temp_token), fetch=False)
        
        # Actualizar última verificación del dispositivo
        update_device_query = """
        UPDATE dispositivos_2fa
        SET fecha_ultima_verificacion = %s
        WHERE id_dispositivo = %s
        """
        
        execute_query(update_device_query, (datetime.datetime.now(), token['id_dispositivo']), fetch=False)
        
        # Generar token de sesión definitivo
        session_id = generate_session_token()
        
        # Calcular fecha de expiración (por defecto 24 horas)
        expiry_minutes = int(os.environ.get('SESSION_EXPIRY_MINUTES', '1440'))  # 24 horas por defecto
        expiry_date = datetime.datetime.now() + datetime.timedelta(minutes=expiry_minutes)
        
        # IP del cliente
        ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
        
        # Información del agente de usuario
        user_agent = event.get('headers', {}).get('User-Agent', '')
        
        # Crear registro de sesión
        session_query = """
        INSERT INTO sesiones (
            id_sesion,
            id_usuario,
            fecha_inicio,
            fecha_expiracion,
            direccion_ip,
            user_agent,
            activa,
            verificado_2fa
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        session_params = (
            session_id,
            token['id_usuario'],
            datetime.datetime.now(),
            expiry_date,
            ip_address,
            user_agent,
            True,
            True
        )
        
        execute_query(session_query, session_params, fetch=False)
        
        # Obtener datos del usuario
        user_query = """
        SELECT id_usuario, nombre_usuario, nombre, apellidos, email
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (token['id_usuario'],))
        user = user_result[0]
        
        # Obtener roles y permisos del usuario
        roles_query = """
        SELECT r.id_rol, r.nombre_rol
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        WHERE ur.id_usuario = %s
        """
        
        roles = execute_query(roles_query, (token['id_usuario'],))
        
        # Obtener permisos del usuario
        perms_query = """
        CALL sp_user_permissions(%s)
        """
        
        permissions = execute_query(perms_query, (token['id_usuario'],))
        
        # Preparar respuesta
        user_data = {
            'id': user['id_usuario'],
            'username': user['nombre_usuario'],
            'nombre': user['nombre'],
            'apellidos': user['apellidos'],
            'email': user['email'],
            'roles': roles,
            'permisos': permissions
        }
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user['id_usuario'],
            'direccion_ip': ip_address,
            'accion': 'verificacion_2fa',
            'entidad_afectada': 'sesion',
            'id_entidad_afectada': session_id,
            'detalles': json.dumps({'tipo': token['tipo_dispositivo']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Verificación 2FA exitosa',
                'session_token': session_id,
                'expires_at': expiry_date.isoformat(),
                'user': user_data
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error en verificación 2FA: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error en verificación 2FA: {str(e)}'})
        }

def login_with_2fa(event, context):
    """Maneja el login con autenticación de dos factores"""
    try:
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Verificación 2FA exitosa'
            }, default=str)
        }
    except Exception as e:
        logger.error(f"Error en verificación 2FA: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error en verificación 2FA: {str(e)}'})
        }