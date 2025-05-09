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

# Configure logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

def lambda_handler(event, context):
    """Main handler that routes to the appropriate functions"""
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
        
        # Extract path parameters if they exist
        path_params = event.get('pathParameters', {}) or {}
        
        # User management routes
        if http_method == 'GET' and path == '/users':
            return list_users(event, context)
        elif http_method == 'GET' and path.startswith('/users/') and not path.endswith('/sessions') and not path.endswith('/activity') and not path.endswith('/roles') and not path.endswith('/groups') and not path.endswith('/permissions'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return get_user(event, context)
        elif http_method == 'GET' and path.startswith('/users/') and path.endswith('/roles'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return get_user_roles(event, context)
        elif http_method == 'GET' and path.startswith('/users/') and path.endswith('/groups'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return get_user_groups(event, context)
        elif http_method == 'GET' and path.startswith('/users/') and path.endswith('/permissions'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return get_user_permissions(event, context)
        elif http_method == 'POST' and path == '/users':
            return create_user(event, context)
        elif http_method == 'PUT' and path.startswith('/users/') and not path.endswith('/roles') and not path.endswith('/disable') and not path.endswith('/force-password-change'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return update_user(event, context)
        elif http_method == 'DELETE' and path.endswith('roles/remove'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return remove_user_roles(event, context)
        elif http_method == 'DELETE' and path.startswith('/users/'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return delete_user(event, context)
        elif http_method == 'GET' and path.endswith('/activity'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return get_user_activity(event, context)
        elif http_method == 'GET' and path.endswith('/sessions'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return get_active_sessions(event, context)
        elif http_method == 'POST' and path.endswith('/roles/assign'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return assign_user_roles(event, context)
        elif http_method == 'POST' and path.endswith('/groups/assign'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return assign_user_groups(event, context)
        elif http_method == 'POST' and path.endswith('/groups/remove'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return remove_user_groups(event, context)
        elif http_method == 'PUT' and path.endswith('/roles'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return update_user_roles(event, context)
        elif http_method == 'PUT' and path.endswith('/disable'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return disable_user(event, context)
        elif http_method == 'PUT' and path.endswith('/force-password-change'):
            user_id = path_params.get('id') or path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return force_password_change(event, context)

                 
        # If no route is found, return 404
        return {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Route not found'})
        }
        
    except Exception as e:
        logger.error(f"Error in main dispatcher: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }

def verify_session_and_permissions(event, required_permission=None):
    """Verify user session and check if the user has the required permission"""
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Token not provided'})}
    
    session_token = auth_header.split(' ')[1]
    
    # Check if the session exists and is active
    check_query = """
    SELECT s.id_usuario, s.activa, s.fecha_expiracion, u.estado
    FROM sesiones s
    JOIN usuarios u ON s.id_usuario = u.id_usuario
    WHERE s.id_sesion = %s
    """
    
    session_result = execute_query(check_query, (session_token,))
    
    if not session_result:
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Invalid session'})}
    
    session = session_result[0]
    
    if not session['activa']:
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Inactive session'})}
    
    if session['fecha_expiracion'] < datetime.datetime.now():
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Expired session'})}
    
    if session['estado'] != 'activo':
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Inactive user'})}
    
    user_id = session['id_usuario']
    
    # If no specific permission is required, just return the user ID
    if not required_permission:
        return user_id, None
    
    # Check if the user has the required permission
    perm_query = """
    SELECT COUNT(*) as has_permission
    FROM usuarios_roles ur
    JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
    JOIN permisos p ON rp.id_permiso = p.id_permiso
    WHERE ur.id_usuario = %s AND p.codigo_permiso = %s
    """
    
    perm_result = execute_query(perm_query, (user_id, required_permission))
    
    if not perm_result or perm_result[0]['has_permission'] == 0:
        return user_id, {'statusCode': 403, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': f'You do not have the required permission: {required_permission}'})}
    
    return user_id, None

def list_users(event, context):
    """List users with pagination and filters (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.usuarios')
        if error:
            return error
        
        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Pagination
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filters
        estado = query_params.get('estado')
        search = query_params.get('search')
        role_id = query_params.get('role_id')
        
        # Build base query
        base_query = """
        SELECT u.id_usuario, u.nombre_usuario, u.nombre, u.apellidos, u.email, 
               u.estado, u.fecha_creacion, u.ultimo_acceso, u.requiere_2fa
        FROM usuarios u
        """
        
        count_query = "SELECT COUNT(*) as total FROM usuarios u"
        
        # Add join for role filter if needed
        if role_id:
            base_query += " JOIN usuarios_roles ur ON u.id_usuario = ur.id_usuario"
            count_query += " JOIN usuarios_roles ur ON u.id_usuario = ur.id_usuario"
        
        # Build WHERE clause
        where_clauses = []
        where_params = []
        
        if estado:
            where_clauses.append("u.estado = %s")
            where_params.append(estado)
        
        if search:
            where_clauses.append("(u.nombre_usuario LIKE %s OR u.nombre LIKE %s OR u.apellidos LIKE %s OR u.email LIKE %s)")
            search_param = f"%{search}%"
            where_params.extend([search_param, search_param, search_param, search_param])
        
        if role_id:
            where_clauses.append("ur.id_rol = %s")
            where_params.append(role_id)
        
        # Add WHERE clause to queries
        if where_clauses:
            where_str = " WHERE " + " AND ".join(where_clauses)
            base_query += where_str
            count_query += where_str
        
        # Add sorting and pagination
        base_query += " ORDER BY u.nombre_usuario LIMIT %s OFFSET %s"
        where_params.append(page_size)
        where_params.append((page - 1) * page_size)
        
        # Execute queries
        users = execute_query(base_query, where_params)
        count_result = execute_query(count_query, where_params[:-2] if where_params else [])
        
        total_users = count_result[0]['total'] if count_result else 0
        total_pages = (total_users + page_size - 1) // page_size if total_users > 0 else 1
        
        # For each user, get their roles
        for user in users:
            roles_query = """
            SELECT r.id_rol, r.nombre_rol
            FROM usuarios_roles ur
            JOIN roles r ON ur.id_rol = r.id_rol
            WHERE ur.id_usuario = %s
            """
            
            user['roles'] = execute_query(roles_query, (user['id_usuario'],))
            
            # Convert dates to string for JSON serialization
            if 'fecha_creacion' in user and user['fecha_creacion']:
                user['fecha_creacion'] = user['fecha_creacion'].isoformat()
            
            if 'ultimo_acceso' in user and user['ultimo_acceso']:
                user['ultimo_acceso'] = user['ultimo_acceso'].isoformat()
        
        # Create response with pagination metadata
        response = {
            'users': users,
            'pagination': {
                'total': total_users,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error listing users: {str(e)}'})
        }

def get_user(event, context):
    """Get information about a specific user"""
    try:
        # Verify session
        requesting_user_id, error = verify_session_and_permissions(event)
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # If not the same user, verify admin permission
        if requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.usuarios')
            if error:
                return error
        
        # Get user details
        user_query = """
        SELECT u.id_usuario, u.nombre_usuario, u.nombre, u.apellidos, u.email, 
               u.estado, u.fecha_creacion, u.ultimo_acceso, u.requiere_2fa
        FROM usuarios u
        WHERE u.id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        user = user_result[0]
        
        # Get user roles
        roles_query = """
        SELECT r.id_rol, r.nombre_rol
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        WHERE ur.id_usuario = %s
        """
        
        user['roles'] = execute_query(roles_query, (user_id,))
        
        # Get user groups
        groups_query = """
        SELECT g.id_grupo, g.nombre_grupo
        FROM usuarios_grupos ug
        JOIN grupos g ON ug.id_grupo = g.id_grupo
        WHERE ug.id_usuario = %s
        """
        
        user['grupos'] = execute_query(groups_query, (user_id,))
        
        # Convert dates to string for JSON serialization
        if 'fecha_creacion' in user and user['fecha_creacion']:
            user['fecha_creacion'] = user['fecha_creacion'].isoformat()
        
        if 'ultimo_acceso' in user and user['ultimo_acceso']:
            user['ultimo_acceso'] = user['ultimo_acceso'].isoformat()
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(user, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting user: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting user: {str(e)}'})
        }

def create_user(event, context):
    """Create a new user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.usuarios')
        if error:
            return error
        
        # Get data from body
        body = json.loads(event['body'])
        
        # Validate required fields
        required_fields = ['nombre_usuario', 'nombre', 'apellidos', 'email', 'password', 'roles']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }
        
        # Validate that username and email are unique
        check_existing_query = """
        SELECT nombre_usuario, email
        FROM usuarios
        WHERE nombre_usuario = %s OR email = %s
        """
        
        existing_result = execute_query(check_existing_query, (body['nombre_usuario'], body['email']))
        
        if existing_result:
            for user in existing_result:
                if user['nombre_usuario'] == body['nombre_usuario']:
                    return {
                        'statusCode': 400,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'Username is already in use'})
                    }
                if user['email'] == body['email']:
                    return {
                        'statusCode': 400,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'Email is already in use'})
                    }
        
        # Generate unique ID for the user
        user_id = generate_uuid()
        
        # Generate password hash
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            body['password'].encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=64
        )
        password_hash = f"{salt}${key.hex()}"
        
        # Insert user
        insert_query = """
        INSERT INTO usuarios (
            id_usuario,
            nombre_usuario,
            nombre,
            apellidos,
            email,
            hash_contrasena,
            salt,
            fecha_creacion,
            fecha_modificacion,
            estado,
            requiere_2fa
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        now = datetime.datetime.now()
        require_2fa = bool(body.get('requiere_2fa', False))
        
        insert_params = (
            user_id,
            body['nombre_usuario'],
            body['nombre'],
            body['apellidos'],
            body['email'],
            password_hash,
            salt,
            now,
            now,
            'activo',
            require_2fa
        )
        
        execute_query(insert_query, insert_params, fetch=False)
        
        # Assign roles to user
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
        
        # Assign groups to user if provided
        if 'grupos' in body and body['grupos']:
            for group_id in body['grupos']:
                group_query = """
                INSERT INTO usuarios_grupos (id_usuario, id_grupo, fecha_asignacion)
                VALUES (%s, %s, %s)
                """
                
                execute_query(group_query, (user_id, group_id, now), fetch=False)
        
        # Log in audit
        audit_data = {
            'fecha_hora': now,
            'usuario_id': admin_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({
                'nombre_usuario': body['nombre_usuario'],
                'email': body['email'],
                'roles': body['roles'],
                'grupos': body.get('grupos', [])
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'User created successfully',
                'user_id': user_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error creating user: {str(e)}'})
        }

def update_user(event, context):
    """Update an existing user"""
    try:
        # Verify session
        requesting_user_id, error = verify_session_and_permissions(event)
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # If not the same user, verify admin permission
        if requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.usuarios')
            if error:
                return error
        
        # Get data from body
        body = json.loads(event['body'])
        
        # Check if user exists
        check_user_query = """
        SELECT id_usuario, nombre_usuario, email, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(check_user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        user = user_result[0]
        
        # If user is inactive, only admin can update
        if user['estado'] != 'activo' and requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.usuarios')
            if error:
                return error
        
        # Check if email or username is changed and validate uniqueness
        if ('email' in body and body['email'] != user['email']) or ('nombre_usuario' in body and body['nombre_usuario'] != user['nombre_usuario']):
            check_existing_query = """
            SELECT nombre_usuario, email
            FROM usuarios
            WHERE (nombre_usuario = %s OR email = %s) AND id_usuario != %s
            """
            
            new_username = body.get('nombre_usuario', user['nombre_usuario'])
            new_email = body.get('email', user['email'])
            
            existing_result = execute_query(check_existing_query, (new_username, new_email, user_id))
            
            if existing_result:
                for existing_user in existing_result:
                    if existing_user['nombre_usuario'] == new_username:
                        return {
                            'statusCode': 400,
                            'headers': add_cors_headers({'Content-Type': 'application/json'}),
                            'body': json.dumps({'error': 'Username is already in use'})
                        }
                    if existing_user['email'] == new_email:
                        return {
                            'statusCode': 400,
                            'headers': add_cors_headers({'Content-Type': 'application/json'}),
                            'body': json.dumps({'error': 'Email is already in use'})
                        }
        
        # Build update query dynamically based on provided fields
        update_fields = []
        update_params = []
        allowed_fields = ['nombre_usuario', 'nombre', 'apellidos', 'email', 'requiere_2fa']
        
        for field in allowed_fields:
            if field in body:
                update_fields.append(f"{field} = %s")
                update_params.append(body[field])
        
        # Only admin can update certain fields
        if requesting_user_id != user_id:
            admin_only_fields = ['estado']
            for field in admin_only_fields:
                if field in body:
                    update_fields.append(f"{field} = %s")
                    update_params.append(body[field])
        
        # Add last modified fields
        update_fields.append("fecha_modificacion = %s")
        # update_fields.append("modificado_por = %s")
        update_params.append(datetime.datetime.now())
        # update_params.append(requesting_user_id)
        
        # Add user ID to parameters
        update_params.append(user_id)
        
        # If no fields to update, return error
        if not update_fields:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No fields to update'})
            }
        
        # Build and execute update query
        update_query = f"""
        UPDATE usuarios
        SET {', '.join(update_fields)}
        WHERE id_usuario = %s
        """
        
        execute_query(update_query, update_params, fetch=False)
        
        # Log in audit
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': requesting_user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'modificar',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({
                'campos_actualizados': {field.split(' = ')[0]: body.get(field.split(' = ')[0]) for field in update_fields if ' = ' in field and field.split(' = ')[0] in body}
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'User updated successfully',
                'user_id': user_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error updating user: {str(e)}'})
        }

def delete_user(event, context):
    """Delete/deactivate a user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.usuarios')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Don't allow self-deletion
        if user_id == admin_id:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'You cannot delete your own account'})
            }
        
        # Check if user exists
        check_user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(check_user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        user = user_result[0]
        
        # If user is already inactive, return error
        if user['estado'] != 'activo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User is already inactive'})
            }
        
        # Update user status instead of actual deletion
        update_query = """
        UPDATE usuarios
        SET estado = 'inactivo',
            fecha_modificacion = %s
        WHERE id_usuario = %s
        """
        
        execute_query(update_query, (
            datetime.datetime.now(),
            user_id
        ), fetch=False)
        
        # Close all active sessions for the user
        close_sessions_query = """
        UPDATE sesiones
        SET activa = FALSE,
            fecha_expiracion = %s
        WHERE id_usuario = %s AND activa = TRUE
        """
        
        execute_query(close_sessions_query, (
            datetime.datetime.now(),
            user_id
        ), fetch=False)
        
        # Log in audit
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': admin_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'desactivar',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({'nombre_usuario': user['nombre_usuario']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'User deactivated successfully'
            })
        }
        
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error deleting user: {str(e)}'})
        }

def get_user_activity(event, context):
    """Get activity log for a specific user"""
    try:
        # Verify session
        requesting_user_id, error = verify_session_and_permissions(event)
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # If not the same user, verify audit permission
        if requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.auditoria')
            if error:
                return error
        
        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Pagination
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 20))
        
        # Filters
        start_date = query_params.get('start_date')
        end_date = query_params.get('end_date')
        action_type = query_params.get('action')
        entity_type = query_params.get('entity')
        
        # Build query
        query = """
        SELECT fecha_hora, accion, entidad_afectada, id_entidad_afectada, 
               direccion_ip, detalles, resultado
        FROM registros_auditoria
        WHERE usuario_id = %s
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM registros_auditoria
        WHERE usuario_id = %s
        """
        
        where_params = [user_id]
        
        # Add additional filters
        if start_date:
            query += " AND fecha_hora >= %s"
            count_query += " AND fecha_hora >= %s"
            where_params.append(start_date)
        
        if end_date:
            query += " AND fecha_hora <= %s"
            count_query += " AND fecha_hora <= %s"
            where_params.append(end_date)
        
        if action_type:
            query += " AND accion = %s"
            count_query += " AND accion = %s"
            where_params.append(action_type)
        
        if entity_type:
            query += " AND entidad_afectada = %s"
            count_query += " AND entidad_afectada = %s"
            where_params.append(entity_type)
        
        # Add sorting and pagination
        query += " ORDER BY fecha_hora DESC LIMIT %s OFFSET %s"
        where_params.append(page_size)
        where_params.append((page - 1) * page_size)
        
        # Execute queries
        activity_logs = execute_query(query, where_params)
        count_result = execute_query(count_query, where_params[:-2])
        
        total_logs = count_result[0]['total'] if count_result else 0
        total_pages = (total_logs + page_size - 1) // page_size if total_logs > 0 else 1
        
        # Process results for JSON
        for log in activity_logs:
            # Convert dates to string
            if 'fecha_hora' in log and log['fecha_hora']:
                log['fecha_hora'] = log['fecha_hora'].isoformat()
            
            # Deserialize details
            if 'detalles' in log and log['detalles']:
                try:
                    log['detalles'] = json.loads(log['detalles'])
                except:
                    # If can't deserialize, leave as string
                    pass
        
        # Create response with pagination metadata
        response = {
            'user_id': user_id,
            'activity': activity_logs,
            'pagination': {
                'total': total_logs,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting user activity: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting user activity: {str(e)}'})
        }

def get_active_sessions(event, context):
    """Get active sessions for a specific user"""
    try:
        # Verify session
        requesting_user_id, error = verify_session_and_permissions(event)
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # If not the same user, verify admin permission
        if requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.usuarios')
            if error:
                return error
        
        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Pagination
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Build query for active sessions
        sessions_query = """
        SELECT id_sesion, fecha_inicio, fecha_expiracion, direccion_ip, 
               user_agent, datos_sesion
        FROM sesiones
        WHERE id_usuario = %s AND activa = TRUE
        ORDER BY fecha_inicio DESC
        LIMIT %s OFFSET %s
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM sesiones
        WHERE id_usuario = %s AND activa = TRUE
        """
        
        # Execute queries
        sessions = execute_query(sessions_query, (user_id, page_size, (page - 1) * page_size))
        count_result = execute_query(count_query, (user_id,))
        
        total_sessions = count_result[0]['total'] if count_result else 0
        total_pages = (total_sessions + page_size - 1) // page_size if total_sessions > 0 else 1
        
        # Process dates for JSON
        for session in sessions:
            for date_field in ['fecha_inicio', 'fecha_expiracion', 'datos_sesion']:
                if date_field in session and session[date_field]:
                    session[date_field] = session[date_field].isoformat()
        
        # Create response with pagination metadata
        response = {
            'user_id': user_id,
            'sessions': sessions,
            'pagination': {
                'total': total_sessions,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting active sessions: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting active sessions: {str(e)}'})
        }

def update_user_roles(event, context):
    """Update roles for a specific user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.roles')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Check if user exists and is active
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        if user_result[0]['estado'] != 'activo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cannot modify roles for an inactive user'})
            }
        
        # Get roles from body
        body = json.loads(event['body'])
        
        if 'roles' not in body or not isinstance(body['roles'], list):
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'A list of roles is required'})
            }
        
        new_roles = body['roles']
        
        # Verify that all roles exist
        roles_check_query = """
        SELECT id_rol
        FROM roles
        WHERE id_rol IN ({})
        """.format(','.join(['%s' for _ in new_roles]))
        
        roles_result = execute_query(roles_check_query, new_roles)
        
        found_roles = [r['id_rol'] for r in roles_result]
        
        if len(found_roles) != len(new_roles):
            invalid_roles = [r for r in new_roles if r not in found_roles]
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Invalid roles: {invalid_roles}'})
            }
        
        # Get current roles of the user
        current_roles_query = """
        SELECT id_rol
        FROM usuarios_roles
        WHERE id_usuario = %s
        """
        
        current_roles_result = execute_query(current_roles_query, (user_id,))
        current_roles = [r['id_rol'] for r in current_roles_result]
        
        # Start transaction
        connection = get_connection()
        try:
            connection.begin()
            cursor = connection.cursor()
            
            # Remove roles that are no longer in the list
            roles_to_remove = [r for r in current_roles if r not in new_roles]
            if roles_to_remove:
                del_query = """
                DELETE FROM usuarios_roles
                WHERE id_usuario = %s AND id_rol IN ({})
                """.format(','.join(['%s' for _ in roles_to_remove]))
                
                del_params = [user_id] + roles_to_remove
                cursor.execute(del_query, del_params)
            
            # Add new roles
            roles_to_add = [r for r in new_roles if r not in current_roles]
            for role_id in roles_to_add:
                add_query = """
                INSERT INTO usuarios_roles (id_usuario, id_rol, ambito, id_ambito)
                VALUES (%s, %s, %s, %s)
                """
                
                cursor.execute(add_query, (
                    user_id, 
                    role_id,
                    'global',
                    '00000000-0000-0000-0000-000000000000'
                ))
            
            connection.commit()
            
            # Log in audit
            now = datetime.datetime.now()
            audit_data = {
                'fecha_hora': now,
                'usuario_id': admin_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'actualizar_roles',
                'entidad_afectada': 'usuario',
                'id_entidad_afectada': user_id,
                'detalles': json.dumps({
                    'nombre_usuario': user_result[0]['nombre_usuario'],
                    'roles_anteriores': current_roles,
                    'roles_nuevos': new_roles,
                    'roles_agregados': roles_to_add,
                    'roles_eliminados': roles_to_remove
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'Roles updated successfully',
                    'previous_roles': current_roles,
                    'new_roles': new_roles
                })
            }
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        
    except Exception as e:
        logger.error(f"Error updating roles: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error updating roles: {str(e)}'})
        }

def disable_user(event, context):
    """Disable a user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.usuarios')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Don't allow self-deactivation
        if user_id == admin_id:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'You cannot disable your own account'})
            }
        
        # Check if user exists and is active
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        if user_result[0]['estado'] != 'activo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User is already disabled'})
            }
        
        # Disable the user
        update_query = """
        UPDATE usuarios
        SET estado = 'inactivo',
            fecha_modificacion = %s
        WHERE id_usuario = %s
        """
        
        now = datetime.datetime.now()
        
        execute_query(update_query, (now, user_id), fetch=False)
        
        # Close all active sessions for the user
        close_sessions_query = """
        UPDATE sesiones
        SET activa = FALSE,
            fecha_expiracion = %s
        WHERE id_usuario = %s AND activa = TRUE
        """
        
        execute_query(close_sessions_query, (now, user_id), fetch=False)
        
        # Log in audit
        audit_data = {
            'fecha_hora': now,
            'usuario_id': admin_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'desactivar_usuario',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({'nombre_usuario': user_result[0]['nombre_usuario']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'User disabled successfully'
            })
        }
        
    except Exception as e:
        logger.error(f"Error disabling user: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error disabling user: {str(e)}'})
        }

def force_password_change(event, context):
    """Force password change for a user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.usuarios')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Check if user exists and is active
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        if user_result[0]['estado'] != 'activo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cannot force password change for an inactive user'})
            }
        
        # Mark user for password change on next login
        update_query = """
        UPDATE usuarios
        SET cambiar_password = TRUE,
            fecha_modificacion = %s,
            modificado_por = %s
        WHERE id_usuario = %s
        """
        
        now = datetime.datetime.now()
        
        execute_query(update_query, (now, admin_id, user_id), fetch=False)
        
        # Log in audit
        audit_data = {
            'fecha_hora': now,
            'usuario_id': admin_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'forzar_cambio_password',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({'nombre_usuario': user_result[0]['nombre_usuario']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'User marked for password change on next login'
            })
        }
        
    except Exception as e:
        logger.error(f"Error forcing password change: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error forcing password change: {str(e)}'})
        }

def get_user_roles(event, context):
    """Get roles assigned to a specific user"""
    try:
        # Verify session
        requesting_user_id, error = verify_session_and_permissions(event)
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # If not the same user, verify admin permission
        if requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.roles')
            if error:
                return error
        
        # Check if user exists
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        # Get roles for the user
        roles_query = """
        SELECT r.id_rol, r.nombre_rol, r.descripcion, ur.ambito, ur.id_ambito
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        WHERE ur.id_usuario = %s
        ORDER BY r.nombre_rol
        """
        
        roles = execute_query(roles_query, (user_id,))
        
        # Return roles
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'user_id': user_id,
                'nombre_usuario': user_result[0]['nombre_usuario'],
                'roles': roles
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting user roles: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting user roles: {str(e)}'})
        }

def assign_user_roles(event, context):
    """Assign new roles to a user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.roles')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Check if user exists and is active
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        if user_result[0]['estado'] != 'activo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cannot assign roles to an inactive user'})
            }
        
        # Get roles to assign from body
        body = json.loads(event['body'])
        
        if 'roles' not in body or not isinstance(body['roles'], list) or len(body['roles']) == 0:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'A non-empty list of roles is required'})
            }
        
        roles_to_assign = body['roles']
        
        # Verify that all roles exist
        roles_check_query = """
        SELECT id_rol
        FROM roles
        WHERE id_rol IN ({})
        """.format(','.join(['%s' for _ in roles_to_assign]))
        
        roles_result = execute_query(roles_check_query, roles_to_assign)
        
        found_roles = [r['id_rol'] for r in roles_result]
        
        if len(found_roles) != len(roles_to_assign):
            invalid_roles = [r for r in roles_to_assign if r not in found_roles]
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Invalid roles: {invalid_roles}'})
            }
        
        # Get current roles of the user
        current_roles_query = """
        SELECT id_rol
        FROM usuarios_roles
        WHERE id_usuario = %s
        """
        
        current_roles_result = execute_query(current_roles_query, (user_id,))
        current_roles = [r['id_rol'] for r in current_roles_result]
        
        # Determine new roles to add (that aren't already assigned)
        roles_to_add = [r for r in roles_to_assign if r not in current_roles]
        
        if not roles_to_add:
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'All roles already assigned to user',
                    'user_id': user_id
                })
            }
        
        # Start transaction
        connection = get_connection()
        try:
            connection.begin()
            cursor = connection.cursor()
            
            # Add new roles
            for role_id in roles_to_add:
                add_query = """
                INSERT INTO usuarios_roles (id_usuario, id_rol, ambito, id_ambito)
                VALUES (%s, %s, %s, %s)
                """
                
                cursor.execute(add_query, (
                    user_id, 
                    role_id,
                    'global',
                    '00000000-0000-0000-0000-000000000000'
                ))
            
            connection.commit()
            
            # Log in audit
            now = datetime.datetime.now()
            audit_data = {
                'fecha_hora': now,
                'usuario_id': admin_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'asignar_roles',
                'entidad_afectada': 'usuario',
                'id_entidad_afectada': user_id,
                'detalles': json.dumps({
                    'nombre_usuario': user_result[0]['nombre_usuario'],
                    'roles_asignados': roles_to_add
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'Roles assigned successfully',
                    'user_id': user_id,
                    'roles_assigned': roles_to_add
                })
            }
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        
    except Exception as e:
        logger.error(f"Error assigning user roles: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error assigning user roles: {str(e)}'})
        }

def remove_user_roles(event, context):
    """Remove roles from a user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.roles')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Check if user exists
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        # Get roles to remove from body
        body = json.loads(event['body'])
        
        if 'roles' not in body or not isinstance(body['roles'], list) or len(body['roles']) == 0:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'A non-empty list of roles is required'})
            }
        
        roles_to_remove = body['roles']
        
        # Verify that specified roles are currently assigned to the user
        current_roles_query = """
        SELECT id_rol
        FROM usuarios_roles
        WHERE id_usuario = %s AND id_rol IN ({})
        """.format(','.join(['%s' for _ in roles_to_remove]))
        
        current_roles_result = execute_query(current_roles_query, [user_id] + roles_to_remove)
        current_roles = [r['id_rol'] for r in current_roles_result]
        
        if len(current_roles) != len(roles_to_remove):
            not_assigned_roles = [r for r in roles_to_remove if r not in current_roles]
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Some roles are not assigned to the user: {not_assigned_roles}'})
            }
        
        # Remove roles
        if roles_to_remove:
            del_query = """
            DELETE FROM usuarios_roles
            WHERE id_usuario = %s AND id_rol IN ({})
            """.format(','.join(['%s' for _ in roles_to_remove]))
            
            del_params = [user_id] + roles_to_remove
            execute_query(del_query, del_params, fetch=False)
        
        # Log in audit
        now = datetime.datetime.now()
        audit_data = {
            'fecha_hora': now,
            'usuario_id': admin_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'eliminar_roles',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({
                'nombre_usuario': user_result[0]['nombre_usuario'],
                'roles_eliminados': roles_to_remove
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Roles removed successfully',
                'user_id': user_id,
                'roles_removed': roles_to_remove
            })
        }
        
    except Exception as e:
        logger.error(f"Error removing user roles: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error removing user roles: {str(e)}'})
        }

def get_user_groups(event, context):
    """Get groups assigned to a specific user"""
    try:
        # Verify session
        requesting_user_id, error = verify_session_and_permissions(event)
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # If not the same user, verify admin permission
        if requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.usuarios')
            if error:
                return error
        
        # Check if user exists
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        # Get groups for the user
        groups_query = """
        SELECT g.id_grupo, g.nombre_grupo, g.descripcion, g.grupo_padre_id,
               ug.fecha_asignacion
        FROM usuarios_grupos ug
        JOIN grupos g ON ug.id_grupo = g.id_grupo
        WHERE ug.id_usuario = %s
        ORDER BY g.nombre_grupo
        """
        
        groups = execute_query(groups_query, (user_id,))
        
        # Format dates for JSON serialization
        for group in groups:
            if 'fecha_asignacion' in group and group['fecha_asignacion']:
                group['fecha_asignacion'] = group['fecha_asignacion'].isoformat()
        
        # Return groups
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'user_id': user_id,
                'nombre_usuario': user_result[0]['nombre_usuario'],
                'groups': groups
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting user groups: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting user groups: {str(e)}'})
        }

def assign_user_groups(event, context):
    """Assign new groups to a user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.usuarios')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Check if user exists and is active
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        if user_result[0]['estado'] != 'activo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cannot assign groups to an inactive user'})
            }
        
        # Get groups to assign from body
        body = json.loads(event['body'])
        
        if 'groups' not in body or not isinstance(body['groups'], list) or len(body['groups']) == 0:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'A non-empty list of groups is required'})
            }
        
        groups_to_assign = body['groups']
        
        # Verify that all groups exist
        groups_check_query = """
        SELECT id_grupo
        FROM grupos
        WHERE id_grupo IN ({})
        """.format(','.join(['%s' for _ in groups_to_assign]))
        
        groups_result = execute_query(groups_check_query, groups_to_assign)
        
        found_groups = [g['id_grupo'] for g in groups_result]
        
        if len(found_groups) != len(groups_to_assign):
            invalid_groups = [g for g in groups_to_assign if g not in found_groups]
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Invalid groups: {invalid_groups}'})
            }
        
        # Get current groups of the user
        current_groups_query = """
        SELECT id_grupo
        FROM usuarios_grupos
        WHERE id_usuario = %s
        """
        
        current_groups_result = execute_query(current_groups_query, (user_id,))
        current_groups = [g['id_grupo'] for g in current_groups_result]
        
        # Determine new groups to add (that aren't already assigned)
        groups_to_add = [g for g in groups_to_assign if g not in current_groups]
        
        if not groups_to_add:
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'All groups already assigned to user',
                    'user_id': user_id
                })
            }
        
        # Start transaction
        connection = get_connection()
        try:
            connection.begin()
            cursor = connection.cursor()
            
            # Add new groups
            now = datetime.datetime.now()
            for group_id in groups_to_add:
                add_query = """
                INSERT INTO usuarios_grupos (id_usuario, id_grupo, fecha_asignacion)
                VALUES (%s, %s, %s)
                """
                
                cursor.execute(add_query, (user_id, group_id, now))
            
            connection.commit()
            
            # Log in audit
            audit_data = {
                'fecha_hora': now,
                'usuario_id': admin_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'asignar_grupos',
                'entidad_afectada': 'usuario',
                'id_entidad_afectada': user_id,
                'detalles': json.dumps({
                    'nombre_usuario': user_result[0]['nombre_usuario'],
                    'grupos_asignados': groups_to_add
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'Groups assigned successfully',
                    'user_id': user_id,
                    'groups_assigned': groups_to_add
                })
            }
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        
    except Exception as e:
        logger.error(f"Error assigning user groups: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error assigning user groups: {str(e)}'})
        }

def remove_user_groups(event, context):
    """Remove groups from a user (admin only)"""
    try:
        # Verify session and permissions
        admin_id, error = verify_session_and_permissions(event, 'admin.usuarios')
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # Check if user exists
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        # Get groups to remove from body
        body = json.loads(event['body'])
        
        if 'groups' not in body or not isinstance(body['groups'], list) or len(body['groups']) == 0:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'A non-empty list of groups is required'})
            }
        
        groups_to_remove = body['groups']
        
        # Verify that specified groups are currently assigned to the user
        current_groups_query = """
        SELECT id_grupo
        FROM usuarios_grupos
        WHERE id_usuario = %s AND id_grupo IN ({})
        """.format(','.join(['%s' for _ in groups_to_remove]))
        
        current_groups_result = execute_query(current_groups_query, [user_id] + groups_to_remove)
        current_groups = [g['id_grupo'] for g in current_groups_result]
        
        if len(current_groups) != len(groups_to_remove):
            not_assigned_groups = [g for g in groups_to_remove if g not in current_groups]
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Some groups are not assigned to the user: {not_assigned_groups}'})
            }
        
        # Remove groups
        if groups_to_remove:
            del_query = """
            DELETE FROM usuarios_grupos
            WHERE id_usuario = %s AND id_grupo IN ({})
            """.format(','.join(['%s' for _ in groups_to_remove]))
            
            del_params = [user_id] + groups_to_remove
            execute_query(del_query, del_params, fetch=False)
        
        # Log in audit
        now = datetime.datetime.now()
        audit_data = {
            'fecha_hora': now,
            'usuario_id': admin_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'eliminar_grupos',
            'entidad_afectada': 'usuario',
            'id_entidad_afectada': user_id,
            'detalles': json.dumps({
                'nombre_usuario': user_result[0]['nombre_usuario'],
                'grupos_eliminados': groups_to_remove
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Groups removed successfully',
                'user_id': user_id,
                'groups_removed': groups_to_remove
            })
        }
        
    except Exception as e:
        logger.error(f"Error removing user groups: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error removing user groups: {str(e)}'})
        }

def get_user_permissions(event, context):
    """Get effective permissions for a specific user"""
    try:
        # Verify session
        requesting_user_id, error = verify_session_and_permissions(event)
        if error:
            return error
        
        # Get user ID from path parameters
        user_id = event['pathParameters']['id']
        
        # If not the same user, verify admin permission
        if requesting_user_id != user_id:
            _, error = verify_session_and_permissions(event, 'admin.usuarios')
            if error:
                return error
        
        # Check if user exists
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'User not found'})
            }
        
        # Get permissions for the user through roles
        perms_query = """
        SELECT DISTINCT p.id_permiso, p.codigo_permiso, p.descripcion, p.categoria,
                        r.id_rol, r.nombre_rol
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        JOIN roles_permisos rp ON r.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s
        ORDER BY p.categoria, p.codigo_permiso
        """
        
        permissions = execute_query(perms_query, (user_id,))
        
        # Organize permissions by category
        permissions_by_category = {}
        for perm in permissions:
            category = perm['categoria']
            if category not in permissions_by_category:
                permissions_by_category[category] = []
            
            # Add permission to category if not already present
            perm_info = {
                'id_permiso': perm['id_permiso'],
                'codigo_permiso': perm['codigo_permiso'],
                'descripcion': perm['descripcion'],
                'otorgado_por': [{
                    'id_rol': perm['id_rol'],
                    'nombre_rol': perm['nombre_rol']
                }]
            }
            
            # Check if permission is already in the list
            existing_perm = next((p for p in permissions_by_category[category] 
                                  if p['id_permiso'] == perm['id_permiso']), None)
            
            if existing_perm:
                # Add role to existing permission if not already present
                role_exists = next((r for r in existing_perm['otorgado_por'] 
                                   if r['id_rol'] == perm['id_rol']), None)
                if not role_exists:
                    existing_perm['otorgado_por'].append({
                        'id_rol': perm['id_rol'],
                        'nombre_rol': perm['nombre_rol']
                    })
            else:
                # Add new permission to category
                permissions_by_category[category].append(perm_info)
        
        # Return permissions
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'user_id': user_id,
                'nombre_usuario': user_result[0]['nombre_usuario'],
                'permissions_by_category': permissions_by_category
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting user permissions: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting user permissions: {str(e)}'})
        }
