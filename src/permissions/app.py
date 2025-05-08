import os
import json
import logging
import datetime
from uuid import uuid4

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
        
        # Rutas de gestión de roles
        if http_method == 'GET' and path == '/roles':
            return list_roles(event, context)
        elif http_method == 'GET' and path.startswith('/roles/') and len(path.split('/')) == 3:
            role_id = path.split('/')[2]
            event['pathParameters'] = {'id': role_id}
            return get_role(event, context)
        elif http_method == 'POST' and path == '/roles':
            return create_role(event, context)
        elif http_method == 'PUT' and path.startswith('/roles/') and len(path.split('/')) == 3:
            role_id = path.split('/')[2]
            event['pathParameters'] = {'id': role_id}
            return update_role(event, context)
        elif http_method == 'DELETE' and path.startswith('/roles/') and len(path.split('/')) == 3:
            role_id = path.split('/')[2]
            event['pathParameters'] = {'id': role_id}
            return delete_role(event, context)
            
        # Rutas de gestión de permisos
        elif http_method == 'GET' and path == '/permissions':
            return list_permissions(event, context)
        elif http_method == 'GET' and path.startswith('/permissions/') and len(path.split('/')) == 3:
            permission_id = path.split('/')[2]
            event['pathParameters'] = {'id': permission_id}
            return get_permission(event, context)
        elif http_method == 'POST' and path == '/permissions':
            return create_permission(event, context)
        elif http_method == 'PUT' and path.startswith('/permissions/') and len(path.split('/')) == 3:
            permission_id = path.split('/')[2]
            event['pathParameters'] = {'id': permission_id}
            return update_permission(event, context)
        elif http_method == 'DELETE' and path.startswith('/permissions/') and len(path.split('/')) == 3:
            permission_id = path.split('/')[2]
            event['pathParameters'] = {'id': permission_id}
            return delete_permission(event, context)
            
        # Rutas de gestión de roles-permisos
        elif http_method == 'GET' and path.startswith('/roles/') and path.endswith('/permissions'):
            role_id = path.split('/')[2]
            event['pathParameters'] = {'id': role_id}
            return get_role_permissions(event, context)
        elif http_method == 'POST' and path.startswith('/roles/') and path.endswith('/permissions'):
            role_id = path.split('/')[2]
            event['pathParameters'] = {'id': role_id}
            return assign_permissions_to_role(event, context)
        elif http_method == 'DELETE' and path.startswith('/roles/') and path.endswith('/permissions'):
            role_id = path.split('/')[2]
            event['pathParameters'] = {'id': role_id}
            return remove_permissions_from_role(event, context)
        elif http_method == 'GET' and path.startswith('/roles/') and '/permissions/' in path:
            parts = path.split('/')
            role_id = parts[2]
            permission_id = parts[4]
            event['pathParameters'] = {'role_id': role_id, 'permission_id': permission_id}
            return check_role_permission(event, context)
            
        # Rutas de gestión de permisos de usuario
        elif http_method == 'GET' and path.startswith('/users/') and path.endswith('/permission'):
            user_id = path.split('/')[2]
            event['pathParameters'] = {'id': user_id}
            return get_user_permissions(event, context)
        elif http_method == 'GET' and path.startswith('/users/') and '/permissions/' in path:
            parts = path.split('/')
            user_id = parts[2]
            permission_code = parts[4]
            event['pathParameters'] = {'user_id': user_id, 'permission_code': permission_code}
            return check_permission(event, context)
            
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
            'body': json.dumps({'error': f'Error interno del servidor: {str(e)}'})
        }

def validate_session(event, required_permission=None):
    """Verify user session and check if the user has the required permission"""
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None, {'statusCode': 401, 'body': json.dumps({'error': 'Token not provided'})}
    
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
        return None, {'statusCode': 401, 'body': json.dumps({'error': 'Invalid session'})}
    
    session = session_result[0]
    
    if not session['activa']:
        return None, {'statusCode': 401, 'body': json.dumps({'error': 'Inactive session'})}
    
    if session['fecha_expiracion'] < datetime.datetime.now():
        return None, {'statusCode': 401, 'body': json.dumps({'error': 'Expired session'})}
    
    if session['estado'] != 'activo':
        return None, {'statusCode': 401, 'body': json.dumps({'error': 'Inactive user'})}
    
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
        return user_id, {'statusCode': 403, 'body': json.dumps({'error': f'You do not have the required permission: {required_permission}'})}
    
    return user_id, None

# ------------------- Funciones de gestión de roles -------------------

def list_roles(event, context):
    """Lista todos los roles del sistema con paginación y filtros"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
            
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filtros
        search = query_params.get('search')
        
        # Construir consulta
        query = """
        SELECT id_rol, nombre_rol, descripcion
        FROM roles
        """
        
        count_query = "SELECT COUNT(*) as total FROM roles"
        
        params = []
        
        # Añadir filtros si existen
        if search:
            query += " WHERE nombre_rol LIKE %s OR descripcion LIKE %s"
            count_query += " WHERE nombre_rol LIKE %s OR descripcion LIKE %s"
            params.extend([f"%{search}%", f"%{search}%"])
        
        # Añadir ordenamiento y paginación
        query += " ORDER BY nombre_rol LIMIT %s OFFSET %s"
        params.extend([page_size, (page - 1) * page_size])
        
        # Ejecutar consultas
        roles = execute_query(query, params)
        count_result = execute_query(count_query, params[:-2] if params else [])
        
        total_roles = count_result[0]['total'] if count_result else 0
        total_pages = (total_roles + page_size - 1) // page_size if total_roles > 0 else 1
        
        # Crear respuesta
        response = {
            'roles': roles,
            'pagination': {
                'total': total_roles,
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
        logger.error(f"Error al listar roles: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al listar roles: {str(e)}'})
        }

def get_role(event, context):
    """Obtiene información detallada de un rol específico"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
        # Obtener ID del rol
        role_id = event['pathParameters']['id']
        
        # Consultar información del rol
        role_query = """
        SELECT id_rol, nombre_rol, descripcion
        FROM roles
        WHERE id_rol = %s
        """
        
        role_result = execute_query(role_query, (role_id,))
        
        if not role_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Rol no encontrado'})
            }
            
        role = role_result[0]
        
        # Obtener permisos asociados al rol
        permissions_query = """
        SELECT p.id_permiso, p.codigo_permiso, p.descripcion, p.categoria
        FROM roles_permisos rp
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE rp.id_rol = %s
        ORDER BY p.categoria, p.codigo_permiso
        """
        
        permissions = execute_query(permissions_query, (role_id,))
        
        # Añadir permisos a la respuesta
        role['permisos'] = permissions
        
        # Contar usuarios con este rol
        users_count_query = """
        SELECT COUNT(DISTINCT id_usuario) as users_count
        FROM usuarios_roles
        WHERE id_rol = %s
        """
        
        users_count_result = execute_query(users_count_query, (role_id,))
        role['usuarios_count'] = users_count_result[0]['users_count']
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(role, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al obtener rol: {str(e)}'})
        }

def create_role(event, context):
    """Crea un nuevo rol en el sistema"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'nombre_rol' not in body:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'El nombre del rol es requerido'})
            }
            
        nombre_rol = body['nombre_rol']
        descripcion = body.get('descripcion')
        
        # Verificar si ya existe un rol con el mismo nombre
        check_query = """
        SELECT COUNT(*) as count
        FROM roles
        WHERE nombre_rol = %s
        """
        
        check_result = execute_query(check_query, (nombre_rol,))
        if check_result[0]['count'] > 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Ya existe un rol con ese nombre'})
            }
            
        # Generar ID del rol
        role_id = generate_uuid()
        
        # Insertar rol
        insert_query = """
        INSERT INTO roles (id_rol, nombre_rol, descripcion)
        VALUES (%s, %s, %s)
        """
        
        execute_query(insert_query, (role_id, nombre_rol, descripcion), fetch=False)
        
        # Asignar permisos iniciales si se proporcionan
        if 'permisos' in body and isinstance(body['permisos'], list) and body['permisos']:
            for permission_id in body['permisos']:
                insert_permission_query = """
                INSERT INTO roles_permisos (id_rol, id_permiso)
                VALUES (%s, %s)
                """
                execute_query(insert_permission_query, (role_id, permission_id), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear',
            'entidad_afectada': 'rol',
            'id_entidad_afectada': role_id,
            'detalles': json.dumps({
                'nombre_rol': nombre_rol,
                'descripcion': descripcion,
                'permisos_iniciales': body.get('permisos', [])
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Rol creado exitosamente',
                'id_rol': role_id,
                'nombre_rol': nombre_rol
            })
        }
        
    except Exception as e:
        logger.error(f"Error al crear rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al crear rol: {str(e)}'})
        }

def update_role(event, context):
    """Actualiza un rol existente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
        # Obtener ID del rol
        role_id = event['pathParameters']['id']
        
        # Verificar si el rol existe
        check_query = """
        SELECT nombre_rol
        FROM roles
        WHERE id_rol = %s
        """
        
        role_result = execute_query(check_query, (role_id,))
        if not role_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Rol no encontrado'})
            }
            
        old_nombre_rol = role_result[0]['nombre_rol']
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'nombre_rol' not in body:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'El nombre del rol es requerido'})
            }
            
        nombre_rol = body['nombre_rol']
        descripcion = body.get('descripcion')
        
        # Verificar si ya existe otro rol con el mismo nombre
        if nombre_rol != old_nombre_rol:
            check_name_query = """
            SELECT COUNT(*) as count
            FROM roles
            WHERE nombre_rol = %s AND id_rol != %s
            """
            
            check_name_result = execute_query(check_name_query, (nombre_rol, role_id))
            if check_name_result[0]['count'] > 0:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Ya existe otro rol con ese nombre'})
                }
        
        # Actualizar rol
        update_query = """
        UPDATE roles
        SET nombre_rol = %s, descripcion = %s
        WHERE id_rol = %s
        """
        
        execute_query(update_query, (nombre_rol, descripcion, role_id), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'actualizar',
            'entidad_afectada': 'rol',
            'id_entidad_afectada': role_id,
            'detalles': json.dumps({
                'nombre_rol_anterior': old_nombre_rol,
                'nombre_rol_nuevo': nombre_rol,
                'descripcion': descripcion
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Rol actualizado exitosamente',
                'id_rol': role_id,
                'nombre_rol': nombre_rol
            })
        }
        
    except Exception as e:
        logger.error(f"Error al actualizar rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al actualizar rol: {str(e)}'})
        }

def delete_role(event, context):
    """Elimina un rol existente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
            
        # Obtener ID del rol
        role_id = event['pathParameters']['id']
        
        # Verificar si el rol existe
        check_query = """
        SELECT nombre_rol
        FROM roles
        WHERE id_rol = %s
        """
        
        role_result = execute_query(check_query, (role_id,))
        if not role_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Rol no encontrado'})
            }
            
        nombre_rol = role_result[0]['nombre_rol']
        
        # Verificar si el rol está en uso
        check_usage_query = """
        SELECT COUNT(*) as count
        FROM usuarios_roles
        WHERE id_rol = %s
        """
        
        check_usage_result = execute_query(check_usage_query, (role_id,))
        if check_usage_result[0]['count'] > 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No se puede eliminar un rol que está asignado a usuarios'})
            }
            
        # Iniciar transacción
        connection = get_connection()
        cursor = connection.cursor()
        
        try:
            # Eliminar las asignaciones de permisos al rol
            cursor.execute("""
            DELETE FROM roles_permisos
            WHERE id_rol = %s
            """, (role_id,))
            
            # Eliminar el rol
            cursor.execute("""
            DELETE FROM roles
            WHERE id_rol = %s
            """, (role_id,))
            
            connection.commit()
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'eliminar',
                'entidad_afectada': 'rol',
                'id_entidad_afectada': role_id,
                'detalles': json.dumps({
                    'nombre_rol': nombre_rol
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Rol eliminado exitosamente'
                })
            }
            
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        
    except Exception as e:
        logger.error(f"Error al eliminar rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al eliminar rol: {str(e)}'})
        }

# ------------------- Funciones de gestión de permisos -------------------

def list_permissions(event, context):
    """Lista todos los permisos del sistema con paginación y filtros"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
            
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 20))
        
        # Filtros
        search = query_params.get('search')
        category = query_params.get('categoria')
        
        # Construir consulta
        query = """
        SELECT id_permiso, codigo_permiso, descripcion, categoria
        FROM permisos
        """
        
        count_query = "SELECT COUNT(*) as total FROM permisos"
        
        where_clauses = []
        params = []
        
        # Añadir filtros si existen
        if search:
            where_clauses.append("(codigo_permiso LIKE %s OR descripcion LIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])
            
        if category:
            where_clauses.append("categoria = %s")
            params.append(category)
            
        # Añadir cláusula WHERE si hay filtros
        if where_clauses:
            where_statement = " WHERE " + " AND ".join(where_clauses)
            query += where_statement
            count_query += where_statement
        
        # Añadir ordenamiento y paginación
        query += " ORDER BY categoria, codigo_permiso LIMIT %s OFFSET %s"
        params.extend([page_size, (page - 1) * page_size])
        
        # Ejecutar consultas
        permissions = execute_query(query, params)
        count_result = execute_query(count_query, params[:-2] if params else [])
        
        total_permissions = count_result[0]['total'] if count_result else 0
        total_pages = (total_permissions + page_size - 1) // page_size if total_permissions > 0 else 1
        
        # Obtener categorías disponibles
        categories_query = """
        SELECT DISTINCT categoria
        FROM permisos
        ORDER BY categoria
        """
        
        categories = execute_query(categories_query)
        available_categories = [c['categoria'] for c in categories]
        
        # Crear respuesta
        response = {
            'permisos': permissions,
            'categorias_disponibles': available_categories,
            'pagination': {
                'total': total_permissions,
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
        logger.error(f"Error al listar permisos: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al listar permisos: {str(e)}'})
        }

def get_permission(event, context):
    """Obtiene información detallada de un permiso específico"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
            
        # Obtener ID del permiso
        permission_id = event['pathParameters']['id']
        
        # Consultar información del permiso
        permission_query = """
        SELECT id_permiso, codigo_permiso, descripcion, categoria
        FROM permisos
        WHERE id_permiso = %s
        """
        
        permission_result = execute_query(permission_query, (permission_id,))
        
        if not permission_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Permiso no encontrado'})
            }
            
        permission = permission_result[0]
        
        # Obtener roles que tienen este permiso
        roles_query = """
        SELECT r.id_rol, r.nombre_rol, r.descripcion
        FROM roles_permisos rp
        JOIN roles r ON rp.id_rol = r.id_rol
        WHERE rp.id_permiso = %s
        ORDER BY r.nombre_rol
        """
        
        roles = execute_query(roles_query, (permission_id,))
        
        # Añadir roles a la respuesta
        permission['roles'] = roles
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(permission, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener permiso: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al obtener permiso: {str(e)}'})
        }

def create_permission(event, context):
    """Crea un nuevo permiso en el sistema"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        required_fields = ['codigo_permiso', 'descripcion', 'categoria']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'El campo {field} es requerido'})
                }
                
        codigo_permiso = body['codigo_permiso']
        descripcion = body['descripcion']
        categoria = body['categoria']
        
        # Validar que la categoría sea válida
        valid_categories = ['documentos', 'administracion', 'configuracion', 'clientes']
        if categoria not in valid_categories:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Categoría inválida. Debe ser una de: {", ".join(valid_categories)}'
                })
            }
            
        # Verificar si ya existe un permiso con el mismo código
        check_query = """
        SELECT COUNT(*) as count
        FROM permisos
        WHERE codigo_permiso = %s
        """
        
        check_result = execute_query(check_query, (codigo_permiso,))
        if check_result[0]['count'] > 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Ya existe un permiso con ese código'})
            }
            
        # Generar ID del permiso
        permission_id = generate_uuid()
        
        # Insertar permiso
        insert_query = """
        INSERT INTO permisos (id_permiso, codigo_permiso, descripcion, categoria)
        VALUES (%s, %s, %s, %s)
        """
        
        execute_query(insert_query, (permission_id, codigo_permiso, descripcion, categoria), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear',
            'entidad_afectada': 'permiso',
            'id_entidad_afectada': permission_id,
            'detalles': json.dumps({
                'codigo_permiso': codigo_permiso,
                'descripcion': descripcion,
                'categoria': categoria
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Permiso creado exitosamente',
                'id_permiso': permission_id,
                'codigo_permiso': codigo_permiso
            })
        }
        
    except Exception as e:
        logger.error(f"Error al crear permiso: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al crear permiso: {str(e)}'})
        }

def update_permission(event, context):
    """Actualiza un permiso existente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
            
        # Obtener ID del permiso
        permission_id = event['pathParameters']['id']
        
        # Verificar si el permiso existe
        check_query = """
        SELECT codigo_permiso, descripcion, categoria
        FROM permisos
        WHERE id_permiso = %s
        """
        
        permission_result = execute_query(check_query, (permission_id,))
        if not permission_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Permiso no encontrado'})
            }
            
        old_permission = permission_result[0]
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        required_fields = ['codigo_permiso', 'descripcion', 'categoria']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'El campo {field} es requerido'})
                }
                
        codigo_permiso = body['codigo_permiso']
        descripcion = body['descripcion']
        categoria = body['categoria']
        
        # Validar que la categoría sea válida
        valid_categories = ['documentos', 'administracion', 'configuracion', 'clientes']
        if categoria not in valid_categories:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Categoría inválida. Debe ser una de: {", ".join(valid_categories)}'
                })
            }
            
        # Verificar si ya existe otro permiso con el mismo código
        if codigo_permiso != old_permission['codigo_permiso']:
            check_code_query = """
            SELECT COUNT(*) as count
            FROM permisos
            WHERE codigo_permiso = %s AND id_permiso != %s
            """
            
            check_code_result = execute_query(check_code_query, (codigo_permiso, permission_id))
            if check_code_result[0]['count'] > 0:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Ya existe otro permiso con ese código'})
                }
        
        # Actualizar permiso
        update_query = """
        UPDATE permisos
        SET codigo_permiso = %s, descripcion = %s, categoria = %s
        WHERE id_permiso = %s
        """
        
        execute_query(update_query, (codigo_permiso, descripcion, categoria, permission_id), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'actualizar',
            'entidad_afectada': 'permiso',
            'id_entidad_afectada': permission_id,
            'detalles': json.dumps({
                'codigo_permiso_anterior': old_permission['codigo_permiso'],
                'codigo_permiso_nuevo': codigo_permiso,
                'descripcion_anterior': old_permission['descripcion'],
                'descripcion_nueva': descripcion,
                'categoria_anterior': old_permission['categoria'],
                'categoria_nueva': categoria
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Permiso actualizado exitosamente',
                'id_permiso': permission_id,
                'codigo_permiso': codigo_permiso
            })
        }
        
    except Exception as e:
        logger.error(f"Error al actualizar permiso: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al actualizar permiso: {str(e)}'})
        }

def delete_permission(event, context):
    """Elimina un permiso existente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
            
        # Obtener ID del permiso
        permission_id = event['pathParameters']['id']
        
        # Verificar si el permiso existe
        check_query = """
        SELECT codigo_permiso
        FROM permisos
        WHERE id_permiso = %s
        """
        
        permission_result = execute_query(check_query, (permission_id,))
        if not permission_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Permiso no encontrado'})
            }
            
        codigo_permiso = permission_result[0]['codigo_permiso']
        
        # Verificar si el permiso está en uso
        check_usage_query = """
        SELECT COUNT(*) as count
        FROM roles_permisos
        WHERE id_permiso = %s
        """
        
        check_usage_result = execute_query(check_usage_query, (permission_id,))
        if check_usage_result[0]['count'] > 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No se puede eliminar un permiso que está asignado a roles'})
            }
            
        # Eliminar el permiso
        delete_query = """
        DELETE FROM permisos
        WHERE id_permiso = %s
        """
        
        execute_query(delete_query, (permission_id,), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'eliminar',
            'entidad_afectada': 'permiso',
            'id_entidad_afectada': permission_id,
            'detalles': json.dumps({
                'codigo_permiso': codigo_permiso
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Permiso eliminado exitosamente'
            })
        }
        
    except Exception as e:
        logger.error(f"Error al eliminar permiso: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al eliminar permiso: {str(e)}'})
        }

# ------------------- Funciones de gestión de roles-permisos -------------------

def get_role_permissions(event, context):
    """Obtiene los permisos asignados a un rol específico"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response

            
        # Obtener ID del rol
        role_id = event['pathParameters']['id']
        
        # Verificar si el rol existe
        check_query = """
        SELECT nombre_rol
        FROM roles
        WHERE id_rol = %s
        """
        
        role_result = execute_query(check_query, (role_id,))
        if not role_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Rol no encontrado'})
            }
            
        nombre_rol = role_result[0]['nombre_rol']
        
        # Obtener permisos asignados al rol
        permissions_query = """
        SELECT p.id_permiso, p.codigo_permiso, p.descripcion, p.categoria
        FROM roles_permisos rp
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE rp.id_rol = %s
        ORDER BY p.categoria, p.codigo_permiso
        """
        
        permissions = execute_query(permissions_query, (role_id,))
        
        # Agrupar permisos por categoría
        permissions_by_category = {}
        for perm in permissions:
            cat = perm['categoria']
            if cat not in permissions_by_category:
                permissions_by_category[cat] = []
            permissions_by_category[cat].append(perm)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'id_rol': role_id,
                'nombre_rol': nombre_rol,
                'permisos': permissions,
                'permisos_por_categoria': permissions_by_category
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener permisos del rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al obtener permisos del rol: {str(e)}'})
        }

def assign_permissions_to_role(event, context):
    """Asigna permisos a un rol"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response

            
        # Obtener ID del rol
        role_id = event['pathParameters']['id']
        
        # Verificar si el rol existe
        check_query = """
        SELECT nombre_rol
        FROM roles
        WHERE id_rol = %s
        """
        
        role_result = execute_query(check_query, (role_id,))
        if not role_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Rol no encontrado'})
            }
            
        nombre_rol = role_result[0]['nombre_rol']
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar datos requeridos
        if 'permisos' not in body or not isinstance(body['permisos'], list):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Se requiere una lista de IDs de permisos'})
            }
            
        permission_ids = body['permisos']
        
        # Validar que los permisos existan
        if permission_ids:
            placeholders = ", ".join(["%s"] * len(permission_ids))
            validate_query = f"""
            SELECT id_permiso, codigo_permiso
            FROM permisos
            WHERE id_permiso IN ({placeholders})
            """
            
            valid_permissions = execute_query(validate_query, permission_ids)
            
            if len(valid_permissions) != len(permission_ids):
                valid_ids = [p['id_permiso'] for p in valid_permissions]
                invalid_ids = [p_id for p_id in permission_ids if p_id not in valid_ids]
                
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'Algunos permisos no existen',
                        'permisos_invalidos': invalid_ids
                    })
                }
                
            # Obtener permisos actuales del rol
            current_query = """
            SELECT id_permiso
            FROM roles_permisos
            WHERE id_rol = %s
            """
            
            current_permissions = execute_query(current_query, (role_id,))
            current_permission_ids = [p['id_permiso'] for p in current_permissions]
            
            # Determinar permisos a agregar (los que no están en los actuales)
            permissions_to_add = [p_id for p_id in permission_ids if p_id not in current_permission_ids]
            
            # Añadir nuevos permisos
            for perm_id in permissions_to_add:
                insert_query = """
                INSERT INTO roles_permisos (id_rol, id_permiso)
                VALUES (%s, %s)
                """
                
                execute_query(insert_query, (role_id, perm_id), fetch=False)
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'asignar_permisos',
                'entidad_afectada': 'rol',
                'id_entidad_afectada': role_id,
                'detalles': json.dumps({
                    'nombre_rol': nombre_rol,
                    'permisos_agregados': [
                        {'id': p['id_permiso'], 'codigo': p['codigo_permiso']}
                        for p in valid_permissions if p['id_permiso'] in permissions_to_add
                    ]
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Permisos asignados exitosamente',
                    'permisos_agregados': len(permissions_to_add)
                })
            }
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No se especificaron permisos para asignar'})
            }
        
    except Exception as e:
        logger.error(f"Error al asignar permisos al rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al asignar permisos al rol: {str(e)}'})
        }

def remove_permissions_from_role(event, context):
    """Quita permisos de un rol"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
            
        # Obtener ID del rol
        role_id = event['pathParameters']['id']
        
        # Verificar si el rol existe
        check_query = """
        SELECT nombre_rol
        FROM roles
        WHERE id_rol = %s
        """
        
        role_result = execute_query(check_query, (role_id,))
        if not role_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Rol no encontrado'})
            }
            
        nombre_rol = role_result[0]['nombre_rol']
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar datos requeridos
        if 'permisos' not in body or not isinstance(body['permisos'], list):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Se requiere una lista de IDs de permisos'})
            }
            
        permission_ids = body['permisos']
        
        # Validar que los permisos existan
        if permission_ids:
            placeholders = ", ".join(["%s"] * len(permission_ids))
            validate_query = f"""
            SELECT id_permiso, codigo_permiso
            FROM permisos
            WHERE id_permiso IN ({placeholders})
            """
            
            valid_permissions = execute_query(validate_query, permission_ids)
            valid_permission_ids = [p['id_permiso'] for p in valid_permissions]
            
            # Eliminar permisos del rol
            delete_query = f"""
            DELETE FROM roles_permisos
            WHERE id_rol = %s AND id_permiso IN ({placeholders})
            """
            
            params = [role_id] + permission_ids
            affected_rows = execute_query(delete_query, params, fetch=False)
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'quitar_permisos',
                'entidad_afectada': 'rol',
                'id_entidad_afectada': role_id,
                'detalles': json.dumps({
                    'nombre_rol': nombre_rol,
                    'permisos_eliminados': [
                        {'id': p['id_permiso'], 'codigo': p['codigo_permiso']}
                        for p in valid_permissions
                    ]
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Permisos eliminados exitosamente',
                    'permisos_eliminados': len(valid_permission_ids)
                })
            }
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No se especificaron permisos para eliminar'})
            }
        
    except Exception as e:
        logger.error(f"Error al quitar permisos del rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al quitar permisos del rol: {str(e)}'})
        }

def check_role_permission(event, context):
    """Verifica si un rol tiene un permiso específico"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
        # Obtener IDs del rol y permiso
        role_id = event['pathParameters']['id']
        permission_id = event['pathParameters']['permission_id']
        
        # Verificar si el rol existe
        role_query = """
        SELECT nombre_rol
        FROM roles
        WHERE id_rol = %s
        """
        
        role_result = execute_query(role_query, (role_id,))
        if not role_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Rol no encontrado'})
            }
            
        # Verificar si el permiso existe
        permission_query = """
        SELECT codigo_permiso
        FROM permisos
        WHERE id_permiso = %s
        """
        
        permission_result = execute_query(permission_query, (permission_id,))
        if not permission_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Permiso no encontrado'})
            }
            
        # Verificar si el rol tiene el permiso
        check_query = """
        SELECT COUNT(*) as has_permission
        FROM roles_permisos
        WHERE id_rol = %s AND id_permiso = %s
        """
        
        check_result = execute_query(check_query, (role_id, permission_id))
        has_permission = check_result[0]['has_permission'] > 0
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'id_rol': role_id,
                'nombre_rol': role_result[0]['nombre_rol'],
                'id_permiso': permission_id,
                'codigo_permiso': permission_result[0]['codigo_permiso'],
                'tiene_permiso': has_permission
            })
        }
        
    except Exception as e:
        logger.error(f"Error al verificar permiso del rol: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al verificar permiso del rol: {str(e)}'})
        }

# ------------------- Funciones de gestión de permisos de usuario -------------------

def get_user_permissions(event, context):
    """Obtiene los permisos efectivos de un usuario"""
    try:
        # Validar sesión
        current_user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
        # Obtener ID del usuario
        user_id = event['pathParameters']['id']
        
            
        # Verificar si el usuario existe
        user_query = """
        SELECT nombre_usuario, nombre, apellidos, email, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        if not user_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Usuario no encontrado'})
            }
            
        if user_result[0]['estado'] != 'activo':
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'El usuario no está activo'})
            }
            
        user_info = user_result[0]
        
        # Obtener roles del usuario
        roles_query = """
        SELECT r.id_rol, r.nombre_rol, r.descripcion,
               ur.ambito, ur.id_ambito
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        WHERE ur.id_usuario = %s
        ORDER BY r.nombre_rol
        """
        
        roles = execute_query(roles_query, (user_id,))
        
        # Obtener permisos únicos del usuario
        # Esta consulta extrae todos los permisos únicos asignados a través de los roles del usuario
        permissions_query = """
        SELECT DISTINCT p.id_permiso, p.codigo_permiso, p.descripcion, p.categoria
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s
        ORDER BY p.categoria, p.codigo_permiso
        """
        
        permissions = execute_query(permissions_query, (user_id,))
        
        # Agrupar permisos por categoría
        permissions_by_category = {}
        for perm in permissions:
            cat = perm['categoria']
            if cat not in permissions_by_category:
                permissions_by_category[cat] = []
            permissions_by_category[cat].append(perm)
        
        # Construir respuesta
        response = {
            'usuario': {
                'id': user_id,
                'nombre_usuario': user_info['nombre_usuario'],
                'nombre_completo': f"{user_info['nombre']} {user_info['apellidos']}",
                'email': user_info['email']
            },
            'roles': roles,
            'permisos': permissions,
            'permisos_por_categoria': permissions_by_category
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener permisos del usuario: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al obtener permisos del usuario: {str(e)}'})
        }

def check_permission(event, context):
    """Verifica si un usuario tiene un permiso específico"""
    try:
        # Validar sesión
        current_user_id, error_response = validate_session(event)
        if error_response:
            return error_response
            
        # Obtener IDs del usuario y el código de permiso
        user_id = event['pathParameters']['id']
        permission_code = event['pathParameters']['permission_code']
            
        # Verificar si el usuario existe
        user_query = """
        SELECT nombre_usuario, estado
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        if not user_result:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Usuario no encontrado'})
            }
            
        if user_result[0]['estado'] != 'activo':
            # Si el usuario no está activo, no tiene ningún permiso
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'id_usuario': user_id,
                    'nombre_usuario': user_result[0]['nombre_usuario'],
                    'codigo_permiso': permission_code,
                    'tiene_permiso': False,
                    'motivo': 'usuario_inactivo'
                })
            }
            
        # Verificar si el usuario tiene el permiso
        permission_query = """
        SELECT COUNT(*) as has_permission
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso = %s
        """
        
        permission_result = execute_query(permission_query, (user_id, permission_code))
        has_permission = permission_result[0]['has_permission'] > 0
        
        # Verificar si el permiso existe (para respuesta más completa)
        check_perm_query = """
        SELECT id_permiso, descripcion, categoria
        FROM permisos
        WHERE codigo_permiso = %s
        """
        
        perm_result = execute_query(check_perm_query, (permission_code,))
        
        response = {
            'id_usuario': user_id,
            'nombre_usuario': user_result[0]['nombre_usuario'],
            'codigo_permiso': permission_code,
            'tiene_permiso': has_permission
        }
        
        # Añadir detalles del permiso si existe
        if perm_result:
            response['permiso_existe'] = True
            response['permiso_info'] = {
                'id': perm_result[0]['id_permiso'],
                'descripcion': perm_result[0]['descripcion'],
                'categoria': perm_result[0]['categoria']
            }
        else:
            response['permiso_existe'] = False
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response)
        }
    except Exception as e:
        logger.error(f"Error al verificar permiso del usuario: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error al verificar permiso del usuario: {str(e)}'})
        }