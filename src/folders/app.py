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

        # Manejar solicitudes OPTIONS para CORS preflight
        if http_method == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': add_cors_headers(),
                'body': ''
            }
        
        # Rutas de gestión de carpetas
        if http_method == 'GET' and path == '/folders':
            return list_folders(event, context)
        elif http_method == 'GET' and path.startswith('/folders/') and path.endswith('/documents'):
            folder_id = path.split('/')[2]
            event['pathParameters'] = {'id': folder_id}
            return list_folder_documents(event, context)
        elif http_method == 'GET' and path.startswith('/folders/') and len(path.split('/')) == 3:
            folder_id = path.split('/')[2]
            event['pathParameters'] = {'id': folder_id}
            return get_folder(event, context)
        elif http_method == 'POST' and path == '/folders':
            return create_folder(event, context)
        elif http_method == 'PUT' and path.startswith('/folders/') and len(path.split('/')) == 3:
            folder_id = path.split('/')[2]
            event['pathParameters'] = {'id': folder_id}
            return update_folder(event, context)
        elif http_method == 'DELETE' and path.startswith('/folders/') and len(path.split('/')) == 3:
            folder_id = path.split('/')[2]
            event['pathParameters'] = {'id': folder_id}
            return delete_folder(event, context)
        elif http_method == 'GET' and path.startswith('/folders/') and path.endswith('/permissions'):
            folder_id = path.split('/')[2]
            event['pathParameters'] = {'id': folder_id}
            return get_folder_permissions(event, context)
        elif http_method == 'POST' and path.startswith('/folders/') and path.endswith('/permissions'):
            folder_id = path.split('/')[2]
            event['pathParameters'] = {'id': folder_id}
            return set_folder_permissions(event, context)
        elif http_method == 'DELETE' and path.startswith('/folders/') and path.endswith('/permissions'):
            folder_id = path.split('/')[2]
            event['pathParameters'] = {'id': folder_id}
            return remove_folder_permissions(event, context)
                 
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

def validate_session(event, required_permission=None):
    """Verifica la sesión del usuario y comprueba si tiene el permiso requerido"""
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Token no proporcionado'})}
    
    session_token = auth_header.split(' ')[1]
    
    # Verificar si la sesión existe y está activa
    check_query = """
    SELECT s.id_usuario, s.activa, s.fecha_expiracion, u.estado
    FROM sesiones s
    JOIN usuarios u ON s.id_usuario = u.id_usuario
    WHERE s.id_sesion = %s
    """
    
    session_result = execute_query(check_query, (session_token,))
    
    if not session_result:
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Sesión inválida'})}
    
    session = session_result[0]
    
    if not session['activa']:
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Sesión inactiva'})}
    
    if session['fecha_expiracion'] < datetime.datetime.now():
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Sesión expirada'})}
    
    if session['estado'] != 'activo':
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Usuario inactivo'})}
    
    user_id = session['id_usuario']
    
    # Si no se requiere un permiso específico, solo devolver el ID del usuario
    if not required_permission:
        return user_id, None
    
    # Verificar si el usuario tiene el permiso requerido
    perm_query = """
    SELECT COUNT(*) as has_permission
    FROM usuarios_roles ur
    JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
    JOIN permisos p ON rp.id_permiso = p.id_permiso
    WHERE ur.id_usuario = %s AND p.codigo_permiso = %s
    """
    
    perm_result = execute_query(perm_query, (user_id, required_permission))
    
    if not perm_result or perm_result[0]['has_permission'] == 0:
        return user_id, {'statusCode': 403, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': f'No tiene el permiso requerido: {required_permission}'})}
    
    return user_id, None

def list_folders(event, context):
    """Lista la estructura jerárquica de carpetas"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.ver')
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Parámetro para listar solo carpetas de primer nivel
        only_root = query_params.get('root_only', 'false').lower() == 'true'
        
        # Filtro de búsqueda para nombres de carpeta
        search = query_params.get('search')
        
        # Parámetro para incluir estadísticas de carpetas
        include_stats = query_params.get('include_stats', 'false').lower() == 'true'
        
        # Construir consulta base
        query = """
        SELECT c.id_carpeta, c.nombre_carpeta, c.descripcion, 
               c.carpeta_padre_id, c.ruta_completa, c.id_propietario,
               c.fecha_creacion, c.fecha_modificacion,
               u.nombre_usuario as propietario_nombre
        FROM carpetas c
        LEFT JOIN usuarios u ON c.id_propietario = u.id_usuario
        WHERE 1=1
        """
        
        params = []
        
        # Filtrar por carpetas accesibles para el usuario
        access_query = """
        AND (
            c.id_propietario = %s
            OR c.id_carpeta IN (
                SELECT pc.id_carpeta 
                FROM permisos_carpetas pc 
                WHERE (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario')
                OR (pc.id_entidad IN (
                    SELECT g.id_grupo 
                    FROM usuarios_grupos ug 
                    JOIN grupos g ON ug.id_grupo = g.id_grupo 
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
        )
        """
        
        query += access_query
        params.extend([user_id, user_id, user_id])
        
        # Filtrar solo carpetas raíz si se solicita
        if only_root:
            query += " AND c.carpeta_padre_id IS NULL"
        
        # Filtrar por búsqueda si se proporciona
        if search:
            query += " AND (c.nombre_carpeta LIKE %s OR c.descripcion LIKE %s)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param])
        
        # Ordenar por ruta
        query += " ORDER BY c.ruta_completa"
        
        # Ejecutar consulta
        folders = execute_query(query, params)
        
        # Procesar resultados
        for folder in folders:
            # Convertir datetime a string
            if 'fecha_creacion' in folder and folder['fecha_creacion']:
                folder['fecha_creacion'] = folder['fecha_creacion'].isoformat()
            if 'fecha_modificacion' in folder and folder['fecha_modificacion']:
                folder['fecha_modificacion'] = folder['fecha_modificacion'].isoformat()
        
        # Incluir estadísticas si se solicita
        if include_stats:
            for folder in folders:
                # Contar documentos en la carpeta
                docs_query = """
                SELECT COUNT(*) as document_count
                FROM documentos
                WHERE id_carpeta = %s AND estado != 'eliminado'
                """
                
                docs_result = execute_query(docs_query, (folder['id_carpeta'],))
                folder['document_count'] = docs_result[0]['document_count'] if docs_result else 0
                
                # Contar subcarpetas
                subfolders_query = """
                SELECT COUNT(*) as subfolder_count
                FROM carpetas
                WHERE carpeta_padre_id = %s
                """
                
                subfolders_result = execute_query(subfolders_query, (folder['id_carpeta'],))
                folder['subfolder_count'] = subfolders_result[0]['subfolder_count'] if subfolders_result else 0
        
        # Construir estructura jerárquica si no se solicitan solo carpetas raíz
        if not only_root:
            # Construir un mapa de carpetas por ID
            folders_map = {folder['id_carpeta']: folder for folder in folders}
            
            # Añadir campo para subcarpetas
            for folder in folders:
                folder['subcarpetas'] = []
            
            # Construir jerarquía
            root_folders = []
            for folder in folders:
                parent_id = folder['carpeta_padre_id']
                if parent_id is None:
                    # Es una carpeta raíz
                    root_folders.append(folder)
                elif parent_id in folders_map:
                    # Añadir como subcarpeta
                    folders_map[parent_id]['subcarpetas'].append(folder)
            
            # Devolver solo las carpetas raíz con su jerarquía
            response = {
                'carpetas': root_folders
            }
        else:
            response = {
                'carpetas': folders
            }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al listar carpetas: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al listar carpetas: {str(e)}'})
        }

def list_folder_documents(event, context):
    """Lista documentos dentro de una carpeta específica"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener ID de la carpeta
        folder_id = event['pathParameters']['id']
        
        # Verificar si la carpeta existe
        folder_query = """
        SELECT id_carpeta, nombre_carpeta, descripcion, 
               carpeta_padre_id, ruta_completa, id_propietario
        FROM carpetas
        WHERE id_carpeta = %s
        """
        
        folder_result = execute_query(folder_query, (folder_id,))
        if not folder_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Carpeta no encontrada'})
            }
        
        folder = folder_result[0]
        
        # Verificar si el usuario tiene permiso para acceder a la carpeta
        if folder['id_propietario'] != user_id:
            # Verificar permisos de carpeta
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (folder_id, user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'No tiene permisos para acceder a esta carpeta'})
                }
        
        # Obtener parámetros de consulta para paginación y filtros
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filtros
        title_search = query_params.get('title')
        document_type = query_params.get('tipo_documento')
        status = query_params.get('estado')
        
        # Consulta base para documentos
        document_query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.fecha_creacion, d.fecha_modificacion,
               d.estado, d.tags, 
               u_creador.nombre_usuario as creado_por_usuario,
               u_modificador.nombre_usuario as modificado_por_usuario
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        WHERE d.id_carpeta = %s AND d.estado != 'eliminado'
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM documentos d
        WHERE d.id_carpeta = %s AND d.estado != 'eliminado'
        """
        
        params = [folder_id]
        count_params = [folder_id]
        
        # Añadir filtros si se proporcionan
        if title_search:
            document_query += " AND (d.titulo LIKE %s OR d.descripcion LIKE %s)"
            count_query += " AND (d.titulo LIKE %s OR d.descripcion LIKE %s)"
            search_param = f"%{title_search}%"
            params.extend([search_param, search_param])
            count_params.extend([search_param, search_param])
        
        if document_type:
            document_query += " AND d.id_tipo_documento = %s"
            count_query += " AND d.id_tipo_documento = %s"
            params.append(document_type)
            count_params.append(document_type)
        
        if status:
            document_query += " AND d.estado = %s"
            count_query += " AND d.estado = %s"
            params.append(status)
            count_params.append(status)
        
        # Añadir ordenamiento y paginación
        document_query += " ORDER BY d.fecha_modificacion DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        documents = execute_query(document_query, params)
        count_result = execute_query(count_query, count_params)
        
        total_documents = count_result[0]['total'] if count_result else 0
        total_pages = (total_documents + page_size - 1) // page_size if total_documents > 0 else 1
        
        # Procesar resultados
        for doc in documents:
            # Convertir datetime a string
            if 'fecha_creacion' in doc and doc['fecha_creacion']:
                doc['fecha_creacion'] = doc['fecha_creacion'].isoformat()
            if 'fecha_modificacion' in doc and doc['fecha_modificacion']:
                doc['fecha_modificacion'] = doc['fecha_modificacion'].isoformat()
            
            # Procesar tags (JSON)
            if 'tags' in doc and doc['tags']:
                try:
                    doc['tags'] = json.loads(doc['tags'])
                except:
                    doc['tags'] = []
        
        # Preparar respuesta
        response = {
            'carpeta': {
                'id': folder['id_carpeta'],
                'nombre': folder['nombre_carpeta'],
                'ruta': folder['ruta_completa']
            },
            'documentos': documents,
            'pagination': {
                'total': total_documents,
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
        logger.error(f"Error al listar documentos de carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al listar documentos de carpeta: {str(e)}'})
        }

def get_folder(event, context):
    """Obtiene información detallada de una carpeta específica"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.ver')
        if error_response:
            return error_response
        
        # Obtener ID de la carpeta
        folder_id = event['pathParameters']['id']
        
        # Verificar si la carpeta existe
        folder_query = """
        SELECT c.id_carpeta, c.nombre_carpeta, c.descripcion, 
               c.carpeta_padre_id, c.ruta_completa, c.id_propietario,
               c.fecha_creacion, c.fecha_modificacion, c.politicas,
               u.nombre_usuario as propietario_nombre,
               p.nombre_carpeta as carpeta_padre_nombre
        FROM carpetas c
        LEFT JOIN usuarios u ON c.id_propietario = u.id_usuario
        LEFT JOIN carpetas p ON c.carpeta_padre_id = p.id_carpeta
        WHERE c.id_carpeta = %s
        """
        
        folder_result = execute_query(folder_query, (folder_id,))
        if not folder_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Carpeta no encontrada'})
            }
        
        folder = folder_result[0]
        
        # Verificar si el usuario tiene permiso para acceder a la carpeta
        if folder['id_propietario'] != user_id:
            # Verificar permisos de carpeta
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (folder_id, user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'No tiene permisos para acceder a esta carpeta'})
                }
        
        # Procesar campos JSON
        if 'politicas' in folder and folder['politicas']:
            try:
                folder['politicas'] = json.loads(folder['politicas'])
            except:
                folder['politicas'] = {}
        
        # Convertir datetime a string
        if 'fecha_creacion' in folder and folder['fecha_creacion']:
            folder['fecha_creacion'] = folder['fecha_creacion'].isoformat()
        if 'fecha_modificacion' in folder and folder['fecha_modificacion']:
            folder['fecha_modificacion'] = folder['fecha_modificacion'].isoformat()
        
        # Obtener subcarpetas
        subfolders_query = """
        SELECT id_carpeta, nombre_carpeta, descripcion, fecha_creacion
        FROM carpetas
        WHERE carpeta_padre_id = %s
        ORDER BY nombre_carpeta
        """
        
        subfolders = execute_query(subfolders_query, (folder_id,))
        
        # Procesar fechas de subcarpetas
        for subfolder in subfolders:
            if 'fecha_creacion' in subfolder and subfolder['fecha_creacion']:
                subfolder['fecha_creacion'] = subfolder['fecha_creacion'].isoformat()
        
        # Contar documentos en la carpeta
        docs_query = """
        SELECT COUNT(*) as document_count
        FROM documentos
        WHERE id_carpeta = %s AND estado != 'eliminado'
        """
        
        docs_result = execute_query(docs_query, (folder_id,))
        document_count = docs_result[0]['document_count'] if docs_result else 0
        
        # Obtener la ruta de la carpeta como array
        path_parts = []
        if folder['ruta_completa']:
            path_parts = folder['ruta_completa'].strip('/').split('/')
        
        # Construir respuesta
        response = {
            'carpeta': folder,
            'subcarpetas': subfolders,
            'estadisticas': {
                'documentos_count': document_count,
                'subcarpetas_count': len(subfolders)
            },
            'ruta_desglosada': path_parts
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener carpeta: {str(e)}'})
        }

def create_folder(event, context):
    """Crea una nueva carpeta"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.crear')
        if error_response:
            return error_response
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'nombre_carpeta' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'El nombre de la carpeta es requerido'})
            }
        
        nombre_carpeta = body['nombre_carpeta']
        descripcion = body.get('descripcion')
        carpeta_padre_id = body.get('carpeta_padre_id')
        politicas = body.get('politicas', {})
        
        # Verificar si el nombre contiene caracteres no permitidos
        if '/' in nombre_carpeta or '\\' in nombre_carpeta:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'El nombre de la carpeta no puede contener los caracteres / o \\'})
            }
        
        # Si se especifica carpeta padre, verificar que existe
        if carpeta_padre_id:
            parent_query = """
            SELECT id_carpeta, nombre_carpeta, ruta_completa, id_propietario
            FROM carpetas
            WHERE id_carpeta = %s
            """
            
            parent_result = execute_query(parent_query, (carpeta_padre_id,))
            if not parent_result:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'La carpeta padre no existe'})
                }
            
            parent_folder = parent_result[0]
            
            # Verificar si el usuario tiene permiso para crear carpetas en la carpeta padre
            if parent_folder['id_propietario'] != user_id:
                # Verificar permisos de carpeta
                access_query = """
                SELECT COUNT(*) as has_write_access
                FROM permisos_carpetas pc
                WHERE pc.id_carpeta = %s AND pc.tipo_permiso IN ('escritura', 'administracion') AND (
                    (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                    (pc.id_entidad IN (
                        SELECT ug.id_grupo
                        FROM usuarios_grupos ug
                        WHERE ug.id_usuario = %s
                    ) AND pc.tipo_entidad = 'grupo')
                )
                """
                
                access_result = execute_query(access_query, (carpeta_padre_id, user_id, user_id))
                if not access_result or access_result[0]['has_write_access'] == 0:
                    return {
                        'statusCode': 403,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'No tiene permisos para crear carpetas en esta ubicación'})
                    }
            
            # Verificar si ya existe una carpeta con el mismo nombre en esa ubicación
            check_query = """
            SELECT COUNT(*) as count
            FROM carpetas
            WHERE carpeta_padre_id = %s AND nombre_carpeta = %s
            """
            
            check_result = execute_query(check_query, (carpeta_padre_id, nombre_carpeta))
            if check_result[0]['count'] > 0:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Ya existe una carpeta con ese nombre en esta ubicación'})
                }
            
            # Construir ruta completa
            ruta_completa = f"{parent_folder['ruta_completa']}{nombre_carpeta}/"
        else:
            # Carpeta de nivel raíz
            # Verificar si el usuario tiene permiso para crear carpetas raíz
            root_perm_query = """
            SELECT COUNT(*) as has_permission
            FROM usuarios_roles ur
            JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
            JOIN permisos p ON rp.id_permiso = p.id_permiso
            WHERE ur.id_usuario = %s AND p.codigo_permiso = 'carpetas.crear'
            """
            
            root_perm_result = execute_query(root_perm_query, (user_id,))
            if not root_perm_result or root_perm_result[0]['has_permission'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'No tiene permisos para crear carpetas en el nivel raíz'})
                }
            
            # Verificar si ya existe una carpeta raíz con el mismo nombre
            check_query = """
            SELECT COUNT(*) as count
            FROM carpetas
            WHERE carpeta_padre_id IS NULL AND nombre_carpeta = %s
            """
            
            check_result = execute_query(check_query, (nombre_carpeta,))
            if check_result[0]['count'] > 0:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Ya existe una carpeta con ese nombre en el nivel raíz'})
                }
            
            # Ruta para carpeta raíz
            ruta_completa = f"/{nombre_carpeta}/"
        
        # Generar ID de carpeta
        folder_id = generate_uuid()
        
        # Insertar carpeta
        insert_query = """
        INSERT INTO carpetas (
            id_carpeta, nombre_carpeta, descripcion, carpeta_padre_id, 
            ruta_completa, id_propietario, fecha_creacion, 
            fecha_modificacion, politicas
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        now = datetime.datetime.now()
        
        insert_params = (
            folder_id, nombre_carpeta, descripcion, carpeta_padre_id,
            ruta_completa, user_id, now, now, json.dumps(politicas)
        )
        
        execute_query(insert_query, insert_params, fetch=False)
        
        # Crear permisos automáticos para el creador
        perms_query = """
        INSERT INTO permisos_carpetas (
            id_carpeta, id_entidad, tipo_entidad, tipo_permiso, herencia
        ) VALUES (%s, %s, %s, %s, %s)
        """
        
        # Crear 4 registros, uno para cada tipo de permiso
        for tipo_permiso in ['lectura', 'escritura', 'eliminacion', 'administracion']:
            execute_query(perms_query, (folder_id, user_id, 'usuario', tipo_permiso, True), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear',
            'entidad_afectada': 'carpeta',
            'id_entidad_afectada': folder_id,
            'detalles': json.dumps({
                'nombre_carpeta': nombre_carpeta,
                'ruta_completa': ruta_completa,
                'carpeta_padre_id': carpeta_padre_id
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Carpeta creada exitosamente',
                'id_carpeta': folder_id,
                'nombre_carpeta': nombre_carpeta,
                'ruta_completa': ruta_completa
            })
        }
        
    except Exception as e:
        logger.error(f"Error al crear carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al crear carpeta: {str(e)}'})
        }

def update_folder(event, context):
    """Actualiza una carpeta existente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.editar')
        if error_response:
            return error_response
        
        # Obtener ID de la carpeta
        folder_id = event['pathParameters']['id']
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Verificar si la carpeta existe
        folder_query = """
        SELECT id_carpeta, nombre_carpeta, descripcion, carpeta_padre_id, 
               ruta_completa, id_propietario
        FROM carpetas
        WHERE id_carpeta = %s
        """
        
        folder_result = execute_query(folder_query, (folder_id,))
        if not folder_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Carpeta no encontrada'})
            }
        
        folder = folder_result[0]
        
        # Verificar si el usuario tiene permiso para editar la carpeta
        if folder['id_propietario'] != user_id:
            # Verificar permisos de carpeta
            access_query = """
            SELECT COUNT(*) as has_write_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND pc.tipo_permiso IN ('escritura', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (folder_id, user_id, user_id))
            if not access_result or access_result[0]['has_write_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'No tiene permisos para editar esta carpeta'})
                }
        
        # Recopilar campos a actualizar
        update_fields = []
        update_params = []
        
        # Nombre de carpeta
        if 'nombre_carpeta' in body and body['nombre_carpeta'] != folder['nombre_carpeta']:
            nombre_carpeta = body['nombre_carpeta']
            
            # Verificar caracteres no permitidos
            if '/' in nombre_carpeta or '\\' in nombre_carpeta:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'El nombre de la carpeta no puede contener los caracteres / o \\'})
                }
            
            # Verificar si ya existe otra carpeta con el mismo nombre en la misma ubicación
            check_query = """
            SELECT COUNT(*) as count
            FROM carpetas
            WHERE carpeta_padre_id = %s AND nombre_carpeta = %s AND id_carpeta != %s
            """
            
            check_result = execute_query(check_query, (folder['carpeta_padre_id'], nombre_carpeta, folder_id))
            if check_result[0]['count'] > 0:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Ya existe otra carpeta con ese nombre en esta ubicación'})
                }
            
            update_fields.append("nombre_carpeta = %s")
            update_params.append(nombre_carpeta)
            
            # Si se cambia el nombre, hay que actualizar la ruta completa de esta carpeta y todas sus subcarpetas
            # Primero obtenemos la ruta actual y la nueva ruta
            old_path = folder['ruta_completa']
            
            # Calculamos la nueva ruta
            if folder['carpeta_padre_id'] is None:
                # Carpeta raíz
                new_path = f"/{nombre_carpeta}/"
            else:
                # Obtenemos la ruta del padre
                parent_query = """
                SELECT ruta_completa
                FROM carpetas
                WHERE id_carpeta = %s
                """
                
                parent_result = execute_query(parent_query, (folder['carpeta_padre_id'],))
                parent_path = parent_result[0]['ruta_completa']
                new_path = f"{parent_path}{nombre_carpeta}/"
            
            # Actualizamos la ruta de esta carpeta
            update_fields.append("ruta_completa = %s")
            update_params.append(new_path)
            
            # Almacenamos información para actualizar subcarpetas después
            need_path_update = True
            old_path_prefix = old_path
            new_path_prefix = new_path
        else:
            need_path_update = False
        
        # Descripción
        if 'descripcion' in body:
            update_fields.append("descripcion = %s")
            update_params.append(body['descripcion'])
        
        # Políticas
        if 'politicas' in body:
            update_fields.append("politicas = %s")
            update_params.append(json.dumps(body['politicas']))
        
        # Si no hay campos para actualizar
        if not update_fields:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se proporcionaron campos para actualizar'})
            }
        
        # Añadir fecha de modificación
        update_fields.append("fecha_modificacion = %s")
        now = datetime.datetime.now()
        update_params.append(now)
        
        # Preparar y ejecutar consulta de actualización
        update_query = f"""
        UPDATE carpetas
        SET {', '.join(update_fields)}
        WHERE id_carpeta = %s
        """
        
        update_params.append(folder_id)
        execute_query(update_query, update_params, fetch=False)
        
        # Si se cambió el nombre, actualizar las rutas de todas las subcarpetas
        if need_path_update:
            # Obtenemos todas las subcarpetas (directas e indirectas)
            subcarpetas_query = """
            SELECT id_carpeta, ruta_completa
            FROM carpetas
            WHERE ruta_completa LIKE %s
            """
            
            subcarpetas_result = execute_query(subcarpetas_query, (f"{old_path_prefix}%",))
            
            # Actualizamos la ruta de cada subcarpeta
            for subcarpeta in subcarpetas_result:
                nueva_ruta = subcarpeta['ruta_completa'].replace(old_path_prefix, new_path_prefix, 1)
                
                update_path_query = """
                UPDATE carpetas
                SET ruta_completa = %s
                WHERE id_carpeta = %s
                """
                
                execute_query(update_path_query, (nueva_ruta, subcarpeta['id_carpeta']), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'actualizar',
            'entidad_afectada': 'carpeta',
            'id_entidad_afectada': folder_id,
            'detalles': json.dumps({
                'campos_actualizados': list(set(body.keys())),
                'nuevo_nombre': body.get('nombre_carpeta'),
                'path_actualizado': need_path_update
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Carpeta actualizada exitosamente',
                'id_carpeta': folder_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error al actualizar carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al actualizar carpeta: {str(e)}'})
        }

def delete_folder(event, context):
    """Elimina una carpeta y opcionalmente su contenido"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.eliminar')
        if error_response:
            return error_response
        
        # Obtener ID de la carpeta
        folder_id = event['pathParameters']['id']
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Flag para indicar si se debe eliminar el contenido
        force = query_params.get('force', 'false').lower() == 'true'
        
        # Verificar si la carpeta existe
        folder_query = """
        SELECT id_carpeta, nombre_carpeta, descripcion, carpeta_padre_id, 
               ruta_completa, id_propietario
        FROM carpetas
        WHERE id_carpeta = %s
        """
        
        folder_result = execute_query(folder_query, (folder_id,))
        if not folder_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Carpeta no encontrada'})
            }
        
        folder = folder_result[0]
        
        # Verificar si el usuario tiene permiso para eliminar la carpeta
        if folder['id_propietario'] != user_id:
            # Verificar permisos de carpeta
            access_query = """
            SELECT COUNT(*) as has_delete_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND pc.tipo_permiso IN ('eliminacion', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (folder_id, user_id, user_id))
            if not access_result or access_result[0]['has_delete_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'No tiene permisos para eliminar esta carpeta'})
                }
        
        # Verificar si la carpeta tiene subcarpetas
        subfolder_query = """
        SELECT COUNT(*) as count
        FROM carpetas
        WHERE carpeta_padre_id = %s
        """
        
        subfolder_result = execute_query(subfolder_query, (folder_id,))
        has_subfolders = subfolder_result[0]['count'] > 0
        
        # Verificar si la carpeta tiene documentos
        docs_query = """
        SELECT COUNT(*) as count
        FROM documentos
        WHERE id_carpeta = %s AND estado != 'eliminado'
        """
        
        docs_result = execute_query(docs_query, (folder_id,))
        has_documents = docs_result[0]['count'] > 0
        
        # Si tiene contenido y no se especificó force, retornar error
        if (has_subfolders or has_documents) and not force:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'error': 'La carpeta contiene subcarpetas o documentos. Use force=true para eliminar todo el contenido.',
                    'subcarpetas': has_subfolders,
                    'documentos': has_documents
                })
            }
        
        # Iniciar transacción para eliminar con seguridad
        connection = get_connection()
        try:
            connection.begin()
            cursor = connection.cursor()
            
            if force:
                # Eliminar documentos en la carpeta y subcarpetas
                cursor.execute("""
                UPDATE documentos
                SET estado = 'eliminado',
                    fecha_modificacion = %s,
                    modificado_por = %s
                WHERE id_carpeta IN (
                    SELECT id_carpeta
                    FROM carpetas
                    WHERE ruta_completa LIKE %s
                )
                """, (datetime.datetime.now(), user_id, f"{folder['ruta_completa']}%"))
                
                deleted_docs_count = cursor.rowcount
                
                # Eliminar permisos de las subcarpetas
                cursor.execute("""
                DELETE FROM permisos_carpetas
                WHERE id_carpeta IN (
                    SELECT id_carpeta
                    FROM carpetas
                    WHERE ruta_completa LIKE %s
                )
                """, (f"{folder['ruta_completa']}%",))
                
                # Eliminar subcarpetas
                cursor.execute("""
                DELETE FROM carpetas
                WHERE ruta_completa LIKE %s AND id_carpeta != %s
                """, (f"{folder['ruta_completa']}%", folder_id))
                
                deleted_subfolders_count = cursor.rowcount
            else:
                deleted_docs_count = 0
                deleted_subfolders_count = 0
            
            # Eliminar permisos de la carpeta
            cursor.execute("""
            DELETE FROM permisos_carpetas
            WHERE id_carpeta = %s
            """, (folder_id,))
            
            # Eliminar la carpeta
            cursor.execute("""
            DELETE FROM carpetas
            WHERE id_carpeta = %s
            """, (folder_id,))
            
            connection.commit()
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'eliminar',
                'entidad_afectada': 'carpeta',
                'id_entidad_afectada': folder_id,
                'detalles': json.dumps({
                    'nombre_carpeta': folder['nombre_carpeta'],
                    'ruta_completa': folder['ruta_completa'],
                    'force': force,
                    'documentos_eliminados': deleted_docs_count,
                    'subcarpetas_eliminadas': deleted_subfolders_count
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'Carpeta eliminada exitosamente',
                    'documentos_eliminados': deleted_docs_count,
                    'subcarpetas_eliminadas': deleted_subfolders_count
                })
            }
            
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        
    except Exception as e:
        logger.error(f"Error al eliminar carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al eliminar carpeta: {str(e)}'})
        }

def get_folder_permissions(event, context):
    """Obtiene los permisos asignados a una carpeta"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.permisos')
        if error_response:
            return error_response
        
        # Obtener ID de la carpeta
        folder_id = event['pathParameters']['id']
        
        # Verificar si la carpeta existe
        folder_query = """
        SELECT id_carpeta, nombre_carpeta, descripcion, carpeta_padre_id, 
               ruta_completa, id_propietario
        FROM carpetas
        WHERE id_carpeta = %s
        """
        
        folder_result = execute_query(folder_query, (folder_id,))
        if not folder_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Carpeta no encontrada'})
            }
        
        folder = folder_result[0]
        
        # Verificar si el usuario tiene permiso para ver los permisos de la carpeta
        can_view_permissions = False
        
        # El propietario siempre puede ver los permisos
        if folder['id_propietario'] == user_id:
            can_view_permissions = True
        else:
            # Verificar si el usuario tiene permiso de administración
            admin_query = """
            SELECT COUNT(*) as is_admin
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND pc.tipo_permiso = 'administracion' AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            admin_result = execute_query(admin_query, (folder_id, user_id, user_id))
            can_view_permissions = admin_result[0]['is_admin'] > 0
        
        if not can_view_permissions:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para ver los permisos de esta carpeta'})
            }
        
        # Obtener permisos de usuarios
        user_perms_query = """
        SELECT pc.id_entidad, pc.tipo_permiso, pc.herencia,
               u.nombre_usuario, u.nombre, u.apellidos
        FROM permisos_carpetas pc
        JOIN usuarios u ON pc.id_entidad = u.id_usuario
        WHERE pc.id_carpeta = %s AND pc.tipo_entidad = 'usuario'
        ORDER BY u.nombre_usuario, pc.tipo_permiso
        """
        
        user_perms = execute_query(user_perms_query, (folder_id,))
        
        # Agrupar permisos de usuarios por usuario
        user_permissions = {}
        for perm in user_perms:
            user_id = perm['id_entidad']
            if user_id not in user_permissions:
                user_permissions[user_id] = {
                    'id_usuario': user_id,
                    'nombre_usuario': perm['nombre_usuario'],
                    'nombre_completo': f"{perm['nombre']} {perm['apellidos']}",
                    'permisos': []
                }
            user_permissions[user_id]['permisos'].append({
                'tipo_permiso': perm['tipo_permiso'],
                'herencia': perm['herencia']
            })
        
        # Obtener permisos de grupos
        group_perms_query = """
        SELECT pc.id_entidad, pc.tipo_permiso, pc.herencia,
               g.nombre_grupo
        FROM permisos_carpetas pc
        JOIN grupos g ON pc.id_entidad = g.id_grupo
        WHERE pc.id_carpeta = %s AND pc.tipo_entidad = 'grupo'
        ORDER BY g.nombre_grupo, pc.tipo_permiso
        """
        
        group_perms = execute_query(group_perms_query, (folder_id,))
        
        # Agrupar permisos de grupos por grupo
        group_permissions = {}
        for perm in group_perms:
            group_id = perm['id_entidad']
            if group_id not in group_permissions:
                group_permissions[group_id] = {
                    'id_grupo': group_id,
                    'nombre_grupo': perm['nombre_grupo'],
                    'permisos': []
                }
            group_permissions[group_id]['permisos'].append({
                'tipo_permiso': perm['tipo_permiso'],
                'herencia': perm['herencia']
            })
        
        # Preparar respuesta
        response = {
            'id_carpeta': folder_id,
            'nombre_carpeta': folder['nombre_carpeta'],
            'ruta_completa': folder['ruta_completa'],
            'propietario_id': folder['id_propietario'],
            'permisos_usuarios': list(user_permissions.values()),
            'permisos_grupos': list(group_permissions.values())
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener permisos de carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener permisos de carpeta: {str(e)}'})
        }

def set_folder_permissions(event, context):
    """Configura permisos para una carpeta"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.permisos')
        if error_response:
            return error_response
        
        # Obtener ID de la carpeta
        folder_id = event['pathParameters']['id']
        
        # Verificar si la carpeta existe
        folder_query = """
        SELECT id_carpeta, nombre_carpeta, descripcion, carpeta_padre_id, 
               ruta_completa, id_propietario
        FROM carpetas
        WHERE id_carpeta = %s
        """
        
        folder_result = execute_query(folder_query, (folder_id,))
        if not folder_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Carpeta no encontrada'})
            }
        
        folder = folder_result[0]
        
        # Verificar si el usuario tiene permiso para gestionar los permisos
        can_manage_permissions = False
        
        # El propietario siempre puede gestionar los permisos
        if folder['id_propietario'] == user_id:
            can_manage_permissions = True
        else:
            # Verificar si el usuario tiene permiso de administración
            admin_query = """
            SELECT COUNT(*) as is_admin
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND pc.tipo_permiso = 'administracion' AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            admin_result = execute_query(admin_query, (folder_id, user_id, user_id))
            can_manage_permissions = admin_result[0]['is_admin'] > 0
        
        if not can_manage_permissions:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para gestionar los permisos de esta carpeta'})
            }
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        required_fields = ['tipo_entidad', 'id_entidad', 'permisos']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Falta el campo requerido: {field}'})
                }
        
        tipo_entidad = body['tipo_entidad']
        id_entidad = body['id_entidad']
        permisos = body['permisos']
        aplicar_subcarpetas = body.get('aplicar_subcarpetas', False)
        
        # Validar tipo de entidad
        if tipo_entidad not in ['usuario', 'grupo']:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Tipo de entidad debe ser "usuario" o "grupo"'})
            }
        
        # Validar que la entidad existe
        if tipo_entidad == 'usuario':
            entity_query = """
            SELECT id_usuario
            FROM usuarios
            WHERE id_usuario = %s AND estado = 'activo'
            """
            
            entity_result = execute_query(entity_query, (id_entidad,))
            if not entity_result:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Usuario no encontrado o inactivo'})
                }
        else:  # grupo
            entity_query = """
            SELECT id_grupo
            FROM grupos
            WHERE id_grupo = %s
            """
            
            entity_result = execute_query(entity_query, (id_entidad,))
            if not entity_result:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Grupo no encontrado'})
                }
        
        # Validar permisos
        if not isinstance(permisos, list) or not permisos:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'El campo permisos debe ser una lista no vacía'})
            }
        
        valid_permissions = ['lectura', 'escritura', 'eliminacion', 'administracion']
        for perm in permisos:
            if not isinstance(perm, dict) or 'tipo_permiso' not in perm:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Cada permiso debe ser un objeto con tipo_permiso'})
                }
            
            if perm['tipo_permiso'] not in valid_permissions:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({
                        'error': f'Tipo de permiso inválido: {perm["tipo_permiso"]}. Debe ser uno de: {", ".join(valid_permissions)}'
                    })
                }
        
        # Preparar y ejecutar la inserción o actualización de permisos
        connection = get_connection()
        try:
            connection.begin()
            cursor = connection.cursor()
            
            # Eliminar permisos existentes para esta entidad en esta carpeta
            cursor.execute("""
            DELETE FROM permisos_carpetas
            WHERE id_carpeta = %s AND tipo_entidad = %s AND id_entidad = %s
            """, (folder_id, tipo_entidad, id_entidad))
            
            # Insertar nuevos permisos
            insert_query = """
            INSERT INTO permisos_carpetas (
                id_carpeta, id_entidad, tipo_entidad, tipo_permiso, herencia
            ) VALUES (%s, %s, %s, %s, %s)
            """
            
            for perm in permisos:
                herencia = perm.get('herencia', True)
                cursor.execute(insert_query, (
                    folder_id, id_entidad, tipo_entidad, perm['tipo_permiso'], herencia
                ))
            
            # Si se solicitó aplicar a subcarpetas
            if aplicar_subcarpetas:
                # Obtener todas las subcarpetas
                cursor.execute("""
                SELECT id_carpeta
                FROM carpetas
                WHERE ruta_completa LIKE %s AND id_carpeta != %s
                """, (f"{folder['ruta_completa']}%", folder_id))
                
                subcarpetas = cursor.fetchall()
                
                # Eliminar permisos existentes en subcarpetas
                for subcarpeta in subcarpetas:
                    cursor.execute("""
                    DELETE FROM permisos_carpetas
                    WHERE id_carpeta = %s AND tipo_entidad = %s AND id_entidad = %s
                    """, (subcarpeta['id_carpeta'], tipo_entidad, id_entidad))
                
                # Aplicar nuevos permisos a subcarpetas
                for subcarpeta in subcarpetas:
                    for perm in permisos:
                        if perm.get('herencia', True):  # Solo aplicar si tiene herencia
                            cursor.execute(insert_query, (
                                subcarpeta['id_carpeta'], id_entidad, tipo_entidad, 
                                perm['tipo_permiso'], perm.get('herencia', True)
                            ))
            
            connection.commit()
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'configurar_permisos',
                'entidad_afectada': 'carpeta',
                'id_entidad_afectada': folder_id,
                'detalles': json.dumps({
                    'tipo_entidad': tipo_entidad,
                    'id_entidad': id_entidad,
                    'permisos': permisos,
                    'aplicado_subcarpetas': aplicar_subcarpetas
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'Permisos configurados exitosamente',
                    'aplicado_subcarpetas': aplicar_subcarpetas
                })
            }
            
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        
    except Exception as e:
        logger.error(f"Error al configurar permisos de carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al configurar permisos de carpeta: {str(e)}'})
        }

def remove_folder_permissions(event, context):
    """Elimina permisos de una carpeta"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'carpetas.permisos')
        if error_response:
            return error_response
        
        # Obtener ID de la carpeta
        folder_id = event['pathParameters']['id']
        
        # Verificar si la carpeta existe
        folder_query = """
        SELECT id_carpeta, nombre_carpeta, descripcion, carpeta_padre_id, 
               ruta_completa, id_propietario
        FROM carpetas
        WHERE id_carpeta = %s
        """
        
        folder_result = execute_query(folder_query, (folder_id,))
        if not folder_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Carpeta no encontrada'})
            }
        
        folder = folder_result[0]
        
        # Verificar si el usuario tiene permiso para gestionar los permisos
        can_manage_permissions = False
        
        # El propietario siempre puede gestionar los permisos
        if folder['id_propietario'] == user_id:
            can_manage_permissions = True
        else:
            # Verificar si el usuario tiene permiso de administración
            admin_query = """
            SELECT COUNT(*) as is_admin
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND pc.tipo_permiso = 'administracion' AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            admin_result = execute_query(admin_query, (folder_id, user_id, user_id))
            can_manage_permissions = admin_result[0]['is_admin'] > 0
        
        if not can_manage_permissions:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para gestionar los permisos de esta carpeta'})
            }
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        required_fields = ['tipo_entidad', 'id_entidad']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Falta el campo requerido: {field}'})
                }
        
        tipo_entidad = body['tipo_entidad']
        id_entidad = body['id_entidad']
        tipos_permiso = body.get('tipos_permiso', [])  # Si está vacío, se eliminarán todos los permisos
        aplicar_subcarpetas = body.get('aplicar_subcarpetas', False)
        
        # Validar tipo de entidad
        if tipo_entidad not in ['usuario', 'grupo']:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Tipo de entidad debe ser "usuario" o "grupo"'})
            }
        
        # Validar que no se está intentando eliminar todos los permisos del propietario
        if tipo_entidad == 'usuario' and id_entidad == folder['id_propietario'] and not tipos_permiso:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se pueden eliminar todos los permisos del propietario de la carpeta'})
            }
        
        # Validar tipos de permiso si se especifican
        valid_permissions = ['lectura', 'escritura', 'eliminacion', 'administracion']
        for perm in tipos_permiso:
            if perm not in valid_permissions:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({
                        'error': f'Tipo de permiso inválido: {perm}. Debe ser uno de: {", ".join(valid_permissions)}'
                    })
                }
        
        # Preparar y ejecutar la eliminación de permisos
        connection = get_connection()
        try:
            connection.begin()
            cursor = connection.cursor()
            
            # Construir consulta de eliminación
            if tipos_permiso:
                # Eliminar solo tipos específicos de permisos
                placeholders = ', '.join(['%s'] * len(tipos_permiso))
                delete_query = f"""
                DELETE FROM permisos_carpetas
                WHERE id_carpeta = %s AND tipo_entidad = %s AND id_entidad = %s
                AND tipo_permiso IN ({placeholders})
                """
                
                delete_params = [folder_id, tipo_entidad, id_entidad] + tipos_permiso
            else:
                # Eliminar todos los permisos
                delete_query = """
                DELETE FROM permisos_carpetas
                WHERE id_carpeta = %s AND tipo_entidad = %s AND id_entidad = %s
                """
                
                delete_params = [folder_id, tipo_entidad, id_entidad]
            
            # Ejecutar eliminación para la carpeta principal
            cursor.execute(delete_query, delete_params)
            removed_count = cursor.rowcount
            
            # Si se solicitó aplicar a subcarpetas
            subcarpetas_count = 0
            if aplicar_subcarpetas:
                # Obtener todas las subcarpetas
                cursor.execute("""
                SELECT id_carpeta
                FROM carpetas
                WHERE ruta_completa LIKE %s AND id_carpeta != %s
                """, (f"{folder['ruta_completa']}%", folder_id))
                
                subcarpetas = cursor.fetchall()
                
                # Aplicar eliminación a cada subcarpeta
                for subcarpeta in subcarpetas:
                    subcarpeta_id = subcarpeta['id_carpeta']
                    
                    if tipos_permiso:
                        # Construir consulta con tipos específicos
                        subcarpeta_delete_query = f"""
                        DELETE FROM permisos_carpetas
                        WHERE id_carpeta = %s AND tipo_entidad = %s AND id_entidad = %s
                        AND tipo_permiso IN ({placeholders})
                        """
                        
                        subcarpeta_delete_params = [subcarpeta_id, tipo_entidad, id_entidad] + tipos_permiso
                    else:
                        # Eliminar todos los permisos
                        subcarpeta_delete_query = """
                        DELETE FROM permisos_carpetas
                        WHERE id_carpeta = %s AND tipo_entidad = %s AND id_entidad = %s
                        """
                        
                        subcarpeta_delete_params = [subcarpeta_id, tipo_entidad, id_entidad]
                    
                    cursor.execute(subcarpeta_delete_query, subcarpeta_delete_params)
                    subcarpetas_count += cursor.rowcount
            
            connection.commit()
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'eliminar_permisos',
                'entidad_afectada': 'carpeta',
                'id_entidad_afectada': folder_id,
                'detalles': json.dumps({
                    'tipo_entidad': tipo_entidad,
                    'id_entidad': id_entidad,
                    'tipos_permiso': tipos_permiso if tipos_permiso else 'todos',
                    'aplicado_subcarpetas': aplicar_subcarpetas,
                    'permisos_eliminados_carpeta': removed_count,
                    'permisos_eliminados_subcarpetas': subcarpetas_count
                }),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'message': 'Permisos eliminados exitosamente',
                    'permisos_eliminados_carpeta': removed_count,
                    'permisos_eliminados_subcarpetas': subcarpetas_count,
                    'aplicado_subcarpetas': aplicar_subcarpetas
                })
            }
            
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        
    except Exception as e:
        logger.error(f"Error al eliminar permisos de carpeta: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al eliminar permisos de carpeta: {str(e)}'})
        }