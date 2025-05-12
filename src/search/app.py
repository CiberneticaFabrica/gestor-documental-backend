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
        
        # Rutas de búsqueda de documentos
        if http_method == 'POST' and path == '/documents/search':
            return search_documents(event, context)
        elif http_method == 'GET' and path == '/documents/suggest':
            return suggest_terms(event, context)
        elif http_method == 'POST' and path == '/documents/metadata-filter':
            return filter_by_metadata(event, context)
        elif http_method == 'POST' and path == '/documents/searches/save':
            return save_search(event, context)
        elif http_method == 'POST' and path == '/documents/searches/execute':
            return execute_saved_search(event, context)
        elif http_method == 'GET' and path == '/documents/searches':
            return get_saved_searches(event, context)
        elif http_method == 'DELETE' and path.startswith('/documents/searches/'):
            search_id = path.split('/')[-1]
            event['pathParameters'] = {'id': search_id}
            return delete_saved_search(event, context)
                 
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

def search_documents(event, context):
    """Realiza una búsqueda avanzada de documentos con múltiples criterios"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener parámetros de búsqueda del cuerpo
        body = json.loads(event['body'])
        
        # Extraer criterios de búsqueda con valores por defecto
        search_term = body.get('search_term', '')
        document_types = body.get('document_types', [])
        status = body.get('status', [])
        date_from = body.get('date_from')
        date_to = body.get('date_to')
        folders = body.get('folders', [])
        tags = body.get('tags', [])
        metadata_filters = body.get('metadata_filters', [])
        creators = body.get('creators', [])
        
        # Paginación
        page = int(body.get('page', 1))
        page_size = int(body.get('page_size', 10))
        
        # Ordenamiento
        sort_by = body.get('sort_by', 'fecha_modificacion')
        sort_order = body.get('sort_order', 'DESC')
        
        # Validar ordenamiento
        valid_sort_fields = ['titulo', 'fecha_creacion', 'fecha_modificacion', 'creado_por', 'codigo_documento']
        if sort_by not in valid_sort_fields:
            sort_by = 'fecha_modificacion'
        
        if sort_order not in ['ASC', 'DESC']:
            sort_order = 'DESC'
        
        # Construir consulta base
        query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.fecha_creacion, d.fecha_modificacion,
               d.id_carpeta, c.nombre_carpeta, c.ruta_completa as carpeta_ruta,
               d.estado, d.tags, 
               u_creador.id_usuario as creado_por_id,
               u_creador.nombre_usuario as creado_por_usuario,
               u_modificador.nombre_usuario as modificado_por_usuario,
               v.mime_type,
               (SELECT COUNT(*) FROM comentarios_documento cd WHERE cd.id_documento = d.id_documento AND cd.estado = 'activo') as comentarios_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        LEFT JOIN versiones_documento v ON d.id_documento = v.id_documento AND v.numero_version = d.version_actual
        """
        
        # Consulta para contar resultados totales
        count_query = """
        SELECT COUNT(*) as total
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        """
        
        # Condiciones WHERE
        where_clauses = []
        params = []
        
        # Excluir documentos eliminados por defecto
        where_clauses.append("d.estado != 'eliminado'")
        
        # Filtro de permisos (solo documentos a los que el usuario tiene acceso)
        access_condition = """
        (
            d.creado_por = %s
            OR d.id_carpeta IN (
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
        where_clauses.append(access_condition)
        params.extend([user_id, user_id, user_id])
        
        # Búsqueda por término en título, descripción y texto extraído
        if search_term:
            # Primero verificamos si hay versiones de documento con texto que contenga el término
            search_in_content = """
            d.id_documento IN (
                SELECT vd.id_documento
                FROM versiones_documento vd
                WHERE vd.texto_extraido LIKE %s
            )
            """
            
            search_term_condition = f"(d.titulo LIKE %s OR d.descripcion LIKE %s OR {search_in_content})"
            search_param = f"%{search_term}%"
            where_clauses.append(search_term_condition)
            params.extend([search_param, search_param, search_param])
        
        # Filtrar por tipos de documento
        if document_types:
            placeholders = ', '.join(['%s'] * len(document_types))
            where_clauses.append(f"d.id_tipo_documento IN ({placeholders})")
            params.extend(document_types)
        
        # Filtrar por estado
        if status:
            placeholders = ', '.join(['%s'] * len(status))
            where_clauses.append(f"d.estado IN ({placeholders})")
            params.extend(status)
        
        # Filtrar por rango de fechas (creación)
        if date_from:
            where_clauses.append("d.fecha_creacion >= %s")
            params.append(date_from)
        
        if date_to:
            where_clauses.append("d.fecha_creacion <= %s")
            params.append(date_to)
        
        # Filtrar por carpetas
        if folders:
            placeholders = ', '.join(['%s'] * len(folders))
            where_clauses.append(f"d.id_carpeta IN ({placeholders})")
            params.extend(folders)
        
        # Filtrar por etiquetas (tags)
        if tags:
            # Para cada tag, necesitamos verificar si está en el JSON array
            for tag in tags:
                where_clauses.append("JSON_CONTAINS(d.tags, %s, '$')")
                params.append(json.dumps(tag))
        
        # Filtrar por creadores
        if creators:
            placeholders = ', '.join(['%s'] * len(creators))
            where_clauses.append(f"d.creado_por IN ({placeholders})")
            params.extend(creators)
        
        # Filtrar por metadatos específicos
        if metadata_filters:
            for filter_item in metadata_filters:
                field = filter_item.get('field')
                operator = filter_item.get('operator', '=')
                value = filter_item.get('value')
                
                if not field or value is None:
                    continue
                
                # Validar operador
                valid_operators = ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'NOT LIKE', 'IN', 'NOT IN', 'CONTAINS']
                if operator not in valid_operators:
                    operator = '='
                
                # Construir condición específica según el operador
                if operator in ('IN', 'NOT IN'):
                    if isinstance(value, list):
                        placeholders = ', '.join(['%s'] * len(value))
                        where_clauses.append(f"JSON_UNQUOTE(JSON_EXTRACT(d.metadatos, '$.{field}')) {operator} ({placeholders})")
                        params.extend(value)
                elif operator == 'CONTAINS':
                    # Para buscar dentro de arrays en JSON
                    where_clauses.append(f"JSON_CONTAINS(JSON_EXTRACT(d.metadatos, '$.{field}'), %s)")
                    params.append(json.dumps(value))
                else:
                    where_clauses.append(f"JSON_UNQUOTE(JSON_EXTRACT(d.metadatos, '$.{field}')) {operator} %s")
                    if operator in ('LIKE', 'NOT LIKE') and '%' not in value:
                        params.append(f"%{value}%")
                    else:
                        params.append(value)
        
        # Añadir WHERE al query principal si hay condiciones
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        # Añadir ordenamiento
        query += f" ORDER BY d.{sort_by} {sort_order}"
        
        # Añadir límite y offset para paginación
        query += " LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        documents = execute_query(query, params)
        count_result = execute_query(count_query, params[:-2] if params else [])
        
        total_documents = count_result[0]['total'] if count_result else 0
        total_pages = (total_documents + page_size - 1) // page_size if total_documents > 0 else 1
        
        # Procesar resultados
        for doc in documents:
            # Convertir datetime a string
            if 'fecha_creacion' in doc and doc['fecha_creacion']:
                doc['fecha_creacion'] = doc['fecha_creacion'].isoformat()
            if 'fecha_modificacion' in doc and doc['fecha_modificacion']:
                doc['fecha_modificacion'] = doc['fecha_modificacion'].isoformat()
            
            # Procesar campos JSON
            if 'tags' in doc and doc['tags']:
                try:
                    doc['tags'] = json.loads(doc['tags'])
                except:
                    doc['tags'] = []
        
        # Registrar la búsqueda en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'buscar',
            'entidad_afectada': 'documento',
            'id_entidad_afectada': None,
            'detalles': json.dumps({
                'termino_busqueda': search_term,
                'filtros': {
                    'tipos_documento': document_types,
                    'estados': status,
                    'fecha_desde': date_from,
                    'fecha_hasta': date_to,
                    'carpetas': folders,
                    'etiquetas': tags,
                    'creadores': creators
                },
                'resultados_encontrados': total_documents
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        # Construir respuesta
        response = {
            'documentos': documents,
            'pagination': {
                'total': total_documents,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            },
            'search_criteria': {
                'search_term': search_term,
                'document_types': document_types,
                'status': status,
                'date_from': date_from,
                'date_to': date_to,
                'folders': folders,
                'tags': tags,
                'metadata_filters': metadata_filters,
                'creators': creators,
                'sort_by': sort_by,
                'sort_order': sort_order
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error en búsqueda de documentos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error en búsqueda de documentos: {str(e)}'})
        }

def suggest_terms(event, context):
    """Sugiere términos para autocompletado basado en contenido existente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Extraer parámetros
        prefix = query_params.get('prefix', '')
        field = query_params.get('field', 'titulo')
        limit = int(query_params.get('limit', 10))
        
        # Validar campo para sugerencias
        valid_fields = ['titulo', 'descripcion', 'tags']
        if field not in valid_fields:
            field = 'titulo'
        
        # Limitar para evitar resultados excesivos
        if limit > 50:
            limit = 50
        
        # Si no hay prefijo, devolver lista vacía
        if not prefix or len(prefix) < 2:
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'suggestions': []})
            }
        
        # Construir consulta según el campo
        if field == 'tags':
            # Para tags, necesitamos extraer valores del JSON
            query = """
            SELECT DISTINCT JSON_UNQUOTE(json_array_elements.value) as suggestion
            FROM documentos d,
            JSON_TABLE(d.tags, '$[*]' COLUMNS (value JSON PATH '$')) as json_array_elements
            WHERE JSON_UNQUOTE(json_array_elements.value) LIKE %s
            AND d.estado != 'eliminado'
            """
            
            # Filtro de acceso
            query += """
            AND (
                d.creado_por = %s
                OR d.id_carpeta IN (
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
            
            query += "ORDER BY suggestion LIMIT %s"
            
            params = [f"{prefix}%", user_id, user_id, user_id, limit]
        else:
            # Para título y descripción
            query = f"""
            SELECT DISTINCT {field} as suggestion
            FROM documentos d
            WHERE d.{field} LIKE %s
            AND d.estado != 'eliminado'
            """
            
            # Filtro de acceso
            query += """
            AND (
                d.creado_por = %s
                OR d.id_carpeta IN (
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
            
            query += f"ORDER BY {field} LIMIT %s"
            
            params = [f"{prefix}%", user_id, user_id, user_id, limit]
        
        # Ejecutar consulta
        suggestions_result = execute_query(query, params)
        
        # Extraer sugerencias
        suggestions = [item['suggestion'] for item in suggestions_result]
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'suggestions': suggestions})
        }
        
    except Exception as e:
        logger.error(f"Error al sugerir términos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al sugerir términos: {str(e)}'})
        }

def filter_by_metadata(event, context):
    """Filtra documentos por campos específicos de metadatos"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener parámetros del cuerpo
        body = json.loads(event['body'])
        
        # Extraer filtros de metadatos
        metadata_filters = body.get('metadata_filters', [])
        document_type_id = body.get('document_type_id')
        
        # Paginación
        page = int(body.get('page', 1))
        page_size = int(body.get('page_size', 10))
        
        # Si no hay filtros y no hay tipo de documento, devolver error
        if not metadata_filters and not document_type_id:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requieren filtros de metadatos o tipo de documento'})
            }
        
        # Construir consulta base
        query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.fecha_creacion, d.fecha_modificacion,
               d.id_carpeta, c.nombre_carpeta, d.estado, d.tags, d.metadatos,
               u_creador.nombre_usuario as creado_por_usuario
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        """
        
        # Consulta para contar
        count_query = """
        SELECT COUNT(*) as total
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        """
        
        # Condiciones WHERE
        where_clauses = []
        params = []
        
        # Excluir documentos eliminados
        where_clauses.append("d.estado != 'eliminado'")
        
        # Filtro de permisos
        access_condition = """
        (
            d.creado_por = %s
            OR d.id_carpeta IN (
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
        where_clauses.append(access_condition)
        params.extend([user_id, user_id, user_id])
        
        # Procesar filtros de metadatos
        for filter_item in metadata_filters:
            field = filter_item.get('field')
            operator = filter_item.get('operator', '=')
            value = filter_item.get('value')
            
            if not field or value is None:
                continue
            
            # Validar operador
            valid_operators = ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'NOT LIKE', 'IN', 'NOT IN', 'CONTAINS']
            if operator not in valid_operators:
                operator = '='
            
            # Construir condición según el operador
            if operator in ('IN', 'NOT IN'):
                if isinstance(value, list):
                    placeholders = ', '.join(['%s'] * len(value))
                    where_clauses.append(f"JSON_UNQUOTE(JSON_EXTRACT(d.metadatos, '$.{field}')) {operator} ({placeholders})")
                    params.extend(value)
            elif operator == 'CONTAINS':
                where_clauses.append(f"JSON_CONTAINS(JSON_EXTRACT(d.metadatos, '$.{field}'), %s)")
                params.append(json.dumps(value))
            else:
                where_clauses.append(f"JSON_UNQUOTE(JSON_EXTRACT(d.metadatos, '$.{field}')) {operator} %s")
                if operator in ('LIKE', 'NOT LIKE') and '%' not in value:
                    params.append(f"%{value}%")
                else:
                    params.append(value)
        
        # Añadir WHERE al query
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        # Añadir ordenamiento y paginación
        query += " ORDER BY d.fecha_modificacion DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        documents = execute_query(query, params)
        count_result = execute_query(count_query, params[:-2] if params else [])
        
        total_documents = count_result[0]['total'] if count_result else 0
        total_pages = (total_documents + page_size - 1) // page_size if total_documents > 0 else 1
        
        # Procesar resultados
        for doc in documents:
            # Convertir datetime a string
            if 'fecha_creacion' in doc and doc['fecha_creacion']:
                doc['fecha_creacion'] = doc['fecha_creacion'].isoformat()
            if 'fecha_modificacion' in doc and doc['fecha_modificacion']:
                doc['fecha_modificacion'] = doc['fecha_modificacion'].isoformat()
            
            # Procesar campos JSON
            for json_field in ['tags', 'metadatos']:
                if json_field in doc and doc[json_field]:
                    try:
                        doc[json_field] = json.loads(doc[json_field])
                    except:
                        doc[json_field] = {} if json_field == 'metadatos' else []
        
        # Construir respuesta
        response = {
            'documentos': documents,
            'pagination': {
                'total': total_documents,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            },
            'metadata_filters': metadata_filters
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al filtrar por metadatos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al filtrar por metadatos: {str(e)}'})
        }

def save_search(event, context):
    """Guarda los criterios de búsqueda para su reutilización"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'name' not in body or 'search_criteria' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requiere nombre y criterios de búsqueda'})
            }
        
        name = body['name']
        search_criteria = body['search_criteria']
        description = body.get('description', '')
        
        # Verificar si ya existe una búsqueda guardada con el mismo nombre para este usuario
        check_query = """
        SELECT id_busqueda 
        FROM busquedas_guardadas
        WHERE id_usuario = %s AND nombre = %s
        """
        
        existing = execute_query(check_query, (user_id, name))
        
        if existing:
            # Si existe, actualizar
            update_query = """
            UPDATE busquedas_guardadas
            SET criterios = %s,
                descripcion = %s,
                fecha_modificacion = %s
            WHERE id_usuario = %s AND nombre = %s
            """
            
            execute_query(update_query, (
                json.dumps(search_criteria),
                description,
                datetime.datetime.now(),
                user_id,
                name
            ), fetch=False)
            
            search_id = existing[0]['id_busqueda']
            is_update = True
        else:
            # Si no existe, crear nueva
            search_id = generate_uuid()
            
            insert_query = """
            INSERT INTO busquedas_guardadas (
                id_busqueda, id_usuario, nombre, descripcion,
                criterios, fecha_creacion, fecha_modificacion
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            
            now = datetime.datetime.now()
            
            execute_query(insert_query, (
                search_id,
                user_id,
                name,
                description,
                json.dumps(search_criteria),
                now,
                now
            ), fetch=False)
            
            is_update = False
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'guardar_busqueda',
            'entidad_afectada': 'busqueda_guardada',
            'id_entidad_afectada': search_id,
            'detalles': json.dumps({
                'nombre': name,
                'descripcion': description,
                'es_actualizacion': is_update
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Búsqueda guardada exitosamente',
                'id_busqueda': search_id,
                'actualizada': is_update
            })
        }
        
    except Exception as e:
        logger.error(f"Error al guardar búsqueda: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al guardar búsqueda: {str(e)}'})
        }

def execute_saved_search(event, context):
    """Ejecuta una búsqueda guardada por ID o nombre"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar que se proporcione ID o nombre de la búsqueda
        if 'id_busqueda' not in body and 'nombre_busqueda' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requiere ID o nombre de la búsqueda guardada'})
            }
        
        # Preparar consulta según el parámetro proporcionado
        if 'id_busqueda' in body:
            search_query = """
            SELECT id_busqueda, nombre, descripcion, criterios
            FROM busquedas_guardadas
            WHERE id_busqueda = %s AND id_usuario = %s
            """
            search_param = body['id_busqueda']
        else:
            search_query = """
            SELECT id_busqueda, nombre, descripcion, criterios
            FROM busquedas_guardadas
            WHERE nombre = %s AND id_usuario = %s
            """
            search_param = body['nombre_busqueda']
        
        # Obtener la búsqueda guardada
        search_result = execute_query(search_query, (search_param, user_id))
        
        if not search_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Búsqueda guardada no encontrada'})
            }
        
        saved_search = search_result[0]
        
        try:
            # Parsear los criterios de búsqueda guardados
            search_criteria = json.loads(saved_search['criterios'])
            
            # Obtener parámetros de paginación
            page = int(body.get('page', 1))
            page_size = int(body.get('page_size', 10))
            
            # Sobrescribir criterios de paginación
            search_criteria['page'] = page
            search_criteria['page_size'] = page_size
            
            # Construir nuevo evento con los criterios de búsqueda
            search_event = {
                'httpMethod': 'POST',
                'path': '/documents/search',
                'headers': event['headers'],
                'queryStringParameters': {},
                'body': json.dumps(search_criteria)
            }
            
            # Ejecutar la búsqueda con los criterios guardados
            search_result = search_documents(search_event, context)
            
            # Modificar la respuesta para incluir información de la búsqueda guardada
            if search_result['statusCode'] == 200:
                response_body = json.loads(search_result['body'])
                response_body['saved_search'] = {
                    'id': saved_search['id_busqueda'],
                    'name': saved_search['nombre'],
                    'description': saved_search['descripcion']
                }
                
                search_result['body'] = json.dumps(response_body, default=str)
            
            # Registrar en auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'ejecutar_busqueda_guardada',
                'entidad_afectada': 'busqueda_guardada',
                'id_entidad_afectada': saved_search['id_busqueda'],
                'detalles': json.dumps({
                    'nombre': saved_search['nombre'],
                    'pagina': page,
                    'resultados_por_pagina': page_size
                }),
                'resultado': 'éxito' if search_result['statusCode'] == 200 else 'error'
            }
            
            insert_audit_record(audit_data)
            
            return search_result
            
        except Exception as e:
            logger.error(f"Error al procesar criterios de búsqueda guardados: {str(e)}")
            return {
                'statusCode': 500,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Error al procesar criterios de búsqueda: {str(e)}'})
            }
        
    except Exception as e:
        logger.error(f"Error al ejecutar búsqueda guardada: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al ejecutar búsqueda guardada: {str(e)}'})
        }

def get_saved_searches(event, context):
    """Obtiene todas las búsquedas guardadas del usuario"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Extraer parámetros
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Consulta para obtener búsquedas guardadas
        query = """
        SELECT id_busqueda, nombre, descripcion, fecha_creacion, 
               fecha_modificacion
        FROM busquedas_guardadas
        WHERE id_usuario = %s
        ORDER BY fecha_modificacion DESC
        LIMIT %s OFFSET %s
        """
        
        # Consulta para contar
        count_query = """
        SELECT COUNT(*) as total
        FROM busquedas_guardadas
        WHERE id_usuario = %s
        """
        
        # Ejecutar consultas
        searches = execute_query(query, (user_id, page_size, (page - 1) * page_size))
        count_result = execute_query(count_query, (user_id,))
        
        total_searches = count_result[0]['total'] if count_result else 0
        total_pages = (total_searches + page_size - 1) // page_size if total_searches > 0 else 1
        
        # Formatear fechas
        for search in searches:
            if 'fecha_creacion' in search and search['fecha_creacion']:
                search['fecha_creacion'] = search['fecha_creacion'].isoformat()
            if 'fecha_modificacion' in search and search['fecha_modificacion']:
                search['fecha_modificacion'] = search['fecha_modificacion'].isoformat()
        
        # Construir respuesta
        response = {
            'busquedas': searches,
            'pagination': {
                'total': total_searches,
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
        logger.error(f"Error al obtener búsquedas guardadas: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener búsquedas guardadas: {str(e)}'})
        }

def delete_saved_search(event, context):
    """Elimina una búsqueda guardada"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener ID de la búsqueda
        search_id = event['pathParameters']['id']
        
        # Verificar que la búsqueda exista y pertenezca al usuario
        check_query = """
        SELECT id_busqueda, nombre
        FROM busquedas_guardadas
        WHERE id_busqueda = %s AND id_usuario = %s
        """
        
        search_result = execute_query(check_query, (search_id, user_id))
        
        if not search_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Búsqueda guardada no encontrada o sin permisos'})
            }
        
        saved_search = search_result[0]
        
        # Eliminar la búsqueda
        delete_query = """
        DELETE FROM busquedas_guardadas
        WHERE id_busqueda = %s AND id_usuario = %s
        """
        
        execute_query(delete_query, (search_id, user_id), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'eliminar_busqueda',
            'entidad_afectada': 'busqueda_guardada',
            'id_entidad_afectada': search_id,
            'detalles': json.dumps({
                'nombre': saved_search['nombre']
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Búsqueda eliminada exitosamente',
                'id_busqueda': search_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error al eliminar búsqueda guardada: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al eliminar búsqueda guardada: {str(e)}'})
        }

    """Guarda los criterios de búsqueda para su reutilización"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        if 'name' not in body or 'search_criteria' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requiere nombre y criterios de búsqueda'})
            }
        
        name = body['name']
        search_criteria = body['search_criteria']
        description = body.get('description', '')
        
        # Verificar si ya existe una búsqueda guardada con el mismo nombre para este usuario
        check_query = """
        SELECT id_busqueda 
        FROM busquedas_guardadas
        WHERE id_usuario = %s AND nombre = %s
        """
        
        existing = execute_query(check_query, (user_id, name))
        
        if existing:
            # Si existe, actualizar
            update_query = """
            UPDATE busquedas_guardadas
            SET criterios = %s,
                descripcion = %s,
                fecha_modificacion = %s
            WHERE id_usuario = %s AND nombre = %s
            """
            
            execute_query(update_query, (
                json.dumps(search_criteria),
                description,
                datetime.datetime.now(),
                user_id,
                name
            ), fetch=False)
            
            search_id = existing[0]['id_busqueda']
            is_update = True
        else:
            # Si no existe, crear nueva
            search_id = generate_uuid()
            
            insert_query = """
            INSERT INTO busquedas_guardadas (
                id_busqueda, id_usuario, nombre, descripcion,
                criterios, fecha_creacion, fecha_modificacion
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            
            now = datetime.datetime.now()
            
            execute_query(insert_query, (
                search_id,
                user_id,
                name,
                description,
                json.dumps(search_criteria),
                now,
                now
            ), fetch=False)
            
            is_update = False
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'guardar_busqueda',
            'entidad_afectada': 'busqueda_guardada',
            'id_entidad_afectada': search_id,
            'detalles': json.dumps({
                'nombre': name,
                'descripcion': description,
                'es_actualizacion': is_update
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Búsqueda guardada exitosamente',
                'id_busqueda': search_id,
                'actualizada': is_update
            })
        }
        
    except Exception as e:
        logger.error(f"Error al guardar búsqueda: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al guardar búsqueda: {str(e)}'})
        }