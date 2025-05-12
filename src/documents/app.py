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
    """Main handler that routes to the corresponding functions"""
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
        
        # Document management routes
        if http_method == 'GET' and path == '/documents':
            return list_documents(event, context)
        elif http_method == 'GET' and path.startswith('/documents/') and len(path.split('/')) == 3:
            doc_id = path.split('/')[2]
            event['pathParameters'] = {'id': doc_id}
            return get_document(event, context)
        elif http_method == 'POST' and path == '/documents':
            return create_document(event, context)
        elif http_method == 'PUT' and path.startswith('/documents/') and len(path.split('/')) == 3:
            doc_id = path.split('/')[2]
            event['pathParameters'] = {'id': doc_id}
            return update_document(event, context)
        elif http_method == 'DELETE' and path.startswith('/documents/') and len(path.split('/')) == 3:
            doc_id = path.split('/')[2]
            event['pathParameters'] = {'id': doc_id}
            return delete_document(event, context)
        
        # Document versions routes
        elif http_method == 'GET' and path.startswith('/documents/') and path.endswith('/versions'):
            doc_id = path.split('/')[2]
            event['pathParameters'] = {'id': doc_id}
            return list_document_versions(event, context)
        elif http_method == 'GET' and '/versions/' in path:
            parts = path.split('/')
            doc_id = parts[2]
            version_id = parts[4]
            event['pathParameters'] = {'id': doc_id, 'version_id': version_id}
            return get_document_version(event, context)
        elif http_method == 'POST' and path.startswith('/documents/') and path.endswith('/versions'):
            doc_id = path.split('/')[2]
            event['pathParameters'] = {'id': doc_id}
            return create_document_version(event, context)
        
        # Document history route
        elif http_method == 'GET' and path.startswith('/documents/') and path.endswith('/history'):
            doc_id = path.split('/')[2]
            event['pathParameters'] = {'id': doc_id}
            return get_document_history(event, context)
                 
        # If no route matches, return 404
        return {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Route not found'})
        }
        
    except Exception as e:
        logger.error(f"Error in main handler: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }

def validate_session(event, required_permission=None):
    """Validates user session and checks permission if required"""
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Token not provided'})}
    
    session_token = auth_header.split(' ')[1]
    
    # Check if session exists and is active
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

def list_documents(event, context):
    """Lists documents with pagination and filters"""
    try:
        # Validate session and check permission
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Pagination
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filters
        title_search = query_params.get('title')
        document_type = query_params.get('tipo_documento')
        status = query_params.get('estado')
        folder_id = query_params.get('id_carpeta')
        tags = query_params.get('tags')
        
        # Base query
        query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.fecha_creacion, d.fecha_modificacion,
               d.id_carpeta, c.nombre_carpeta, d.estado, d.tags, 
               u_creador.nombre_usuario as creado_por_usuario,
               u_modificador.nombre_usuario as modificado_por_usuario
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        """
        
        count_query = """
        SELECT COUNT(*) as total 
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        """
        
        # Build where clauses
        where_clauses = []
        params = []
        
        # Add filter for non-deleted documents by default
        where_clauses.append("d.estado != 'eliminado'")
        
        # Add user permissions filter (users can see documents from their folders or shared with them)
        folders_access_query = """
        (d.id_carpeta IN (
            SELECT pc.id_carpeta 
            FROM permisos_carpetas pc 
            WHERE (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario')
            OR (pc.id_entidad IN (
                SELECT g.id_grupo 
                FROM usuarios_grupos ug 
                JOIN grupos g ON ug.id_grupo = g.id_grupo 
                WHERE ug.id_usuario = %s
            ) AND pc.tipo_entidad = 'grupo')
        ) OR d.creado_por = %s)
        """
        where_clauses.append(folders_access_query)
        params.extend([user_id, user_id, user_id])
        
        # Title search
        if title_search:
            where_clauses.append("(d.titulo LIKE %s OR d.descripcion LIKE %s)")
            search_param = f"%{title_search}%"
            params.extend([search_param, search_param])
        
        # Document type filter
        if document_type:
            where_clauses.append("d.id_tipo_documento = %s")
            params.append(document_type)
        
        # Status filter
        if status:
            where_clauses.append("d.estado = %s")
            params.append(status)
        
        # Folder filter
        if folder_id:
            where_clauses.append("d.id_carpeta = %s")
            params.append(folder_id)
        
        # Tags filter (JSON contains)
        if tags:
            tag_list = json.loads(tags) if isinstance(tags, str) else tags
            if isinstance(tag_list, list) and tag_list:
                # For each tag, add a JSON_CONTAINS condition
                for tag in tag_list:
                    where_clauses.append("JSON_CONTAINS(d.tags, %s, '$')")
                    params.append(json.dumps(tag))
        
        # Add WHERE clause to queries
        if where_clauses:
            where_str = " WHERE " + " AND ".join(where_clauses)
            query += where_str
            count_query += where_str
        
        # Add ordering and pagination
        query += " ORDER BY d.fecha_modificacion DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Execute queries
        documents = execute_query(query, params)
        count_result = execute_query(count_query, params[:-2])
        
        total_documents = count_result[0]['total'] if count_result else 0
        total_pages = (total_documents + page_size - 1) // page_size if total_documents > 0 else 1
        
        # Process results
        for doc in documents:
            # Convert datetime to string
            if 'fecha_creacion' in doc and doc['fecha_creacion']:
                doc['fecha_creacion'] = doc['fecha_creacion'].isoformat()
            if 'fecha_modificacion' in doc and doc['fecha_modificacion']:
                doc['fecha_modificacion'] = doc['fecha_modificacion'].isoformat()
            
            # Parse JSON fields
            if 'tags' in doc and doc['tags']:
                try:
                    doc['tags'] = json.loads(doc['tags'])
                except:
                    doc['tags'] = []
        
        # Prepare response with pagination metadata
        response = {
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
        logger.error(f"Error listing documents: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error listing documents: {str(e)}'})
        }

def get_document(event, context):
    """Gets a specific document details"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Get document ID
        doc_id = event['pathParameters']['id']
        
        # Get document details
        query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.fecha_creacion, d.fecha_modificacion,
               d.id_carpeta, c.nombre_carpeta, c.ruta_completa as carpeta_ruta,
               d.estado, d.tags, d.metadatos, d.estadisticas, 
               d.confianza_extraccion, d.validado_manualmente,
               d.fecha_validacion, d.validado_por,
               u_creador.id_usuario as creado_por_id,
               u_creador.nombre_usuario as creado_por_usuario,
               u_modificador.id_usuario as modificado_por_id,
               u_modificador.nombre_usuario as modificado_por_usuario,
               v.id_version as version_actual_id,
               v.ubicacion_almacenamiento_ruta as ruta_archivo,
               v.ubicacion_almacenamiento_tipo as tipo_almacenamiento,
               v.mime_type, v.tamano_bytes,
               v.nombre_original, v.extension
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        LEFT JOIN versiones_documento v ON d.id_documento = v.id_documento AND v.numero_version = d.version_actual
        WHERE d.id_documento = %s
        """
        
        results = execute_query(query, (doc_id,))
        
        if not results:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Document not found'})
            }
        
        document = results[0]
        
        # Check user permission to access this document
        if document['creado_por_id'] != user_id:
            # Check if user has access to the document's folder
            folder_permission_query = """
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
            
            folder_access = execute_query(folder_permission_query, (document['id_carpeta'], user_id, user_id))
            
            if not folder_access or folder_access[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have permission to access this document'})
                }
        
        # Parse JSON fields
        json_fields = ['tags', 'metadatos', 'estadisticas']
        for field in json_fields:
            if field in document and document[field]:
                try:
                    document[field] = json.loads(document[field])
                except:
                    document[field] = {}
        
        # Get document versions count
        versions_query = """
        SELECT COUNT(*) as versions_count
        FROM versiones_documento
        WHERE id_documento = %s
        """
        
        versions_result = execute_query(versions_query, (doc_id,))
        document['versions_count'] = versions_result[0]['versions_count'] if versions_result else 0
        
        # Get document comments count
        comments_query = """
        SELECT COUNT(*) as comments_count
        FROM comentarios_documento
        WHERE id_documento = %s AND estado = 'activo'
        """
        
        comments_result = execute_query(comments_query, (doc_id,))
        document['comments_count'] = comments_result[0]['comments_count'] if comments_result else 0
        
        # Get related documents
        references_query = """
        SELECT r.id_documento_destino, r.tipo_referencia, 
               d.titulo, d.codigo_documento, d.estado
        FROM referencias_documento r
        JOIN documentos d ON r.id_documento_destino = d.id_documento
        WHERE r.id_documento_origen = %s
        
        UNION
        
        SELECT r.id_documento_origen, 
               CASE 
                   WHEN r.tipo_referencia = 'padre' THEN 'hijo'
                   WHEN r.tipo_referencia = 'hijo' THEN 'padre'
                   WHEN r.tipo_referencia = 'reemplaza' THEN 'reemplazado_por'
                   ELSE r.tipo_referencia 
               END as tipo_referencia,
               d.titulo, d.codigo_documento, d.estado
        FROM referencias_documento r
        JOIN documentos d ON r.id_documento_origen = d.id_documento
        WHERE r.id_documento_destino = %s
        """
        
        references = execute_query(references_query, (doc_id, doc_id))
        document['documentos_relacionados'] = references
        
        # Format datetime fields
        datetime_fields = ['fecha_creacion', 'fecha_modificacion', 'fecha_validacion']
        for field in datetime_fields:
            if field in document and document[field]:
                document[field] = document[field].isoformat()
        
        # Register document view in audit log
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'documento',
            'id_entidad_afectada': doc_id,
            'detalles': json.dumps({'titulo': document['titulo']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(document, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting document: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting document: {str(e)}'})
        }

def create_document(event, context):
    """Creates a new document record"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.crear')
        if error_response:
            return error_response
        
        # Get request body
        body = json.loads(event['body'])
        
        # Validate required fields
        required_fields = ['titulo', 'id_tipo_documento']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }
        
        # Get fields from body
        titulo = body['titulo']
        id_tipo_documento = body['id_tipo_documento']
        descripcion = body.get('descripcion')
        tags = body.get('tags', [])
        metadatos = body.get('metadatos', {})
        
        # Handle id_carpeta - set to None if not provided or empty
        id_carpeta = body.get('id_carpeta')
        if id_carpeta == "" or id_carpeta is None:
            id_carpeta = None
            logger.info("No folder specified, document will be created without folder assignment")
        else:
            # Check if folder exists
            folder_query = """
            SELECT id_carpeta, nombre_carpeta
            FROM carpetas
            WHERE id_carpeta = %s
            """
            
            folder_result = execute_query(folder_query, (id_carpeta,))
            if not folder_result:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Invalid folder ID'})
                }
            
            # Check if user has write access to the folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('escritura', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (id_carpeta, user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have write permission for this folder'})
                }
        
        # Check if document type exists
        type_query = """
        SELECT id_tipo_documento, nombre_tipo, prefijo_nomenclatura
        FROM tipos_documento
        WHERE id_tipo_documento = %s
        """
        
        type_result = execute_query(type_query, (id_tipo_documento,))
        if not type_result:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Invalid document type'})
            }
        
        doc_type = type_result[0]
        
        # Generate document ID
        doc_id = generate_uuid()
        
        # Generate document code
        prefix = doc_type['prefijo_nomenclatura'] or "DOC"
        current_date = datetime.datetime.now().strftime("%Y%m%d")
        
        # Get the next sequence number for this document type today
        seq_query = """
        SELECT COUNT(*) as seq
        FROM documentos
        WHERE id_tipo_documento = %s AND DATE(fecha_creacion) = CURDATE()
        """
        
        seq_result = execute_query(seq_query, (id_tipo_documento,))
        sequence = (seq_result[0]['seq'] + 1) if seq_result else 1
        
        # Format document code
        codigo_documento = f"{prefix}-{current_date}-{sequence:04d}"
        
        # Insert document record
        now = datetime.datetime.now()
        
        insert_query = """
        INSERT INTO documentos (
            id_documento, codigo_documento, id_tipo_documento, titulo,
            descripcion, version_actual, fecha_creacion, fecha_modificacion,
            creado_por, modificado_por, id_carpeta, estado, tags, metadatos
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        insert_params = (
            doc_id, codigo_documento, id_tipo_documento, titulo,
            descripcion, 1, now, now,
            user_id, user_id, id_carpeta, 'borrador',
            json.dumps(tags), json.dumps(metadatos)
        )
        
        logger.info(f"Attempting to insert document with params: id_carpeta={id_carpeta}, id_tipo_documento={id_tipo_documento}")
        execute_query(insert_query, insert_params, fetch=False)
        
        # Log document creation
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear',
            'entidad_afectada': 'documento',
            'id_entidad_afectada': doc_id,
            'detalles': json.dumps({
                'titulo': titulo,
                'tipo_documento': doc_type['nombre_tipo'],
                'carpeta': id_carpeta
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Document created successfully',
                'id_documento': doc_id,
                'codigo_documento': codigo_documento
            })
        }
        
    except Exception as e:
        logger.error(f"Error creating document: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error creating document: {str(e)}'})
        }

def update_document(event, context):
    """Updates document metadata"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.editar')
        if error_response:
            return error_response
        
        # Get document ID
        doc_id = event['pathParameters']['id']
        
        # Get request body
        body = json.loads(event['body'])
        
        # Check if document exists and user has permission
        check_query = """
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por
        FROM documentos d
        WHERE d.id_documento = %s AND d.estado != 'eliminado'
        """
        
        doc_result = execute_query(check_query, (doc_id,))
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Document not found or already deleted'})
            }
        
        document = doc_result[0]
        
        # Check if user has permission to edit the document
        if document['creado_por'] != user_id:
            # Check if user has write access to the document's folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('escritura', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (document['id_carpeta'], user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have permission to edit this document'})
                }
        
        # Get updatable fields
        fields_to_update = []
        params = []
        
        updateable_fields = {
            'titulo': 'titulo',
            'descripcion': 'descripcion',
            'id_carpeta': 'id_carpeta',
            'estado': 'estado',
            'tags': 'tags',
            'metadatos': 'metadatos'
        }
        
        # Check if folder is being updated and validate access
        if 'id_carpeta' in body and body['id_carpeta'] != document['id_carpeta']:
            new_folder_id = body['id_carpeta']
            
            # Check if new folder exists
            folder_query = """
            SELECT id_carpeta
            FROM carpetas
            WHERE id_carpeta = %s
            """
            
            folder_result = execute_query(folder_query, (new_folder_id,))
            if not folder_result:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Invalid folder ID'})
                }
            
            # Check if user has write access to the new folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('escritura', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (new_folder_id, user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have write permission for the target folder'})
                }
        
        # Validate status change
        if 'estado' in body:
            valid_statuses = ['borrador', 'publicado', 'archivado']
            if body['estado'] not in valid_statuses:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'})
                }
        
        # Build update query
        for field, db_field in updateable_fields.items():
            if field in body:
                value = body[field]
                
                # Convert JSON fields to string
                if field in ['tags', 'metadatos'] and value is not None:
                    value = json.dumps(value)
                
                fields_to_update.append(f"{db_field} = %s")
                params.append(value)
        
        # If no fields to update, return error
        if not fields_to_update:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No fields to update'})
            }
        
        # Add modification metadata
        fields_to_update.append("fecha_modificacion = %s")
        params.append(datetime.datetime.now())
        
        fields_to_update.append("modificado_por = %s")
        params.append(user_id)
        
        # Construct and execute update query
        update_query = f"""
        UPDATE documentos
        SET {', '.join(fields_to_update)}
        WHERE id_documento = %s
        """
        
        params.append(doc_id)
        execute_query(update_query, params, fetch=False)
        
        # Log document update
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'modificar',
            'entidad_afectada': 'documento',
            'id_entidad_afectada': doc_id,
            'detalles': json.dumps({
                'campos_actualizados': list(set(updateable_fields.keys()) & set(body.keys()))
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Document updated successfully',
                'id_documento': doc_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error updating document: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error updating document: {str(e)}'})
        }

def delete_document(event, context):
    """Marks a document as deleted"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.eliminar')
        if error_response:
            return error_response
        
        # Get document ID
        doc_id = event['pathParameters']['id']
        
        # Check if document exists and user has permission
        check_query = """
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por
        FROM documentos d
        WHERE d.id_documento = %s AND d.estado != 'eliminado'
        """
        
        doc_result = execute_query(check_query, (doc_id,))
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Document not found or already deleted'})
            }
        
        document = doc_result[0]
        
        # Check if user has permission to delete the document
        if document['creado_por'] != user_id:
            # Check if user has delete access to the document's folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('eliminacion', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (document['id_carpeta'], user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have permission to delete this document'})
                }
        
        # Mark document as deleted
        update_query = """
        UPDATE documentos
        SET estado = 'eliminado',
            fecha_modificacion = %s,
            modificado_por = %s
        WHERE id_documento = %s
        """
        
        now = datetime.datetime.now()
        execute_query(update_query, (now, user_id, doc_id), fetch=False)
        
        # Log document deletion
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'eliminar',
            'entidad_afectada': 'documento',
            'id_entidad_afectada': doc_id,
            'detalles': json.dumps({
                'titulo': document['titulo'],
                'estado_anterior': document['estado']
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Document marked as deleted successfully',
                'id_documento': doc_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error deleting document: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error deleting document: {str(e)}'})
        }

def list_document_versions(event, context):
    """Lists all versions of a document"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Get document ID
        doc_id = event['pathParameters']['id']
        
        # Check if document exists and user has permission to access it
        check_query = """
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por
        FROM documentos d
        WHERE d.id_documento = %s AND d.estado != 'eliminado'
        """
        
        doc_result = execute_query(check_query, (doc_id,))
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Document not found or deleted'})
            }
        
        document = doc_result[0]
        
        # Check if user has permission to view the document
        if document['creado_por'] != user_id:
            # Check if user has read access to the document's folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('lectura', 'escritura', 'eliminacion', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (document['id_carpeta'], user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have permission to view this document'})
                }
        
        # Get query parameters for pagination
        query_params = event.get('queryStringParameters', {}) or {}
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Query to get versions
        versions_query = """
        SELECT v.id_version, v.numero_version, v.fecha_creacion,
               v.creado_por, u.nombre_usuario as creado_por_usuario,
               v.comentario_version, v.tamano_bytes, v.nombre_original,
               v.extension, v.mime_type, v.estado_ocr,
               v.ubicacion_almacenamiento_tipo, v.ubicacion_almacenamiento_ruta
        FROM versiones_documento v
        JOIN usuarios u ON v.creado_por = u.id_usuario
        WHERE v.id_documento = %s
        ORDER BY v.numero_version DESC
        LIMIT %s OFFSET %s
        """
        
        # Count query
        count_query = """
        SELECT COUNT(*) as total
        FROM versiones_documento
        WHERE id_documento = %s
        """
        
        # Execute queries
        versions = execute_query(versions_query, (doc_id, page_size, (page - 1) * page_size))
        count_result = execute_query(count_query, (doc_id,))
        
        total_versions = count_result[0]['total'] if count_result else 0
        total_pages = (total_versions + page_size - 1) // page_size if total_versions > 0 else 1
        
        # Format datetime fields
        for version in versions:
            if 'fecha_creacion' in version and version['fecha_creacion']:
                version['fecha_creacion'] = version['fecha_creacion'].isoformat()
        
        # Prepare response with pagination metadata
        response = {
            'document_id': doc_id,
            'title': document['titulo'],
            'versions': versions,
            'pagination': {
                'total': total_versions,
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
        logger.error(f"Error listing document versions: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error listing document versions: {str(e)}'})
        }

def get_document_version(event, context):
    """Gets details of a specific document version"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Get document ID and version ID
        doc_id = event['pathParameters']['id']
        version_id = event['pathParameters']['version_id']
        
        # Check if document exists and user has permission to access it
        check_query = """
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por, d.version_actual
        FROM documentos d
        WHERE d.id_documento = %s AND d.estado != 'eliminado'
        """
        
        doc_result = execute_query(check_query, (doc_id,))
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Document not found or deleted'})
            }
        
        document = doc_result[0]
        
        # Check if user has permission to view the document
        if document['creado_por'] != user_id:
            # Check if user has read access to the document's folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('lectura', 'escritura', 'eliminacion', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (document['id_carpeta'], user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have permission to view this document'})
                }
        
        # Query to get version details
        version_query = """
        SELECT v.id_version, v.numero_version, v.fecha_creacion,
               v.creado_por, u.nombre_usuario as creado_por_usuario,
               v.comentario_version, v.tamano_bytes, v.hash_contenido,
               v.ubicacion_almacenamiento_tipo, v.ubicacion_almacenamiento_ruta,
               v.ubicacion_almacenamiento_parametros,
               v.nombre_original, v.extension, v.mime_type,
               v.metadatos_extraidos, v.texto_extraido,
               v.estado_ocr, v.miniaturas_generadas
        FROM versiones_documento v
        JOIN usuarios u ON v.creado_por = u.id_usuario
        WHERE v.id_documento = %s AND v.id_version = %s
        """
        
        version_result = execute_query(version_query, (doc_id, version_id))
        if not version_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Version not found'})
            }
        
        version = version_result[0]
        
        # Format datetime fields
        if 'fecha_creacion' in version and version['fecha_creacion']:
            version['fecha_creacion'] = version['fecha_creacion'].isoformat()
        
        # Parse JSON fields
        json_fields = ['ubicacion_almacenamiento_parametros', 'metadatos_extraidos']
        for field in json_fields:
            if field in version and version[field]:
                try:
                    version[field] = json.loads(version[field])
                except:
                    version[field] = {}
        
        # Add flag to indicate if this is the current version
        version['is_current_version'] = (document['version_actual'] == version['numero_version'])
        
        # Truncate extracted text if too long
        if 'texto_extraido' in version and version['texto_extraido'] and len(version['texto_extraido']) > 1000:
            version['texto_extraido'] = version['texto_extraido'][:1000] + "... (truncated)"
        
        # Log version view
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'version_documento',
            'id_entidad_afectada': version_id,
            'detalles': json.dumps({
                'id_documento': doc_id,
                'numero_version': version['numero_version']
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'document_id': doc_id,
                'document_title': document['titulo'],
                'version': version
            }, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting document version: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting document version: {str(e)}'})
        }

def create_document_version(event, context):
    """Creates a new version for an existing document"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.editar')
        if error_response:
            return error_response
        
        # Get document ID
        doc_id = event['pathParameters']['id']
        
        # Check if document exists and user has permission to edit it
        check_query = """
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por, d.version_actual
        FROM documentos d
        WHERE d.id_documento = %s AND d.estado != 'eliminado'
        """
        
        doc_result = execute_query(check_query, (doc_id,))
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Document not found or deleted'})
            }
        
        document = doc_result[0]
        
        # Check if user has permission to edit the document
        if document['creado_por'] != user_id:
            # Check if user has write access to the document's folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('escritura', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (document['id_carpeta'], user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have permission to edit this document'})
                }
        
        # Parse request body
        body = json.loads(event['body'])
        
        # Validate required fields
        required_fields = [
            'nombre_original', 
            'tamano_bytes', 
            'hash_contenido', 
            'mime_type',
            'ubicacion_almacenamiento_tipo',
            'ubicacion_almacenamiento_ruta'
        ]
        
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }
        
        # Extract fields from body
        nombre_original = body['nombre_original']
        tamano_bytes = body['tamano_bytes']
        hash_contenido = body['hash_contenido']
        mime_type = body['mime_type']
        ubicacion_tipo = body['ubicacion_almacenamiento_tipo']
        ubicacion_ruta = body['ubicacion_almacenamiento_ruta']
        ubicacion_parametros = body.get('ubicacion_almacenamiento_parametros', {})
        comentario_version = body.get('comentario_version')
        extension = body.get('extension')
        metadatos_extraidos = body.get('metadatos_extraidos', {})
        texto_extraido = body.get('texto_extraido')
        estado_ocr = body.get('estado_ocr', 'no_aplica')
        miniaturas_generadas = body.get('miniaturas_generadas', False)
        
        # Generate new version number
        new_version_number = document['version_actual'] + 1
        
        # Generate version ID
        version_id = generate_uuid()
        
        # Insert new version
        now = datetime.datetime.now()
        
        insert_query = """
        INSERT INTO versiones_documento (
            id_version, id_documento, numero_version, fecha_creacion,
            creado_por, comentario_version, tamano_bytes, hash_contenido,
            ubicacion_almacenamiento_tipo, ubicacion_almacenamiento_ruta,
            ubicacion_almacenamiento_parametros, nombre_original,
            extension, mime_type, metadatos_extraidos, texto_extraido,
            estado_ocr, miniaturas_generadas
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        insert_params = (
            version_id, doc_id, new_version_number, now,
            user_id, comentario_version, tamano_bytes, hash_contenido,
            ubicacion_tipo, ubicacion_ruta, json.dumps(ubicacion_parametros),
            nombre_original, extension, mime_type, json.dumps(metadatos_extraidos),
            texto_extraido, estado_ocr, miniaturas_generadas
        )
        
        execute_query(insert_query, insert_params, fetch=False)
        
        # Update document's current version
        update_query = """
        UPDATE documentos
        SET version_actual = %s,
            fecha_modificacion = %s,
            modificado_por = %s
        WHERE id_documento = %s
        """
        
        execute_query(update_query, (new_version_number, now, user_id, doc_id), fetch=False)
        
        # Log version creation
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear',
            'entidad_afectada': 'version_documento',
            'id_entidad_afectada': version_id,
            'detalles': json.dumps({
                'id_documento': doc_id,
                'numero_version': new_version_number,
                'nombre_archivo': nombre_original
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Document version created successfully',
                'document_id': doc_id,
                'version_id': version_id,
                'version_number': new_version_number
            })
        }
        
    except Exception as e:
        logger.error(f"Error creating document version: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error creating document version: {str(e)}'})
        }

def get_document_history(event, context):
    """Gets the history of changes for a document"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Get document ID
        doc_id = event['pathParameters']['id']
        
        # Check if document exists and user has permission to view it
        check_query = """
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por, d.version_actual
        FROM documentos d
        WHERE d.id_documento = %s AND d.estado != 'eliminado'
        """
        
        doc_result = execute_query(check_query, (doc_id,))
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Document not found or deleted'})
            }
        
        document = doc_result[0]
        
        # Check if user has permission to view the document
        if document['creado_por'] != user_id:
            # Check if user has read access to the document's folder
            access_query = """
            SELECT COUNT(*) as has_access
            FROM permisos_carpetas pc
            WHERE pc.id_carpeta = %s AND tipo_permiso IN ('lectura', 'escritura', 'eliminacion', 'administracion') AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (
                    SELECT ug.id_grupo
                    FROM usuarios_grupos ug
                    WHERE ug.id_usuario = %s
                ) AND pc.tipo_entidad = 'grupo')
            )
            """
            
            access_result = execute_query(access_query, (document['id_carpeta'], user_id, user_id))
            if not access_result or access_result[0]['has_access'] == 0:
                return {
                    'statusCode': 403,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'You do not have permission to view this document'})
                }
        
        # Get pagination parameters
        query_params = event.get('queryStringParameters', {}) or {}
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 20))
        
        # Get document history from audit logs
        audit_query = """
        SELECT a.id_registro, a.fecha_hora, a.usuario_id, 
               u.nombre_usuario as usuario_nombre,
               a.accion, a.detalles, a.resultado
        FROM registros_auditoria a
        JOIN usuarios u ON a.usuario_id = u.id_usuario
        WHERE a.entidad_afectada IN ('documento', 'version_documento') 
        AND a.id_entidad_afectada IN (
            %s,  -- Document ID
            (SELECT id_version FROM versiones_documento WHERE id_documento = %s)  -- Version IDs
        )
        ORDER BY a.fecha_hora DESC
        LIMIT %s OFFSET %s
        """
        
        # Count query
        count_query = """
        SELECT COUNT(*) as total
        FROM registros_auditoria a
        WHERE a.entidad_afectada IN ('documento', 'version_documento') 
        AND a.id_entidad_afectada IN (
            %s,  -- Document ID
            (SELECT id_version FROM versiones_documento WHERE id_documento = %s)  -- Version IDs
        )
        """
        
        # Execute queries
        history = execute_query(audit_query, (doc_id, doc_id, page_size, (page - 1) * page_size))
        count_result = execute_query(count_query, (doc_id, doc_id))
        
        total_entries = count_result[0]['total'] if count_result else 0
        total_pages = (total_entries + page_size - 1) // page_size if total_entries > 0 else 1
        
        # Process history entries
        for entry in history:
            # Format datetime
            if 'fecha_hora' in entry and entry['fecha_hora']:
                entry['fecha_hora'] = entry['fecha_hora'].isoformat()
            
            # Parse JSON details
            if 'detalles' in entry and entry['detalles']:
                try:
                    entry['detalles'] = json.loads(entry['detalles'])
                except:
                    entry['detalles'] = {}
        
        # Prepare response with pagination metadata
        response = {
            'document_id': doc_id,
            'document_title': document['titulo'],
            'history': history,
            'pagination': {
                'total': total_entries,
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
        logger.error(f"Error getting document history: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting document history: {str(e)}'})
        }