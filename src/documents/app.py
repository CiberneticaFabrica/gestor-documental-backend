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
        client_id = query_params.get('id_cliente')  # Added client filter
        tags = query_params.get('tags')
        
        # Base query - expanded to include client information and more relevant data
        query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.fecha_creacion, d.fecha_modificacion,
               d.id_carpeta, c.nombre_carpeta, d.estado, d.tags, d.metadatos,
               d.confianza_extraccion, d.validado_manualmente,
               u_creador.nombre_usuario as creado_por_usuario,
               u_modificador.nombre_usuario as modificado_por_usuario,
               dc.id_cliente, cl.nombre_razon_social as cliente_nombre,
               cl.codigo_cliente, cl.tipo_cliente,
               cl.segmento_bancario, cl.nivel_riesgo,
               v.hash_contenido, v.tamano_bytes, v.mime_type, v.nombre_original,
               v.extension
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        LEFT JOIN versiones_documento v ON d.id_documento = v.id_documento AND v.numero_version = d.version_actual
        LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
        LEFT JOIN clientes cl ON dc.id_cliente = cl.id_cliente
        """
        
        count_query = """
        SELECT COUNT(DISTINCT d.id_documento) as total 
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
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
            
        # Client filter
        if client_id:
            where_clauses.append("dc.id_cliente = %s")
            params.append(client_id)
        
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
            json_fields = ['tags', 'metadatos']
            for field in json_fields:
                if field in doc and doc[field]:
                    try:
                        doc[field] = json.loads(doc[field])
                    except:
                        doc[field] = [] if field == 'tags' else {}
            
            # Get IA analysis if available
            if 'id_documento' in doc:
                analysis_query = """
                SELECT id_analisis, tipo_documento, confianza_clasificacion,
                       estado_analisis, fecha_analisis, verificado
                FROM analisis_documento_ia
                WHERE id_documento = %s
                ORDER BY fecha_analisis DESC
                LIMIT 1
                """
                
                analysis_result = execute_query(analysis_query, (doc['id_documento'],))
                if analysis_result:
                    doc['analisis_ia'] = {
                        'id_analisis': analysis_result[0]['id_analisis'],
                        'tipo_documento': analysis_result[0]['tipo_documento'],
                        'confianza': analysis_result[0]['confianza_clasificacion'],
                        'estado': analysis_result[0]['estado_analisis'],
                        'verificado': analysis_result[0]['verificado']
                    }
                    
                    if analysis_result[0]['fecha_analisis']:
                        doc['analisis_ia']['fecha'] = analysis_result[0]['fecha_analisis'].isoformat()
            
            # Add additional client data if associated
            if doc.get('id_cliente'):
                # Check if there are any active requests for this document
                request_query = """
                SELECT COUNT(*) as count
                FROM documentos_solicitados
                WHERE id_cliente = %s AND id_documento_recibido = %s
                """
                
                request_result = execute_query(request_query, (doc['id_cliente'], doc['id_documento']))
                doc['fue_solicitado'] = request_result[0]['count'] > 0 if request_result else False
                
                # Add client document category if available
                category_query = """
                SELECT cat.id_categoria, cat.nombre_categoria
                FROM categorias_documento_cliente cat
                JOIN documentos d ON d.id_tipo_documento = %s
                WHERE d.id_documento = %s
                LIMIT 1
                """
                
                category_result = execute_query(category_query, (doc['id_tipo_documento'], doc['id_documento']))
                if category_result:
                    doc['categoria_cliente'] = {
                        'id': category_result[0]['id_categoria'],
                        'nombre': category_result[0]['nombre_categoria']
                    }
        
        # Get document types for filter options
        doc_types_query = """
        SELECT id_tipo_documento, nombre_tipo
        FROM tipos_documento
        ORDER BY nombre_tipo
        """
        
        doc_types = execute_query(doc_types_query)
        
        # Prepare response with pagination metadata and filter options
        response = {
            'documentos': documents,
            'tipos_documento': doc_types,
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
        
        # Get document details with client information
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
               v.nombre_original, v.extension,
               dc.id_cliente, cl.nombre_razon_social as cliente_nombre,
               cl.codigo_cliente, cl.tipo_cliente, cl.documento_identificacion,
               cl.segmento_bancario, cl.nivel_riesgo, cl.estado_documental,
               cl.gestor_principal_id, u_gestor.nombre_usuario as gestor_nombre,
               dc.fecha_asignacion, u_asignador.nombre_usuario as asignado_por_nombre
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        LEFT JOIN versiones_documento v ON d.id_documento = v.id_documento AND v.numero_version = d.version_actual
        LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
        LEFT JOIN clientes cl ON dc.id_cliente = cl.id_cliente
        LEFT JOIN usuarios u_gestor ON cl.gestor_principal_id = u_gestor.id_usuario
        LEFT JOIN usuarios u_asignador ON dc.asignado_por = u_asignador.id_usuario
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
                    document[field] = {} if field != 'tags' else []
        
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
        
        # Get IA analysis details if available
        analysis_query = """
        SELECT id_analisis, tipo_documento, confianza_clasificacion,
               estado_analisis, fecha_analisis, verificado, verificado_por,
               texto_extraido, entidades_detectadas, metadatos_extraccion
        FROM analisis_documento_ia
        WHERE id_documento = %s
        ORDER BY fecha_analisis DESC
        LIMIT 1
        """
        
        analysis_result = execute_query(analysis_query, (doc_id,))
        if analysis_result:
            analysis = analysis_result[0]
            
            # Process JSON fields in analysis
            json_analysis_fields = ['entidades_detectadas', 'metadatos_extraccion']
            for field in json_analysis_fields:
                if field in analysis and analysis[field]:
                    try:
                        analysis[field] = json.loads(analysis[field])
                    except:
                        analysis[field] = {}
            
            # Format dates
            if 'fecha_analisis' in analysis and analysis['fecha_analisis']:
                analysis['fecha_analisis'] = analysis['fecha_analisis'].isoformat()
            
            # Truncate text if too long
            if 'texto_extraido' in analysis and analysis['texto_extraido'] and len(analysis['texto_extraido']) > 1000:
                analysis['texto_extraido_preview'] = analysis['texto_extraido'][:1000] + "... (truncated)"
                # Keep full text in separate field if needed
                analysis['texto_extraido_full'] = analysis['texto_extraido']
                del analysis['texto_extraido']
            
            document['analisis_ia'] = analysis
        
        # If document is associated with a client, get more details
        if document.get('id_cliente'):
            # Check if there are any active requests for this document
            request_query = """
            SELECT ds.id_solicitud, ds.fecha_solicitud, ds.estado,
                   ds.fecha_limite, ds.solicitado_por, 
                   u.nombre_usuario as solicitado_por_nombre
            FROM documentos_solicitados ds
            JOIN usuarios u ON ds.solicitado_por = u.id_usuario
            WHERE ds.id_cliente = %s AND ds.id_documento_recibido = %s
            """
            
            request_result = execute_query(request_query, (document['id_cliente'], doc_id))
            if request_result:
                request = request_result[0]
                # Format dates
                if 'fecha_solicitud' in request and request['fecha_solicitud']:
                    request['fecha_solicitud'] = request['fecha_solicitud'].isoformat()
                if 'fecha_limite' in request and request['fecha_limite']:
                    request['fecha_limite'] = request['fecha_limite'].isoformat()
                
                document['solicitud'] = request
            
            # Check if document has specific financial or banking information
            if document['id_tipo_documento']:
                # Check for banking contract info
                contract_query = """
                SELECT tipo_contrato, numero_contrato, fecha_inicio, fecha_fin,
                       estado, valor_contrato, tasa_interes, moneda,
                       numero_producto, firmado_digitalmente
                FROM contratos_bancarios
                WHERE id_documento = %s
                """
                
                contract_result = execute_query(contract_query, (doc_id,))
                if contract_result:
                    contract = contract_result[0]
                    # Format dates
                    date_fields = ['fecha_inicio', 'fecha_fin']
                    for field in date_fields:
                        if field in contract and contract[field]:
                            contract[field] = contract[field].isoformat()
                    
                    document['contrato_bancario'] = contract
                
                # Check for ID document info
                id_doc_query = """
                SELECT tipo_documento, numero_documento, fecha_emision,
                       fecha_expiracion, genero, nombre_completo, pais_emision
                FROM documentos_identificacion
                WHERE id_documento = %s
                """
                
                id_doc_result = execute_query(id_doc_query, (doc_id,))
                if id_doc_result:
                    id_doc = id_doc_result[0]
                    # Format dates
                    date_fields = ['fecha_emision', 'fecha_expiracion']
                    for field in date_fields:
                        if field in id_doc and id_doc[field]:
                            id_doc[field] = id_doc[field].isoformat()
                    
                    document['documento_identificacion'] = id_doc
                
                # Check for financial document info
                fin_doc_query = """
                SELECT tipo_documento_financiero, periodo_inicio, periodo_fin,
                       institucion_emisora, ingresos_reportados, activos_reportados,
                       pasivos_reportados, score_crediticio, moneda, verificado
                FROM documentos_financieros
                WHERE id_documento = %s
                """
                
                fin_doc_result = execute_query(fin_doc_query, (doc_id,))
                if fin_doc_result:
                    fin_doc = fin_doc_result[0]
                    # Format dates
                    date_fields = ['periodo_inicio', 'periodo_fin']
                    for field in date_fields:
                        if field in fin_doc and fin_doc[field]:
                            fin_doc[field] = fin_doc[field].isoformat()
                    
                    document['documento_financiero'] = fin_doc
        
        # Format datetime fields
        datetime_fields = ['fecha_creacion', 'fecha_modificacion', 'fecha_validacion', 'fecha_asignacion']
        for field in datetime_fields:
            if field in document and document[field]:
                document[field] = document[field].isoformat()
        
        # Add document processing history
        process_history_query = """
        SELECT id_registro, tipo_proceso, estado_proceso, 
               timestamp_inicio, timestamp_fin, duracion_ms,
               servicio_procesador, confianza
        FROM registro_procesamiento_documento
        WHERE id_documento = %s
        ORDER BY timestamp_inicio DESC
        LIMIT 10
        """
        
        process_history = execute_query(process_history_query, (doc_id,))
        
        # Format datetime fields in process history
        for record in process_history:
            for field in ['timestamp_inicio', 'timestamp_fin']:
                if field in record and record[field]:
                    record[field] = record[field].isoformat()
        
        document['historial_procesamiento'] = process_history
        
        # Organize document in a more structured way
        structured_response = {
            'documento': {
                'id': document['id_documento'],
                'codigo': document['codigo_documento'],
                'titulo': document['titulo'],
                'descripcion': document['descripcion'],
                'estado': document['estado'],
                'fechas': {
                    'creacion': document['fecha_creacion'],
                    'modificacion': document['fecha_modificacion'],
                    'validacion': document['fecha_validacion']
                },
                'tags': document.get('tags', []),
                'metadatos': document.get('metadatos', {}),
                'estadisticas': document.get('estadisticas', {})
            },
            'tipo_documento': {
                'id': document['id_tipo_documento'],
                'nombre': document['tipo_documento']
            },
            'version_actual': {
                'numero': document['version_actual'],
                'id': document['version_actual_id'],
                'ruta': document['ruta_archivo'],
                'tipo_almacenamiento': document['tipo_almacenamiento'],
                'mime_type': document['mime_type'],
                'tamano_bytes': document['tamano_bytes'],
                'nombre_original': document['nombre_original'],
                'extension': document['extension']
            },
            'creacion_modificacion': {
                'creado_por': {
                    'id': document['creado_por_id'],
                    'nombre': document['creado_por_usuario']
                },
                'modificado_por': {
                    'id': document['modificado_por_id'],
                    'nombre': document['modificado_por_usuario']
                }
            },
            'ubicacion': {
                'id_carpeta': document['id_carpeta'],
                'nombre_carpeta': document['nombre_carpeta'],
                'ruta_carpeta': document['carpeta_ruta']
            },
            'validacion': {
                'validado_manualmente': document['validado_manualmente'],
                'confianza_extraccion': document['confianza_extraccion'],
                'validado_por': document['validado_por']
            },
            'references': document['documentos_relacionados'],
            'comentarios_count': document['comments_count'],
            'versiones_count': document['versions_count'],
            'historial_procesamiento': document.get('historial_procesamiento', [])
        }
        
        # Add analysis section if available
        if 'analisis_ia' in document:
            structured_response['analisis_ia'] = document['analisis_ia']
        
        # Add client information if available
        if document.get('id_cliente'):
            structured_response['cliente'] = {
                'id': document['id_cliente'],
                'nombre': document['cliente_nombre'],
                'codigo': document['codigo_cliente'],
                'tipo': document['tipo_cliente'],
                'documento_identificacion': document['documento_identificacion'],
                'segmento_bancario': document['segmento_bancario'],
                'nivel_riesgo': document['nivel_riesgo'],
                'estado_documental': document['estado_documental'],
                'gestor': {
                    'id': document['gestor_principal_id'],
                    'nombre': document['gestor_nombre']
                },
                'asignacion_documento': {
                    'fecha': document.get('fecha_asignacion'),
                    'asignado_por': document.get('asignado_por_nombre')
                }
            }
            
            # Add solicitud if available
            if 'solicitud' in document:
                structured_response['cliente']['solicitud'] = document['solicitud']
        
        # Add specialized document info if available
        specialized_docs = {}
        if 'contrato_bancario' in document:
            specialized_docs['contrato_bancario'] = document['contrato_bancario']
        
        if 'documento_identificacion' in document:
            specialized_docs['documento_identificacion'] = document['documento_identificacion']
        
        if 'documento_financiero' in document:
            specialized_docs['documento_financiero'] = document['documento_financiero']
        
        if specialized_docs:
            structured_response['documento_especializado'] = specialized_docs
        
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
            'body': json.dumps(structured_response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error getting document: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting document: {str(e)}'})
        }

def create_document(event, context):
    """
    Genera una URL prefirmada para subir un archivo directamente a S3 con los metadatos
    necesarios, especialmente el ID del cliente, sin crear registros en la base de datos.
    """
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'documentos.crear')
        if error_response:
            return error_response
       
        # Get request body
        body = json.loads(event['body'])
       
        # Validate required fields
        required_fields = ['id_cliente', 'filename']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Campo requerido faltante: {field}'})
                }
       
        # Get fields from body
        id_cliente = body['id_cliente']
        filename = body['filename']
        #id_tipo_documento = body.get('id_tipo_documento', '')
        content_type = body.get('content_type', 'application/octet-stream')
       
        # Generate document ID
        doc_id = generate_uuid()
       
        # Initialize S3 client
        import boto3
        from botocore.config import Config
       
        # Configuración de reintentos para servicios AWS
        retry_config = Config(
            retries={
                'max_attempts': 3,
                'mode': 'standard'
            }
        )
       
        s3_client = boto3.client('s3', config=retry_config)
       
        # Definir el bucket y la ruta en S3
        upload_bucket = 'gestor-documental-bancario-documents-input'  # Usando el nombre específico que mencionaste
        s3_key = f"incoming/{doc_id}/{filename}"
       
        # Generar URL prefirmada para carga directa a S3 con metadatos
        presigned_post = s3_client.generate_presigned_post(
            Bucket=upload_bucket,
            Key=s3_key,
            Fields={
                'Content-Type': content_type,
                'x-amz-meta-client-id': id_cliente,
                'x-amz-meta-document-id': doc_id
               
            },
            Conditions=[
                ['content-length-range', 1, 20 * 1024 * 1024],  # Limitar tamaño a 20MB
                ['eq', '$Content-Type', content_type],
                ['eq', '$x-amz-meta-client-id', id_cliente],
                ['eq', '$x-amz-meta-document-id', doc_id]
            ],
            ExpiresIn=900  # URL válida por 15 minutos
        )
       
        # Preparar respuesta con instrucciones y URL para carga
        upload_instructions = {
            'message': 'URL generada exitosamente. Utilice esta URL para subir el archivo directamente a S3.',
            'id_documento': doc_id,
            'upload_url': presigned_post['url'],
            'upload_fields': presigned_post['fields'],
            'metadata': {
                'client-id': id_cliente,
                'document-id': doc_id
            },
            'ruta_s3': f"incoming/{doc_id}/",
            'expira_en': 900  # segundos
        }
       
        # Registrar en auditoría si es necesario
        try:
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'generar_url_carga',
                'entidad_afectada': 'documento',
                'id_entidad_afectada': doc_id,
                'detalles': json.dumps({
                    'id_cliente': id_cliente,
                    'filename': filename,
                    'content_type': content_type
                }),
                'resultado': 'éxito'
            }
           
            insert_audit_record(audit_data)
        except Exception as audit_error:
            logger.warning(f"Error al registrar auditoría (no crítico): {str(audit_error)}")
       
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(upload_instructions)
        }
       
    except Exception as e:
        logger.error(f"Error al crear documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al crear documento: {str(e)}'})
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
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por, d.id_tipo_documento
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
        
        # Get document type information
        type_query = """
        SELECT id_tipo_documento, nombre_tipo, descripcion
        FROM tipos_documento 
        WHERE id_tipo_documento = %s
        """
        
        type_result = execute_query(type_query, (document['id_tipo_documento'],))
        document_type = type_result[0] if type_result else None
        
        # Get client information associated with the document
        client_query = """
        SELECT c.id_cliente, c.codigo_cliente, c.nombre_razon_social, c.tipo_cliente,
               c.segmento_bancario, c.nivel_riesgo, c.estado,
               dc.fecha_asignacion, 
               u.nombre_usuario as asignado_por_nombre
        FROM documentos_clientes dc
        JOIN clientes c ON dc.id_cliente = c.id_cliente
        LEFT JOIN usuarios u ON dc.asignado_por = u.id_usuario
        WHERE dc.id_documento = %s
        """
        
        clients = execute_query(client_query, (doc_id,))
        
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
               v.ubicacion_almacenamiento_tipo, v.ubicacion_almacenamiento_ruta,
               CASE WHEN v.numero_version = d.version_actual THEN TRUE ELSE FALSE END as es_version_actual
        FROM versiones_documento v
        JOIN usuarios u ON v.creado_por = u.id_usuario
        JOIN documentos d ON v.id_documento = d.id_documento
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
        
        # Format client dates
        for client in clients:
            if 'fecha_asignacion' in client and client['fecha_asignacion']:
                client['fecha_asignacion'] = client['fecha_asignacion'].isoformat()
        
        # Prepare response with pagination metadata and enhanced information
        response = {
            'document_id': doc_id,
            'title': document['titulo'],
            'document_type': document_type,
            'clients': clients,  # Added client information
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
        SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por, 
               d.version_actual, d.id_tipo_documento, d.codigo_documento,
               d.fecha_creacion, d.fecha_modificacion
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
        
        # Get document type information
        type_query = """
        SELECT id_tipo_documento, nombre_tipo, descripcion, requiere_aprobacion
        FROM tipos_documento 
        WHERE id_tipo_documento = %s
        """
        
        type_result = execute_query(type_query, (document['id_tipo_documento'],))
        document_type = type_result[0] if type_result else None
        
        # Get client information associated with the document
        client_query = """
        SELECT c.id_cliente, c.codigo_cliente, c.nombre_razon_social, c.tipo_cliente,
               c.segmento_bancario, c.nivel_riesgo, c.estado, c.estado_documental,
               dc.fecha_asignacion, 
               u.nombre_usuario as asignado_por_nombre
        FROM documentos_clientes dc
        JOIN clientes c ON dc.id_cliente = c.id_cliente
        LEFT JOIN usuarios u ON dc.asignado_por = u.id_usuario
        WHERE dc.id_documento = %s
        """
        
        clients = execute_query(client_query, (doc_id,))
        
        # Format client dates
        for client in clients:
            if 'fecha_asignacion' in client and client['fecha_asignacion']:
                client['fecha_asignacion'] = client['fecha_asignacion'].isoformat()
        
        # Get folder path if exists
        folder_info = None
        if document['id_carpeta']:
            folder_query = """
            SELECT id_carpeta, nombre_carpeta, ruta_completa
            FROM carpetas
            WHERE id_carpeta = %s
            """
            
            folder_result = execute_query(folder_query, (document['id_carpeta'],))
            folder_info = folder_result[0] if folder_result else None
        
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
        
        if 'fecha_creacion' in document and document['fecha_creacion']:
            document['fecha_creacion'] = document['fecha_creacion'].isoformat()
            
        if 'fecha_modificacion' in document and document['fecha_modificacion']:
            document['fecha_modificacion'] = document['fecha_modificacion'].isoformat()
        
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
        
        # Check if there's any analysis from AI processing
        analysis_query = """
        SELECT id_analisis, tipo_documento, confianza_clasificacion, 
               entidades_detectadas, estado_analisis, fecha_analisis
        FROM analisis_documento_ia
        WHERE id_documento = %s
        ORDER BY fecha_analisis DESC
        LIMIT 1
        """
        
        analysis_result = execute_query(analysis_query, (doc_id,))
        analysis_info = None
        
        if analysis_result:
            analysis = analysis_result[0]
            # Format analysis dates
            if 'fecha_analisis' in analysis and analysis['fecha_analisis']:
                analysis['fecha_analisis'] = analysis['fecha_analisis'].isoformat()
            
            # Parse JSON fields in analysis
            if analysis['entidades_detectadas']:
                try:
                    analysis['entidades_detectadas'] = json.loads(analysis['entidades_detectadas'])
                except:
                    analysis['entidades_detectadas'] = {}
            
            analysis_info = analysis
        
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
        
        # Prepare enhanced response with additional information
        response = {
            'document': {
                'id': doc_id,
                'codigo': document['codigo_documento'],
                'title': document['titulo'],
                'version_actual': document['version_actual'],
                'fecha_creacion': document['fecha_creacion'],
                'fecha_modificacion': document['fecha_modificacion'],
                'estado': document['estado']
            },
            'document_type': document_type,
            'clients': clients,  # Added client information
            'folder': folder_info,
            'version': version,
            'analysis': analysis_info
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
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