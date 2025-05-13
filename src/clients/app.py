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
        
        # Rutas de gestión de clientes
        if http_method == 'GET' and path == '/clients':
            return list_clients(event, context)
        elif http_method == 'POST' and path == '/clients':
            return create_client(event, context)
        elif http_method == 'GET' and path.startswith('/clients/') and not path.endswith('/documents') and not path.endswith('/requests'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_client(event, context)
        elif http_method == 'PUT' and path.startswith('/clients/'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return update_client(event, context)
        elif http_method == 'DELETE' and path.startswith('/clients/'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return delete_client(event, context)
        elif http_method == 'GET' and path.endswith('/documents'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_client_documents(event, context)
        elif http_method == 'GET' and path.endswith('/requests') and len(path.split('/')) == 4:
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_client_requests(event, context)
        elif http_method == 'POST' and path.endswith('/requests'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return create_document_request(event, context)
        elif http_method == 'PUT' and '/requests/' in path:
            parts = path.split('/')
            client_id = parts[2]
            request_id = parts[4]
            event['pathParameters'] = {'client_id': client_id, 'request_id': request_id}
            return update_document_request(event, context)
        
        # Rutas adicionales para la vista 360° del cliente
        elif http_method == 'GET' and path.endswith('/completeness'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_client_document_completeness(event, context)
        elif http_method == 'GET' and path.endswith('/risk'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_client_document_risk(event, context)
        elif http_method == 'GET' and path.endswith('/activity'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_client_activity(event, context)
        elif http_method == 'GET' and path.endswith('/documents/status'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_client_document_status(event, context)
        elif http_method == 'GET' and path.endswith('/documents/pending'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_pending_documents(event, context)
        elif http_method == 'GET' and path.endswith('/documents/expiring'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return get_expiring_documents(event, context)
        elif http_method == 'GET' and path.endswith('/documents/requests'):
            client_id = path.split('/')[2]
            event['pathParameters'] = {'id': client_id}
            return track_document_request(event, context) # dame codigo de esto
                 
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

def call_generar_solicitudes(cliente_id):
    """Llama al procedimiento que genera solicitudes documentales para un cliente"""
    query = "CALL generar_solicitudes_documentos_cliente(%s)"
    return execute_query(query, (cliente_id,), fetch=False)
        
def call_crear_estructura_carpetas(cliente_id):
    """Llama al procedimiento que crea la estructura de carpetas para un cliente"""
    query = "CALL crear_estructura_carpetas_cliente(%s)"
    return execute_query(query, (cliente_id,), fetch=False)
 
def list_clients(event, context):
    """Lista clientes con paginación y filtros"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filtros
        search = query_params.get('search')
        tipo_cliente = query_params.get('tipo_cliente')
        segmento = query_params.get('segmento')
        segmento_bancario = query_params.get('segmento_bancario')
        estado = query_params.get('estado')
        nivel_riesgo = query_params.get('nivel_riesgo')
        estado_documental = query_params.get('estado_documental')
        gestor_id = query_params.get('gestor_id')
        
        # Construir consulta base
        query = """
        SELECT c.id_cliente, c.codigo_cliente, c.tipo_cliente, c.nombre_razon_social,
               c.documento_identificacion, c.fecha_alta, c.estado, c.segmento,
               c.segmento_bancario, c.nivel_riesgo, c.estado_documental,
               c.fecha_ultima_revision_kyc, c.proxima_revision_kyc,
               c.fecha_ultima_actividad, c.gestor_principal_id, 
               u.nombre_usuario as gestor_principal_nombre,
               c.gestor_kyc_id, u2.nombre_usuario as gestor_kyc_nombre
        FROM clientes c
        LEFT JOIN usuarios u ON c.gestor_principal_id = u.id_usuario
        LEFT JOIN usuarios u2 ON c.gestor_kyc_id = u2.id_usuario
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM clientes c
        """
        
        # Construir cláusulas WHERE
        where_clauses = []
        params = []
        
        # Añadir filtros si existen
        if search:
            where_clauses.append("(c.nombre_razon_social LIKE %s OR c.documento_identificacion LIKE %s OR c.codigo_cliente LIKE %s)")
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        
        if tipo_cliente:
            where_clauses.append("c.tipo_cliente = %s")
            params.append(tipo_cliente)
        
        if segmento:
            where_clauses.append("c.segmento = %s")
            params.append(segmento)
        
        if segmento_bancario:
            where_clauses.append("c.segmento_bancario = %s")
            params.append(segmento_bancario)
        
        if estado:
            where_clauses.append("c.estado = %s")
            params.append(estado)
        
        if nivel_riesgo:
            where_clauses.append("c.nivel_riesgo = %s")
            params.append(nivel_riesgo)
        
        if estado_documental:
            where_clauses.append("c.estado_documental = %s")
            params.append(estado_documental)
        
        if gestor_id:
            where_clauses.append("(c.gestor_principal_id = %s OR c.gestor_kyc_id = %s)")
            params.extend([gestor_id, gestor_id])
        
        # Verificar permisos de usuario - si no es administrador, mostrar solo los clientes asignados
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso = 'admin.clientes'
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin:
            where_clauses.append("(c.gestor_principal_id = %s OR c.gestor_kyc_id = %s)")
            params.extend([user_id, user_id])
        
        # Añadir cláusula WHERE a las consultas
        if where_clauses:
            where_str = " WHERE " + " AND ".join(where_clauses)
            query += where_str
            count_query += where_str
        
        # Añadir ordenamiento y paginación
        query += " ORDER BY c.fecha_alta DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        clients = execute_query(query, params)
        count_result = execute_query(count_query, params[:-2] if params else [])
        
        total_clients = count_result[0]['total'] if count_result else 0
        total_pages = (total_clients + page_size - 1) // page_size if total_clients > 0 else 1
        
        # Procesar resultados
        for client in clients:
            # Convertir datetime a string
            for date_field in ['fecha_alta', 'fecha_ultima_revision_kyc', 'proxima_revision_kyc', 'fecha_ultima_actividad']:
                if date_field in client and client[date_field]:
                    client[date_field] = client[date_field].isoformat()
            
            # Deserializar campos JSON
            fields_to_deserialize = ['datos_contacto', 'preferencias_comunicacion', 'metadata_personalizada', 'documentos_pendientes']
            for client_data in execute_query("SELECT datos_contacto, preferencias_comunicacion, metadata_personalizada, documentos_pendientes FROM clientes WHERE id_cliente = %s", (client['id_cliente'],)):
                for field in fields_to_deserialize:
                    if field in client_data and client_data[field]:
                        try:
                            client[field] = json.loads(client_data[field])
                        except:
                            client[field] = {}
        
        # Crear respuesta con metadata de paginación
        response = {
            'clientes': clients,
            'pagination': {
                'total': total_clients,
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
        logger.error(f"Error al listar clientes: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al listar clientes: {str(e)}'})
        }

def get_client(event, context):
    """Obtiene información detallada de un cliente específico"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        client_query = """
        SELECT c.id_cliente, c.codigo_cliente, c.tipo_cliente, c.nombre_razon_social,
               c.documento_identificacion, c.fecha_alta, c.estado, c.segmento,
               c.gestor_principal_id, u.nombre_usuario as gestor_principal_nombre,
               c.datos_contacto, c.preferencias_comunicacion, c.metadata_personalizada,
               c.segmento_bancario, c.nivel_riesgo, c.fecha_ultima_revision_kyc,
               c.proxima_revision_kyc, c.estado_documental, c.documentos_pendientes,
               c.gestor_kyc_id, u2.nombre_usuario as gestor_kyc_nombre,
               c.fecha_ultima_actividad, c.anotaciones_especiales, c.clasificacion_fatca
        FROM clientes c
        LEFT JOIN usuarios u ON c.gestor_principal_id = u.id_usuario
        LEFT JOIN usuarios u2 ON c.gestor_kyc_id = u2.id_usuario
        WHERE c.id_cliente = %s
        """
        
        client_result = execute_query(client_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso = 'admin.clientes'
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para ver este cliente'})
            }
        
        # Convertir datetime a string
        for date_field in ['fecha_alta', 'fecha_ultima_revision_kyc', 'proxima_revision_kyc', 'fecha_ultima_actividad']:
            if date_field in client and client[date_field]:
                client[date_field] = client[date_field].isoformat()
        
        # Deserializar campos JSON
        for field in ['datos_contacto', 'preferencias_comunicacion', 'metadata_personalizada', 'documentos_pendientes']:
            if field in client and client[field]:
                try:
                    client[field] = json.loads(client[field])
                except:
                    client[field] = {}
        
        # Obtener conteo de documentos del cliente
        docs_query = """
        SELECT COUNT(*) as document_count
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
        """
        
        docs_result = execute_query(docs_query, (client_id,))
        document_count = docs_result[0]['document_count'] if docs_result else 0
        
        # Obtener conteo de solicitudes pendientes
        requests_query = """
        SELECT 
            COUNT(*) as total_requests,
            SUM(CASE WHEN estado = 'pendiente' THEN 1 ELSE 0 END) as pending_requests,
            SUM(CASE WHEN estado = 'recordatorio_enviado' THEN 1 ELSE 0 END) as reminder_sent,
            SUM(CASE WHEN estado = 'recibido' THEN 1 ELSE 0 END) as received_requests,
            SUM(CASE WHEN fecha_limite < CURDATE() AND estado IN ('pendiente', 'recordatorio_enviado') THEN 1 ELSE 0 END) as overdue_requests
        FROM documentos_solicitados
        WHERE id_cliente = %s
        """
        
        requests_result = execute_query(requests_query, (client_id,))
        requests_stats = requests_result[0] if requests_result else {}
        
        # Obtener documentos próximos a vencer
        expiring_docs_query = """
        SELECT td.nombre_tipo, cb.validez_en_dias, d.fecha_modificacion,
               DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) as fecha_vencimiento,
               DATEDIFF(DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY), CURDATE()) as dias_restantes
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE dc.id_cliente = %s 
          AND d.estado = 'publicado' 
          AND cb.validez_en_dias IS NOT NULL
          AND DATEDIFF(DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY), CURDATE()) BETWEEN 0 AND 30
        ORDER BY dias_restantes
        LIMIT 5
        """
        
        expiring_docs = execute_query(expiring_docs_query, (client_id,))
        
        # Formatear las fechas en los documentos por vencer
        for doc in expiring_docs:
            if 'fecha_modificacion' in doc and doc['fecha_modificacion']:
                doc['fecha_modificacion'] = doc['fecha_modificacion'].isoformat()
            if 'fecha_vencimiento' in doc and doc['fecha_vencimiento']:
                doc['fecha_vencimiento'] = doc['fecha_vencimiento'].isoformat()
        
        # Obtener actividad reciente
        activity_query = """
        SELECT fecha_hora, accion, entidad_afectada, detalles, resultado
        FROM registros_auditoria
        WHERE (
            (entidad_afectada = 'cliente' AND id_entidad_afectada = %s) OR
            (entidad_afectada = 'documento' AND detalles LIKE %s)
        )
        ORDER BY fecha_hora DESC
        LIMIT 10
        """
        
        activity = execute_query(activity_query, (client_id, f'%"id_cliente":"{client_id}"%'))
        
        # Formatear fechas y deserializar detalles
        for entry in activity:
            if 'fecha_hora' in entry and entry['fecha_hora']:
                entry['fecha_hora'] = entry['fecha_hora'].isoformat()
            if 'detalles' in entry and entry['detalles']:
                try:
                    entry['detalles'] = json.loads(entry['detalles'])
                except:
                    pass
        
        # Obtener información de la cache de vista
        cache_query = """
        SELECT ultima_actualizacion, resumen_actividad, kpis_cliente
        FROM vista_cliente_cache
        WHERE id_cliente = %s
        """
        
        cache_result = execute_query(cache_query, (client_id,))
        cache_data = {}
        
        if cache_result:
            cache_entry = cache_result[0]
            
            if 'ultima_actualizacion' in cache_entry and cache_entry['ultima_actualizacion']:
                cache_data['ultima_actualizacion'] = cache_entry['ultima_actualizacion'].isoformat()
            
            for field in ['resumen_actividad', 'kpis_cliente']:
                if field in cache_entry and cache_entry[field]:
                    try:
                        cache_data[field] = json.loads(cache_entry[field])
                    except:
                        cache_data[field] = {}
        
        # Construir respuesta
        response = {
            'cliente': client,
            'estadisticas': {
                'documentos_count': document_count,
                'solicitudes': requests_stats,
                'documentos_por_vencer': expiring_docs
            },
            'actividad_reciente': activity,
            'vista_cache': cache_data
        }
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'cliente',
            'id_entidad_afectada': client_id,
            'detalles': json.dumps({'nombre_cliente': client['nombre_razon_social']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener cliente: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener cliente: {str(e)}'})
        }

def create_client(event, context):
    """Crea un nuevo cliente en el sistema"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.crear')
        if error_response:
            return error_response
        
        # Verificar que user_id existe en la base de datos
        if user_id:
            check_user_query = """
            SELECT id_usuario 
            FROM usuarios 
            WHERE id_usuario = %s
            """
            user_exists = execute_query(check_user_query, (user_id,))
            
            if not user_exists:
                # Si el usuario de la sesión no existe, buscar un usuario admin por defecto
                admin_query = """
                SELECT id_usuario 
                FROM usuarios 
                WHERE estado = 'activo' 
                LIMIT 1
                """
                admin_result = execute_query(admin_query)
                if admin_result:
                    user_id = admin_result[0]['id_usuario']
                else:
                    return {
                        'statusCode': 500,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'No se pudo asignar un gestor válido'})
                    }
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        required_fields = ['tipo_cliente', 'nombre_razon_social', 'datos_contacto']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Falta el campo requerido: {field}'})
                }
        
        # Extraer campos
        tipo_cliente = body['tipo_cliente']
        nombre_razon_social = body['nombre_razon_social']
        documento_identificacion = body.get('documento_identificacion', '') 
        datos_contacto = body['datos_contacto']
        
        # Validar tipo de cliente
        valid_types = ['persona_fisica', 'empresa', 'organismo_publico']
        if tipo_cliente not in valid_types:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Tipo de cliente inválido. Debe ser uno de: {", ".join(valid_types)}'})
            }
        
        # Validar datos de contacto
        if not isinstance(datos_contacto, dict) or 'email' not in datos_contacto or 'telefono' not in datos_contacto:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Los datos de contacto deben incluir email y teléfono'})
            }

        # Solo verificar duplicados si el documento de identificación no está vacío
        if documento_identificacion and documento_identificacion.strip():
            # Verificar si ya existe un cliente con el mismo documento de identificación
            check_query = """
            SELECT id_cliente, codigo_cliente
            FROM clientes
            WHERE documento_identificacion = %s
            """
            
            existing_client = execute_query(check_query, (documento_identificacion,))
            if existing_client:
                return {
                    'statusCode': 409,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({
                        'error': 'Ya existe un cliente con este documento de identificación',
                        'id_cliente': existing_client[0]['id_cliente'],
                        'codigo_cliente': existing_client[0]['codigo_cliente']
                    })
                }
        
        # Generar ID de cliente
        client_id = generate_uuid()
        
        # Generar código de cliente
        # Formato: TIPO-YYYYMMDD-XXXX (TIPO: PF/EM/OP, fecha actual, secuencia)
        now = datetime.datetime.now()
        date_part = now.strftime("%Y%m%d")
        
        tipo_prefix = {
            'persona_fisica': 'PF',
            'empresa': 'EM',
            'organismo_publico': 'OP'
        }[tipo_cliente]
        
        # Obtener secuencia para el código
        seq_query = """
        SELECT COUNT(*) as seq
        FROM clientes
        WHERE tipo_cliente = %s AND DATE(fecha_alta) = CURDATE()
        """
        
        seq_result = execute_query(seq_query, (tipo_cliente,))
        sequence = (seq_result[0]['seq'] + 1) if seq_result else 1
        
        # Formato final del código
        codigo_cliente = f"{tipo_prefix}-{date_part}-{sequence:04d}"
        
        # Determinar valores predeterminados
        estado = body.get('estado', 'activo')
        segmento = body.get('segmento')
        if segmento == '':
            segmento = None
            
        segmento_bancario = body.get('segmento_bancario')
        if segmento_bancario == '':
            segmento_bancario = None
            
        nivel_riesgo = body.get('nivel_riesgo', 'bajo')
        
        preferencias_comunicacion = body.get('preferencias_comunicacion', {})
        metadata_personalizada = body.get('metadata_personalizada', {})
        
        # Determinar gestor principal (si no se especifica o es vacío, será el usuario actual)
        gestor_principal_id = body.get('gestor_principal_id')
        if gestor_principal_id is None or gestor_principal_id == '':
            gestor_principal_id = user_id
            
        # Determinar gestor KYC (si es vacío, será NULL)
        gestor_kyc_id = body.get('gestor_kyc_id')
        if gestor_kyc_id == '':
            gestor_kyc_id = None
        
        # Verificar que gestor_principal_id existe
        if gestor_principal_id:
            gestor_query = """
            SELECT id_usuario 
            FROM usuarios 
            WHERE id_usuario = %s
            """
            gestor_exists = execute_query(gestor_query, (gestor_principal_id,))
            if not gestor_exists:
                gestor_principal_id = user_id  # Usar el usuario de la sesión como fallback
        
        # Verificar que gestor_kyc_id existe si no es None
        if gestor_kyc_id:
            gestor_kyc_query = """
            SELECT id_usuario 
            FROM usuarios 
            WHERE id_usuario = %s
            """
            gestor_kyc_exists = execute_query(gestor_kyc_query, (gestor_kyc_id,))
            if not gestor_kyc_exists:
                gestor_kyc_id = None  # Establecer a NULL si no existe
        
        estado_documental = body.get('estado_documental', 'incompleto')
        documentos_pendientes = body.get('documentos_pendientes', [])
        
        fecha_ultima_revision_kyc = body.get('fecha_ultima_revision_kyc')
        proxima_revision_kyc = body.get('proxima_revision_kyc')
        
        # Si no se especifican fechas KYC, establecer valores predeterminados
        if not fecha_ultima_revision_kyc:
            fecha_ultima_revision_kyc = now.date()
        
        if not proxima_revision_kyc:
            # Por defecto, próxima revisión en 1 año
            proxima_revision_kyc = (now + datetime.timedelta(days=365)).date()
        
        # Validar estados
        valid_estados = ['activo', 'inactivo', 'prospecto']
        if estado not in valid_estados:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Estado inválido. Debe ser uno de: {", ".join(valid_estados)}'})
            }
        
        valid_segmentos_bancarios = ['retail', 'premium', 'privada', 'empresas', 'corporativa', 'institucional', None]
        if segmento_bancario not in valid_segmentos_bancarios:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Segmento bancario inválido. Debe ser uno de: {", ".join([s for s in valid_segmentos_bancarios if s])}'})
            }
        
        valid_niveles_riesgo = ['bajo', 'medio', 'alto', 'muy_alto']
        if nivel_riesgo not in valid_niveles_riesgo:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Nivel de riesgo inválido. Debe ser uno de: {", ".join(valid_niveles_riesgo)}'})
            }
        
        valid_estados_documentales = ['completo', 'incompleto', 'pendiente_actualizacion', 'en_revision']
        if estado_documental not in valid_estados_documentales:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Estado documental inválido. Debe ser uno de: {", ".join(valid_estados_documentales)}'})
            }
        
        # Insertar cliente
        insert_query = """
        INSERT INTO clientes (
            id_cliente, codigo_cliente, tipo_cliente, nombre_razon_social,
            documento_identificacion, fecha_alta, estado, segmento,
            gestor_principal_id, datos_contacto, preferencias_comunicacion,
            metadata_personalizada, segmento_bancario, nivel_riesgo,
            fecha_ultima_revision_kyc, proxima_revision_kyc, estado_documental,
            documentos_pendientes, gestor_kyc_id
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        """
        
        # Llamar a los procedimientos para generar solicitudes y crear estructura de carpetas
        call_generar_solicitudes(client_id)
        call_crear_estructura_carpetas(client_id)

        # Para depuración, imprimir los valores antes de insertar
        logger.info(f"Insertando cliente con gestor_principal_id: {gestor_principal_id}, gestor_kyc_id: {gestor_kyc_id}")
        
        insert_params = (
            client_id, codigo_cliente, tipo_cliente, nombre_razon_social,
            documento_identificacion, now, estado, segmento,
            gestor_principal_id, json.dumps(datos_contacto), json.dumps(preferencias_comunicacion),
            json.dumps(metadata_personalizada), segmento_bancario, nivel_riesgo,
            fecha_ultima_revision_kyc, proxima_revision_kyc, estado_documental,
            json.dumps(documentos_pendientes), gestor_kyc_id
        )
        
        execute_query(insert_query, insert_params, fetch=False)
        
        # Crear entrada inicial en la caché de vista
        cache_entry = {
            'resumen_actividad': {
                'ultima_actividad': 'Cliente creado',
                'fecha': now.isoformat(),
                'usuario': user_id
            },
            'kpis_cliente': {
                'documentos_completos': 0,
                'documentos_pendientes': len(documentos_pendientes) if isinstance(documentos_pendientes, list) else 0,
                'dias_hasta_proxima_revision': (proxima_revision_kyc - now.date()).days if proxima_revision_kyc else 365
            }
        }
        
        cache_query = """
        INSERT INTO vista_cliente_cache (
            id_cliente, ultima_actualizacion, resumen_actividad, kpis_cliente
        ) VALUES (%s, %s, %s, %s)
        """
        
        execute_query(cache_query, (
            client_id, now, json.dumps(cache_entry['resumen_actividad']), 
            json.dumps(cache_entry['kpis_cliente'])
        ), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'crear',
            'entidad_afectada': 'cliente',
            'id_entidad_afectada': client_id,
            'detalles': json.dumps({
                'codigo_cliente': codigo_cliente,
                'nombre_razon_social': nombre_razon_social,
                'tipo_cliente': tipo_cliente,
                'documento_identificacion': documento_identificacion
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Cliente creado exitosamente',
                'id_cliente': client_id,
                'codigo_cliente': codigo_cliente
            })
        }
        
    except Exception as e:
        logger.error(f"Error al crear cliente: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al crear cliente: {str(e)}'})
        }

def update_client(event, context):
    """Actualiza un cliente existente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.editar')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, tipo_cliente, nombre_razon_social,
               documento_identificacion, estado, segmento_bancario, nivel_riesgo,
               estado_documental, gestor_principal_id, gestor_kyc_id
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso = 'admin.clientes'
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para editar este cliente'})
            }
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Construir consulta de actualización
        update_fields = []
        update_params = []
        
        # Campos que se pueden actualizar
        updatable_fields = [
            'nombre_razon_social', 'estado', 'segmento', 'gestor_principal_id',
            'datos_contacto', 'preferencias_comunicacion', 'metadata_personalizada',
            'segmento_bancario', 'nivel_riesgo', 'fecha_ultima_revision_kyc',
            'proxima_revision_kyc', 'estado_documental', 'documentos_pendientes',
            'gestor_kyc_id', 'anotaciones_especiales', 'clasificacion_fatca'
        ]
        
        # Campos que necesitan ser validados contra listas de valores válidos
        validation_rules = {
            'estado': ['activo', 'inactivo', 'prospecto'],
            'segmento_bancario': ['retail', 'premium', 'privada', 'empresas', 'corporativa', 'institucional'],
            'nivel_riesgo': ['bajo', 'medio', 'alto', 'muy_alto'],
            'estado_documental': ['completo', 'incompleto', 'pendiente_actualizacion', 'en_revision']
        }
        
        # Validar y añadir campos para actualización
        for field in updatable_fields:
            if field in body:
                value = body[field]
                
                # Validar contra reglas si es necesario
                if field in validation_rules and value is not None:
                    valid_values = validation_rules[field]
                    if value not in valid_values:
                        return {
                            'statusCode': 400,
                            'headers': add_cors_headers({'Content-Type': 'application/json'}),
                            'body': json.dumps({'error': f'Valor inválido para {field}. Debe ser uno de: {", ".join(valid_values)}'})
                        }
                
                # Convertir a JSON si es un campo de objeto/lista
                if field in ['datos_contacto', 'preferencias_comunicacion', 'metadata_personalizada', 'documentos_pendientes']:
                    value = json.dumps(value)
                
                update_fields.append(f"{field} = %s")
                update_params.append(value)
        
        # Si se intenta actualizar el documento de identificación, verificar que no exista otro cliente con ese documento
        if 'documento_identificacion' in body and body['documento_identificacion'] != client['documento_identificacion']:
            check_doc_query = """
            SELECT id_cliente
            FROM clientes
            WHERE documento_identificacion = %s AND id_cliente != %s
            """
            
            existing_with_doc = execute_query(check_doc_query, (body['documento_identificacion'], client_id))
            if existing_with_doc:
                return {
                    'statusCode': 409,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Ya existe otro cliente con este documento de identificación'})
                }
            
            # Añadir campo a la actualización
            update_fields.append("documento_identificacion = %s")
            update_params.append(body['documento_identificacion'])
        
        # Si no hay campos para actualizar
        if not update_fields:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se proporcionaron campos para actualizar'})
            }
        
        # Añadir campo de fecha de última actividad
        update_fields.append("fecha_ultima_actividad = %s")
        now = datetime.datetime.now()
        update_params.append(now.date())
        
        # Construir y ejecutar consulta de actualización
        update_query = f"""
        UPDATE clientes
        SET {', '.join(update_fields)}
        WHERE id_cliente = %s
        """
        
        update_params.append(client_id)
        execute_query(update_query, update_params, fetch=False)
        
        # Actualizar caché de vista
        # Primero verificamos si existe una entrada
        cache_check_query = """
        SELECT COUNT(*) as exists_cache
        FROM vista_cliente_cache
        WHERE id_cliente = %s
        """
        
        cache_exists = execute_query(cache_check_query, (client_id,))
        cache_exists = cache_exists[0]['exists_cache'] > 0 if cache_exists else False
        
        cache_entry = {
            'resumen_actividad': {
                'ultima_actividad': 'Cliente actualizado',
                'fecha': now.isoformat(),
                'usuario': user_id,
                'campos_actualizados': [field.split(' = ')[0] for field in update_fields]
            }
        }
        
        # Actualizar KPIs si cambiaron ciertos campos
        if 'estado_documental' in body or 'documentos_pendientes' in body or 'proxima_revision_kyc' in body:
            # Obtenemos los datos actualizados del cliente
            updated_client_query = """
            SELECT estado_documental, documentos_pendientes, proxima_revision_kyc
            FROM clientes
            WHERE id_cliente = %s
            """
            
            updated_client = execute_query(updated_client_query, (client_id,))[0]
            
            docs_pendientes = 0
            if updated_client['documentos_pendientes']:
                try:
                    docs_pendientes_data = json.loads(updated_client['documentos_pendientes'])
                    docs_pendientes = len(docs_pendientes_data) if isinstance(docs_pendientes_data, list) else 0
                except:
                    pass
            
            dias_proxima_revision = 0
            if updated_client['proxima_revision_kyc']:
                dias_proxima_revision = (updated_client['proxima_revision_kyc'] - now.date()).days
            
            cache_entry['kpis_cliente'] = {
                'documentos_completos': 1 if updated_client['estado_documental'] == 'completo' else 0,
                'documentos_pendientes': docs_pendientes,
                'dias_hasta_proxima_revision': dias_proxima_revision
            }
        
        # Insertar o actualizar cache
        if cache_exists:
            cache_update_fields = []
            cache_update_params = []
            
            cache_update_fields.append("ultima_actualizacion = %s")
            cache_update_params.append(now)
            
            cache_update_fields.append("resumen_actividad = %s")
            cache_update_params.append(json.dumps(cache_entry['resumen_actividad']))
            
            if 'kpis_cliente' in cache_entry:
                cache_update_fields.append("kpis_cliente = %s")
                cache_update_params.append(json.dumps(cache_entry['kpis_cliente']))
            
            cache_update_query = f"""
            UPDATE vista_cliente_cache
            SET {', '.join(cache_update_fields)}
            WHERE id_cliente = %s
            """
            
            cache_update_params.append(client_id)
            execute_query(cache_update_query, cache_update_params, fetch=False)
        else:
            # Si no existe, crear nueva entrada
            cache_insert_query = """
            INSERT INTO vista_cliente_cache (
                id_cliente, ultima_actualizacion, resumen_actividad, kpis_cliente
            ) VALUES (%s, %s, %s, %s)
            """
            
            kpis = cache_entry.get('kpis_cliente', {})
            execute_query(cache_insert_query, (
                client_id, now, json.dumps(cache_entry['resumen_actividad']), json.dumps(kpis)
            ), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'actualizar',
            'entidad_afectada': 'cliente',
            'id_entidad_afectada': client_id,
            'detalles': json.dumps({
                'codigo_cliente': client['codigo_cliente'],
                'nombre_razon_social': client['nombre_razon_social'],
                'campos_actualizados': [field.split(' = ')[0] for field in update_fields]
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Cliente actualizado exitosamente',
                'id_cliente': client_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error al actualizar cliente: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al actualizar cliente: {str(e)}'})
        }

def delete_client(event, context):
    """Elimina un cliente (marcándolo como inactivo)"""
    try:
        # Validar sesión - requiere permiso especial
        user_id, error_response = validate_session(event, 'admin.clientes')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar si ya está inactivo
        if client['estado'] == 'inactivo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'El cliente ya está inactivo'})
            }
        
        # Marcar cliente como inactivo
        update_query = """
        UPDATE clientes
        SET estado = 'inactivo'
        WHERE id_cliente = %s
        """
        
        execute_query(update_query, (client_id,), fetch=False)
        
        # Registrar en auditoría
        now = datetime.datetime.now()
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'eliminar',
            'entidad_afectada': 'cliente',
            'id_entidad_afectada': client_id,
            'detalles': json.dumps({
                'codigo_cliente': client['codigo_cliente'],
                'nombre_razon_social': client['nombre_razon_social'],
                'estado_anterior': client['estado']
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        # Actualizar caché de vista
        cache_update_query = """
        UPDATE vista_cliente_cache
        SET ultima_actualizacion = %s,
            resumen_actividad = %s
        WHERE id_cliente = %s
        """
        
        resumen = {
            'ultima_actividad': 'Cliente marcado como inactivo',
            'fecha': now.isoformat(),
            'usuario': user_id
        }
        
        execute_query(cache_update_query, (now, json.dumps(resumen), client_id), fetch=False)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Cliente marcado como inactivo exitosamente',
                'id_cliente': client_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error al eliminar cliente: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al eliminar cliente: {str(e)}'})
        }

def get_client_documents(event, context):
    """Obtiene los documentos asociados a un cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado,
               gestor_principal_id, gestor_kyc_id
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso IN ('admin.clientes', 'admin.documentos')
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para ver los documentos de este cliente'})
            }
        
        # Obtener parámetros de consulta para paginación y filtros
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filtros
        title_search = query_params.get('title')
        tipo_documento_id = query_params.get('tipo_documento')
        categoria_id = query_params.get('categoria')
        estado = query_params.get('estado')
        
        # Consulta base para documentos del cliente - MODIFICADA PARA REMOVER TABLA FALTANTE
        query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.fecha_creacion, d.fecha_modificacion,
               d.id_carpeta, c.nombre_carpeta, d.estado, d.tags,
               u_creador.nombre_usuario as creado_por_usuario,
               u_modificador.nombre_usuario as modificado_por_usuario,
               dc.fecha_asignacion, dc.asignado_por,
               u_asignador.nombre_usuario as asignado_por_usuario
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        JOIN usuarios u_asignador ON dc.asignado_por = u_asignador.id_usuario
        WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
        """
        
        count_query = """
        SELECT COUNT(DISTINCT d.id_documento) as total
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
        """
        
        params = [client_id]
        count_params = [client_id]
        
        # Añadir filtros si se proporcionan
        if title_search:
            query += " AND (d.titulo LIKE %s OR d.descripcion LIKE %s)"
            count_query += " AND (d.titulo LIKE %s OR d.descripcion LIKE %s)"
            search_param = f"%{title_search}%"
            params.extend([search_param, search_param])
            count_params.extend([search_param, search_param])
        
        if tipo_documento_id:
            query += " AND d.id_tipo_documento = %s"
            count_query += " AND d.id_tipo_documento = %s"
            params.append(tipo_documento_id)
            count_params.append(tipo_documento_id)
        
        # Eliminamos filtro de categoría ya que no tenemos la tabla
        # Ya no filtramos por categoria_id
        
        if estado:
            query += " AND d.estado = %s"
            count_query += " AND d.estado = %s"
            params.append(estado)
            count_params.append(estado)
        
        # Añadir ordenamiento y paginación
        query += " ORDER BY d.fecha_modificacion DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        documents = execute_query(query, params)
        count_result = execute_query(count_query, count_params)
        
        total_documents = count_result[0]['total'] if count_result else 0
        total_pages = (total_documents + page_size - 1) // page_size if total_documents > 0 else 1
        
        # Procesar resultados
        for doc in documents:
            # Convertir datetime a string
            for date_field in ['fecha_creacion', 'fecha_modificacion', 'fecha_asignacion']:
                if date_field in doc and doc[date_field]:
                    doc[date_field] = doc[date_field].isoformat()
            
            # Deserializar tags (JSON)
            if 'tags' in doc and doc['tags']:
                try:
                    doc['tags'] = json.loads(doc['tags'])
                except:
                    doc['tags'] = []
        
        # Obtener tipos de documento disponibles para filtrado
        types_query = """
        SELECT DISTINCT td.id_tipo_documento, td.nombre_tipo, td.descripcion
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
        ORDER BY td.nombre_tipo
        """
        
        document_types = execute_query(types_query, (client_id,))
        
        # Crear respuesta (sin incluir categorías)
        response = {
            'cliente': {
                'id': client['id_cliente'],
                'codigo': client['codigo_cliente'],
                'nombre': client['nombre_razon_social']
            },
            'documentos': documents,
            'tipos_documento_disponibles': document_types,
            'pagination': {
                'total': total_documents,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            }
        }
        
        # Registrar en auditoría (opcional, podría generar muchas entradas)
        if page == 1:  # Solo registrar la primera página para no llenar la auditoría
            audit_data = {
                'fecha_hora': datetime.datetime.now(),
                'usuario_id': user_id,
                'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
                'accion': 'listar',
                'entidad_afectada': 'documentos_cliente',
                'id_entidad_afectada': client_id,
                'detalles': json.dumps({'nombre_cliente': client['nombre_razon_social']}),
                'resultado': 'éxito'
            }
            
            insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener documentos del cliente: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener documentos del cliente: {str(e)}'})
        }

def get_client_requests(event, context):
    """Obtiene las solicitudes de documentos para un cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado,
               gestor_principal_id, gestor_kyc_id
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso IN ('admin.clientes', 'admin.documentos')
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para ver las solicitudes de este cliente'})
            }
        
        # Obtener parámetros de consulta para paginación y filtros
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filtros
        estado = query_params.get('estado')
        tipo_documento_id = query_params.get('tipo_documento')
        vencidas = query_params.get('vencidas', 'false').lower() == 'true'
        
        # Consulta base para solicitudes
        query = """
        SELECT ds.id_solicitud, ds.id_cliente, ds.id_tipo_documento, ds.fecha_solicitud,
               ds.solicitado_por, u_solicitante.nombre_usuario as solicitado_por_nombre,
               ds.fecha_limite, ds.estado, ds.id_documento_recibido, ds.notas,
               td.nombre_tipo as tipo_documento_nombre, td.descripcion as tipo_documento_descripcion,
               d.codigo_documento, d.titulo as documento_titulo
        FROM documentos_solicitados ds
        JOIN tipos_documento td ON ds.id_tipo_documento = td.id_tipo_documento
        JOIN usuarios u_solicitante ON ds.solicitado_por = u_solicitante.id_usuario
        LEFT JOIN documentos d ON ds.id_documento_recibido = d.id_documento
        WHERE ds.id_cliente = %s
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM documentos_solicitados ds
        WHERE ds.id_cliente = %s
        """
        
        params = [client_id]
        count_params = [client_id]
        
        # Añadir filtros si se proporcionan
        if estado:
            query += " AND ds.estado = %s"
            count_query += " AND ds.estado = %s"
            params.append(estado)
            count_params.append(estado)
        
        if tipo_documento_id:
            query += " AND ds.id_tipo_documento = %s"
            count_query += " AND ds.id_tipo_documento = %s"
            params.append(tipo_documento_id)
            count_params.append(tipo_documento_id)
        
        if vencidas:
            query += " AND ds.fecha_limite < CURDATE() AND ds.estado IN ('pendiente', 'recordatorio_enviado')"
            count_query += " AND ds.fecha_limite < CURDATE() AND ds.estado IN ('pendiente', 'recordatorio_enviado')"
        
        # Añadir ordenamiento y paginación
        query += " ORDER BY ds.fecha_solicitud DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        requests = execute_query(query, params)
        count_result = execute_query(count_query, count_params)
        
        total_requests = count_result[0]['total'] if count_result else 0
        total_pages = (total_requests + page_size - 1) // page_size if total_requests > 0 else 1
        
        # Procesar resultados
        for req in requests:
            # Convertir datetime a string
            for date_field in ['fecha_solicitud', 'fecha_limite']:
                if date_field in req and req[date_field]:
                    req[date_field] = req[date_field].isoformat()
        
        # Obtener tipos de documento disponibles para filtrado
        types_query = """
        SELECT DISTINCT td.id_tipo_documento, td.nombre_tipo, td.descripcion
        FROM documentos_solicitados ds
        JOIN tipos_documento td ON ds.id_tipo_documento = td.id_tipo_documento
        WHERE ds.id_cliente = %s
        ORDER BY td.nombre_tipo
        """
        
        document_types = execute_query(types_query, (client_id,))
        
        # Obtener estadísticas de solicitudes
        stats_query = """
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN estado = 'pendiente' THEN 1 ELSE 0 END) as pendientes,
            SUM(CASE WHEN estado = 'recordatorio_enviado' THEN 1 ELSE 0 END) as recordatorio,
            SUM(CASE WHEN estado = 'recibido' THEN 1 ELSE 0 END) as recibidos,
            SUM(CASE WHEN estado = 'cancelado' THEN 1 ELSE 0 END) as cancelados,
            SUM(CASE WHEN fecha_limite < CURDATE() AND estado IN ('pendiente', 'recordatorio_enviado') THEN 1 ELSE 0 END) as vencidas
        FROM documentos_solicitados
        WHERE id_cliente = %s
        """
        
        stats_result = execute_query(stats_query, (client_id,))
        stats = stats_result[0] if stats_result else {}
        
        # Crear respuesta
        response = {
            'cliente': {
                'id': client['id_cliente'],
                'codigo': client['codigo_cliente'],
                'nombre': client['nombre_razon_social']
            },
            'solicitudes': requests,
            'tipos_documento_disponibles': document_types,
            'estadisticas': stats,
            'pagination': {
                'total': total_requests,
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
        logger.error(f"Error al obtener solicitudes del cliente: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener solicitudes del cliente: {str(e)}'})
        }

def create_document_request(event, context):
    """Crea una nueva solicitud de documento para un cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.solicitar')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado,
               gestor_principal_id, gestor_kyc_id
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar que el cliente esté activo
        if client['estado'] != 'activo':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se pueden solicitar documentos a un cliente inactivo'})
            }
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso IN ('admin.clientes', 'admin.documentos')
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para solicitar documentos a este cliente'})
            }
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        required_fields = ['id_tipo_documento']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Falta el campo requerido: {field}'})
                }
        
        # Extraer campos
        tipo_documento_id = body['id_tipo_documento']
        fecha_limite = body.get('fecha_limite')
        notas = body.get('notas')
        
        # Verificar que el tipo de documento existe
        tipo_query = """
        SELECT id_tipo_documento, nombre_tipo
        FROM tipos_documento
        WHERE id_tipo_documento = %s
        """
        
        tipo_result = execute_query(tipo_query, (tipo_documento_id,))
        
        if not tipo_result:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Tipo de documento no encontrado'})
            }
        
        tipo_documento = tipo_result[0]
        
        # Verificar si ya existe una solicitud activa para este tipo de documento
        check_existing_query = """
        SELECT id_solicitud
        FROM documentos_solicitados
        WHERE id_cliente = %s AND id_tipo_documento = %s AND estado IN ('pendiente', 'recordatorio_enviado')
        """
        
        existing_request = execute_query(check_existing_query, (client_id, tipo_documento_id))
        
        if existing_request:
            return {
                'statusCode': 409,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'error': 'Ya existe una solicitud activa para este tipo de documento',
                    'id_solicitud': existing_request[0]['id_solicitud']
                })
            }
        
        # Generar ID de solicitud
        request_id = generate_uuid()
        
        # Establecer fecha de solicitud
        now = datetime.datetime.now()
        
        # Si no se especifica fecha límite, establecer por defecto a 30 días
        if not fecha_limite:
            fecha_limite = (now + datetime.timedelta(days=30)).date()
        
        # Insertar solicitud
        insert_query = """
        INSERT INTO documentos_solicitados (
            id_solicitud, id_cliente, id_tipo_documento, fecha_solicitud,
            solicitado_por, fecha_limite, estado, notas
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        insert_params = (
            request_id, client_id, tipo_documento_id, now,
            user_id, fecha_limite, 'pendiente', notas
        )
        
        execute_query(insert_query, insert_params, fetch=False)
        
        # Actualizar datos del cliente para reflejar documento pendiente
        update_client_query = """
        SELECT documentos_pendientes
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_pending_docs = execute_query(update_client_query, (client_id,))
        
        try:
            # Obtener lista actual de documentos pendientes
            pendientes = json.loads(client_pending_docs[0]['documentos_pendientes']) if client_pending_docs[0]['documentos_pendientes'] else []
            
            # Verificar si es una lista y añadir el nuevo documento
            if not isinstance(pendientes, list):
                pendientes = []
            
            # Añadir nuevo documento pendiente si no existe ya
            new_pending = {
                'id_tipo_documento': tipo_documento_id,
                'nombre_tipo': tipo_documento['nombre_tipo'],
                'fecha_solicitud': now.isoformat(),
                'fecha_limite': fecha_limite.isoformat() if isinstance(fecha_limite, datetime.date) else fecha_limite,
                'id_solicitud': request_id
            }
            
            # Verificar si ya existe este tipo de documento en pendientes
            exists = False
            for i, doc in enumerate(pendientes):
                if doc.get('id_tipo_documento') == tipo_documento_id:
                    pendientes[i] = new_pending
                    exists = True
                    break
            
            if not exists:
                pendientes.append(new_pending)
            
            # Actualizar cliente
            update_query = """
            UPDATE clientes
            SET documentos_pendientes = %s,
                estado_documental = 'incompleto',
                fecha_ultima_actividad = %s
            WHERE id_cliente = %s
            """
            
            execute_query(update_query, (json.dumps(pendientes), now.date(), client_id), fetch=False)
            
        except Exception as e:
            logger.warning(f"Error al actualizar documentos pendientes del cliente: {str(e)}")
        
        # Actualizar caché de vista
        cache_update_query = """
        UPDATE vista_cliente_cache
        SET ultima_actualizacion = %s,
            resumen_actividad = %s
        WHERE id_cliente = %s
        """
        
        resumen = {
            'ultima_actividad': f'Solicitud de documento: {tipo_documento["nombre_tipo"]}',
            'fecha': now.isoformat(),
            'usuario': user_id
        }
        
        execute_query(cache_update_query, (now, json.dumps(resumen), client_id), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'solicitar',
            'entidad_afectada': 'documento',
            'id_entidad_afectada': request_id,
            'detalles': json.dumps({
                'id_cliente': client_id,
                'nombre_cliente': client['nombre_razon_social'],
                'tipo_documento': tipo_documento['nombre_tipo'],
                'fecha_limite': fecha_limite.isoformat() if isinstance(fecha_limite, datetime.date) else fecha_limite
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 201,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Solicitud de documento creada exitosamente',
                'id_solicitud': request_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error al crear solicitud de documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al crear solicitud de documento: {str(e)}'})
        }

def update_document_request(event, context):
    """Actualiza el estado de una solicitud de documento"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.solicitar')
        if error_response:
            return error_response
        
        # Obtener IDs del cliente y la solicitud
        client_id = event['pathParameters']['client_id']
        request_id = event['pathParameters']['request_id']
        
        # Verificar si el cliente existe
        check_client_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado,
               gestor_principal_id, gestor_kyc_id
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_client_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar si la solicitud existe y pertenece al cliente
        check_request_query = """
        SELECT id_solicitud, id_cliente, id_tipo_documento, estado, 
               fecha_solicitud, fecha_limite, id_documento_recibido
        FROM documentos_solicitados
        WHERE id_solicitud = %s AND id_cliente = %s
        """
        
        request_result = execute_query(check_request_query, (request_id, client_id))
        
        if not request_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Solicitud no encontrada o no pertenece al cliente especificado'})
            }
        
        request = request_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso IN ('admin.clientes', 'admin.documentos')
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para actualizar solicitudes de este cliente'})
            }
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Validar campos requeridos
        required_fields = ['estado']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Falta el campo requerido: {field}'})
                }
        
        # Extraer campos
        nuevo_estado = body['estado']
        id_documento_recibido = body.get('id_documento_recibido')
        notas = body.get('notas')
        
        # Validar estado
        valid_states = ['pendiente', 'recordatorio_enviado', 'recibido', 'cancelado']
        if nuevo_estado not in valid_states:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Estado inválido. Debe ser uno de: {", ".join(valid_states)}'})
            }
        
        # Si se marca como recibido, debe especificarse un documento
        if nuevo_estado == 'recibido' and not id_documento_recibido:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Para marcar como recibido, debe especificar el documento recibido'})
            }
        
        # Si se especifica un documento, verificar que existe
        if id_documento_recibido:
            doc_query = """
            SELECT id_documento, id_tipo_documento
            FROM documentos
            WHERE id_documento = %s AND estado != 'eliminado'
            """
            
            doc_result = execute_query(doc_query, (id_documento_recibido,))
            
            if not doc_result:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Documento no encontrado o eliminado'})
                }
            
            # Verificar que el documento sea del tipo solicitado
            if doc_result[0]['id_tipo_documento'] != request['id_tipo_documento']:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'El documento recibido no coincide con el tipo de documento solicitado'})
                }
            
            # Verificar si el documento ya está asociado al cliente
            check_doc_assoc_query = """
            SELECT id_documento
            FROM documentos_clientes
            WHERE id_documento = %s AND id_cliente = %s
            """
            
            doc_assoc_result = execute_query(check_doc_assoc_query, (id_documento_recibido, client_id))
            
            # Si no está asociado, crear la asociación
            if not doc_assoc_result:
                assoc_query = """
                INSERT INTO documentos_clientes (
                    id_documento, id_cliente, fecha_asignacion, asignado_por
                ) VALUES (%s, %s, %s, %s)
                """
                
                now = datetime.datetime.now()
                execute_query(assoc_query, (id_documento_recibido, client_id, now, user_id), fetch=False)
        
        # Actualizar solicitud
        update_fields = ["estado = %s"]
        update_params = [nuevo_estado]
        
        if id_documento_recibido:
            update_fields.append("id_documento_recibido = %s")
            update_params.append(id_documento_recibido)
        
        if notas is not None:
            update_fields.append("notas = %s")
            update_params.append(notas)
        
        update_query = f"""
        UPDATE documentos_solicitados
        SET {', '.join(update_fields)}
        WHERE id_solicitud = %s
        """
        
        update_params.append(request_id)
        execute_query(update_query, update_params, fetch=False)
        
        # Si se marca como recibido o cancelado, actualizar la lista de documentos pendientes del cliente
        if nuevo_estado in ['recibido', 'cancelado']:
            try:
                # Obtener lista actual de documentos pendientes
                pending_docs_query = """
                SELECT documentos_pendientes, estado_documental
                FROM clientes
                WHERE id_cliente = %s
                """
                
                pending_docs_result = execute_query(pending_docs_query, (client_id,))
                
                if pending_docs_result:
                    # Obtener documento pendientes actuales
                    pendientes = []
                    if pending_docs_result[0]['documentos_pendientes']:
                        try:
                            pendientes = json.loads(pending_docs_result[0]['documentos_pendientes'])
                        except:
                            pendientes = []
                    
                    # Eliminar el documento de la lista de pendientes
                    pendientes = [doc for doc in pendientes if doc.get('id_solicitud') != request_id]
                    
                    # Determinar estado documental (USAR LOS VALORES CORRECTOS DEL ENUM)
                    # 'completo','incompleto','pendiente_actualizacion','en_revision'
                    estado_documental = 'completo' if len(pendientes) == 0 else 'incompleto'
                    
                    # Actualizar cliente - CORREGIDO PARA USAR SÓLO estado_documental Y NO TOCAR estado
                    client_update_query = """
                    UPDATE clientes
                    SET documentos_pendientes = %s,
                        estado_documental = %s,
                        fecha_ultima_actividad = %s
                    WHERE id_cliente = %s
                    """
                    
                    now = datetime.datetime.now()
                    execute_query(client_update_query, (
                        json.dumps(pendientes), 
                        estado_documental,
                        now.date(), 
                        client_id
                    ), fetch=False)
                    
                    # Actualizar caché de vista
                    cache_update_query = """
                    UPDATE vista_cliente_cache
                    SET ultima_actualizacion = %s,
                        resumen_actividad = %s,
                        kpis_cliente = JSON_SET(
                            COALESCE(kpis_cliente, '{}'),
                            '$.documentos_pendientes', %s,
                            '$.documentos_completos', %s
                        )
                    WHERE id_cliente = %s
                    """
                    
                    resumen = {
                        'ultima_actividad': f'Solicitud {nuevo_estado}',
                        'fecha': now.isoformat(),
                        'usuario': user_id
                    }
                    
                    execute_query(
                        cache_update_query, 
                        (
                            now, 
                            json.dumps(resumen), 
                            len(pendientes),
                            1 if estado_documental == 'completo' else 0,
                            client_id
                        ), 
                        fetch=False
                    )
            except Exception as e:
                logger.warning(f"Error al actualizar documentos pendientes del cliente: {str(e)}")
        
        # Registrar en auditoría
        now = datetime.datetime.now()
        audit_data = {
            'fecha_hora': now,
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'actualizar',
            'entidad_afectada': 'solicitud_documento',
            'id_entidad_afectada': request_id,
            'detalles': json.dumps({
                'id_cliente': client_id,
                'nombre_cliente': client['nombre_razon_social'],
                'estado_anterior': request['estado'],
                'estado_nuevo': nuevo_estado,
                'id_documento_recibido': id_documento_recibido
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Solicitud actualizada exitosamente',
                'id_solicitud': request_id,
                'estado': nuevo_estado
            })
        }
        
    except Exception as e:
        logger.error(f"Error al actualizar solicitud de documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al actualizar solicitud de documento: {str(e)}'})
        }



def calculate_document_completeness(client_id):
    """Calcula el nivel de completitud documental del cliente"""
    try:
        # Obtener los tipos de documento requeridos según el perfil del cliente
        required_docs_query = """
        SELECT td.id_tipo_documento, td.nombre_tipo
        FROM tipos_documento td
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE cb.requiere_validacion = 1
        """
        
        required_docs = execute_query(required_docs_query)
        
        # Obtener los documentos que el cliente ya tiene
        existing_docs_query = """
        SELECT d.id_tipo_documento, d.estado
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
        """
        
        existing_docs = execute_query(existing_docs_query, (client_id,))
        
        # Crear un conjunto de los tipos de documento que el cliente ya tiene
        existing_doc_types = {doc['id_tipo_documento'] for doc in existing_docs}
        
        # Contar documentos requeridos y documentos existentes
        total_required = len(required_docs)
        total_existing = sum(1 for doc_type in required_docs if doc_type['id_tipo_documento'] in existing_doc_types)
        
        # Calcular porcentaje de completitud
        completeness_percentage = (total_existing / total_required * 100) if total_required > 0 else 100
        
        # Determinar nivel de completitud
        completeness_level = 'Completo'
        if completeness_percentage < 50:
            completeness_level = 'Crítico'
        elif completeness_percentage < 80:
            completeness_level = 'Incompleto'
        elif completeness_percentage < 100:
            completeness_level = 'Casi completo'
        
        # Identificar documentos faltantes
        missing_docs = [doc for doc in required_docs if doc['id_tipo_documento'] not in existing_doc_types]
        
        return {
            'completeness_percentage': round(completeness_percentage, 2),
            'completeness_level': completeness_level,
            'total_required': total_required,
            'total_existing': total_existing,
            'missing_documents': missing_docs
        }
    except Exception as e:
        logger.error(f"Error calculando completitud documental: {str(e)}")
        raise

def calculate_document_risk(client_id):
    """Calcula el nivel de riesgo documental del cliente"""
    try:
        # Obtener información del cliente
        client_query = """
        SELECT c.nivel_riesgo, c.segmento_bancario, c.fecha_ultima_revision_kyc,
               c.proxima_revision_kyc, c.estado_documental
        FROM clientes c
        WHERE c.id_cliente = %s
        """
        
        client_result = execute_query(client_query, (client_id,))
        if not client_result:
            return None
        
        client = client_result[0]
        
        # Calcular días hasta próxima revisión KYC
        now = datetime.datetime.now().date()
        days_to_kyc_review = (client['proxima_revision_kyc'] - now).days if client['proxima_revision_kyc'] else 365
        
        # Obtener documentos por vencer
        expiring_docs_query = """
        SELECT td.nombre_tipo, cb.validez_en_dias, d.fecha_modificacion,
               DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) as fecha_vencimiento,
               DATEDIFF(DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY), CURDATE()) as dias_restantes
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE dc.id_cliente = %s 
          AND d.estado = 'publicado' 
          AND cb.validez_en_dias IS NOT NULL
        ORDER BY dias_restantes
        """
        
        expiring_docs = execute_query(expiring_docs_query, (client_id,))
        
        # Contar documentos por vencer pronto (menos de 30 días)
        expiring_soon_count = sum(1 for doc in expiring_docs if doc['dias_restantes'] is not None and doc['dias_restantes'] <= 30)
        
        # Contar documentos vencidos
        expired_count = sum(1 for doc in expiring_docs if doc['dias_restantes'] is not None and doc['dias_restantes'] <= 0)
        
        # Calcular nivel de riesgo documental
        risk_level = 'Bajo'
        risk_score = 0
        
        # Factor de riesgo por nivel de riesgo del cliente
        risk_factor_mapping = {
            'bajo': 1,
            'medio': 2,
            'alto': 3,
            'muy_alto': 4
        }
        
        risk_score += risk_factor_mapping.get(client['nivel_riesgo'], 1)
        
        # Factor de riesgo por estado documental
        if client['estado_documental'] == 'incompleto':
            risk_score += 2
        elif client['estado_documental'] == 'pendiente_actualizacion':
            risk_score += 3
        
        # Factor de riesgo por documentos vencidos o por vencer
        risk_score += expired_count * 2 + expiring_soon_count
        
        # Factor de riesgo por cercanía a revisión KYC
        if days_to_kyc_review <= 30:
            risk_score += 2
        elif days_to_kyc_review <= 90:
            risk_score += 1
        
        # Determinar nivel de riesgo según puntuación
        if risk_score >= 8:
            risk_level = 'Alto'
        elif risk_score >= 5:
            risk_level = 'Medio'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'days_to_kyc_review': days_to_kyc_review,
            'expired_documents': expired_count,
            'expiring_soon_documents': expiring_soon_count,
            'client_risk_level': client['nivel_riesgo'],
            'document_status': client['estado_documental']
        }
    except Exception as e:
        logger.error(f"Error calculando riesgo documental: {str(e)}")
        raise

def get_client_activity(event, context):
    """Obtiene la actividad reciente del cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Obtener parámetros de consulta para paginación
        query_params = event.get('queryStringParameters', {}) or {}
        limit = int(query_params.get('limit', 20))
        
        # Obtener actividad de auditoría
        audit_query = """
        SELECT ra.fecha_hora, ra.accion, ra.entidad_afectada, 
               ra.id_entidad_afectada, ra.detalles, ra.resultado,
               u.nombre_usuario as usuario_nombre
        FROM registros_auditoria ra
        JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE (
            (ra.entidad_afectada = 'cliente' AND ra.id_entidad_afectada = %s) OR
            (ra.entidad_afectada = 'documento' AND ra.detalles LIKE %s) OR
            (ra.entidad_afectada = 'solicitud_documento' AND ra.detalles LIKE %s)
        )
        ORDER BY ra.fecha_hora DESC
        LIMIT %s
        """
        
        activities = execute_query(
            audit_query, 
            (
                client_id, 
                f'%"id_cliente":"{client_id}"%', 
                f'%"id_cliente":"{client_id}"%',
                limit
            )
        )
        
        # Procesar resultados
        for activity in activities:
            if 'fecha_hora' in activity and activity['fecha_hora']:
                activity['fecha_hora'] = activity['fecha_hora'].isoformat()
            
            if 'detalles' in activity and activity['detalles']:
                try:
                    activity['detalles'] = json.loads(activity['detalles'])
                except:
                    pass
        
        response = {
            'client_id': client_id,
            'client_name': client['nombre_razon_social'],
            'client_code': client['codigo_cliente'],
            'activities': activities
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener actividad del cliente: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener actividad del cliente: {str(e)}'})
        }

def get_client_kpis(client_id):
    """Obtiene los indicadores clave de desempeño del cliente"""
    try:
        # Obtener información del cliente
        client_query = """
        SELECT c.nivel_riesgo, c.segmento_bancario, c.fecha_ultima_revision_kyc,
               c.proxima_revision_kyc, c.estado_documental, c.fecha_alta,
               c.fecha_ultima_actividad
        FROM clientes c
        WHERE c.id_cliente = %s
        """
        
        client_result = execute_query(client_query, (client_id,))
        if not client_result:
            return None
        
        client = client_result[0]
        
        # Calcular antigüedad del cliente en días
        now = datetime.datetime.now().date()
        client_age_days = (now - client['fecha_alta'].date()).days if client['fecha_alta'] else 0
        
        # Calcular días desde última actividad
        days_since_last_activity = (now - client['fecha_ultima_actividad']).days if client['fecha_ultima_actividad'] else None
        
        # Calcular días hasta próxima revisión KYC
        days_to_kyc_review = (client['proxima_revision_kyc'] - now).days if client['proxima_revision_kyc'] else None
        
        # Obtener conteo de documentos
        docs_query = """
        SELECT COUNT(*) as total_docs,
               SUM(CASE WHEN d.estado = 'publicado' THEN 1 ELSE 0 END) as active_docs,
               SUM(CASE WHEN d.estado = 'borrador' THEN 1 ELSE 0 END) as draft_docs,
               SUM(CASE WHEN d.estado = 'archivado' THEN 1 ELSE 0 END) as archived_docs
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
        """
        
        docs_result = execute_query(docs_query, (client_id,))
        
        # Obtener conteo de solicitudes
        requests_query = """
        SELECT COUNT(*) as total_requests,
               SUM(CASE WHEN estado = 'pendiente' THEN 1 ELSE 0 END) as pending_requests,
               SUM(CASE WHEN estado = 'recordatorio_enviado' THEN 1 ELSE 0 END) as reminder_sent,
               SUM(CASE WHEN estado = 'recibido' THEN 1 ELSE 0 END) as received_requests,
               SUM(CASE WHEN fecha_limite < CURDATE() AND estado IN ('pendiente', 'recordatorio_enviado') THEN 1 ELSE 0 END) as overdue_requests
        FROM documentos_solicitados
        WHERE id_cliente = %s
        """
        
        requests_result = execute_query(requests_query, (client_id,))
        
        # Obtener información de completitud y riesgo
        completeness_info = calculate_document_completeness(client_id)
        risk_info = calculate_document_risk(client_id)
        
        # Construir objeto de KPIs
        kpis = {
            'client_age_days': client_age_days,
            'days_since_last_activity': days_since_last_activity,
            'days_to_kyc_review': days_to_kyc_review,
            'documents': docs_result[0] if docs_result else {},
            'requests': requests_result[0] if requests_result else {},
            'completeness': {
                'percentage': completeness_info['completeness_percentage'],
                'level': completeness_info['completeness_level']
            },
            'risk': {
                'level': risk_info['risk_level'],
                'score': risk_info['risk_score']
            }
        }
        
        return kpis
    except Exception as e:
        logger.error(f"Error obteniendo KPIs del cliente: {str(e)}")
        raise

def get_client_document_status(event, context):
    """Obtiene el estado de los documentos del cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado, estado_documental
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Obtener resumen de estado de documentos por tipo y categoría
        status_query = """
        SELECT td.id_tipo_documento, td.nombre_tipo, cb.nombre_categoria as categoria_bancaria,
               d.estado, COUNT(*) as cantidad,
               MAX(d.fecha_modificacion) as ultima_actualizacion
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        LEFT JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
        GROUP BY td.id_tipo_documento, td.nombre_tipo, cb.nombre_categoria, d.estado
        ORDER BY cb.nombre_categoria, td.nombre_tipo, d.estado
        """
        
        status_results = execute_query(status_query, (client_id,))
        
        # Agrupar por categoría y tipo
        status_by_category = {}
        
        for status in status_results:
            category = status['categoria_bancaria'] or 'Sin categoría'
            doc_type = status['nombre_tipo']
            doc_status = status['estado']
            
            if category not in status_by_category:
                status_by_category[category] = {}
            
            if doc_type not in status_by_category[category]:
                status_by_category[category][doc_type] = {
                    'id_tipo_documento': status['id_tipo_documento'],
                    'estados': {}
                }
            
            status_by_category[category][doc_type]['estados'][doc_status] = {
                'cantidad': status['cantidad'],
                'ultima_actualizacion': status['ultima_actualizacion'].isoformat() if status['ultima_actualizacion'] else None
            }
        
        # Obtener completitud documental
        completeness_info = calculate_document_completeness(client_id)
        
        response = {
            'client_id': client_id,
            'client_name': client['nombre_razon_social'],
            'client_code': client['codigo_cliente'],
            'estado_documental': client['estado_documental'],
            'completeness': {
                'percentage': completeness_info['completeness_percentage'],
                'level': completeness_info['completeness_level'],
                'total_required': completeness_info['total_required'],
                'total_existing': completeness_info['total_existing']
            },
            'status_by_category': status_by_category
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener estado de documentos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener estado de documentos: {str(e)}'})
        }

def get_pending_documents(event, context):
    """Obtiene los documentos pendientes del cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado, documentos_pendientes
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Obtener documentos pendientes almacenados en el campo JSON
        pending_docs = []
        if client['documentos_pendientes']:
            try:
                pending_docs = json.loads(client['documentos_pendientes'])
            except:
                pending_docs = []
        
        # Obtener documentos solicitados
        requests_query = """
        SELECT ds.id_solicitud, ds.id_tipo_documento, ds.fecha_solicitud,
               ds.solicitado_por, u.nombre_usuario as solicitado_por_nombre,
               ds.fecha_limite, ds.estado, ds.notas,
               td.nombre_tipo, td.descripcion,
               DATEDIFF(ds.fecha_limite, CURDATE()) as dias_restantes
        FROM documentos_solicitados ds
        JOIN tipos_documento td ON ds.id_tipo_documento = td.id_tipo_documento
        JOIN usuarios u ON ds.solicitado_por = u.id_usuario
        WHERE ds.id_cliente = %s
        AND ds.estado IN ('pendiente', 'recordatorio_enviado')
        ORDER BY ds.fecha_limite
        """
        
        requests = execute_query(requests_query, (client_id,))
        
        # Procesar resultados
        for request in requests:
            if 'fecha_solicitud' in request and request['fecha_solicitud']:
                request['fecha_solicitud'] = request['fecha_solicitud'].isoformat()
            if 'fecha_limite' in request and request['fecha_limite']:
                request['fecha_limite'] = request['fecha_limite'].isoformat()
            request['vencido'] = request['dias_restantes'] < 0 if request['dias_restantes'] is not None else False
        
        # Obtener documentos faltantes según completitud
        completeness_info = calculate_document_completeness(client_id)
        missing_docs = completeness_info['missing_documents']
        
        response = {
            'client_id': client_id,
            'client_name': client['nombre_razon_social'],
            'client_code': client['codigo_cliente'],
            'pending_documents': pending_docs,
            'document_requests': requests,
            'missing_documents': missing_docs,
            'completeness_percentage': completeness_info['completeness_percentage']
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener documentos pendientes: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener documentos pendientes: {str(e)}'})
        }

def get_expiring_documents(event, context):
    """Obtiene los documentos próximos a vencer del cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        days_threshold = int(query_params.get('days', 90))  # Por defecto 90 días
        
        # Obtener documentos por vencer
        expiring_docs_query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo,
               td.id_tipo_documento, td.nombre_tipo, 
               cb.id_categoria_bancaria, cb.nombre_categoria, cb.validez_en_dias,
               d.fecha_modificacion as fecha_documento,
               DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) as fecha_vencimiento,
               DATEDIFF(DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY), CURDATE()) as dias_restantes
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE dc.id_cliente = %s 
          AND d.estado = 'publicado' 
          AND cb.validez_en_dias IS NOT NULL
          AND DATEDIFF(DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY), CURDATE()) BETWEEN -30 AND %s
        ORDER BY dias_restantes
        """
        
        expiring_docs = execute_query(expiring_docs_query, (client_id, days_threshold))
        
        # Categorizar documentos
        expired_docs = []
        critical_docs = []
        warning_docs = []
        upcoming_docs = []
        
        for doc in expiring_docs:
            # Formatear fechas
            if 'fecha_documento' in doc and doc['fecha_documento']:
                doc['fecha_documento'] = doc['fecha_documento'].isoformat()
            if 'fecha_vencimiento' in doc and doc['fecha_vencimiento']:
                doc['fecha_vencimiento'] = doc['fecha_vencimiento'].isoformat()
            
            # Categorizar según días restantes
            if doc['dias_restantes'] <= 0:
                expired_docs.append(doc)
            elif doc['dias_restantes'] <= 15:
                critical_docs.append(doc)
            elif doc['dias_restantes'] <= 30:
                warning_docs.append(doc)
            else:
                upcoming_docs.append(doc)
        
        response = {
            'client_id': client_id,
            'client_name': client['nombre_razon_social'],
            'client_code': client['codigo_cliente'],
            'expired': expired_docs,
            'critical': critical_docs,
            'warning': warning_docs,
            'upcoming': upcoming_docs,
            'summary': {
                'expired_count': len(expired_docs),
                'critical_count': len(critical_docs),
                'warning_count': len(warning_docs),
                'upcoming_count': len(upcoming_docs),
                'total_expiring': len(expiring_docs)
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener documentos por vencer: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener documentos por vencer: {str(e)}'})
        }



def get_client_document_completeness(event, context):
    """Calcula y devuelve la completitud documental de un cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado,
               gestor_principal_id, gestor_kyc_id, estado_documental,
               fecha_ultima_revision_kyc, proxima_revision_kyc
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso IN ('admin.clientes', 'admin.documentos')
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para ver este cliente'})
            }
        
        # Calcular métricas de completitud documental
        completeness = info_calculate_document_completeness(client_id)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'consultar',
            'entidad_afectada': 'completitud_documento',
            'id_entidad_afectada': client_id,
            'detalles': json.dumps({'nombre_cliente': client['nombre_razon_social']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        # Preparar respuesta
        response = {
            'cliente': {
                'id': client_id,
                'codigo': client['codigo_cliente'],
                'nombre': client['nombre_razon_social'],
                'estado_documental': client['estado_documental']
            },
            'completitud': completeness
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al calcular completitud documental: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al calcular completitud documental: {str(e)}'})
        }

def info_calculate_document_completeness(client_id):
    """Función interna para calcular la completitud documental de un cliente"""
    try:
        # Obtener documentos necesarios según el tipo de cliente
        required_docs_query = """
        SELECT c.tipo_cliente, c.segmento_bancario, c.nivel_riesgo,
               c.documentos_pendientes
        FROM clientes c
        WHERE c.id_cliente = %s
        """
        
        client_info = execute_query(required_docs_query, (client_id,))
        
        if not client_info:
            return {
                'porcentaje_completitud': 0,
                'estado': 'desconocido',
                'documentos_requeridos': 0,
                'documentos_completados': 0,
                'documentos_pendientes': 0,
                'documentos_vencidos': 0,
                'detalle': []
            }
        
        client_type = client_info[0]['tipo_cliente']
        risk_level = client_info[0]['nivel_riesgo']
        segment = client_info[0]['segmento_bancario']
        
        # Obtener lista de documentos requeridos según perfil del cliente
        required_docs_by_profile_query = """
        SELECT td.id_tipo_documento, td.nombre_tipo, 
               tdb.requiere_validacion_manual,
               cb.validez_en_dias, cb.requiere_validacion
        FROM tipos_documento td
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE (
            CASE 
                WHEN %s = 'persona_fisica' THEN td.es_documento_bancario = 1 AND cb.nombre_categoria IN ('identificacion_personal', 'prueba_domicilio', 'informacion_financiera')
                WHEN %s = 'empresa' THEN td.es_documento_bancario = 1 AND cb.nombre_categoria IN ('documento_constitucion', 'identificacion_representante', 'informacion_financiera_empresa', 'prueba_domicilio_empresa')
                ELSE td.es_documento_bancario = 1 AND cb.nombre_categoria IN ('documento_identidad_organismo', 'prueba_legal')
            END
        )
        """
        
        required_docs = execute_query(required_docs_by_profile_query, (client_type, client_type))
        
        # Documentos adicionales basados en nivel de riesgo
        if risk_level in ['alto', 'muy_alto']:
            additional_docs_query = """
            SELECT td.id_tipo_documento, td.nombre_tipo, 
                   tdb.requiere_validacion_manual,
                   cb.validez_en_dias, cb.requiere_validacion
            FROM tipos_documento td
            JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
            JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
            WHERE cb.nombre_categoria IN ('declaracion_origen_fondos', 'documentacion_extendida_kyc')
            """
            
            additional_docs = execute_query(additional_docs_query)
            required_docs.extend(additional_docs)
        
        # Lista consolidada de documentos requeridos
        required_doc_types = [doc['id_tipo_documento'] for doc in required_docs]
        
        # Obtener documentos actuales del cliente
        current_docs_query = """
        SELECT d.id_documento, d.id_tipo_documento, td.nombre_tipo,
               d.fecha_modificacion, d.estado, d.validado_manualmente,
               d.confianza_extraccion
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        LEFT JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE dc.id_cliente = %s AND d.estado = 'publicado'
        """
        
        current_docs = execute_query(current_docs_query, (client_id,))
        
        # Calcular documentos completados, pendientes y vencidos
        now = datetime.datetime.now()
        doc_statuses = []
        completed_docs = 0
        expired_docs = 0
        
        # Documentos pendientes del cliente
        pending_docs = []
        if client_info[0]['documentos_pendientes']:
            try:
                pending_docs = json.loads(client_info[0]['documentos_pendientes'])
                if not isinstance(pending_docs, list):
                    pending_docs = []
            except:
                pending_docs = []
        
        # Procesar cada tipo de documento requerido
        for req_doc in required_docs:
            doc_id = req_doc['id_tipo_documento']
            doc_name = req_doc['nombre_tipo']
            validity_days = req_doc['validez_en_dias']
            requires_validation = req_doc['requiere_validacion'] == 1
            
            matching_docs = [d for d in current_docs if d['id_tipo_documento'] == doc_id]
            
            status = {
                'id_tipo_documento': doc_id,
                'nombre_tipo': doc_name,
                'estado': 'pendiente',
                'fecha_vencimiento': None,
                'dias_restantes': None,
                'requiere_validacion': requires_validation,
                'validado': False
            }
            
            if matching_docs:
                # Tomar el documento más reciente
                latest_doc = sorted(matching_docs, key=lambda x: x['fecha_modificacion'], reverse=True)[0]
                
                status['validado'] = latest_doc['validado_manualmente'] == 1
                
                # Calcular fecha de vencimiento si aplica
                if validity_days:
                    expiry_date = latest_doc['fecha_modificacion'] + datetime.timedelta(days=validity_days)
                    status['fecha_vencimiento'] = expiry_date.isoformat()
                    
                    days_remaining = (expiry_date - now).days
                    status['dias_restantes'] = days_remaining
                    
                    if days_remaining < 0:
                        status['estado'] = 'vencido'
                        expired_docs += 1
                    else:
                        status['estado'] = 'completado' if not requires_validation or status['validado'] else 'pendiente_validacion'
                        if status['estado'] == 'completado':
                            completed_docs += 1
                else:
                    status['estado'] = 'completado' if not requires_validation or status['validado'] else 'pendiente_validacion'
                    if status['estado'] == 'completado':
                        completed_docs += 1
            else:
                # Verificar si está en la lista de documentos pendientes
                is_pending = any(p.get('id_tipo_documento') == doc_id for p in pending_docs)
                if is_pending:
                    pending_info = next((p for p in pending_docs if p.get('id_tipo_documento') == doc_id), None)
                    status['estado'] = 'solicitado'
                    
                    if pending_info and 'fecha_limite' in pending_info:
                        try:
                            fecha_limite = datetime.datetime.fromisoformat(pending_info['fecha_limite'])
                            status['fecha_vencimiento'] = fecha_limite.isoformat()
                            days_remaining = (fecha_limite - now).days
                            status['dias_restantes'] = days_remaining
                        except:
                            pass
            
            doc_statuses.append(status)
        
        # Calcular porcentaje de completitud
        total_required = len(required_docs)
        completeness_percentage = (completed_docs / total_required * 100) if total_required > 0 else 0
        
        # Determinar estado general
        if completeness_percentage == 100:
            status = 'completo'
        elif expired_docs > 0:
            status = 'documentos_vencidos'
        elif completed_docs == 0:
            status = 'sin_documentacion'
        else:
            status = 'incompleto'
        
        # Resultado
        result = {
            'porcentaje_completitud': round(completeness_percentage, 2),
            'estado': status,
            'documentos_requeridos': total_required,
            'documentos_completados': completed_docs,
            'documentos_pendientes': total_required - completed_docs,
            'documentos_vencidos': expired_docs,
            'detalle': doc_statuses
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error en cálculo de completitud: {str(e)}")
        return {
            'porcentaje_completitud': 0,
            'estado': 'error',
            'documentos_requeridos': 0,
            'documentos_completados': 0,
            'documentos_pendientes': 0,
            'documentos_vencidos': 0,
            'error': str(e)
        }



def get_client_document_risk(event, context):
    """Calcula y devuelve el riesgo documental de un cliente"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado,
               gestor_principal_id, gestor_kyc_id, nivel_riesgo,
               fecha_ultima_revision_kyc, proxima_revision_kyc
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso IN ('admin.clientes', 'admin.documentos')
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para ver este cliente'})
            }
        
        # Calcular métricas de riesgo documental
        risk = info_calculate_document_risk(client_id)
        
        # Actualizar caché de vista del cliente si es necesario
        if risk['nivel_riesgo_calculado'] != client['nivel_riesgo']:
            update_query = """
            UPDATE vista_cliente_cache
            SET ultima_actualizacion = %s,
                kpis_cliente = JSON_SET(
                    COALESCE(kpis_cliente, '{}'),
                    '$.nivel_riesgo_calculado', %s
                )
            WHERE id_cliente = %s
            """
            
            now = datetime.datetime.now()
            execute_query(update_query, (now, risk['nivel_riesgo_calculado'], client_id), fetch=False)
        
        # Registrar en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'consultar',
            'entidad_afectada': 'riesgo_documento',
            'id_entidad_afectada': client_id,
            'detalles': json.dumps({'nombre_cliente': client['nombre_razon_social']}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        # Preparar respuesta
        response = {
            'cliente': {
                'id': client_id,
                'codigo': client['codigo_cliente'],
                'nombre': client['nombre_razon_social'],
                'nivel_riesgo_actual': client['nivel_riesgo']
            },
            'riesgo': risk
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al calcular riesgo documental: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al calcular riesgo documental: {str(e)}'})
        }

def info_calculate_document_risk(client_id):
    """Función interna para calcular el riesgo documental de un cliente"""
    try:
        # Obtener información del cliente
        client_query = """
        SELECT c.tipo_cliente, c.segmento_bancario, c.nivel_riesgo, 
               c.fecha_ultima_revision_kyc, c.proxima_revision_kyc,
               c.estado_documental, c.fecha_alta, c.clasificacion_fatca
        FROM clientes c
        WHERE c.id_cliente = %s
        """
        
        client_info = execute_query(client_query, (client_id,))
        
        if not client_info:
            return {
                'nivel_riesgo_calculado': 'desconocido',
                'puntuacion_riesgo': 0,
                'factores_riesgo': [],
                'recomendaciones': []
            }
        
        client = client_info[0]
        current_risk = client['nivel_riesgo'] or 'bajo'
        
        # Inicializar factores y puntuación de riesgo
        risk_factors = []
        risk_score = 0
        factor_weights = {
            'documentacion_incompleta': 30,
            'documentos_vencidos': 25,
            'alta_reciente': 15,
            'revision_vencida': 20,
            'clasificacion_fatca': 10,
            'tipo_cliente': 15,
            'segmento': 10,
            'confianza_documentos': 15
        }
        
        # Obtener completitud documental
        completeness = calculate_document_completeness(client_id)
        
        # Factor 1: Documentación incompleta
        if completeness['porcentaje_completitud'] < 100:
            risk_level = 'bajo'
            points = 0
            
            if completeness['porcentaje_completitud'] < 25:
                risk_level = 'muy_alto'
                points = factor_weights['documentacion_incompleta']
            elif completeness['porcentaje_completitud'] < 50:
                risk_level = 'alto'
                points = int(factor_weights['documentacion_incompleta'] * 0.75)
            elif completeness['porcentaje_completitud'] < 75:
                risk_level = 'medio'
                points = int(factor_weights['documentacion_incompleta'] * 0.5)
            else:
                risk_level = 'bajo'
                points = int(factor_weights['documentacion_incompleta'] * 0.25)
                
            risk_score += points
            risk_factors.append({
                'factor': 'documentacion_incompleta',
                'descripcion': f'Documentación incompleta ({completeness["porcentaje_completitud"]}%)',
                'nivel_riesgo': risk_level,
                'puntos': points
            })
        
        # Factor 2: Documentos vencidos
        if completeness['documentos_vencidos'] > 0:
            points = factor_weights['documentos_vencidos']
            risk_score += points
            risk_factors.append({
                'factor': 'documentos_vencidos',
                'descripcion': f'Tiene {completeness["documentos_vencidos"]} documentos vencidos',
                'nivel_riesgo': 'alto',
                'puntos': points
            })
        
        # Factor 3: Cliente reciente (menos de 3 meses)
        if client['fecha_alta']:
            now = datetime.datetime.now()
            days_since_creation = (now - client['fecha_alta']).days
            
            if days_since_creation < 90:
                points = int(factor_weights['alta_reciente'] * (1 - days_since_creation/90))
                risk_score += points
                risk_factors.append({
                    'factor': 'alta_reciente',
                    'descripcion': f'Cliente nuevo (hace {days_since_creation} días)',
                    'nivel_riesgo': 'medio',
                    'puntos': points
                })
        
        # Factor 4: Revisión KYC vencida
        if client['proxima_revision_kyc'] and client['proxima_revision_kyc'] < datetime.datetime.now().date():
            days_overdue = (datetime.datetime.now().date() - client['proxima_revision_kyc']).days
            risk_level = 'bajo'
            points = 0
            
            if days_overdue > 180:  # Más de 6 meses vencido
                risk_level = 'muy_alto'
                points = factor_weights['revision_vencida']
            elif days_overdue > 90:  # Más de 3 meses vencido
                risk_level = 'alto'
                points = int(factor_weights['revision_vencida'] * 0.75)
            elif days_overdue > 30:  # Más de 1 mes vencido
                risk_level = 'medio'
                points = int(factor_weights['revision_vencida'] * 0.5)
            else:
                risk_level = 'bajo'
                points = int(factor_weights['revision_vencida'] * 0.25)
                
            risk_score += points
            risk_factors.append({
                'factor': 'revision_vencida',
                'descripcion': f'Revisión KYC vencida hace {days_overdue} días',
                'nivel_riesgo': risk_level,
                'puntos': points
            })
        
        # Factor 5: Clasificación FATCA
        if client['clasificacion_fatca'] and 'recalcitrante' in client['clasificacion_fatca'].lower():
            points = factor_weights['clasificacion_fatca']
            risk_score += points
            risk_factors.append({
                'factor': 'clasificacion_fatca',
                'descripcion': f'Clasificación FATCA: {client["clasificacion_fatca"]}',
                'nivel_riesgo': 'alto',
                'puntos': points
            })
        
        # Factor 6: Tipo de cliente
        if client['tipo_cliente'] == 'empresa':
            points = int(factor_weights['tipo_cliente'] * 0.5)
            risk_score += points
            risk_factors.append({
                'factor': 'tipo_cliente',
                'descripcion': 'Cliente empresarial',
                'nivel_riesgo': 'medio',
                'puntos': points
            })
        
        # Factor 7: Segmento bancario
        if client['segmento_bancario'] in ['corporativa', 'institucional']:
            points = factor_weights['segmento']
            risk_score += points
            risk_factors.append({
                'factor': 'segmento',
                'descripcion': f'Segmento bancario: {client["segmento_bancario"]}',
                'nivel_riesgo': 'medio',
                'puntos': points
            })
        
        # Factor 8: Verificar confianza en los documentos
        docs_query = """
        SELECT AVG(d.confianza_extraccion) as confianza_promedio,
               COUNT(*) as total_docs,
               SUM(CASE WHEN d.validado_manualmente = 1 THEN 1 ELSE 0 END) as docs_validados
        FROM documentos_clientes dc
        JOIN documentos d ON dc.id_documento = d.id_documento
        WHERE dc.id_cliente = %s AND d.estado = 'publicado'
        """
        
        docs_info = execute_query(docs_query, (client_id,))
        
        if docs_info and docs_info[0]['total_docs'] > 0:
            confianza_promedio = docs_info[0]['confianza_promedio'] or 0
            total_docs = docs_info[0]['total_docs']
            docs_validados = docs_info[0]['docs_validados']
            
            if confianza_promedio < 0.7 and docs_validados / total_docs < 0.5:
                points = factor_weights['confianza_documentos']
                risk_score += points
                risk_factors.append({
                    'factor': 'confianza_documentos',
                    'descripcion': f'Baja confianza en documentos (promedio: {confianza_promedio:.2f})',
                    'nivel_riesgo': 'medio',
                    'puntos': points
                })
        
        # Calcular nivel de riesgo basado en puntuación
        calculated_risk = 'bajo'
        max_possible_score = sum(factor_weights.values())
        risk_percentage = (risk_score / max_possible_score) * 100
        
        if risk_percentage >= 75:
            calculated_risk = 'muy_alto'
        elif risk_percentage >= 50:
            calculated_risk = 'alto'
        elif risk_percentage >= 25:
            calculated_risk = 'medio'
        else:
            calculated_risk = 'bajo'
        
        # Generar recomendaciones
        recommendations = []
        
        if completeness['porcentaje_completitud'] < 100:
            recommendations.append('Completar la documentación faltante')
        
        if completeness['documentos_vencidos'] > 0:
            recommendations.append('Actualizar documentos vencidos')
        
        if client['proxima_revision_kyc'] and client['proxima_revision_kyc'] < datetime.datetime.now().date():
            recommendations.append('Realizar revisión KYC pendiente')
        
        # Resultado
        result = {
            'nivel_riesgo_calculado': calculated_risk,
            'puntuacion_riesgo': risk_score,
            'porcentaje_riesgo': round(risk_percentage, 2),
            'nivel_riesgo_actual': current_risk,
            'cambio_recomendado': calculated_risk != current_risk,
            'factores_riesgo': risk_factors,
            'recomendaciones': recommendations
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error en cálculo de riesgo: {str(e)}")
        return {
            'nivel_riesgo_calculado': 'error',
            'puntuacion_riesgo': 0,
            'factores_riesgo': [],
            'recomendaciones': [],
            'error': str(e)
        }



def track_document_request(event, context):
    """Seguimiento de solicitudes de documentos para un cliente específico"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'clientes.ver')
        if error_response:
            return error_response
        
        # Obtener ID del cliente
        client_id = event['pathParameters']['id']
        
        # Verificar si el cliente existe
        check_query = """
        SELECT id_cliente, codigo_cliente, nombre_razon_social, estado,
               gestor_principal_id, gestor_kyc_id
        FROM clientes
        WHERE id_cliente = %s
        """
        
        client_result = execute_query(check_query, (client_id,))
        
        if not client_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        client = client_result[0]
        
        # Verificar permisos - el usuario debe ser gestor del cliente o tener permiso admin
        is_admin_query = """
        SELECT COUNT(*) as is_admin
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s AND p.codigo_permiso IN ('admin.clientes', 'admin.documentos')
        """
        
        is_admin_result = execute_query(is_admin_query, (user_id,))
        is_admin = is_admin_result[0]['is_admin'] > 0 if is_admin_result else False
        
        if not is_admin and client['gestor_principal_id'] != user_id and client['gestor_kyc_id'] != user_id:
            return {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para acceder a esta información'})
            }
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Filtros
        estado = query_params.get('estado')
        dias_limite = query_params.get('dias_limite')  # Para filtrar por días restantes hasta la fecha límite
        fecha_inicio = query_params.get('fecha_inicio')
        fecha_fin = query_params.get('fecha_fin')
        
        # Construir consulta para el seguimiento de solicitudes
        query = """
        SELECT ds.id_solicitud, ds.id_cliente, ds.id_tipo_documento, ds.fecha_solicitud,
               ds.solicitado_por, u_solicitante.nombre_usuario as solicitado_por_nombre,
               ds.fecha_limite, ds.estado, ds.id_documento_recibido, ds.notas,
               td.nombre_tipo as tipo_documento_nombre,
               DATEDIFF(ds.fecha_limite, CURDATE()) as dias_restantes,
               CASE WHEN ds.fecha_limite < CURDATE() AND ds.estado IN ('pendiente', 'recordatorio_enviado') 
                    THEN 1 ELSE 0 END as vencido
        FROM documentos_solicitados ds
        JOIN tipos_documento td ON ds.id_tipo_documento = td.id_tipo_documento
        JOIN usuarios u_solicitante ON ds.solicitado_por = u_solicitante.id_usuario
        WHERE ds.id_cliente = %s
        """
        
        params = [client_id]
        
        # Aplicar filtros
        if estado:
            query += " AND ds.estado = %s"
            params.append(estado)
        
        if dias_limite:
            query += " AND DATEDIFF(ds.fecha_limite, CURDATE()) <= %s"
            params.append(int(dias_limite))
        
        if fecha_inicio:
            query += " AND ds.fecha_solicitud >= %s"
            params.append(fecha_inicio)
        
        if fecha_fin:
            query += " AND ds.fecha_solicitud <= %s"
            params.append(fecha_fin)
        
        # Ordenar por estado (pendientes primero) y fecha límite (más cercanos primero)
        query += """ 
        ORDER BY 
            CASE ds.estado 
                WHEN 'pendiente' THEN 1 
                WHEN 'recordatorio_enviado' THEN 2 
                WHEN 'recibido' THEN 3 
                WHEN 'cancelado' THEN 4 
            END,
            ds.fecha_limite
        """
        
        # Ejecutar consulta
        requests = execute_query(query, params)
        
        # Procesar resultados
        for req in requests:
            # Convertir fechas para JSON
            if 'fecha_solicitud' in req and req['fecha_solicitud']:
                req['fecha_solicitud'] = req['fecha_solicitud'].isoformat()
            if 'fecha_limite' in req and req['fecha_limite']:
                req['fecha_limite'] = req['fecha_limite'].isoformat()
        
        # Obtener estadísticas de seguimiento
        stats_query = """
        SELECT 
            COUNT(*) as total_solicitudes,
            SUM(CASE WHEN estado = 'pendiente' THEN 1 ELSE 0 END) as pendientes,
            SUM(CASE WHEN estado = 'recordatorio_enviado' THEN 1 ELSE 0 END) as recordatorios,
            SUM(CASE WHEN estado = 'recibido' THEN 1 ELSE 0 END) as recibidos,
            SUM(CASE WHEN estado = 'cancelado' THEN 1 ELSE 0 END) as cancelados,
            SUM(CASE WHEN fecha_limite < CURDATE() AND estado IN ('pendiente', 'recordatorio_enviado') 
                     THEN 1 ELSE 0 END) as vencidos,
            AVG(CASE WHEN estado = 'recibido' 
                    THEN DATEDIFF(CASE WHEN id_documento_recibido IS NOT NULL 
                                      THEN (SELECT fecha_creacion FROM versiones_documento 
                                            WHERE id_documento = id_documento_recibido ORDER BY numero_version LIMIT 1)
                                  ELSE CURDATE() END, fecha_solicitud)
                 END) as promedio_dias_respuesta
        FROM documentos_solicitados
        WHERE id_cliente = %s
        """
        
        stats_result = execute_query(stats_query, (client_id,))
        stats = stats_result[0] if stats_result else {}
        
        # Obtener historia y tendencias de cumplimiento de solicitudes
        # Últimos 6 meses
        timeline_query = """
        SELECT 
            DATE_FORMAT(fecha_solicitud, '%Y-%m-01') as mes,
            COUNT(*) as total_solicitudes,
            SUM(CASE WHEN estado = 'recibido' THEN 1 ELSE 0 END) as completadas,
            SUM(CASE WHEN fecha_limite < CURDATE() AND estado IN ('pendiente', 'recordatorio_enviado') 
                     THEN 1 ELSE 0 END) as vencidas
        FROM documentos_solicitados
        WHERE id_cliente = %s
        AND fecha_solicitud >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY DATE_FORMAT(fecha_solicitud, '%Y-%m-01')
        ORDER BY mes
        """
        
        timeline = execute_query(timeline_query, (client_id,))
        
        # Crear respuesta
        response = {
            'cliente': {
                'id': client_id,
                'codigo': client['codigo_cliente'],
                'nombre': client['nombre_razon_social']
            },
            'solicitudes': requests,
            'estadisticas': stats,
            'tendencia_temporal': timeline
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener seguimiento de solicitudes: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener seguimiento de solicitudes: {str(e)}'})
        }

