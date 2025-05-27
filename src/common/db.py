import json
import os
import uuid
import logging
import pymysql
import datetime

# Configuración del logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")


def generate_uuid():
    """Genera un UUID único"""
    return str(uuid.uuid4())


def get_connection():
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            db=DB_NAME,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=60
        )
        logger.info("Conexión a la base de datos establecida correctamente")
        return conn
    except Exception as e:
        logger.error(f"Error al conectar a la base de datos: {str(e)}")
        raise


def execute_query(query, params=None, fetch=True):
    """Ejecuta una consulta SQL y retorna los resultados"""
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            try:
                cursor.execute(query, params)
                if fetch:
                    result = cursor.fetchall()
                else:
                    connection.commit()
                    result = cursor.lastrowid
                return result
            except pymysql.err.MySQLError as mysql_err:
                # Capturar errores específicos de MySQL para mejor diagnóstico
                logger.error(f"Error MySQL: {str(mysql_err)}")
                if len(mysql_err.args) >= 2:
                    error_code = mysql_err.args[0]
                    error_message = mysql_err.args[1]
                    logger.error(f"Error MySQL {error_code}: {error_message}")
                else:
                    logger.error(f"MySQL error args: {mysql_err.args}")
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params}")
                connection.rollback()
                raise
    except Exception as e:
        logger.error(f"Error al ejecutar consulta: {str(e)}")
        connection.rollback()
        raise
    finally:
        connection.close()

  
def insert_audit_record(audit_data):
    """Inserta un registro en la tabla de auditoría"""
    query = """
    INSERT INTO registros_auditoria (
        fecha_hora,
        usuario_id,
        direccion_ip,
        accion,
        entidad_afectada,
        id_entidad_afectada,
        detalles,
        resultado
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s
    )
    """
    return execute_query(query, (
        audit_data['fecha_hora'],
        audit_data['usuario_id'],
        audit_data['direccion_ip'],
        audit_data['accion'],
        audit_data['entidad_afectada'],
        audit_data['id_entidad_afectada'],
        audit_data['detalles'],
        audit_data['resultado']
    ), fetch=False)


def check_document_access(document_id, user_id, require_write=False):
    """
    Verifica si un usuario tiene acceso a un documento.
    
    Args:
        document_id: ID del documento a verificar
        user_id: ID del usuario
        require_write: Si True, verifica permisos de escritura, si False, solo lectura
        
    Returns:
        Boolean indicando si tiene acceso
    """
    permission_types = "('escritura', 'administracion')" if require_write else "('lectura', 'escritura', 'administracion')"
    
    query = f"""
        SELECT 1
        FROM documentos d
        LEFT JOIN permisos_carpetas pc ON d.id_carpeta = pc.id_carpeta
        WHERE d.id_documento = %s
        AND (
            d.creado_por = %s
            OR (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario' AND pc.tipo_permiso IN {permission_types})
            OR (pc.id_entidad IN (SELECT id_grupo FROM usuarios_grupos WHERE id_usuario = %s) AND pc.tipo_entidad = 'grupo' AND pc.tipo_permiso IN {permission_types})
            OR EXISTS (SELECT 1 FROM usuarios_roles ur WHERE ur.id_usuario = %s AND ur.id_rol IN (
                SELECT id_rol FROM roles_permisos WHERE id_permiso = (SELECT id_permiso FROM permisos WHERE codigo_permiso = 'admin.todas_operaciones')
            ))
        )
    """
    
    try:
        result = execute_query(query, [document_id, user_id, user_id, user_id, user_id], True)
        return bool(result)
    except Exception as e:
        logger.error(f"Error al verificar acceso a documento: {str(e)}")
        return False


def call_generar_solicitudes(cliente_id):
    """Llama al procedimiento que genera solicitudes documentales para un cliente"""
    query = "CALL generar_solicitudes_documentos_cliente(%s)"
    return execute_query(query, (cliente_id,), fetch=False)
 

def call_crear_estructura_carpetas(cliente_id):
    """Llama al procedimiento que crea la estructura de carpetas para un cliente"""
    query = "CALL crear_estructura_carpetas_cliente(%s)"
    return execute_query(query, (cliente_id,), fetch=False)


def search_documents_sp(user_id, search_criteria, direccion_ip='0.0.0.0'):
    """
    Busca documentos usando el Stored Procedure buscar_documentos_avanzado
    
    Args:
        user_id: ID del usuario que realiza la búsqueda
        search_criteria: Diccionario con criterios de búsqueda
        direccion_ip: IP del cliente que realiza la solicitud
        
    Returns:
        Tupla con (documentos, total_documentos)
    """
    # Valores por defecto y extracción de parámetros
    search_term = search_criteria.get('search_term', '')
    document_types = ','.join(search_criteria.get('document_types', []))
    status = ','.join(search_criteria.get('status', []))
    date_from = search_criteria.get('date_from', '')
    date_to = search_criteria.get('date_to', '')
    fecha_modificacion_desde = search_criteria.get('fecha_modificacion_desde', '')
    fecha_modificacion_hasta = search_criteria.get('fecha_modificacion_hasta', '')
    folders = ','.join(search_criteria.get('folders', []))
    tags = json.dumps(search_criteria.get('tags', []))
    metadata_filters = json.dumps(search_criteria.get('metadata_filters', []))
    creators = ','.join(search_criteria.get('creators', []))
    modificado_por = ','.join(search_criteria.get('modificado_por', []))
    cliente_id = ','.join(search_criteria.get('cliente_id', []))
    cliente_nombre = search_criteria.get('cliente_nombre', '')
    tipo_cliente = ','.join(search_criteria.get('tipo_cliente', []))
    segmento_cliente = ','.join(search_criteria.get('segmento_cliente', []))
    nivel_riesgo = ','.join(search_criteria.get('nivel_riesgo', []))
    estado_documental = ','.join(search_criteria.get('estado_documental', []))
    categoria_bancaria = ','.join(search_criteria.get('categoria_bancaria', []))
    confianza_extraccion_min = search_criteria.get('confianza_extraccion_min')
    validado_manualmente = search_criteria.get('validado_manualmente', -1)
    incluir_eliminados = search_criteria.get('incluir_eliminados', 0)
    texto_extraido = search_criteria.get('texto_extraido', '')
    con_alertas_documento = search_criteria.get('con_alertas_documento', -1)
    con_comentarios = search_criteria.get('con_comentarios', -1)
    tipo_formato = ','.join(search_criteria.get('tipo_formato', []))
    
    # Paginación
    page = int(search_criteria.get('page', 1))
    page_size = int(search_criteria.get('page_size', 10))
    
    # Ordenamiento
    sort_by = search_criteria.get('sort_by', 'fecha_modificacion')
    sort_order = search_criteria.get('sort_order', 'DESC')
    
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            # Ejecutar el procedimiento almacenado
            cursor.callproc('buscar_documentos_avanzado', [
                user_id, search_term, document_types, status, date_from, date_to,
                fecha_modificacion_desde, fecha_modificacion_hasta, folders, 
                tags, metadata_filters, creators, modificado_por, cliente_id,
                cliente_nombre, tipo_cliente, segmento_cliente, nivel_riesgo,
                estado_documental, categoria_bancaria, confianza_extraccion_min,
                validado_manualmente, incluir_eliminados, texto_extraido,
                con_alertas_documento, con_comentarios, tipo_formato,
                sort_by, sort_order, page_size, page, direccion_ip
            ])
            
            # La primera consulta devuelve el total de documentos
            total_result = cursor.fetchall()
            total = total_result[0]['total'] if total_result else 0
            
            # Consumir el resultado del primer EXECUTE
            cursor.nextset()
            
            # Obtener los documentos del segundo EXECUTE
            documents = cursor.fetchall()
            
            # Procesar documentos (convertir campos JSON, etc.)
            for doc in documents:
         # Procesar campos JSON
                for json_field in ['tags', 'metadatos', 'cliente_info']:
                    if json_field in doc and doc[json_field]:
                        try:
                            doc[json_field] = json.loads(doc[json_field])
                        except:
                            doc[json_field] = {} if json_field != 'tags' else []
                
                # Convertir fechas a formato ISO
                if 'fecha_creacion' in doc and doc['fecha_creacion']:
                    doc['fecha_creacion'] = doc['fecha_creacion'].isoformat()
                if 'fecha_modificacion' in doc and doc['fecha_modificacion']:
                    doc['fecha_modificacion'] = doc['fecha_modificacion'].isoformat()
            
            return documents, total
            
    except Exception as e:
        logger.error(f"Error en búsqueda de documentos SP: {str(e)}")
        raise
    finally:
        connection.close()

def get_response_quality_analytics(params):
    """Análisis de calidad de respuestas"""
    days = params.get('days', 30)
    
    query = """
    SELECT 
        satisfaccion_usuario,
        COUNT(*) as cantidad,
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM consultas_globales_sistema 
                                   WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)), 2) as porcentaje,
        AVG(tiempo_procesamiento_ms) as tiempo_promedio
    FROM consultas_globales_sistema
    WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    AND satisfaccion_usuario IS NOT NULL
    GROUP BY satisfaccion_usuario
    ORDER BY 
        CASE satisfaccion_usuario
            WHEN 'muy_bueno' THEN 1
            WHEN 'bueno' THEN 2
            WHEN 'regular' THEN 3
            WHEN 'malo' THEN 4
            WHEN 'muy_malo' THEN 5
        END
    """
    
    return execute_query(query, [days, days], True)

def get_peak_usage_analytics(params):
    """Análisis de picos de uso por horas y días"""
    days = params.get('days', 14)
    
    # Análisis por hora del día
    hourly_query = """
    SELECT 
        HOUR(fecha_consulta) as hora,
        COUNT(*) as consultas,
        COUNT(DISTINCT id_usuario) as usuarios_unicos,
        AVG(tiempo_procesamiento_ms) as tiempo_promedio
    FROM consultas_globales_sistema
    WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    GROUP BY HOUR(fecha_consulta)
    ORDER BY hora
    """
    
    # Análisis por día de la semana
    daily_query = """
    SELECT 
        DAYOFWEEK(fecha_consulta) as dia_semana,
        CASE DAYOFWEEK(fecha_consulta)
            WHEN 1 THEN 'Domingo'
            WHEN 2 THEN 'Lunes'
            WHEN 3 THEN 'Martes'
            WHEN 4 THEN 'Miércoles'
            WHEN 5 THEN 'Jueves'
            WHEN 6 THEN 'Viernes'
            WHEN 7 THEN 'Sábado'
        END as nombre_dia,
        COUNT(*) as consultas,
        COUNT(DISTINCT id_usuario) as usuarios_unicos
    FROM consultas_globales_sistema
    WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    GROUP BY DAYOFWEEK(fecha_consulta), nombre_dia
    ORDER BY dia_semana
    """
    
    hourly_data = execute_query(hourly_query, [days], True)
    daily_data = execute_query(daily_query, [days], True)
    
    return {
        'usage_by_hour': hourly_data,
        'usage_by_day': daily_data
    }

def get_client_query_analytics(params):
    """Análisis de consultas relacionadas con clientes específicos"""
    days = params.get('days', 30)
    
    query = """
    SELECT 
        JSON_EXTRACT(entidades_detectadas, '$[0]') as cliente_mencionado,
        COUNT(*) as veces_consultado,
        COUNT(DISTINCT id_usuario) as usuarios_diferentes,
        AVG(CASE WHEN satisfaccion_usuario = 'muy_bueno' THEN 5
                 WHEN satisfaccion_usuario = 'bueno' THEN 4
                 WHEN satisfaccion_usuario = 'regular' THEN 3
                 WHEN satisfaccion_usuario = 'malo' THEN 2
                 WHEN satisfaccion_usuario = 'muy_malo' THEN 1
                 ELSE NULL END) as satisfaccion_promedio,
        MAX(fecha_consulta) as ultima_consulta
    FROM consultas_globales_sistema
    WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    AND intent_detectado = 'client_documents'
    AND JSON_LENGTH(entidades_detectadas) > 0
    GROUP BY JSON_EXTRACT(entidades_detectadas, '$[0]')
    HAVING veces_consultado > 1
    ORDER BY veces_consultado DESC
    LIMIT 15
    """
    
    return execute_query(query, [days], True)

def get_general_analytics(params):
    """Análisis general del sistema de chat"""
    days = params.get('days', 30)
    
    # Métricas generales
    general_query = """
    SELECT 
        COUNT(*) as total_consultas,
        COUNT(DISTINCT id_usuario) as usuarios_unicos,
        AVG(tiempo_procesamiento_ms) as tiempo_promedio,
        MIN(fecha_consulta) as primera_consulta,
        MAX(fecha_consulta) as ultima_consulta,
        COUNT(CASE WHEN satisfaccion_usuario IN ('bueno', 'muy_bueno') THEN 1 END) as consultas_positivas,
        COUNT(CASE WHEN satisfaccion_usuario IS NOT NULL THEN 1 END) as consultas_evaluadas
    FROM consultas_globales_sistema
    WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    """
    
    # Top consultas
    top_queries_query = """
    SELECT 
        pregunta,
        COUNT(*) as frecuencia,
        intent_detectado,
        AVG(CASE WHEN satisfaccion_usuario = 'muy_bueno' THEN 5
                 WHEN satisfaccion_usuario = 'bueno' THEN 4
                 WHEN satisfaccion_usuario = 'regular' THEN 3
                 WHEN satisfaccion_usuario = 'malo' THEN 2
                 WHEN satisfaccion_usuario = 'muy_malo' THEN 1
                 ELSE NULL END) as puntuacion_promedio
    FROM consultas_globales_sistema
    WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    GROUP BY pregunta, intent_detectado
    HAVING frecuencia > 1
    ORDER BY frecuencia DESC
    LIMIT 10
    """
    
    general_metrics = execute_query(general_query, [days], True)
    top_queries = execute_query(top_queries_query, [days], True)
    
    return {
        'general_metrics': general_metrics[0] if general_metrics else {},
        'top_queries': top_queries
    }

# Funciones específicas para el chat global que complementan las existentes

def get_client_documents_by_name(client_name, user_id, limit=20):
    """
    Obtiene documentos de un cliente específico por nombre (optimizada para chat global)
    """
    # Primero buscar el cliente
    client_search_query = """
    SELECT id_cliente, nombre_razon_social, estado_documental
    FROM clientes
    WHERE nombre_razon_social LIKE %s
    ORDER BY 
        CASE 
            WHEN nombre_razon_social = %s THEN 1
            WHEN nombre_razon_social LIKE %s THEN 2
            ELSE 3
        END
    LIMIT 1
    """
    
    search_pattern = f"%{client_name}%"
    exact_match = client_name
    starts_with = f"{client_name}%"
    
    client_result = execute_query(client_search_query, [search_pattern, exact_match, starts_with], True)
    
    if not client_result:
        return None, "Cliente no encontrado"
    
    client = client_result[0]
    client_id = client['id_cliente']
    
    # Obtener documentos del cliente
    docs_query = """
    SELECT 
        d.id_documento,
        d.codigo_documento,
        d.titulo,
        td.nombre_tipo,
        d.estado,
        d.fecha_creacion,
        d.confianza_extraccion,
        d.validado_manualmente,
        di.numero_documento,
        di.fecha_expiracion,
        CASE 
            WHEN di.fecha_expiracion IS NOT NULL AND di.fecha_expiracion < CURDATE() THEN 'VENCIDO'
            WHEN di.fecha_expiracion IS NOT NULL AND di.fecha_expiracion <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) THEN 'POR_VENCER'
            WHEN d.validado_manualmente = 1 THEN 'VALIDADO'
            WHEN d.confianza_extraccion >= 0.8 THEN 'CONFIABLE'
            ELSE 'REQUIERE_REVISION'
        END as estado_documento
    FROM documentos d
    JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
    JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
    LEFT JOIN documentos_identificacion di ON d.id_documento = di.id_documento
    WHERE dc.id_cliente = %s
    AND d.estado != 'eliminado'
    AND (d.creado_por = %s OR EXISTS (
        SELECT 1 FROM permisos_carpetas pc 
        WHERE pc.id_carpeta = d.id_carpeta 
        AND (
            (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
            (pc.id_entidad IN (SELECT id_grupo FROM usuarios_grupos WHERE id_usuario = %s) AND pc.tipo_entidad = 'grupo')
        )
        AND pc.tipo_permiso IN ('lectura', 'escritura', 'administracion')
    ))
    ORDER BY d.fecha_creacion DESC
    LIMIT %s
    """
    
    documents = execute_query(docs_query, [client_id, user_id, user_id, user_id, limit], True)
    
    return {
        'client_info': client,
        'documents': documents,
        'total_documents': len(documents)
    }, None

def get_expiring_documents_for_chat(days=30, user_id=None, limit=50):
    """
    Obtiene documentos próximos a expirar (optimizada para chat global)
    """
    query = """
    SELECT 
        di.id_documento,
        d.titulo,
        d.codigo_documento,
        di.tipo_documento,
        di.numero_documento,
        di.fecha_expiracion,
        di.nombre_completo,
        c.nombre_razon_social as cliente_nombre,
        c.id_cliente,
        DATEDIFF(di.fecha_expiracion, CURDATE()) as dias_restantes,
        CASE 
            WHEN DATEDIFF(di.fecha_expiracion, CURDATE()) <= 0 THEN 'VENCIDO'
            WHEN DATEDIFF(di.fecha_expiracion, CURDATE()) <= 5 THEN 'CRÍTICO'
            WHEN DATEDIFF(di.fecha_expiracion, CURDATE()) <= 15 THEN 'URGENTE'
            WHEN DATEDIFF(di.fecha_expiracion, CURDATE()) <= 30 THEN 'PRÓXIMO'
            ELSE 'NORMAL'
        END as nivel_urgencia
    FROM documentos_identificacion di
    JOIN documentos d ON di.id_documento = d.id_documento
    LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
    LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
    WHERE di.fecha_expiracion BETWEEN DATE_SUB(CURDATE(), INTERVAL 30 DAY) AND DATE_ADD(CURDATE(), INTERVAL %s DAY)
    AND d.estado = 'publicado'
    AND (%s IS NULL OR d.creado_por = %s OR EXISTS (
        SELECT 1 FROM permisos_carpetas pc 
        WHERE pc.id_carpeta = d.id_carpeta 
        AND (
            (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
            (pc.id_entidad IN (SELECT id_grupo FROM usuarios_grupos WHERE id_usuario = %s) AND pc.tipo_entidad = 'grupo')
        )
        AND pc.tipo_permiso IN ('lectura', 'escritura', 'administracion')
    ))
    ORDER BY di.fecha_expiracion ASC, nivel_urgencia DESC
    LIMIT %s
    """
    
    return execute_query(query, [days, user_id, user_id, user_id, user_id, limit], True)

def get_user_document_stats_for_chat(user_id, time_range='week'):
    """
    Obtiene estadísticas de documentos del usuario (para chat global)
    """
    # Determinar condición de fecha
    if time_range == 'today':
        date_condition = "DATE(d.fecha_creacion) = CURDATE()"
    elif time_range == 'yesterday':
        date_condition = "DATE(d.fecha_creacion) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)"
    elif time_range == 'week':
        date_condition = "d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)"
    elif time_range == 'month':
        date_condition = "d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)"
    else:
        date_condition = "1=1"  # Todos los documentos
    
    # Estadísticas generales
    stats_query = f"""
    SELECT 
        COUNT(*) as total_documentos,
        COUNT(CASE WHEN DATE(d.fecha_creacion) = CURDATE() THEN 1 END) as subidos_hoy,
        COUNT(CASE WHEN DATE(d.fecha_creacion) = DATE_SUB(CURDATE(), INTERVAL 1 DAY) THEN 1 END) as subidos_ayer,
        COUNT(CASE WHEN d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 END) as subidos_semana,
        COUNT(CASE WHEN d.validado_manualmente = 1 THEN 1 END) as validados,
        COUNT(CASE WHEN d.confianza_extraccion < 0.7 THEN 1 END) as requieren_revision,
        AVG(d.confianza_extraccion) as confianza_promedio
    FROM documentos d
    WHERE d.creado_por = %s
    AND d.estado != 'eliminado'
    AND {date_condition}
    """
    
    # Distribución por tipo
    types_query = f"""
    SELECT 
        td.nombre_tipo,
        COUNT(*) as cantidad
    FROM documentos d
    JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
    WHERE d.creado_por = %s
    AND d.estado != 'eliminado'
    AND {date_condition}
    GROUP BY td.nombre_tipo
    ORDER BY cantidad DESC
    """
    
    stats = execute_query(stats_query, [user_id], True)
    types = execute_query(types_query, [user_id], True)
    
    return {
        'general_stats': stats[0] if stats else {},
        'distribution_by_type': types
    }

def register_global_chat_query(user_id, question, answer, intent_detected, data_sources, processing_time_ms=None):
    """
    Registra una consulta del chat global en la base de datos
    """
    query_id = generate_uuid()
    
    query = """
    INSERT INTO consultas_globales_sistema (
        id_consulta,
        id_usuario,
        pregunta,
        respuesta,
        intent_detectado,
        entidades_detectadas,
        fuentes_datos_utilizadas,
        fecha_consulta,
        servicio_ia_utilizado,
        tiempo_procesamiento_ms
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s)
    """
    
    # Convertir data_sources a JSON si es una lista
    if isinstance(data_sources, list):
        data_sources_json = json.dumps(data_sources)
    else:
        data_sources_json = data_sources
    
    execute_query(query, [
        query_id,
        user_id,
        question,
        answer,
        intent_detected,
        json.dumps([]),  # entidades_detectadas - se puede expandir después
        data_sources_json,
        'bedrock',
        processing_time_ms
    ], fetch=False)
    
    return query_id

def update_chat_query_feedback(query_id, satisfaction_rating, comment=None):
    """
    Actualiza el feedback de una consulta del chat global
    """
    if comment:
        # Si hay comentario, actualizar ambos campos
        query = """
        UPDATE consultas_globales_sistema
        SET satisfaccion_usuario = %s
        WHERE id_consulta = %s
        """
        execute_query(query, [satisfaction_rating, query_id], fetch=False)
        
        # Insertar comentario en tabla separada si existe
        try:
            comment_query = """
            INSERT INTO feedback_chat_detallado (
                id_feedback, id_consulta, comentario, fecha_feedback
            ) VALUES (UUID(), %s, %s, NOW())
            """
            execute_query(comment_query, [query_id, comment], fetch=False)
        except:
            # Si la tabla no existe, solo actualizar satisfacción
            pass
    else:
        # Solo actualizar satisfacción
        query = """
        UPDATE consultas_globales_sistema
        SET satisfaccion_usuario = %s
        WHERE id_consulta = %s
        """
        execute_query(query, [satisfaction_rating, query_id], fetch=False)

def get_chat_suggestions_data(user_role='user', context=''):
    """
    Obtiene datos para generar sugerencias del chat global
    """
    # Obtener patrones más frecuentes
    patterns_query = """
    SELECT 
        patron_pregunta,
        intent_asociado,
        frecuencia_uso
    FROM patrones_consultas_frecuentes
    WHERE activo = 1
    ORDER BY frecuencia_uso DESC
    LIMIT 10
    """
    
    patterns = execute_query(patterns_query, [], True)
    
    # Si es admin o supervisor, obtener alertas adicionales
    alerts = []
    if user_role in ['admin', 'supervisor']:
        alerts_query = """
        SELECT 
            'documentos_por_vencer' as tipo_alerta,
            COUNT(*) as cantidad
        FROM documentos_identificacion di
        JOIN documentos d ON di.id_documento = d.id_documento
        WHERE di.fecha_expiracion BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
        AND d.estado = 'publicado'
        
        UNION ALL
        
        SELECT 
            'documentos_baja_confianza' as tipo_alerta,
            COUNT(*) as cantidad
        FROM documentos
        WHERE confianza_extraccion < 0.7
        AND validado_manualmente = 0
        AND estado = 'publicado'
        """
        
        alerts = execute_query(alerts_query, [], True)
    
    return {
        'frequent_patterns': patterns,
        'system_alerts': alerts
    }

# Agregar estas funciones al final de tu archivo db_connector.py

def process_analytics_request(event):
    """
    Procesa solicitudes de análisis específicas del chat global
    
    Args:
        event: Evento con el tipo de análisis solicitado
        
    Returns:
        Resultados del análisis solicitado
    """
    try:
        analysis_type = event.get('analysis_type', 'general')
        params = event.get('parameters', {})
        
        if analysis_type == 'user_activity':
            return get_user_activity_analytics(params)
        elif analysis_type == 'intent_patterns':
            return get_intent_pattern_analytics(params)
        elif analysis_type == 'response_quality':
            return get_response_quality_analytics(params)
        elif analysis_type == 'peak_usage':
            return get_peak_usage_analytics(params)
        elif analysis_type == 'client_queries':
            return get_client_query_analytics(params)
        else:
            return get_general_analytics(params)
            
    except Exception as e:
        logger.error(f"Error en process_analytics_request: {str(e)}")
        raise

def get_user_activity_analytics(params):
    """Análisis de actividad de usuarios del chat"""
    days = params.get('days', 30)
    
    query = """
    SELECT 
        u.nombre_usuario,
        u.nombre,
        u.apellidos,
        COUNT(c.id_consulta) as total_consultas,
        COUNT(DISTINCT DATE(c.fecha_consulta)) as dias_activos,
        AVG(c.tiempo_procesamiento_ms) as tiempo_promedio,
        MAX(c.fecha_consulta) as ultima_consulta,
        COUNT(CASE WHEN c.satisfaccion_usuario IN ('bueno', 'muy_bueno') THEN 1 END) as consultas_satisfactorias
    FROM usuarios u
    LEFT JOIN consultas_globales_sistema c ON u.id_usuario = c.id_usuario
        AND c.fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    GROUP BY u.id_usuario, u.nombre_usuario, u.nombre, u.apellidos
    HAVING total_consultas > 0
    ORDER BY total_consultas DESC
    LIMIT 20
    """
    
    return execute_query(query, [days], True)

def get_intent_pattern_analytics(params):
    """Análisis de patrones de intenciones"""
    days = params.get('days', 30)
    
    query = """
    SELECT 
        intent_detectado,
        COUNT(*) as frecuencia,
        AVG(tiempo_procesamiento_ms) as tiempo_promedio,
        COUNT(DISTINCT id_usuario) as usuarios_unicos,
        AVG(CASE WHEN satisfaccion_usuario = 'muy_bueno' THEN 5
                 WHEN satisfaccion_usuario = 'bueno' THEN 4
                 WHEN satisfaccion_usuario = 'regular' THEN 3
                 WHEN satisfaccion_usuario = 'malo' THEN 2
                 WHEN satisfaccion_usuario = 'muy_malo' THEN 1
                 ELSE NULL END) as puntuacion_promedio,
        DATE(MIN(fecha_consulta)) as primera_aparicion,
        DATE(MAX(fecha_consulta)) as ultima_aparicion
    FROM consultas_globales_sistema
    WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
    GROUP BY intent_detectado
    ORDER BY frecuencia DESC
    """
    
    return execute_query(query, [days], True)

def get_client_status(analysis, user_id):
    """Obtiene estado de completitud de clientes"""
    
    if analysis.get('client_info'):
        # Estado específico de un cliente
        client_name = analysis['client_info']
        query = """
        SELECT 
            c.id_cliente,
            c.nombre_razon_social,
            c.estado_documental,
            c.documentos_pendientes,
            vcc.kpis_cliente
        FROM clientes c
        LEFT JOIN vista_cliente_cache vcc ON c.id_cliente = vcc.id_cliente
        WHERE c.nombre_razon_social LIKE %s
        LIMIT 5
        """
        
        search_pattern = f"%{analysis['client_info']}%"
        results = execute_query(query, [search_pattern], True)
    else:
        # Estado general
        query = """
        SELECT 
            estado_documental,
            COUNT(*) as cantidad
        FROM clientes
        GROUP BY estado_documental
        """
        
        results = execute_query(query, [], True)
    
    return results or []

def search_documents(analysis, user_id):
    """Busca documentos basado en criterios de la pregunta"""
    
    # Construir búsqueda flexible
    conditions = ["1=1"]
    params = []
    
    if analysis.get('document_types'):
        # Buscar por tipos específicos
        type_conditions = []
        for doc_type in analysis['document_types']:
            if doc_type == 'cedula':
                type_conditions.append("di.tipo_documento IN ('cedula', 'dni')")
            else:
                type_conditions.append("td.nombre_tipo LIKE %s")
                params.append(f"%{doc_type}%")
        
        if type_conditions:
            conditions.append(f"({' OR '.join(type_conditions)})")
    
    query = f"""
    SELECT 
        d.id_documento,
        d.titulo,
        td.nombre_tipo,
        d.fecha_creacion,
        c.nombre_razon_social,
        di.numero_documento,
        COALESCE(di.nombre_completo, '') as nombre_en_documento
    FROM documentos d
    JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
    LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
    LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
    LEFT JOIN documentos_identificacion di ON d.id_documento = di.id_documento
    WHERE {' AND '.join(conditions)}
    ORDER BY d.fecha_creacion DESC
    LIMIT 20
    """
    
    results = execute_query(query, params, True)
    return results or []

def get_user_context(user_id):
    """Obtiene contexto general del usuario"""
    context = {}
    
    try:
        # Información del usuario
        user_query = """
        SELECT nombre_usuario, nombre, apellidos
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, [user_id], True)
        if user_result:
            context['user'] = user_result[0]
        
        # Estadísticas rápidas
        stats_query = """
        SELECT 
            COUNT(*) as total_docs,
            COUNT(CASE WHEN DATE(fecha_creacion) = CURDATE() THEN 1 END) as docs_hoy
        FROM documentos 
        WHERE creado_por = %s
        """
        
        stats_result = execute_query(stats_query, [user_id], True)
        if stats_result:
            context['stats'] = stats_result[0]
            
    except Exception as e:
        logger.error(f"Error obteniendo contexto: {str(e)}")
    
    return context

