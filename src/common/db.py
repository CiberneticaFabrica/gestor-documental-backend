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





