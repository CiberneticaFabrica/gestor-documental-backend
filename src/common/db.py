import os
import uuid
import logging
import pymysql

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









