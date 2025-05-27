# src/document_viewer/app.py
import os
import json
import uuid
import base64
import logging
import datetime
import boto3
from botocore.exceptions import ClientError

from common.db import (
    execute_query,
    get_connection,
    generate_uuid,
    insert_audit_record
)

from common.headers import add_cors_headers

# Configurar logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Configurar el cliente de S3
s3_client = boto3.client('s3')
BUCKET_NAME = os.environ.get('DOCUMENTS_BUCKET', 'gestor-documental-documents-processed')
URL_EXPIRATION = int(os.environ.get('URL_EXPIRATION_SECONDS', 3600))  # 1 hora por defecto
PREVIEW_SIZE = os.environ.get('PREVIEW_SIZE', '800x600')

def lambda_handler(event, context):
    """Manejador principal para el visor de documentos"""
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
        
        # Extraer partes de la ruta
        path_parts = path.split('/')
        if len(path_parts) < 4:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Ruta de solicitud inválida'})
            }
        
        doc_id = path_parts[2]
        action = path_parts[3]
        
        # Enrutar a la función correspondiente según la acción
        if http_method == 'GET':
            if action == 'content':
                return get_document_content(event, doc_id)
            elif action == 'preview':
                return get_document_preview(event, doc_id)
            elif action == 'preview-version':
                # Para el endpoint: /documents/{doc_id}/preview-version/{version_id}
                if len(path_parts) < 5:
                    return {
                        'statusCode': 400,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'version_id es requerido en la ruta'})
                    }
                version_id = path_parts[4]
                return get_document_preview_version(event, doc_id, version_id)
            elif action == 'download':
                return generate_download_url(event, doc_id)
            elif action == 'extracted':
                return get_extracted_data(event, doc_id)
            elif action == 'metadata':
                return get_document_metadata(event, doc_id)
        
        # Si no coincide con ninguna ruta definida
        return {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Ruta no encontrada'})
        }
    
    except Exception as e:
        logger.error(f"Error en el manejador principal: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error interno del servidor: {str(e)}'})
        }

def validate_session(event, required_permission=None):
    """Valida la sesión del usuario y verifica permisos si es necesario"""
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
    
    # Si no se requiere un permiso específico, solo retornar el ID de usuario
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
        return user_id, {'statusCode': 403, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': f'No tienes el permiso requerido: {required_permission}'})}
    
    return user_id, None

def check_document_access(user_id, doc_id):
    """Verifica si el usuario tiene acceso al documento"""
    # Obtener información del documento
    doc_query = """
    SELECT d.id_documento, d.titulo, d.estado, d.id_carpeta, d.creado_por
    FROM documentos d
    WHERE d.id_documento = %s AND d.estado != 'eliminado'
    """
    
    doc_result = execute_query(doc_query, (doc_id,))
    if not doc_result:
        return None, {'statusCode': 404, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Documento no encontrado o eliminado'})}
    
    document = doc_result[0]
    
    # Si el usuario es el creador, tiene acceso
    if document['creado_por'] == user_id:
        return document, None
    
    # Verificar si el usuario tiene acceso a la carpeta del documento
    if document['id_carpeta']:
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
            return None, {'statusCode': 403, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'No tienes permiso para acceder a este documento'})}
    else:
        # Si no está en una carpeta y el usuario no es el creador, no tiene acceso
        return None, {'statusCode': 403, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'No tienes permiso para acceder a este documento'})}
    
    return document, None

def get_current_version(doc_id):
    """Obtiene la versión actual del documento"""
    version_query = """
    SELECT v.id_version, v.numero_version, v.tamano_bytes, v.hash_contenido,
           v.ubicacion_almacenamiento_tipo, v.ubicacion_almacenamiento_ruta,
           v.ubicacion_almacenamiento_parametros, v.nombre_original,
           v.extension, v.mime_type, v.metadatos_extraidos,
           v.miniaturas_generadas,v.ubicacion_miniatura
    FROM documentos d
    JOIN versiones_documento v ON d.id_documento = v.id_documento
    WHERE d.id_documento = %s AND v.numero_version = d.version_actual
    """
    
    version_result = execute_query(version_query, (doc_id,))
    if not version_result:
        return None
    
    version = version_result[0]
    
    # Convertir campos JSON a diccionarios
    if version['ubicacion_almacenamiento_parametros']:
        try:
            version['ubicacion_almacenamiento_parametros'] = json.loads(version['ubicacion_almacenamiento_parametros'])
        except:
            version['ubicacion_almacenamiento_parametros'] = {}
    
    if version['metadatos_extraidos']:
        try:
            version['metadatos_extraidos'] = json.loads(version['metadatos_extraidos'])
        except:
            version['metadatos_extraidos'] = {}
    
    return version

def log_document_access(user_id, doc_id, version_id, action, ip_address, result='éxito'):
    """Registra el acceso al documento en la auditoría"""
    audit_data = {
        'fecha_hora': datetime.datetime.now(),
        'usuario_id': user_id,
        'direccion_ip': ip_address,
        'accion': action,
        'entidad_afectada': 'documento',
        'id_entidad_afectada': doc_id,
        'detalles': json.dumps({
            'id_version': version_id,
            'tipo_acceso': action
        }),
        'resultado': result
    }
    
    insert_audit_record(audit_data)

def get_document_content(event, doc_id):
    """Obtiene el contenido del documento (vista en línea)"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Verificar acceso al documento
        document, error_response = check_document_access(user_id, doc_id)
        if error_response:
            return error_response
        
        # Obtener versión actual
        version = get_current_version(doc_id)
        if not version:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se encontró la versión actual del documento'})
            }
        
        # Validar tipo de almacenamiento
        if version['ubicacion_almacenamiento_tipo'] != 's3':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Tipo de almacenamiento no soportado: {version["ubicacion_almacenamiento_tipo"]}'})
            }
        
        # Generar URL firmada para visualización en línea
        try:
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': BUCKET_NAME,
                    'Key': version['ubicacion_almacenamiento_ruta'],
                    'ResponseContentDisposition': f'inline; filename="{version["nombre_original"]}"',
                    'ResponseContentType': version['mime_type']
                },
                ExpiresIn=URL_EXPIRATION
            )
            
            # Registrar acceso en auditoría
            ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
            log_document_access(user_id, doc_id, version['id_version'], 'visualizar', ip_address)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'url': url,
                    'mime_type': version['mime_type'],
                    'nombre_archivo': version['nombre_original'],
                    'tamano_bytes': version['tamano_bytes'],
                    'expiracion_url': URL_EXPIRATION
                })
            }
        except ClientError as e:
            logger.error(f"Error al generar URL de S3: {str(e)}")
            return {
                'statusCode': 500,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Error al generar URL para visualización'})
            }
    
    except Exception as e:
        logger.error(f"Error al obtener contenido del documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener contenido del documento: {str(e)}'})
        }

def get_document_preview(event, doc_id):
    """Genera una vista previa del documento"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Verificar acceso al documento
        document, error_response = check_document_access(user_id, doc_id)
        if error_response:
            return error_response
        
        # Obtener versión actual
        version = get_current_version(doc_id)
        if not version:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se encontró la versión actual del documento'})
            }
        
        # Variables para almacenar URLs y respuesta
        document_url = None
        thumbnail_url = None
        response_data = {}
        
        # Agregar logs para depuración
        logger.info(f"Versión obtenida: {version}")
        logger.info(f"ubicacion_miniatura: {version.get('ubicacion_miniatura')}")
        logger.info(f"miniaturas_generadas: {version.get('miniaturas_generadas')}")
        
        # 1. Generar URL para el documento original (siempre)
        try:
            storage_path = version['ubicacion_almacenamiento_ruta']
            
            if '/' in storage_path:
                parts = storage_path.split('/', 1)
                bucket = parts[0]
                key = parts[1]
            else:
                bucket = BUCKET_NAME
                key = storage_path
            
            # URL para el documento original
            document_url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket,
                    'Key': key,
                    'ResponseContentType': version['mime_type'],
                    'ResponseContentDisposition': f'inline; filename="{version["nombre_original"]}"'
                },
                ExpiresIn=URL_EXPIRATION
            )
            
            # Agregar datos del documento original
            response_data['url_documento'] = document_url
            response_data['mime_type'] = version['mime_type']
            response_data['nombre_archivo'] = version['nombre_original']
            response_data['tamano_bytes'] = version['tamano_bytes']
            response_data['expiracion_url'] = URL_EXPIRATION
        except ClientError as e:
            logger.error(f"Error al generar URL del documento original: {str(e)}")
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Documento original no encontrado'})
            }
        
        # 2. Generar URL para la miniatura
        # Verificar si el campo ubicacion_miniatura existe y no es None/vacío
        thumbnail_path = version.get('ubicacion_miniatura')
        
        if thumbnail_path and thumbnail_path.strip():
            try:
                # Extraer correctamente bucket y key para la miniatura
                if '/' in thumbnail_path:
                    parts = thumbnail_path.split('/', 1)
                    bucket = parts[0]
                    key = parts[1]
                else:
                    bucket = BUCKET_NAME
                    key = thumbnail_path
                
                logger.info(f"Generando URL de miniatura para bucket={bucket}, key={key}")
                
                # URL para la miniatura
                thumbnail_url = s3_client.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': bucket,
                        'Key': key,
                        'ResponseContentType': 'image/jpeg',
                        'ResponseContentDisposition': f'inline; filename="{os.path.basename(key)}"'
                    },
                    ExpiresIn=URL_EXPIRATION
                )
                
                # Agregar datos de la miniatura a la respuesta
                response_data['url_miniatura'] = thumbnail_url
                response_data['miniatura_mime_type'] = 'image/jpeg'
                response_data['miniatura_nombre'] = os.path.basename(key)
                response_data['tiene_miniatura'] = True
                
                logger.info(f"URL de miniatura generada: {thumbnail_url}")
            except ClientError as e:
                logger.error(f"Error al generar URL de miniatura: {str(e)}")
                response_data['tiene_miniatura'] = False
                response_data['url_miniatura'] = None
        else:
            logger.warning(f"No se encontró ubicacion_miniatura en la versión del documento")
            response_data['tiene_miniatura'] = False
            response_data['url_miniatura'] = None
            
            # Programar generación de miniaturas si no existen
            if not version.get('miniaturas_generadas'):
                try:
                    sqs_client = boto3.client('sqs')
                    THUMBNAILS_QUEUE_URL = os.environ.get('THUMBNAILS_QUEUE_URL')
                    
                    if THUMBNAILS_QUEUE_URL:
                        storage_path = version['ubicacion_almacenamiento_ruta']
                        
                        if '/' in storage_path:
                            parts = storage_path.split('/', 1)
                            bucket = parts[0]
                            key = parts[1]
                        else:
                            bucket = BUCKET_NAME
                            key = storage_path
                        
                        # Crear mensaje para generar miniaturas
                        message = {
                            'document_id': doc_id,
                            'version_id': version['id_version'],
                            'bucket': bucket,
                            'key': key,
                            'extension': version['extension'],
                            'mime_type': version['mime_type']
                        }
                        
                        # Enviar mensaje a SQS
                        sqs_client.send_message(
                            QueueUrl=THUMBNAILS_QUEUE_URL,
                            MessageBody=json.dumps(message)
                        )
                        
                        logger.info(f"Generación de miniaturas programada para documento {doc_id}")
                except Exception as e:
                    logger.error(f"Error al programar generación de miniaturas: {str(e)}")
        
        # Registrar acceso en auditoría
        ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
        log_document_access(user_id, doc_id, version['id_version'], 'previsualizar', ip_address)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response_data)
        }
    
    except Exception as e:
        logger.error(f"Error al obtener vista previa del documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener vista previa del documento: {str(e)}'})
        }

def generate_download_url(event, doc_id):
    """Genera una URL para descarga del documento"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.descargar')
        if error_response:
            return error_response
        
        # Verificar acceso al documento
        document, error_response = check_document_access(user_id, doc_id)
        if error_response:
            return error_response
        
        # Obtener versión actual
        version = get_current_version(doc_id)
        if not version:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se encontró la versión actual del documento'})
            }
        
        # Validar tipo de almacenamiento
        if version['ubicacion_almacenamiento_tipo'] != 's3':
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f'Tipo de almacenamiento no soportado: {version["ubicacion_almacenamiento_tipo"]}'})
            }
        
        try:
            # Generar URL firmada para descarga
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': BUCKET_NAME,
                    'Key': version['ubicacion_almacenamiento_ruta'],
                    'ResponseContentDisposition': f'attachment; filename="{version["nombre_original"]}"',
                    'ResponseContentType': version['mime_type']
                },
                ExpiresIn=URL_EXPIRATION
            )
            
            # Registrar descarga en auditoría
            ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
            log_document_access(user_id, doc_id, version['id_version'], 'descargar', ip_address)
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({
                    'url': url,
                    'nombre_archivo': version['nombre_original'],
                    'mime_type': version['mime_type'],
                    'tamano_bytes': version['tamano_bytes'],
                    'expiracion_url': URL_EXPIRATION
                })
            }
        except ClientError as e:
            logger.error(f"Error al generar URL de descarga: {str(e)}")
            return {
                'statusCode': 500,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Error al generar URL para descarga'})
            }
    
    except Exception as e:
        logger.error(f"Error al generar URL de descarga: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al generar URL de descarga: {str(e)}'})
        }

def get_extracted_data(event, doc_id):
    """Obtiene los datos extraídos del documento"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Verificar acceso al documento
        document, error_response = check_document_access(user_id, doc_id)
        if error_response:
            return error_response
        
        # Obtener datos extraídos de la tabla analisis_documento_ia
        query = """
        SELECT a.id_analisis, a.tipo_documento, a.confianza_clasificacion,
               a.entidades_detectadas, a.metadatos_extraccion,
               a.fecha_analisis, a.estado_analisis,
               a.verificado, a.fecha_verificacion,
               u.nombre_usuario as verificado_por_nombre
        FROM analisis_documento_ia a
        LEFT JOIN usuarios u ON a.verificado_por = u.id_usuario
        WHERE a.id_documento = %s
        ORDER BY a.fecha_analisis DESC
        LIMIT 1
        """
        
        analysis_result = execute_query(query, (doc_id,))
        
        if not analysis_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se encontraron datos extraídos para este documento'})
            }
        
        analysis = analysis_result[0]
        
        # Convertir campos JSON a diccionarios
        if analysis['entidades_detectadas']:
            try:
                analysis['entidades_detectadas'] = json.loads(analysis['entidades_detectadas'])
            except:
                analysis['entidades_detectadas'] = {}
        
        if analysis['metadatos_extraccion']:
            try:
                analysis['metadatos_extraccion'] = json.loads(analysis['metadatos_extraccion'])
            except:
                analysis['metadatos_extraccion'] = {}
        
        # Obtener datos extraídos de la tabla documentos
        doc_query = """
        SELECT datos_extraidos_ia, confianza_extraccion, validado_manualmente,
               fecha_validacion, validado_por
        FROM documentos
        WHERE id_documento = %s
        """
        
        doc_result = execute_query(doc_query, (doc_id,))
        
        if doc_result and doc_result[0]['datos_extraidos_ia']:
            try:
                datos_extraidos = json.loads(doc_result[0]['datos_extraidos_ia'])
            except:
                datos_extraidos = {}
            
            analysis['datos_extraidos'] = datos_extraidos
            analysis['confianza_extraccion'] = doc_result[0]['confianza_extraccion']
            analysis['validado_manualmente'] = doc_result[0]['validado_manualmente']
            analysis['fecha_validacion'] = doc_result[0]['fecha_validacion']
        
        # Formatear fechas
        if 'fecha_analisis' in analysis and analysis['fecha_analisis']:
            analysis['fecha_analisis'] = analysis['fecha_analisis'].isoformat()
        
        if 'fecha_verificacion' in analysis and analysis['fecha_verificacion']:
            analysis['fecha_verificacion'] = analysis['fecha_verificacion'].isoformat()
        
        # Registrar acceso en auditoría
        ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
        log_document_access(user_id, doc_id, analysis['id_analisis'], 'consultar_datos_extraidos', ip_address)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(analysis, default=str)
        }
    
    except Exception as e:
        logger.error(f"Error al obtener datos extraídos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener datos extraídos: {str(e)}'})
        }

def get_current_by_version(version_id):
    """Obtiene información de una versión específica del documento"""
    version_query = """
    SELECT v.id_version, v.numero_version, v.tamano_bytes, v.hash_contenido,
           v.ubicacion_almacenamiento_tipo, v.ubicacion_almacenamiento_ruta,
           v.ubicacion_almacenamiento_parametros, v.nombre_original,
           v.extension, v.mime_type, v.metadatos_extraidos,
           v.miniaturas_generadas, v.ubicacion_miniatura, v.id_documento
    FROM versiones_documento v
    WHERE v.id_version = %s
    """
    
    version_result = execute_query(version_query, (version_id,))
    if not version_result:
        return None
    
    version = version_result[0]
    
    # Convertir campos JSON a diccionarios
    if version['ubicacion_almacenamiento_parametros']:
        try:
            version['ubicacion_almacenamiento_parametros'] = json.loads(version['ubicacion_almacenamiento_parametros'])
        except:
            version['ubicacion_almacenamiento_parametros'] = {}
    
    if version['metadatos_extraidos']:
        try:
            version['metadatos_extraidos'] = json.loads(version['metadatos_extraidos'])
        except:
            version['metadatos_extraidos'] = {}
    
    return version

def get_document_preview_version(event, doc_id, version_id):
    """Genera una vista previa de una versión específica del documento"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Verificar acceso al documento
        document, error_response = check_document_access(user_id, doc_id)
        if error_response:
            return error_response
        
        # Obtener versión específica
        version = get_current_by_version(version_id)
        if not version:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No se encontró la versión solicitada del documento'})
            }
        
        # Verificar que la versión pertenece al documento solicitado
        if version['id_documento'] != doc_id:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'La versión no pertenece al documento especificado'})
            }
        
        # Variables para almacenar URLs y respuesta
        document_url = None
        thumbnail_url = None
        response_data = {}
        
        # Agregar logs para depuración
        logger.info(f"Versión específica obtenida: {version}")
        logger.info(f"ubicacion_miniatura: {version.get('ubicacion_miniatura')}")
        logger.info(f"miniaturas_generadas: {version.get('miniaturas_generadas')}")
        
        # 1. Generar URL para el documento original (siempre)
        try:
            storage_path = version['ubicacion_almacenamiento_ruta']
            
            if '/' in storage_path:
                parts = storage_path.split('/', 1)
                bucket = parts[0]
                key = parts[1]
            else:
                bucket = BUCKET_NAME
                key = storage_path
            
            # URL para el documento original
            document_url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket,
                    'Key': key,
                    'ResponseContentType': version['mime_type'],
                    'ResponseContentDisposition': f'inline; filename="{version["nombre_original"]}"'
                },
                ExpiresIn=URL_EXPIRATION
            )
            
            # Agregar datos del documento original
            response_data['url_documento'] = document_url
            response_data['mime_type'] = version['mime_type']
            response_data['nombre_archivo'] = version['nombre_original']
            response_data['tamano_bytes'] = version['tamano_bytes']
            response_data['numero_version'] = version['numero_version']
            response_data['id_version'] = version['id_version']
            response_data['expiracion_url'] = URL_EXPIRATION
        except ClientError as e:
            logger.error(f"Error al generar URL del documento original: {str(e)}")
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Documento original no encontrado'})
            }
        
        # 2. Generar URL para la miniatura
        # Verificar si el campo ubicacion_miniatura existe y no es None/vacío
        thumbnail_path = version.get('ubicacion_miniatura')
        
        if thumbnail_path and thumbnail_path.strip():
            try:
                # Extraer correctamente bucket y key para la miniatura
                if '/' in thumbnail_path:
                    parts = thumbnail_path.split('/', 1)
                    bucket = parts[0]
                    key = parts[1]
                else:
                    bucket = BUCKET_NAME
                    key = thumbnail_path
                
                logger.info(f"Generando URL de miniatura para bucket={bucket}, key={key}")
                
                # URL para la miniatura
                thumbnail_url = s3_client.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': bucket,
                        'Key': key,
                        'ResponseContentType': 'image/jpeg',
                        'ResponseContentDisposition': f'inline; filename="{os.path.basename(key)}"'
                    },
                    ExpiresIn=URL_EXPIRATION
                )
                
                # Agregar datos de la miniatura a la respuesta
                response_data['url_miniatura'] = thumbnail_url
                response_data['miniatura_mime_type'] = 'image/jpeg'
                response_data['miniatura_nombre'] = os.path.basename(key)
                response_data['tiene_miniatura'] = True
                
                logger.info(f"URL de miniatura generada: {thumbnail_url}")
            except ClientError as e:
                logger.error(f"Error al generar URL de miniatura: {str(e)}")
                response_data['tiene_miniatura'] = False
                response_data['url_miniatura'] = None
        else:
            logger.warning(f"No se encontró ubicacion_miniatura en la versión del documento")
            response_data['tiene_miniatura'] = False
            response_data['url_miniatura'] = None
            
            # Programar generación de miniaturas si no existen
            if not version.get('miniaturas_generadas'):
                try:
                    sqs_client = boto3.client('sqs')
                    THUMBNAILS_QUEUE_URL = os.environ.get('THUMBNAILS_QUEUE_URL')
                    
                    if THUMBNAILS_QUEUE_URL:
                        storage_path = version['ubicacion_almacenamiento_ruta']
                        
                        if '/' in storage_path:
                            parts = storage_path.split('/', 1)
                            bucket = parts[0]
                            key = parts[1]
                        else:
                            bucket = BUCKET_NAME
                            key = storage_path
                        
                        # Crear mensaje para generar miniaturas
                        message = {
                            'document_id': doc_id,
                            'version_id': version['id_version'],
                            'bucket': bucket,
                            'key': key,
                            'extension': version['extension'],
                            'mime_type': version['mime_type']
                        }
                        
                        # Enviar mensaje a SQS
                        sqs_client.send_message(
                            QueueUrl=THUMBNAILS_QUEUE_URL,
                            MessageBody=json.dumps(message)
                        )
                        
                        logger.info(f"Generación de miniaturas programada para documento {doc_id}, versión {version_id}")
                except Exception as e:
                    logger.error(f"Error al programar generación de miniaturas: {str(e)}")
        
        # Registrar acceso en auditoría
        ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
        log_document_access(user_id, doc_id, version['id_version'], 'previsualizar_version', ip_address)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response_data)
        }
    
    except Exception as e:
        logger.error(f"Error al obtener vista previa de la versión del documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener vista previa de la versión del documento: {str(e)}'})
        }

def get_document_metadata(event, doc_id):
    """Obtiene los metadatos completos del documento"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Verificar acceso al documento
        document, error_response = check_document_access(user_id, doc_id)
        if error_response:
            return error_response
        
        # Obtener información del documento
        doc_query = """
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
               u_modificador.nombre_usuario as modificado_por_usuario
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN carpetas c ON d.id_carpeta = c.id_carpeta
        JOIN usuarios u_creador ON d.creado_por = u_creador.id_usuario
        JOIN usuarios u_modificador ON d.modificado_por = u_modificador.id_usuario
        WHERE d.id_documento = %s
        """
        
        doc_result = execute_query(doc_query, (doc_id,))
        
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Documento no encontrado'})
            }
        
        metadata = doc_result[0]
        
        # Obtener información de la versión actual
        version = get_current_version(doc_id)
        if version:
            metadata['version'] = {
                'id_version': version['id_version'],
                'numero_version': version['numero_version'],
                'nombre_original': version['nombre_original'],
                'extension': version['extension'],
                'mime_type': version['mime_type'],
                'tamano_bytes': version['tamano_bytes'],
                'hash_contenido': version['hash_contenido'],
                'miniaturas_generadas': version['miniaturas_generadas']
            }
        
        # Convertir campos JSON a diccionarios
        json_fields = ['tags', 'metadatos', 'estadisticas']
        for field in json_fields:
            if field in metadata and metadata[field]:
                try:
                    metadata[field] = json.loads(metadata[field])
                except:
                    metadata[field] = {}
        
        # Formatear fechas
        date_fields = ['fecha_creacion', 'fecha_modificacion', 'fecha_validacion']
        for field in date_fields:
            if field in metadata and metadata[field]:
                metadata[field] = metadata[field].isoformat()
        
        # Obtener información de documentos relacionados
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
        metadata['documentos_relacionados'] = references
        
        # Registrar acceso en auditoría
        ip_address = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')
        log_document_access(user_id, doc_id, version['id_version'] if version else None, 'consultar_metadatos', ip_address)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(metadata, default=str)
        }
    
    except Exception as e:
        logger.error(f"Error al obtener metadatos del documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener metadatos del documento: {str(e)}'})
        }