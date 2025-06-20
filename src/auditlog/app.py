import os
import json
import logging
import datetime
import csv
import io
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
        
        # Rutas de auditoría
        if http_method == 'GET' and path == '/audit-logs':
            return query_audit_logs(event, context)
        elif http_method == 'GET' and path == '/audit-logs/security':
            return get_security_events(event, context)
        elif http_method == 'GET' and path.startswith('/audit-logs/') and len(path.split('/')) == 3:
            log_id = path.split('/')[2]
            event['pathParameters'] = {'id': log_id}
            return get_audit_event(event, context)
        elif http_method == 'POST' and path == '/audit-logs/export':
            return export_audit_logs(event, context)
        elif http_method == 'GET' and path.startswith('/audit-logs/users/'):
            user_id = path.split('/')[3]
            event['pathParameters'] = {'user_id': user_id}
            return get_user_activity(event, context)
        elif http_method == 'GET' and path.startswith('/audit-logs/documents/'):
            document_id = path.split('/')[3]
            event['pathParameters'] = {'document_id': document_id}
            return get_document_activity(event, context)
        elif http_method == 'GET' and path == '/audit-logs/clients-documents-activity':
            return get_clients_with_documents_activity(event, context)
        
                 
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

def query_audit_logs(event, context):
    """Consultar logs de auditoría con filtros y paginación"""
    try:
        # Validar sesión con permiso de auditoría
        user_id, error_response = validate_session(event, 'admin.auditoria')
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 50))
        
        # Filtros
        start_date = query_params.get('start_date')
        end_date = query_params.get('end_date')
        usuario_id = query_params.get('usuario_id')
        accion = query_params.get('accion')
        entidad = query_params.get('entidad')
        resultado = query_params.get('resultado')
        direccion_ip = query_params.get('direccion_ip')
        id_entidad = query_params.get('id_entidad')
        
        # Construir consulta base
        query = """
        SELECT ra.id_registro, ra.fecha_hora, ra.usuario_id, 
               u.nombre_usuario, ra.direccion_ip, ra.accion, 
               ra.entidad_afectada, ra.id_entidad_afectada, 
               ra.detalles, ra.resultado
        FROM registros_auditoria ra
        LEFT JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE 1=1
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM registros_auditoria ra
        WHERE 1=1
        """
        
        # Construir cláusulas WHERE para filtros
        where_clauses = []
        params = []
        count_params = []
        
        if start_date:
            where_clauses.append("ra.fecha_hora >= %s")
            params.append(start_date)
            count_params.append(start_date)
        
        if end_date:
            where_clauses.append("ra.fecha_hora <= %s")
            params.append(end_date)
            count_params.append(end_date)
        
        if usuario_id:
            where_clauses.append("ra.usuario_id = %s")
            params.append(usuario_id)
            count_params.append(usuario_id)
        
        if accion:
            where_clauses.append("ra.accion = %s")
            params.append(accion)
            count_params.append(accion)
        
        if entidad:
            where_clauses.append("ra.entidad_afectada = %s")
            params.append(entidad)
            count_params.append(entidad)
        
        if resultado:
            where_clauses.append("ra.resultado = %s")
            params.append(resultado)
            count_params.append(resultado)
        
        if direccion_ip:
            where_clauses.append("ra.direccion_ip LIKE %s")
            params.append(f"%{direccion_ip}%")
            count_params.append(f"%{direccion_ip}%")
        
        if id_entidad:
            where_clauses.append("ra.id_entidad_afectada = %s")
            params.append(id_entidad)
            count_params.append(id_entidad)
        
        # Añadir cláusulas WHERE a las consultas
        if where_clauses:
            where_str = " AND " + " AND ".join(where_clauses)
            query += where_str
            count_query += where_str
        
        # Añadir ordenamiento y paginación
        query += " ORDER BY ra.fecha_hora DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        logs = execute_query(query, params)
        count_result = execute_query(count_query, count_params)
        
        total_logs = count_result[0]['total'] if count_result else 0
        total_pages = (total_logs + page_size - 1) // page_size if total_logs > 0 else 1
        
        # Procesar resultados
        for log in logs:
            # Formatear fechas para JSON
            if 'fecha_hora' in log and log['fecha_hora']:
                log['fecha_hora'] = log['fecha_hora'].isoformat()
            
            # Deserializar campo detalles
            if 'detalles' in log and log['detalles']:
                try:
                    log['detalles'] = json.loads(log['detalles'])
                except:
                    # Si falla la deserialización, mantener como cadena
                    pass
        
        # Obtener información de acciones y entidades disponibles para filtros
        actions_query = """
        SELECT DISTINCT accion
        FROM registros_auditoria
        ORDER BY accion
        """
        
        entities_query = """
        SELECT DISTINCT entidad_afectada
        FROM registros_auditoria
        ORDER BY entidad_afectada
        """
        
        results_query = """
        SELECT DISTINCT resultado
        FROM registros_auditoria
        ORDER BY resultado
        """
        
        actions = execute_query(actions_query)
        entities = execute_query(entities_query)
        results = execute_query(results_query)
        
        # Construir respuesta
        response = {
            'logs': logs,
            'pagination': {
                'total': total_logs,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            },
            'filtros_disponibles': {
                'acciones': [a['accion'] for a in actions],
                'entidades': [e['entidad_afectada'] for e in entities],
                'resultados': [r['resultado'] for r in results]
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al consultar logs de auditoría: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al consultar logs de auditoría: {str(e)}'})
        }

def get_audit_event(event, context):
    """Obtener un evento específico de auditoría por ID"""
    try:
        # Validar sesión con permiso de auditoría
        user_id, error_response = validate_session(event, 'admin.auditoria')
        if error_response:
            return error_response
        
        # Obtener ID del log
        log_id = event['pathParameters']['id']
        
        # Consultar evento
        query = """
        SELECT ra.id_registro, ra.fecha_hora, ra.usuario_id, 
               u.nombre_usuario, u.nombre, u.apellidos,
               ra.direccion_ip, ra.accion, 
               ra.entidad_afectada, ra.id_entidad_afectada, 
               ra.detalles, ra.resultado
        FROM registros_auditoria ra
        LEFT JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE ra.id_registro = %s
        """
        
        log_result = execute_query(query, (log_id,))
        
        if not log_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Evento de auditoría no encontrado'})
            }
        
        log = log_result[0]
        
        # Formatear fechas para JSON
        if 'fecha_hora' in log and log['fecha_hora']:
            log['fecha_hora'] = log['fecha_hora'].isoformat()
        
        # Deserializar campo detalles
        if 'detalles' in log and log['detalles']:
            try:
                log['detalles'] = json.loads(log['detalles'])
            except:
                # Si falla la deserialización, mantener como cadena
                pass
        
        # Obtener información adicional según el tipo de entidad
        if log['entidad_afectada'] == 'documento' and log['id_entidad_afectada']:
            doc_query = """
            SELECT id_documento, codigo_documento, titulo, estado
            FROM documentos
            WHERE id_documento = %s
            """
            
            doc_result = execute_query(doc_query, (log['id_entidad_afectada'],))
            if doc_result:
                log['entidad_info'] = doc_result[0]
        
        elif log['entidad_afectada'] == 'usuario' and log['id_entidad_afectada']:
            user_query = """
            SELECT id_usuario, nombre_usuario, nombre, apellidos, email, estado
            FROM usuarios
            WHERE id_usuario = %s
            """
            
            user_result = execute_query(user_query, (log['id_entidad_afectada'],))
            if user_result:
                log['entidad_info'] = user_result[0]
        
        elif log['entidad_afectada'] == 'carpeta' and log['id_entidad_afectada']:
            folder_query = """
            SELECT id_carpeta, nombre_carpeta, ruta_completa
            FROM carpetas
            WHERE id_carpeta = %s
            """
            
            folder_result = execute_query(folder_query, (log['id_entidad_afectada'],))
            if folder_result:
                log['entidad_info'] = folder_result[0]
        
        elif log['entidad_afectada'] == 'cliente' and log['id_entidad_afectada']:
            client_query = """
            SELECT id_cliente, codigo_cliente, nombre_razon_social, tipo_cliente
            FROM clientes
            WHERE id_cliente = %s
            """
            
            client_result = execute_query(client_query, (log['id_entidad_afectada'],))
            if client_result:
                log['entidad_info'] = client_result[0]
        
        # Obtener eventos relacionados
        related_query = """
        SELECT id_registro, fecha_hora, accion, resultado
        FROM registros_auditoria
        WHERE usuario_id = %s 
          AND fecha_hora BETWEEN DATE_SUB(%s, INTERVAL 1 HOUR) AND DATE_ADD(%s, INTERVAL 1 HOUR)
          AND id_registro != %s
        ORDER BY fecha_hora
        LIMIT 10
        """
        
        related_logs = execute_query(related_query, (
            log['usuario_id'], 
            log['fecha_hora'], 
            log['fecha_hora'],
            log_id
        ))
        
        # Formatear fechas de eventos relacionados
        for related in related_logs:
            if 'fecha_hora' in related and related['fecha_hora']:
                related['fecha_hora'] = related['fecha_hora'].isoformat()
        
        log['eventos_relacionados'] = related_logs
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(log, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener evento de auditoría: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener evento de auditoría: {str(e)}'})
        }

def export_audit_logs(event, context):
    """Exportar logs de auditoría con filtros aplicados"""
    try:
        # Validar sesión con permiso de auditoría
        user_id, error_response = validate_session(event, 'admin.auditoria')
        if error_response:
            return error_response
        
        # Obtener datos del cuerpo
        body = json.loads(event['body'])
        
        # Obtener formato de exportación (CSV o JSON)
        export_format = body.get('formato', 'csv').lower()
        if export_format not in ['csv', 'json']:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Formato de exportación no válido. Use "csv" o "json"'})
            }
        
        # Obtener filtros
        filtros = body.get('filtros', {})
        
        # Construir consulta base
        query = """
        SELECT ra.id_registro, ra.fecha_hora, ra.usuario_id, 
               u.nombre_usuario, ra.direccion_ip, ra.accion, 
               ra.entidad_afectada, ra.id_entidad_afectada, 
               ra.detalles, ra.resultado
        FROM registros_auditoria ra
        LEFT JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE 1=1
        """
        
        # Construir cláusulas WHERE para filtros
        where_clauses = []
        params = []
        
        if 'start_date' in filtros and filtros['start_date']:
            where_clauses.append("ra.fecha_hora >= %s")
            params.append(filtros['start_date'])
        
        if 'end_date' in filtros and filtros['end_date']:
            where_clauses.append("ra.fecha_hora <= %s")
            params.append(filtros['end_date'])
        
        if 'usuario_id' in filtros and filtros['usuario_id']:
            where_clauses.append("ra.usuario_id = %s")
            params.append(filtros['usuario_id'])
        
        if 'accion' in filtros and filtros['accion']:
            where_clauses.append("ra.accion = %s")
            params.append(filtros['accion'])
        
        if 'entidad' in filtros and filtros['entidad']:
            where_clauses.append("ra.entidad_afectada = %s")
            params.append(filtros['entidad'])
        
        if 'resultado' in filtros and filtros['resultado']:
            where_clauses.append("ra.resultado = %s")
            params.append(filtros['resultado'])
        
        if 'direccion_ip' in filtros and filtros['direccion_ip']:
            where_clauses.append("ra.direccion_ip LIKE %s")
            params.append(f"%{filtros['direccion_ip']}%")
        
        if 'id_entidad' in filtros and filtros['id_entidad']:
            where_clauses.append("ra.id_entidad_afectada = %s")
            params.append(filtros['id_entidad'])
        
        # Añadir cláusulas WHERE a la consulta
        if where_clauses:
            where_str = " AND " + " AND ".join(where_clauses)
            query += where_str
        
        # Añadir ordenamiento
        query += " ORDER BY ra.fecha_hora DESC"
        
        # Limitar a máximo 10,000 registros para evitar sobrecarga
        query += " LIMIT 10000"
        
        # Ejecutar consulta
        logs = execute_query(query, params)
        
        # Procesar resultados
        processed_logs = []
        for log in logs:
            # Formatear fechas para JSON
            if 'fecha_hora' in log and log['fecha_hora']:
                log['fecha_hora'] = log['fecha_hora'].isoformat()
            
            # Deserializar campo detalles
            if 'detalles' in log and log['detalles']:
                try:
                    log['detalles'] = json.loads(log['detalles'])
                except:
                    # Si falla la deserialización, mantener como cadena
                    pass
            
            processed_logs.append(log)
        
        # Registrar la exportación en auditoría
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'exportar',
            'entidad_afectada': 'auditoria',
            'id_entidad_afectada': None,
            'detalles': json.dumps({
                'formato': export_format,
                'filtros': filtros,
                'registros_exportados': len(processed_logs)
            }),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        # Exportar según formato seleccionado
        if export_format == 'json':
            export_data = json.dumps(processed_logs, default=str)
            content_type = 'application/json'
            filename = f"audit_logs_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        else:  # CSV
            # Crear CSV en memoria
            output = io.StringIO()
            csv_writer = csv.writer(output)
            
            # Encabezados
            headers = [
                'ID', 'Fecha y Hora', 'ID Usuario', 'Nombre Usuario', 'Dirección IP',
                'Acción', 'Entidad Afectada', 'ID Entidad', 'Detalles', 'Resultado'
            ]
            csv_writer.writerow(headers)
            
            # Filas de datos
            for log in processed_logs:
                detalles = json.dumps(log['detalles']) if isinstance(log['detalles'], dict) else log['detalles']
                row = [
                    log['id_registro'],
                    log['fecha_hora'],
                    log['usuario_id'],
                    log['nombre_usuario'],
                    log['direccion_ip'],
                    log['accion'],
                    log['entidad_afectada'],
                    log['id_entidad_afectada'],
                    detalles,
                    log['resultado']
                ]
                csv_writer.writerow(row)
            
            export_data = output.getvalue()
            content_type = 'text/csv'
            filename = f"audit_logs_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # Preparar respuesta con datos exportados
        response = {
            'statusCode': 200,
            'headers': add_cors_headers({
                'Content-Type': content_type,
                'Content-Disposition': f'attachment; filename="{filename}"'
            }),
            'body': export_data,
            'isBase64Encoded': False
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Error al exportar logs de auditoría: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al exportar logs de auditoría: {str(e)}'})
        }

def get_user_activity(event, context):
    """Obtener actividad de un usuario específico"""
    try:
        # Validar sesión
        requesting_user_id, error_response = validate_session(event)
        if error_response:
            return error_response
        
        # Obtener ID del usuario
        user_id = event['pathParameters']['user_id']
        
        # Si no es el mismo usuario, verificar permiso de auditoría
        if requesting_user_id != user_id:
            _, error_response = validate_session(event, 'admin.auditoria')
            if error_response:
                return error_response
        
        # Verificar si el usuario existe
        user_query = """
        SELECT id_usuario, nombre_usuario, nombre, apellidos, email, estado,
               ultimo_acceso
        FROM usuarios
        WHERE id_usuario = %s
        """
        
        user_result = execute_query(user_query, (user_id,))
        
        if not user_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Usuario no encontrado'})
            }
        
        user = user_result[0]
        
        # Formatear fechas
        if 'ultimo_acceso' in user and user['ultimo_acceso']:
            user['ultimo_acceso'] = user['ultimo_acceso'].isoformat()
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 20))
        
        # Filtros
        start_date = query_params.get('start_date')
        end_date = query_params.get('end_date')
        accion = query_params.get('accion')
        entidad = query_params.get('entidad')
        
        # Consulta de actividad del usuario
        activity_query = """
        SELECT ra.id_registro, ra.fecha_hora, ra.direccion_ip, ra.accion, 
               ra.entidad_afectada, ra.id_entidad_afectada, 
               ra.detalles, ra.resultado
        FROM registros_auditoria ra
        WHERE ra.usuario_id = %s
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM registros_auditoria ra
        WHERE ra.usuario_id = %s
        """
        
        # Parámetros para las consultas
        params = [user_id]
        count_params = [user_id]
        
        # Añadir filtros
        if start_date:
            activity_query += " AND ra.fecha_hora >= %s"
            count_query += " AND ra.fecha_hora >= %s"
            params.append(start_date)
            count_params.append(start_date)
        
        if end_date:
            activity_query += " AND ra.fecha_hora <= %s"
            count_query += " AND ra.fecha_hora <= %s"
            params.append(end_date)
            count_params.append(end_date)
        
        if accion:
            activity_query += " AND ra.accion = %s"
            count_query += " AND ra.accion = %s"
            params.append(accion)
            count_params.append(accion)
        
        if entidad:
            activity_query += " AND ra.entidad_afectada = %s"
            count_query += " AND ra.entidad_afectada = %s"
            params.append(entidad)
            count_params.append(entidad)
        
        # Añadir ordenamiento y paginación
        activity_query += " ORDER BY ra.fecha_hora DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        activities = execute_query(activity_query, params)
        count_result = execute_query(count_query, count_params)
        
        total_activities = count_result[0]['total'] if count_result else 0
        total_pages = (total_activities + page_size - 1) // page_size if total_activities > 0 else 1
        
        # Procesar resultados
        for activity in activities:
            # Formatear fechas
            if 'fecha_hora' in activity and activity['fecha_hora']:
                activity['fecha_hora'] = activity['fecha_hora'].isoformat()
            
            # Deserializar detalles
            if 'detalles' in activity and activity['detalles']:
                try:
                    activity['detalles'] = json.loads(activity['detalles'])
                except:
                    pass
        
        # Obtener estadísticas de actividad
        stats_query = """
        SELECT 
            ra.accion, 
            COUNT(*) as count,
            MIN(ra.fecha_hora) as primera_accion,
            MAX(ra.fecha_hora) as ultima_accion
        FROM registros_auditoria ra
        WHERE ra.usuario_id = %s
        GROUP BY ra.accion
        ORDER BY count DESC
        """
        
        stats = execute_query(stats_query, (user_id,))
        
        # Formatear fechas en estadísticas
        for stat in stats:
            if 'primera_accion' in stat and stat['primera_accion']:
                stat['primera_accion'] = stat['primera_accion'].isoformat()
            if 'ultima_accion' in stat and stat['ultima_accion']:
                stat['ultima_accion'] = stat['ultima_accion'].isoformat()
        
        # Obtener estadísticas por entidad
        entity_stats_query = """
        SELECT 
            ra.entidad_afectada, 
            COUNT(*) as count
        FROM registros_auditoria ra
        WHERE ra.usuario_id = %s
        GROUP BY ra.entidad_afectada
        ORDER BY count DESC
        """
        
        entity_stats = execute_query(entity_stats_query, (user_id,))
        
        # Obtener sesiones del usuario
        sessions_query = """
        SELECT id_sesion, fecha_inicio, fecha_expiracion, direccion_ip, 
               user_agent, activa
        FROM sesiones
        WHERE id_usuario = %s
        ORDER BY fecha_inicio DESC
        LIMIT 10
        """
        
        sessions = execute_query(sessions_query, (user_id,))
        
        # Formatear fechas en sesiones
        for session in sessions:
            if 'fecha_inicio' in session and session['fecha_inicio']:
                session['fecha_inicio'] = session['fecha_inicio'].isoformat()
            if 'fecha_expiracion' in session and session['fecha_expiracion']:
                session['fecha_expiracion'] = session['fecha_expiracion'].isoformat()
        
        # Preparar respuesta
        response = {
            'usuario': user,
            'actividad': activities,
            'estadisticas': {
                'por_accion': stats,
                'por_entidad': entity_stats
            },
            'sesiones_recientes': sessions,
            'pagination': {
                'total': total_activities,
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
        logger.error(f"Error al obtener actividad del usuario: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener actividad del usuario: {str(e)}'})
        }

def get_document_activity(event, context):
    """Obtener actividad relacionada con un documento específico"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener ID del documento
        document_id = event['pathParameters']['document_id']
        
        # Verificar si el documento existe y el usuario tiene acceso a él
        doc_query = """
        SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
               d.id_tipo_documento, td.nombre_tipo as tipo_documento,
               d.version_actual, d.creado_por, d.id_carpeta
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE d.id_documento = %s AND d.estado != 'eliminado'
        """
        
        doc_result = execute_query(doc_query, (document_id,))
        
        if not doc_result:
            return {
                'statusCode': 404,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Documento no encontrado o eliminado'})
            }
        
        documento = doc_result[0]
        
        # Verificar permisos para ver el documento
        if documento['creado_por'] != user_id:
            # Verificar si el usuario tiene permiso para la carpeta
            folder_access_query = """
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
            
            if documento['id_carpeta']:
                access_result = execute_query(folder_access_query, (documento['id_carpeta'], user_id, user_id))
                if not access_result or access_result[0]['has_access'] == 0:
                    # Verificar si tiene permiso administrativo
                    admin_query = """
                    SELECT COUNT(*) as is_admin
                    FROM usuarios_roles ur
                    JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
                    JOIN permisos p ON rp.id_permiso = p.id_permiso
                    WHERE ur.id_usuario = %s AND p.codigo_permiso = 'admin.documentos'
                    """
                    
                    admin_result = execute_query(admin_query, (user_id,))
                    if not admin_result or admin_result[0]['is_admin'] == 0:
                        return {
                            'statusCode': 403,
                            'headers': add_cors_headers({'Content-Type': 'application/json'}),
                            'body': json.dumps({'error': 'No tiene permisos para ver la actividad de este documento'})
                        }
            else:
                # Si no está en una carpeta y no es el creador
                admin_query = """
                SELECT COUNT(*) as is_admin
                FROM usuarios_roles ur
                JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
                JOIN permisos p ON rp.id_permiso = p.id_permiso
                WHERE ur.id_usuario = %s AND p.codigo_permiso = 'admin.documentos'
                """
                
                admin_result = execute_query(admin_query, (user_id,))
                if not admin_result or admin_result[0]['is_admin'] == 0:
                    return {
                        'statusCode': 403,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'No tiene permisos para ver la actividad de este documento'})
                    }
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 20))
        
        # Filtros adicionales
        start_date = query_params.get('start_date')
        end_date = query_params.get('end_date')
        
        # Construir consulta para la actividad del documento
        activity_query = """
        SELECT ra.id_registro, ra.fecha_hora, ra.usuario_id, u.nombre_usuario,
               ra.direccion_ip, ra.accion, ra.detalles, ra.resultado
        FROM registros_auditoria ra
        LEFT JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE (
            (ra.entidad_afectada = 'documento' AND ra.id_entidad_afectada = %s)
            OR
            (ra.entidad_afectada = 'version_documento' AND ra.id_entidad_afectada IN (
                SELECT id_version
                FROM versiones_documento
                WHERE id_documento = %s
            ))
        )
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM registros_auditoria ra
        WHERE (
            (ra.entidad_afectada = 'documento' AND ra.id_entidad_afectada = %s)
            OR
            (ra.entidad_afectada = 'version_documento' AND ra.id_entidad_afectada IN (
                SELECT id_version
                FROM versiones_documento
                WHERE id_documento = %s
            ))
        )
        """
        
        # Parámetros para las consultas
        params = [document_id, document_id]
        count_params = [document_id, document_id]
        
        # Añadir filtros de fecha
        if start_date:
            activity_query += " AND ra.fecha_hora >= %s"
            count_query += " AND ra.fecha_hora >= %s"
            params.append(start_date)
            count_params.append(start_date)
        
        if end_date:
            activity_query += " AND ra.fecha_hora <= %s"
            count_query += " AND ra.fecha_hora <= %s"
            params.append(end_date)
            count_params.append(end_date)
        
        # Añadir ordenamiento y paginación
        activity_query += " ORDER BY ra.fecha_hora DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        activities = execute_query(activity_query, params)
        count_result = execute_query(count_query, count_params)
        
        total_activities = count_result[0]['total'] if count_result else 0
        total_pages = (total_activities + page_size - 1) // page_size if total_activities > 0 else 1
        
        # Procesar resultados
        for activity in activities:
            # Formatear fechas
            if 'fecha_hora' in activity and activity['fecha_hora']:
                activity['fecha_hora'] = activity['fecha_hora'].isoformat()
            
            # Deserializar detalles
            if 'detalles' in activity and activity['detalles']:
                try:
                    activity['detalles'] = json.loads(activity['detalles'])
                except:
                    pass
        
        # Obtener historial de versiones del documento
        versions_query = """
        SELECT v.id_version, v.numero_version, v.fecha_creacion,
               v.creado_por, u.nombre_usuario as creado_por_nombre,
               v.comentario_version, v.tamano_bytes, v.hash_contenido
        FROM versiones_documento v
        JOIN usuarios u ON v.creado_por = u.id_usuario
        WHERE v.id_documento = %s
        ORDER BY v.numero_version DESC
        """
        
        versions = execute_query(versions_query, (document_id,))
        
        # Formatear fechas en versiones
        for version in versions:
            if 'fecha_creacion' in version and version['fecha_creacion']:
                version['fecha_creacion'] = version['fecha_creacion'].isoformat()
        
        # Preparar respuesta
        response = {
            'documento': {
                'id': documento['id_documento'],
                'codigo': documento['codigo_documento'],
                'titulo': documento['titulo'],
                'tipo_documento': documento['tipo_documento'],
                'version_actual': documento['version_actual']
            },
            'actividad': activities,
            'versiones': versions,
            'pagination': {
                'total': total_activities,
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
        logger.error(f"Error al obtener actividad del documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener actividad del documento: {str(e)}'})
        }

def get_security_events(event, context):
    """Obtener eventos de seguridad del sistema"""
    try:
        # Validar sesión con permiso administrativo de seguridad
        user_id, error_response = validate_session(event, 'admin.seguridad')
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 50))
        
        # Filtros de fecha
        start_date = query_params.get('start_date')
        end_date = query_params.get('end_date')
        
        # Construir consulta para eventos de seguridad
        # Los eventos de seguridad son login, logout, validacion, expiracion y otros relacionados con acceso
        security_query = """
        SELECT ra.id_registro, ra.fecha_hora, ra.usuario_id, u.nombre_usuario,
               ra.direccion_ip, ra.accion, ra.entidad_afectada, 
               ra.id_entidad_afectada, ra.detalles, ra.resultado
        FROM registros_auditoria ra
        LEFT JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE ra.accion IN ('login', 'logout', 'validacion', 'expiracion', 'invalidacion', 
                         'solicitud_reset', 'reset_password', 'cambio_password',
                         'verificacion_2fa', 'configurar_2fa', 'renovacion')
           OR (ra.entidad_afectada = 'sesion')
           OR (ra.resultado = 'error' AND ra.accion IN ('ver', 'modificar', 'eliminar', 'crear'))
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM registros_auditoria ra
        WHERE ra.accion IN ('login', 'logout', 'validacion', 'expiracion', 'invalidacion', 
                         'solicitud_reset', 'reset_password', 'cambio_password',
                         'verificacion_2fa', 'configurar_2fa', 'renovacion')
           OR (ra.entidad_afectada = 'sesion')
           OR (ra.resultado = 'error' AND ra.accion IN ('ver', 'modificar', 'eliminar', 'crear'))
        """
        
        # Parámetros para las consultas
        params = []
        count_params = []
        
        # Añadir filtros de fecha
        if start_date:
            security_query += " AND ra.fecha_hora >= %s"
            count_query += " AND ra.fecha_hora >= %s"
            params.append(start_date)
            count_params.append(start_date)
        
        if end_date:
            security_query += " AND ra.fecha_hora <= %s"
            count_query += " AND ra.fecha_hora <= %s"
            params.append(end_date)
            count_params.append(end_date)
        
        # Añadir ordenamiento y paginación
        security_query += " ORDER BY ra.fecha_hora DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        events = execute_query(security_query, params)
        count_result = execute_query(count_query, count_params)
        
        total_events = count_result[0]['total'] if count_result else 0
        total_pages = (total_events + page_size - 1) // page_size if total_events > 0 else 1
        
        # Procesar resultados
        for event_item in events:
            # Formatear fechas
            if 'fecha_hora' in event_item and event_item['fecha_hora']:
                event_item['fecha_hora'] = event_item['fecha_hora'].isoformat()
            
            # Deserializar detalles
            if 'detalles' in event_item and event_item['detalles']:
                try:
                    event_item['detalles'] = json.loads(event_item['detalles'])
                except:
                    pass
        
        # Obtener estadísticas de seguridad
        # 1. Intentos de login fallidos en las últimas 24 horas
        failed_logins_query = """
        SELECT COUNT(*) as count
        FROM registros_auditoria
        WHERE accion = 'login' 
          AND resultado = 'error'
          AND fecha_hora >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """
        
        failed_logins = execute_query(failed_logins_query)
        failed_login_count = failed_logins[0]['count'] if failed_logins else 0
        
        # 2. Distribución de resultados de eventos de seguridad
        results_dist_query = """
        SELECT resultado, COUNT(*) as count
        FROM registros_auditoria
        WHERE accion IN ('login', 'logout', 'validacion', 'expiracion', 'invalidacion', 
                      'solicitud_reset', 'reset_password', 'cambio_password',
                      'verificacion_2fa', 'configurar_2fa', 'renovacion')
           OR (entidad_afectada = 'sesion')
        GROUP BY resultado
        """
        
        results_dist = execute_query(results_dist_query)
        
        # 3. Top 10 IPs con más errores de login
        top_ips_query = """
        SELECT direccion_ip, COUNT(*) as count
        FROM registros_auditoria
        WHERE accion = 'login' AND resultado = 'error'
        GROUP BY direccion_ip
        ORDER BY count DESC
        LIMIT 10
        """
        
        top_error_ips = execute_query(top_ips_query)
        
        # 4. Cambios de contraseña en el último mes
        password_changes_query = """
        SELECT DATE(fecha_hora) as fecha, COUNT(*) as count
        FROM registros_auditoria
        WHERE accion = 'cambio_password'
        AND fecha_hora >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY DATE(fecha_hora)
        ORDER BY fecha
        """
        
        password_changes = execute_query(password_changes_query)
        
        # Formatear fechas en cambios de contraseña
        for change in password_changes:
            if 'fecha' in change and change['fecha']:
                change['fecha'] = change['fecha'].isoformat()
        
        # Preparar respuesta
        response = {
            'eventos': events,
            'estadisticas': {
                'intentos_login_fallidos_24h': failed_login_count,
                'distribucion_resultados': results_dist,
                'top_ips_error': top_error_ips,
                'cambios_password_ultimo_mes': password_changes
            },
            'pagination': {
                'total': total_events,
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
        logger.error(f"Error al obtener eventos de seguridad: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener eventos de seguridad: {str(e)}'})
        }

def get_clients_with_documents_activity(event, context):
    """Obtener todos los clientes con sus documentos y actividad limitada"""
    try:
        # Validar sesión
        user_id, error_response = validate_session(event, 'documentos.ver')
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Paginación para clientes
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filtros opcionales
        estado_cliente = query_params.get('estado_cliente')  # activo, inactivo, prospecto
        tipo_cliente = query_params.get('tipo_cliente')      # persona_fisica, empresa, organismo_publico
        segmento = query_params.get('segmento')             # retail, premium, etc.
        
        # Query principal para obtener clientes
        clients_query = """
        SELECT c.id_cliente, c.codigo_cliente, c.tipo_cliente, c.nombre_razon_social,
               c.documento_identificacion, c.estado, c.segmento, c.segmento_bancario,
               c.nivel_riesgo, c.estado_documental, c.fecha_alta,
               u.nombre_usuario as gestor_principal
        FROM clientes c
        LEFT JOIN usuarios u ON c.gestor_principal_id = u.id_usuario
        WHERE 1=1
        """
        
        count_query = """
        SELECT COUNT(*) as total
        FROM clientes c
        WHERE 1=1
        """
        
        params = []
        count_params = []
        
        # Aplicar filtros
        if estado_cliente:
            clients_query += " AND c.estado = %s"
            count_query += " AND c.estado = %s"
            params.append(estado_cliente)
            count_params.append(estado_cliente)
        
        if tipo_cliente:
            clients_query += " AND c.tipo_cliente = %s"
            count_query += " AND c.tipo_cliente = %s"
            params.append(tipo_cliente)
            count_params.append(tipo_cliente)
        
        if segmento:
            clients_query += " AND c.segmento = %s"
            count_query += " AND c.segmento = %s"
            params.append(segmento)
            count_params.append(segmento)
        
        # Ordenamiento y paginación
        clients_query += " ORDER BY c.fecha_alta DESC LIMIT %s OFFSET %s"
        params.append(page_size)
        params.append((page - 1) * page_size)
        
        # Ejecutar consultas
        clients = execute_query(clients_query, params)
        count_result = execute_query(count_query, count_params)
        
        total_clients = count_result[0]['total'] if count_result else 0
        total_pages = (total_clients + page_size - 1) // page_size if total_clients > 0 else 1
        
        # Para cada cliente, obtener sus documentos
        for client in clients:
            client_id = client['id_cliente']
            
            # Formatear fecha
            if 'fecha_alta' in client and client['fecha_alta']:
                client['fecha_alta'] = client['fecha_alta'].isoformat()
            
            # Obtener documentos del cliente
            documents_query = """
            SELECT d.id_documento, d.codigo_documento, d.titulo, d.descripcion,
                   d.version_actual, d.fecha_creacion, d.estado,
                   td.nombre_tipo as tipo_documento,
                   dc.fecha_asignacion
            FROM documentos_clientes dc
            JOIN documentos d ON dc.id_documento = d.id_documento
            JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
            WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
            ORDER BY dc.fecha_asignacion DESC
            """
            
            documents = execute_query(documents_query, (client_id,))
            
            # Para cada documento, obtener las últimas 5 actividades
            for document in documents:
                document_id = document['id_documento']
                
                # Formatear fechas del documento
                if 'fecha_creacion' in document and document['fecha_creacion']:
                    document['fecha_creacion'] = document['fecha_creacion'].isoformat()
                if 'fecha_asignacion' in document and document['fecha_asignacion']:
                    document['fecha_asignacion'] = document['fecha_asignacion'].isoformat()
                
                # Obtener últimas 5 actividades del documento
                activity_query = """
                SELECT ra.id_registro, ra.fecha_hora, ra.usuario_id, u.nombre_usuario,
                       ra.direccion_ip, ra.accion, ra.detalles, ra.resultado
                FROM registros_auditoria ra
                LEFT JOIN usuarios u ON ra.usuario_id = u.id_usuario
                WHERE (
                    (ra.entidad_afectada = 'documento' AND ra.id_entidad_afectada = %s)
                    OR
                    (ra.entidad_afectada = 'version_documento' AND ra.id_entidad_afectada IN (
                        SELECT id_version
                        FROM versiones_documento
                        WHERE id_documento = %s
                    ))
                )
                ORDER BY ra.fecha_hora DESC
                LIMIT 5
                """
                
                activities = execute_query(activity_query, (document_id, document_id))
                
                # Procesar actividades
                for activity in activities:
                    # Formatear fechas
                    if 'fecha_hora' in activity and activity['fecha_hora']:
                        activity['fecha_hora'] = activity['fecha_hora'].isoformat()
                    
                    # Deserializar detalles
                    if 'detalles' in activity and activity['detalles']:
                        try:
                            activity['detalles'] = json.loads(activity['detalles'])
                        except:
                            pass
                
                # Obtener conteo total de actividades para este documento
                total_activity_query = """
                SELECT COUNT(*) as total_activities
                FROM registros_auditoria ra
                WHERE (
                    (ra.entidad_afectada = 'documento' AND ra.id_entidad_afectada = %s)
                    OR
                    (ra.entidad_afectada = 'version_documento' AND ra.id_entidad_afectada IN (
                        SELECT id_version
                        FROM versiones_documento
                        WHERE id_documento = %s
                    ))
                )
                """
                
                total_activity_result = execute_query(total_activity_query, (document_id, document_id))
                total_activities_count = total_activity_result[0]['total_activities'] if total_activity_result else 0
                
                # Agregar actividades al documento
                document['actividades'] = activities
                document['total_actividades'] = total_activities_count
                document['mostrando_actividades'] = len(activities)
            
            # Obtener conteo de documentos del cliente
            doc_count_query = """
            SELECT COUNT(*) as total_documentos
            FROM documentos_clientes dc
            JOIN documentos d ON dc.id_documento = d.id_documento
            WHERE dc.id_cliente = %s AND d.estado != 'eliminado'
            """
            
            doc_count_result = execute_query(doc_count_query, (client_id,))
            total_documents_count = doc_count_result[0]['total_documentos'] if doc_count_result else 0
            
            # Agregar documentos al cliente
            client['documentos'] = documents
            client['total_documentos'] = total_documents_count
        
        # Preparar respuesta
        response = {
            'clientes': clients,
            'pagination': {
                'total': total_clients,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            },
            'summary': {
                'total_clientes': total_clients,
                'clientes_en_pagina': len(clients),
                'limite_actividades_por_documento': 5
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error al obtener clientes con documentos y actividad: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al obtener clientes con documentos y actividad: {str(e)}'})
        }        