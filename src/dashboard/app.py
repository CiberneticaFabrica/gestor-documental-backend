# src/dashboard_metrics/app.py
import os
import json
import logging
import datetime
from decimal import Decimal

from common.db import (
    execute_query,
    get_connection
)

from common.headers import add_cors_headers

# Configuración del logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

class DecimalEncoder(json.JSONEncoder):
    """Encoder personalizado para manejar objetos Decimal en JSON"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

def lambda_handler(event, context):
    """Manejador principal para la función de métricas del dashboard"""
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
        
        # Validar autenticación básica
        auth_header = event.get('headers', {}).get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Autorización requerida'})
            }
        
        session_token = auth_header.split(' ')[1]
        user_id, error_response = validate_session(session_token)
        if error_response:
            return error_response
        
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        period = query_params.get('period', 'month')  # Periodo: day, week, month, year
        start_date = query_params.get('start_date')
        end_date = query_params.get('end_date')
        
        # Si no se especifican fechas, establecer defaults en función del periodo
        if not start_date or not end_date:
            end_date = datetime.datetime.now()
            if period == 'day':
                start_date = end_date - datetime.timedelta(days=1)
            elif period == 'week':
                start_date = end_date - datetime.timedelta(days=7)
            elif period == 'month':
                start_date = end_date - datetime.timedelta(days=30)
            elif period == 'year':
                start_date = end_date - datetime.timedelta(days=365)
            else:  # Por defecto, último mes
                start_date = end_date - datetime.timedelta(days=30)
                period = 'month'
            
            start_date = start_date.strftime('%Y-%m-%d')
            end_date = end_date.strftime('%Y-%m-%d')
        
        # Si solo se solicita una sección específica
        section = query_params.get('section')
        if section:
            section = section.lower()
            if section == 'summary':
                metrics = get_summary_metrics(user_id, start_date, end_date)
            elif section == 'processing':
                metrics = get_processing_metrics(user_id, start_date, end_date)
            elif section == 'classification':
                metrics = get_classification_accuracy(user_id, start_date, end_date)
            elif section == 'extraction':
                metrics = get_extraction_confidence(user_id, start_date, end_date)
            elif section == 'volume':
                metrics = get_document_volume_trends(user_id, start_date, end_date, period)
            elif section == 'processing_times':
                metrics = get_processing_times(user_id, start_date, end_date)
            elif section == 'compliance':
                metrics = get_compliance_status(user_id, start_date, end_date)
            elif section == 'expiring_documents':
                metrics = get_expiring_documents(user_id)
            elif section == 'recent_activity':
                metrics = get_recent_activity(user_id, limit=query_params.get('limit', 10))
            else:
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f'Sección no válida: {section}'})
                }
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps(metrics, cls=DecimalEncoder)
            }
        
        # Si no se especifica sección, devolver todas las métricas
        metrics = {
            'summary': get_summary_metrics(user_id, start_date, end_date),
            'processing': get_processing_metrics(user_id, start_date, end_date),
            'classification': get_classification_accuracy(user_id, start_date, end_date),
            'extraction': get_extraction_confidence(user_id, start_date, end_date),
            'volume': get_document_volume_trends(user_id, start_date, end_date, period),
            'processing_times': get_processing_times(user_id, start_date, end_date),
            'compliance': get_compliance_status(user_id, start_date, end_date),
            'expiring_documents': get_expiring_documents(user_id),
            'recent_activity': get_recent_activity(user_id, limit=10)
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(metrics, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error en el manejador de métricas: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error interno del servidor: {str(e)}'})
        }

def validate_session(session_token):
    """Valida la sesión y devuelve el ID de usuario"""
    try:
        # Verificar si la sesión existe y está activa
        check_query = """
        SELECT s.id_usuario, s.activa, s.fecha_expiracion, u.estado
        FROM sesiones s
        JOIN usuarios u ON s.id_usuario = u.id_usuario
        WHERE s.id_sesion = %s
        """
        
        session_result = execute_query(check_query, (session_token,))
        
        if not session_result:
            return None, {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión inválida'})
            }
        
        session = session_result[0]
        
        if not session['activa']:
            return None, {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión inactiva'})
            }
        
        if session['fecha_expiracion'] < datetime.datetime.now():
            return None, {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Sesión expirada'})
            }
        
        if session['estado'] != 'activo':
            return None, {
                'statusCode': 401,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Usuario inactivo'})
            }
        
        # Verificar permisos para acceder a las métricas del dashboard
        perm_query = """
        SELECT COUNT(*) as has_permission
        FROM usuarios_roles ur
        JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
        JOIN permisos p ON rp.id_permiso = p.id_permiso
        WHERE ur.id_usuario = %s 
        AND (p.codigo_permiso = 'admin.dashboard' OR p.codigo_permiso = 'documentos.ver')
        """
        
        perm_result = execute_query(perm_query, (session['id_usuario'],))
        
        if not perm_result or perm_result[0]['has_permission'] == 0:
            return None, {
                'statusCode': 403,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'No tiene permisos para acceder a las métricas del dashboard'})
            }
        
        return session['id_usuario'], None
        
    except Exception as e:
        logger.error(f"Error al validar sesión: {str(e)}")
        return None, {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error al validar sesión: {str(e)}'})
        }

def get_summary_metrics(user_id, start_date, end_date):
    """Obtiene un resumen de las métricas principales"""
    try:
        # Total de documentos
        total_docs_query = """
        SELECT COUNT(*) as total_documents
        FROM documentos
        WHERE estado != 'eliminado'
        """
        
        total_docs_result = execute_query(total_docs_query)
        total_documents = total_docs_result[0]['total_documents'] if total_docs_result else 0
        
        # Total de usuarios
        users_query = """
        SELECT COUNT(*) as total_users
        FROM usuarios
        WHERE estado = 'activo'
        """
        
        users_result = execute_query(users_query)
        total_users = users_result[0]['total_users'] if users_result else 0
        
        # Total de carpetas
        folders_query = """
        SELECT COUNT(*) as total_folders
        FROM carpetas
        """
        
        folders_result = execute_query(folders_query)
        total_folders = folders_result[0]['total_folders'] if folders_result else 0
        
        # Documentos pendientes
        pending_docs_query = """
        SELECT COUNT(*) as pending_documents
        FROM documentos
        WHERE estado = 'borrador'
        """
        
        pending_docs_result = execute_query(pending_docs_query)
        pending_documents = pending_docs_result[0]['pending_documents'] if pending_docs_result else 0
        
        # Total de documentos procesados (con análisis de IA)
        processed_docs_query = """
        SELECT COUNT(*) as processed_documents
        FROM analisis_documento_ia
        WHERE estado_analisis = 'procesado'
        """
        
        processed_docs_result = execute_query(processed_docs_query)
        processed_documents = processed_docs_result[0]['processed_documents'] if processed_docs_result else 0
        
        # Tasa de éxito (procesados correctamente / total procesados)
        success_rate_query = """
        SELECT 
            COUNT(*) as total_processed,
            SUM(CASE WHEN estado_analisis = 'procesado' THEN 1 ELSE 0 END) as successful_processed
        FROM analisis_documento_ia
        """
        
        success_rate_result = execute_query(success_rate_query)
        if success_rate_result and success_rate_result[0]['total_processed'] > 0:
            success_rate = (success_rate_result[0]['successful_processed'] / success_rate_result[0]['total_processed']) * 100
        else:
            success_rate = 0
        
        # Documentos pendientes de procesar (colas)
        queue_query = """
        SELECT COUNT(*) as queue_documents
        FROM documentos d
        LEFT JOIN analisis_documento_ia a ON d.id_documento = a.id_documento
        WHERE d.estado = 'borrador' AND a.id_analisis IS NULL
        """
        
        queue_result = execute_query(queue_query)
        queue_documents = queue_result[0]['queue_documents'] if queue_result else 0
        
        # Documentos que requieren revisión manual
        manual_review_query = """
        SELECT COUNT(*) as manual_review
        FROM analisis_documento_ia
        WHERE requiere_verificacion = 1 AND verificado = 0
        """
        
        manual_review_result = execute_query(manual_review_query)
        manual_review = manual_review_result[0]['manual_review'] if manual_review_result else 0
        
        # Documentos vencidos o por vencer (usando la función auxiliar)
        expiring_docs = get_expiring_documents(user_id)
        
        return {
            'total_documents': total_documents,
            'total_users': total_users,
            'total_folders': total_folders,
            'pending_documents': pending_documents,
            'processed_documents': processed_documents,
            'success_rate': success_rate,
            'queue_documents': queue_documents,
            'manual_review': manual_review,
            'expiring_documents': {
                'expired': expiring_docs['expired'],
                'expiring_5_days': expiring_docs['expiring_5_days'],
                'expiring_15_days': expiring_docs['expiring_15_days'],
                'expiring_30_days': expiring_docs['expiring_30_days'],
            }
        }
        
    except Exception as e:
        logger.error(f"Error al obtener métricas de resumen: {str(e)}")
        return {'error': str(e)}

def get_processing_metrics(user_id, start_date, end_date):
    """Obtiene métricas de procesamiento de documentos"""
    try:
        # Métricas de procesamiento por tipo
        processing_query = """
        SELECT 
            tipo_proceso,
            COUNT(*) as total_processed,
            SUM(CASE WHEN estado_proceso = 'completado' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN estado_proceso = 'error' THEN 1 ELSE 0 END) as errors,
            SUM(CASE WHEN estado_proceso = 'advertencia' THEN 1 ELSE 0 END) as warnings,
            AVG(duracion_ms) as avg_duration_ms
        FROM registro_procesamiento_documento
        WHERE timestamp_inicio BETWEEN %s AND %s
        GROUP BY tipo_proceso
        """
        
        processing_result = execute_query(processing_query, (start_date, end_date))
        
        # Errores por tipo de proceso
        errors_query = """
        SELECT 
            tipo_proceso,
            mensaje_error,
            COUNT(*) as count
        FROM registro_procesamiento_documento
        WHERE estado_proceso = 'error'
            AND timestamp_inicio BETWEEN %s AND %s
        GROUP BY tipo_proceso, mensaje_error
        ORDER BY count DESC
        LIMIT 10
        """
        
        errors_result = execute_query(errors_query, (start_date, end_date))
        
        # Estadísticas de procesamiento por día
        daily_stats_query = """
        SELECT 
            DATE(timestamp_inicio) as day,
            COUNT(*) as total_processed,
            SUM(CASE WHEN estado_proceso = 'completado' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN estado_proceso = 'error' THEN 1 ELSE 0 END) as errors
        FROM registro_procesamiento_documento
        WHERE timestamp_inicio BETWEEN %s AND %s
        GROUP BY DATE(timestamp_inicio)
        ORDER BY day ASC
        """
        
        daily_stats_result = execute_query(daily_stats_query, (start_date, end_date))
        
        # Formatear fechas para JSON
        for stat in daily_stats_result:
            if 'day' in stat and stat['day']:
                stat['day'] = stat['day'].isoformat()
        
        return {
            'processing_by_type': processing_result,
            'errors_by_type': errors_result,
            'daily_stats': daily_stats_result
        }
        
    except Exception as e:
        logger.error(f"Error al obtener métricas de procesamiento: {str(e)}")
        return {'error': str(e)}

def get_classification_accuracy(user_id, start_date, end_date):
    """Obtiene métricas de precisión de clasificación"""
    try:
        # Precisión de clasificación global
        accuracy_query = """
        SELECT 
            AVG(confianza_clasificacion) as avg_confidence,
            MIN(confianza_clasificacion) as min_confidence,
            MAX(confianza_clasificacion) as max_confidence
        FROM analisis_documento_ia
        WHERE fecha_analisis BETWEEN %s AND %s
            AND confianza_clasificacion IS NOT NULL
        """
        
        accuracy_result = execute_query(accuracy_query, (start_date, end_date))
        
        # Documentos verificados manualmente vs. automáticos
        verification_query = """
        SELECT 
            SUM(CASE WHEN verificado = 1 THEN 1 ELSE 0 END) as verified,
            SUM(CASE WHEN verificado = 0 THEN 1 ELSE 0 END) as not_verified,
            COUNT(*) as total
        FROM analisis_documento_ia
        WHERE fecha_analisis BETWEEN %s AND %s
        """
        
        verification_result = execute_query(verification_query, (start_date, end_date))
        
        # Precisión por tipo de documento
        accuracy_by_type_query = """
        SELECT 
            tipo_documento,
            COUNT(*) as count,
            AVG(confianza_clasificacion) as avg_confidence
        FROM analisis_documento_ia
        WHERE fecha_analisis BETWEEN %s AND %s
            AND confianza_clasificacion IS NOT NULL
        GROUP BY tipo_documento
        ORDER BY avg_confidence DESC
        """
        
        accuracy_by_type_result = execute_query(accuracy_by_type_query, (start_date, end_date))
        
        return {
            'global_accuracy': accuracy_result[0] if accuracy_result else {},
            'verification_stats': verification_result[0] if verification_result else {},
            'accuracy_by_type': accuracy_by_type_result
        }
        
    except Exception as e:
        logger.error(f"Error al obtener métricas de precisión de clasificación: {str(e)}")
        return {'error': str(e)}

def get_extraction_confidence(user_id, start_date, end_date):
    """Obtiene métricas de confianza de extracción"""
    try:
        # Confianza de extracción global
        confidence_query = """
        SELECT 
            AVG(confianza_extraccion) as avg_confidence,
            MIN(confianza_extraccion) as min_confidence,
            MAX(confianza_extraccion) as max_confidence
        FROM documentos
        WHERE fecha_modificacion BETWEEN %s AND %s
            AND confianza_extraccion IS NOT NULL
        """
        
        confidence_result = execute_query(confidence_query, (start_date, end_date))
        
        # Distribución de confianza de extracción
        distribution_query = """
        SELECT 
            CASE 
                WHEN confianza_extraccion >= 0.9 THEN 'Muy alta (90-100%)'
                WHEN confianza_extraccion >= 0.8 THEN 'Alta (80-89%)'
                WHEN confianza_extraccion >= 0.7 THEN 'Media (70-79%)'
                WHEN confianza_extraccion >= 0.6 THEN 'Baja (60-69%)'
                ELSE 'Muy baja (<60%)'
            END as confidence_range,
            COUNT(*) as count
        FROM documentos
        WHERE fecha_modificacion BETWEEN %s AND %s
            AND confianza_extraccion IS NOT NULL
        GROUP BY confidence_range
        ORDER BY MIN(confianza_extraccion) DESC
        """
        
        distribution_result = execute_query(distribution_query, (start_date, end_date))
        
        # Documentos con entidades detectadas
        entities_query = """
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN entidades_detectadas IS NOT NULL 
                      AND entidades_detectadas != '{}' 
                      AND entidades_detectadas != '[]' 
                      THEN 1 ELSE 0 END) as with_entities
        FROM analisis_documento_ia
        WHERE fecha_analisis BETWEEN %s AND %s
        """
        
        entities_result = execute_query(entities_query, (start_date, end_date))
        
        # Métricas de calidad de extracción
        quality_metrics = {
            'avg_confidence': confidence_result[0]['avg_confidence'] if confidence_result else 0,
            'distribution': distribution_result,
            'entities_detection': entities_result[0] if entities_result else {}
        }
        
        # Revisar validaciones manuales
        manual_validations_query = """
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN validado_manualmente = 1 THEN 1 ELSE 0 END) as manually_validated
        FROM documentos
        WHERE fecha_modificacion BETWEEN %s AND %s
        """
        
        validations_result = execute_query(manual_validations_query, (start_date, end_date))
        
        return {
            'confidence_metrics': confidence_result[0] if confidence_result else {},
            'confidence_distribution': distribution_result,
            'entities_detection': entities_result[0] if entities_result else {},
            'manual_validations': validations_result[0] if validations_result else {},
            'quality_metrics': quality_metrics
        }
        
    except Exception as e:
        logger.error(f"Error al obtener métricas de confianza de extracción: {str(e)}")
        return {'error': str(e)}

def get_document_volume_trends(user_id, start_date, end_date, period='month'):
    """Obtiene tendencias de volumen de documentos"""
    try:
        # Determinar el formato de agrupación según el período
        if period == 'day':
            group_format = 'DATE(fecha_creacion)'
            unit_label = 'day'
        elif period == 'week':
            group_format = 'YEARWEEK(fecha_creacion)'
            unit_label = 'week'
        elif period == 'month':
            group_format = 'DATE_FORMAT(fecha_creacion, "%Y-%m")'
            unit_label = 'month'
        elif period == 'year':
            group_format = 'YEAR(fecha_creacion)'
            unit_label = 'year'
        else:
            group_format = 'DATE(fecha_creacion)'
            unit_label = 'day'
        
        # Tendencias de volumen por período
        volume_query = f"""
        SELECT 
            {group_format} as time_unit,
            COUNT(*) as document_count
        FROM documentos
        WHERE fecha_creacion BETWEEN %s AND %s
            AND estado != 'eliminado'
        GROUP BY time_unit
        ORDER BY time_unit ASC
        """
        
        volume_result = execute_query(volume_query, (start_date, end_date))
        
        # Volumen por tipo de documento
        type_query = """
        SELECT 
            td.nombre_tipo,
            COUNT(*) as document_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE d.fecha_creacion BETWEEN %s AND %s
            AND d.estado != 'eliminado'
        GROUP BY td.nombre_tipo
        ORDER BY document_count DESC
        LIMIT 10
        """
        
        type_result = execute_query(type_query, (start_date, end_date))
        
        # Volumen por estado
        status_query = """
        SELECT 
            estado,
            COUNT(*) as document_count
        FROM documentos
        WHERE fecha_creacion BETWEEN %s AND %s
            AND estado != 'eliminado'
        GROUP BY estado
        ORDER BY document_count DESC
        """
        
        status_result = execute_query(status_query, (start_date, end_date))
        
        # Sumarizar la tendencia
        total_documents = sum(item['document_count'] for item in volume_result) if volume_result else 0
        
        # Calcular crecimiento
        growth = 0
        if len(volume_result) >= 2:
            first_period = volume_result[0]['document_count']
            last_period = volume_result[-1]['document_count']
            if first_period > 0:
                growth = ((last_period - first_period) / first_period) * 100
        
        return {
            'period': period,
            'volume_trends': volume_result,
            'volume_by_type': type_result,
            'volume_by_status': status_result,
            'total_documents': total_documents,
            'growth_percentage': growth
        }
        
    except Exception as e:
        logger.error(f"Error al obtener tendencias de volumen: {str(e)}")
        return {'error': str(e)}

def get_processing_times(user_id, start_date, end_date):
    """Obtiene métricas de tiempos de procesamiento"""
    try:
        # Tiempo promedio de procesamiento por tipo
        time_query = """
        SELECT 
            tipo_proceso,
            COUNT(*) as total_processed,
            AVG(duracion_ms) as avg_duration_ms,
            MIN(duracion_ms) as min_duration_ms,
            MAX(duracion_ms) as max_duration_ms
        FROM registro_procesamiento_documento
        WHERE timestamp_inicio BETWEEN %s AND %s
            AND estado_proceso = 'completado'
            AND duracion_ms IS NOT NULL
        GROUP BY tipo_proceso
        ORDER BY avg_duration_ms DESC
        """
        
        time_result = execute_query(time_query, (start_date, end_date))
        
        # Tendencia de tiempos de procesamiento por día
        trend_query = """
        SELECT 
            DATE(timestamp_inicio) as day,
            tipo_proceso,
            AVG(duracion_ms) as avg_duration_ms
        FROM registro_procesamiento_documento
        WHERE timestamp_inicio BETWEEN %s AND %s
            AND estado_proceso = 'completado'
            AND duracion_ms IS NOT NULL
        GROUP BY DATE(timestamp_inicio), tipo_proceso
        ORDER BY day ASC, tipo_proceso
        """
        
        trend_result = execute_query(trend_query, (start_date, end_date))
        
        # Formatear fechas para JSON
        for trend in trend_result:
            if 'day' in trend and trend['day']:
                trend['day'] = trend['day'].isoformat()
        
        # Distribución de tiempos de procesamiento
        distribution_query = """
        SELECT 
            CASE 
                WHEN duracion_ms < 1000 THEN 'Menos de 1 segundo'
                WHEN duracion_ms < 5000 THEN '1-5 segundos'
                WHEN duracion_ms < 10000 THEN '5-10 segundos'
                WHEN duracion_ms < 30000 THEN '10-30 segundos'
                WHEN duracion_ms < 60000 THEN '30-60 segundos'
                ELSE 'Más de 1 minuto'
            END as duration_range,
            COUNT(*) as count
        FROM registro_procesamiento_documento
        WHERE timestamp_inicio BETWEEN %s AND %s
            AND estado_proceso = 'completado'
            AND duracion_ms IS NOT NULL
        GROUP BY duration_range
        ORDER BY MIN(duracion_ms) ASC
        """
        
        distribution_result = execute_query(distribution_query, (start_date, end_date))
        
        return {
            'processing_times': time_result,
            'time_trends': trend_result,
            'time_distribution': distribution_result
        }
        
    except Exception as e:
        logger.error(f"Error al obtener tiempos de procesamiento: {str(e)}")
        return {'error': str(e)}

def get_compliance_status(user_id, start_date, end_date):
    """Obtiene métricas de cumplimiento legal"""
    try:
        # Resumen de cumplimiento normativo
        compliance_query = """
        SELECT 
            cn.nombre_normativa,
            cn.fecha_implementacion,
            COUNT(DISTINCT d.id_documento) as document_count
        FROM cumplimiento_legal cn
        LEFT JOIN documentos d ON (
            d.estado != 'eliminado' AND
            d.metadatos IS NOT NULL AND
            JSON_CONTAINS_PATH(d.metadatos, 'one', '$.normativas')
        )
        GROUP BY cn.id_normativa
        ORDER BY document_count DESC
        """
        
        compliance_result = execute_query(compliance_query)
        
        # Formatear fechas para JSON
        for item in compliance_result:
            if 'fecha_implementacion' in item and item['fecha_implementacion']:
                item['fecha_implementacion'] = item['fecha_implementacion'].isoformat()
        
        # Documentos por revisar (pendientes de validación)
        pending_review_query = """
        SELECT 
            td.nombre_tipo,
            COUNT(*) as document_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN analisis_documento_ia a ON d.id_documento = a.id_documento
        WHERE d.estado = 'borrador'
            AND (a.requiere_verificacion = 1 OR a.id_analisis IS NULL)
        GROUP BY td.nombre_tipo
        ORDER BY document_count DESC
        """
        
        pending_review_result = execute_query(pending_review_query)
        
        # Documentos con alertas o incidencias
        alerts_query = """
        SELECT 
            COUNT(*) as total_documents,
            SUM(CASE WHEN alertas_documento IS NOT NULL 
                      AND alertas_documento != '{}' 
                      AND alertas_documento != '[]' 
                      THEN 1 ELSE 0 END) as documents_with_alerts
        FROM documentos
        WHERE estado != 'eliminado'
        """
        
        alerts_result = execute_query(alerts_query)
        
        # Actividad de auditoría
        audit_query = """
        SELECT 
            accion,
            entidad_afectada,
            COUNT(*) as action_count
        FROM registros_auditoria
        WHERE fecha_hora BETWEEN %s AND %s
        GROUP BY accion, entidad_afectada
        ORDER BY action_count DESC
        LIMIT 10
        """
        
        # Actividad de auditoría
        audit_query = """
        SELECT 
            accion,
            entidad_afectada,
            COUNT(*) as action_count
        FROM registros_auditoria
        WHERE fecha_hora BETWEEN %s AND %s
        GROUP BY accion, entidad_afectada
        ORDER BY action_count DESC
        LIMIT 10
        """
        
        audit_result = execute_query(audit_query, (start_date, end_date))
        
        # Errores críticos
        critical_errors_query = """
        SELECT 
            entidad_afectada,
            COUNT(*) as error_count
        FROM registros_auditoria
        WHERE fecha_hora BETWEEN %s AND %s
            AND resultado = 'error'
        GROUP BY entidad_afectada
        ORDER BY error_count DESC
        """
        
        critical_errors_result = execute_query(critical_errors_query, (start_date, end_date))
        
        return {
            'regulatory_compliance': compliance_result,
            'pending_review': pending_review_result,
            'alerts': alerts_result[0] if alerts_result else {},
            'audit_activity': audit_result,
            'critical_errors': critical_errors_result
        }
        
    except Exception as e:
        logger.error(f"Error al obtener estado de cumplimiento: {str(e)}")
        return {'error': str(e)}

def get_expiring_documents(user_id):
    """Obtiene documentos que están por vencer"""
    try:
        # Documentos ya vencidos
        expired_query = """
        SELECT 
            COUNT(*) as expired_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE d.estado = 'publicado'
            AND cb.validez_en_dias IS NOT NULL
            AND DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) < CURDATE()
        """
        
        expired_result = execute_query(expired_query)
        
        # Documentos que vencen en los próximos 5 días
        expiring_5_days_query = """
        SELECT 
            COUNT(*) as expiring_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE d.estado = 'publicado'
            AND cb.validez_en_dias IS NOT NULL
            AND DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 5 DAY)
        """
        
        expiring_5_days_result = execute_query(expiring_5_days_query)
        
        # Documentos que vencen en los próximos 15 días
        expiring_15_days_query = """
        SELECT 
            COUNT(*) as expiring_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE d.estado = 'publicado'
            AND cb.validez_en_dias IS NOT NULL
            AND DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 15 DAY)
        """
        
        expiring_15_days_result = execute_query(expiring_15_days_query)
        
        # Documentos que vencen en los próximos 30 días
        expiring_30_days_query = """
        SELECT 
            COUNT(*) as expiring_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE d.estado = 'publicado'
            AND cb.validez_en_dias IS NOT NULL
            AND DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
        """
        
        expiring_30_days_result = execute_query(expiring_30_days_query)
        
        # Documentos por tipo que vencerán pronto (próximos 30 días)
        expiring_by_type_query = """
        SELECT 
            td.nombre_tipo,
            COUNT(*) as count,
            MIN(DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY)) as earliest_expiry
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
        WHERE d.estado = 'publicado'
            AND cb.validez_en_dias IS NOT NULL
            AND DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
        GROUP BY td.nombre_tipo
        ORDER BY earliest_expiry ASC
        """
        
        expiring_by_type_result = execute_query(expiring_by_type_query)
        
        # Formatear fechas para JSON
        for item in expiring_by_type_result:
            if 'earliest_expiry' in item and item['earliest_expiry']:
                item['earliest_expiry'] = item['earliest_expiry'].isoformat()
        
        # Documentos renovados recientemente (últimos 30 días)
        renovations_query = """
        SELECT 
            COUNT(*) as renewed_count
        FROM versiones_documento v
        JOIN documentos d ON v.id_documento = d.id_documento
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
        WHERE v.numero_version > 1
            AND v.fecha_creacion BETWEEN DATE_SUB(CURDATE(), INTERVAL 30 DAY) AND CURDATE()
        """
        
        renovations_result = execute_query(renovations_query)
        
        # Preparar resultado
        return {
            'expired': expired_result[0]['expired_count'] if expired_result else 0,
            'expiring_5_days': expiring_5_days_result[0]['expiring_count'] if expiring_5_days_result else 0,
            'expiring_15_days': expiring_15_days_result[0]['expiring_count'] if expiring_15_days_result else 0,
            'expiring_30_days': expiring_30_days_result[0]['expiring_count'] if expiring_30_days_result else 0,
            'expiring_by_type': expiring_by_type_result,
            'recent_renovations': renovations_result[0]['renewed_count'] if renovations_result else 0
        }
        
    except Exception as e:
        logger.error(f"Error al obtener documentos por vencer: {str(e)}")
        return {'error': str(e)}

def get_recent_activity(user_id, limit=10):
    """Obtiene la actividad reciente en el sistema"""
    try:
        # Actividad reciente general
        activity_query = """
        SELECT 
            ra.id_registro,
            ra.fecha_hora,
            ra.usuario_id,
            u.nombre_usuario,
            ra.accion,
            ra.entidad_afectada,
            ra.id_entidad_afectada,
            ra.resultado
        FROM registros_auditoria ra
        JOIN usuarios u ON ra.usuario_id = u.id_usuario
        ORDER BY ra.fecha_hora DESC
        LIMIT %s
        """
        
        activity_result = execute_query(activity_query, (limit,))
        
        # Formatear fechas para JSON
        for activity in activity_result:
            if 'fecha_hora' in activity and activity['fecha_hora']:
                activity['fecha_hora'] = activity['fecha_hora'].isoformat()
        
        # Actividad de documentos reciente
        document_activity_query = """
        SELECT 
            ra.id_registro,
            ra.fecha_hora,
            ra.usuario_id,
            u.nombre_usuario,
            ra.accion,
            d.id_documento,
            d.titulo,
            d.codigo_documento,
            ra.resultado
        FROM registros_auditoria ra
        JOIN usuarios u ON ra.usuario_id = u.id_usuario
        JOIN documentos d ON ra.id_entidad_afectada = d.id_documento
        WHERE ra.entidad_afectada = 'documento'
        ORDER BY ra.fecha_hora DESC
        LIMIT %s
        """
        
        document_activity_result = execute_query(document_activity_query, (limit,))
        
        # Formatear fechas para JSON
        for activity in document_activity_result:
            if 'fecha_hora' in activity and activity['fecha_hora']:
                activity['fecha_hora'] = activity['fecha_hora'].isoformat()
        
        # Actividad de clientes reciente
        client_activity_query = """
        SELECT 
            ra.id_registro,
            ra.fecha_hora,
            ra.usuario_id,
            u.nombre_usuario,
            ra.accion,
            c.id_cliente,
            c.nombre_razon_social,
            c.codigo_cliente,
            ra.resultado
        FROM registros_auditoria ra
        JOIN usuarios u ON ra.usuario_id = u.id_usuario
        JOIN clientes c ON ra.id_entidad_afectada = c.id_cliente
        WHERE ra.entidad_afectada = 'cliente'
        ORDER BY ra.fecha_hora DESC
        LIMIT %s
        """
        
        client_activity_result = execute_query(client_activity_query, (limit,))
        
        # Formatear fechas para JSON
        for activity in client_activity_result:
            if 'fecha_hora' in activity and activity['fecha_hora']:
                activity['fecha_hora'] = activity['fecha_hora'].isoformat()
        
        # Documentos modificados recientemente
        recent_documents_query = """
        SELECT 
            d.id_documento,
            d.codigo_documento,
            d.titulo,
            d.fecha_modificacion,
            u.nombre_usuario as modificado_por,
            d.estado,
            td.nombre_tipo as tipo_documento
        FROM documentos d
        JOIN usuarios u ON d.modificado_por = u.id_usuario
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE d.estado != 'eliminado'
        ORDER BY d.fecha_modificacion DESC
        LIMIT %s
        """
        
        recent_documents_result = execute_query(recent_documents_query, (limit,))
        
        # Formatear fechas para JSON
        for doc in recent_documents_result:
            if 'fecha_modificacion' in doc and doc['fecha_modificacion']:
                doc['fecha_modificacion'] = doc['fecha_modificacion'].isoformat()
        
        return {
            'general_activity': activity_result,
            'document_activity': document_activity_result,
            'client_activity': client_activity_result,
            'recent_documents': recent_documents_result
        }
        
    except Exception as e:
        logger.error(f"Error al obtener actividad reciente: {str(e)}")
        return {'error': str(e)}