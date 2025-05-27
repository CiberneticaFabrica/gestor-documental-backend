# src/chat_analytics/app.py
import json
import logging
import os
from datetime import datetime, timedelta
from common.db import get_connection, execute_query,generate_uuid,process_analytics_request
# Configurar el logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

def lambda_handler(event, context):
    """
    Handler principal para análisis de patrones del chat global.
    """
    try:
        # Determinar el tipo de operación
        if 'source' in event and event['source'] == 'aws.events':
            # Ejecución programada - análisis diario
            return daily_analytics_job()
        elif 'httpMethod' in event:
            # Llamada desde API Gateway
            return handle_api_request(event, context)
        else:
            # Procesamiento directo
            return process_analytics_request(event)
            
    except Exception as e:
        logger.error(f"Error en análisis de chat: {str(e)}")
        return create_response(500, {'error': 'Error interno del servidor'})

def handle_api_request(event, context):
    """Maneja requests desde API Gateway"""
    path = event.get('path', '')
    method = event.get('httpMethod', '')
    
    if path == '/chat/analytics' and method == 'GET':
        return get_analytics_dashboard()
    elif path == '/chat/popular-queries' and method == 'GET':
        return get_popular_queries()
    elif path == '/chat/feedback' and method == 'POST':
        return process_user_feedback(event)
    else:
        return create_response(404, {'error': 'Endpoint no encontrado'})

def daily_analytics_job():
    """Trabajo de análisis diario ejecutado automáticamente"""
    try:
        logger.info("Iniciando análisis diario del chat global")
        
        # 1. Actualizar frecuencias de patrones
        update_pattern_frequencies()
        
        # 2. Generar métricas diarias
        generate_daily_metrics()
        
        # 3. Detectar nuevos patrones
        detect_new_patterns()
        
        # 4. Limpiar datos antiguos
        cleanup_old_data()
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Análisis diario completado exitosamente',
                'timestamp': datetime.utcnow().isoformat()
            })
        }
        
    except Exception as e:
        logger.error(f"Error en análisis diario: {str(e)}")
        raise

def update_pattern_frequencies():
    """Actualiza las frecuencias de patrones basado en consultas recientes"""
    
    
    try:
        # Llamar al procedimiento almacenado
        execute_query("CALL ActualizarFrecuenciaPatrones()", [], False)
        logger.info("Frecuencias de patrones actualizadas")
    except Exception as e:
        logger.error(f"Error actualizando frecuencias: {str(e)}")

def generate_daily_metrics():
    """Genera métricas diarias del chat"""
     
    
    try:
        yesterday = (datetime.now() - timedelta(days=1)).date()
        
        # Obtener métricas del día anterior
        metrics_query = """
        SELECT 
            COUNT(*) as total_consultas,
            COUNT(DISTINCT id_usuario) as usuarios_activos,
            AVG(tiempo_procesamiento_ms) as tiempo_promedio,
            intent_detectado,
            COUNT(*) as consultas_por_intent
        FROM consultas_globales_sistema
        WHERE DATE(fecha_consulta) = %s
        GROUP BY intent_detectado
        """
        
        metrics = execute_query(metrics_query, [yesterday], True)
        
        # Almacenar métricas agregadas
        for metric in metrics:
            store_metric_query = """
            INSERT INTO metricas_chat_diarias (
                fecha, intent, total_consultas, usuarios_activos, 
                tiempo_promedio_ms, fecha_creacion
            ) VALUES (%s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                total_consultas = VALUES(total_consultas),
                usuarios_activos = VALUES(usuarios_activos),
                tiempo_promedio_ms = VALUES(tiempo_promedio_ms)
            """
            
            execute_query(store_metric_query, [
                yesterday,
                metric['intent_detectado'],
                metric['total_consultas'],
                metric['usuarios_activos'],
                metric['tiempo_promedio']
            ], False)
        
        logger.info(f"Métricas diarias generadas para {yesterday}")
        
    except Exception as e:
        logger.error(f"Error generando métricas diarias: {str(e)}")

def detect_new_patterns():
    """Detecta nuevos patrones de consulta emergentes"""
    
    
    try:
        # Buscar consultas frecuentes que no tienen patrón asociado
        new_patterns_query = """
        SELECT 
            pregunta,
            intent_detectado,
            COUNT(*) as frecuencia
        FROM consultas_globales_sistema c
        WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        AND NOT EXISTS (
            SELECT 1 FROM patrones_consultas_frecuentes p
            WHERE p.intent_asociado = c.intent_detectado
            AND c.pregunta LIKE CONCAT('%', p.patron_pregunta, '%')
        )
        GROUP BY pregunta, intent_detectado
        HAVING frecuencia >= 3
        ORDER BY frecuencia DESC
        LIMIT 10
        """
        
        new_patterns = execute_query(new_patterns_query, [], True)
        
        # Crear nuevos patrones automáticamente
        for pattern in new_patterns:
            create_pattern_query = """
            INSERT INTO patrones_consultas_frecuentes (
                id_patron, patron_pregunta, intent_asociado, 
                frecuencia_uso, requiere_datos_dinamicos
            ) VALUES (UUID(), %s, %s, %s, 1)
            """
            
            execute_query(create_pattern_query, [
                pattern['pregunta'][:500],  # Truncar si es muy largo
                pattern['intent_detectado'],
                pattern['frecuencia']
            ], False)
        
        logger.info(f"Detectados {len(new_patterns)} nuevos patrones")
        
    except Exception as e:
        logger.error(f"Error detectando nuevos patrones: {str(e)}")

def cleanup_old_data():
    """Limpia datos antiguos según políticas de retención"""
     
    
    try:
        retention_days = int(os.environ.get('ANALYTICS_RETENTION_DAYS', '90'))
        
        # Eliminar consultas muy antiguas (mantener solo registros de auditoría)
        cleanup_query = """
        DELETE FROM consultas_globales_sistema
        WHERE fecha_consulta < DATE_SUB(CURDATE(), INTERVAL %s DAY)
        AND satisfaccion_usuario IS NULL
        """
        
        result = execute_query(cleanup_query, [retention_days], False)
        logger.info(f"Limpieza completada: datos anteriores a {retention_days} días")
        
    except Exception as e:
        logger.error(f"Error en limpieza de datos: {str(e)}")

def get_analytics_dashboard():
    """Obtiene datos para el dashboard de análisis"""
    
    
    try:
        # Métricas de los últimos 30 días
        dashboard_data = {}
        
        # 1. Métricas generales
        general_metrics_query = """
        SELECT 
            COUNT(*) as total_consultas,
            COUNT(DISTINCT id_usuario) as usuarios_unicos,
            AVG(tiempo_procesamiento_ms) as tiempo_promedio,
            COUNT(CASE WHEN satisfaccion_usuario IN ('bueno', 'muy_bueno') THEN 1 END) as consultas_satisfactorias
        FROM consultas_globales_sistema
        WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        """
        
        general_metrics = execute_query(general_metrics_query, [], True)
        dashboard_data['general_metrics'] = general_metrics[0] if general_metrics else {}
        
        # 2. Consultas por intent
        intent_metrics_query = """
        SELECT 
            intent_detectado,
            COUNT(*) as cantidad,
            AVG(tiempo_procesamiento_ms) as tiempo_promedio
        FROM consultas_globales_sistema
        WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        GROUP BY intent_detectado
        ORDER BY cantidad DESC
        """
        
        intent_metrics = execute_query(intent_metrics_query, [], True)
        dashboard_data['intent_distribution'] = intent_metrics or []
        
        # 3. Tendencia por días
        trend_query = """
        SELECT 
            DATE(fecha_consulta) as fecha,
            COUNT(*) as consultas_dia,
            COUNT(DISTINCT id_usuario) as usuarios_dia
        FROM consultas_globales_sistema
        WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL 14 DAY)
        GROUP BY DATE(fecha_consulta)
        ORDER BY fecha
        """
        
        trend_data = execute_query(trend_query, [], True)
        dashboard_data['daily_trend'] = trend_data or []
        
        # 4. Patrones más frecuentes
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
        
        patterns_data = execute_query(patterns_query, [], True)
        dashboard_data['top_patterns'] = patterns_data or []
        
        return create_response(200, dashboard_data)
        
    except Exception as e:
        logger.error(f"Error obteniendo dashboard: {str(e)}")
        return create_response(500, {'error': 'Error obteniendo métricas'})

def get_popular_queries():
    """Obtiene las consultas más populares"""
     
    
    try:
        popular_queries_query = """
        SELECT 
            pregunta,
            intent_detectado,
            COUNT(*) as frecuencia,
            AVG(CASE WHEN satisfaccion_usuario IN ('bueno', 'muy_bueno') THEN 1 ELSE 0 END) as satisfaccion_promedio
        FROM consultas_globales_sistema
        WHERE fecha_consulta >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY pregunta, intent_detectado
        HAVING frecuencia >= 2
        ORDER BY frecuencia DESC, satisfaccion_promedio DESC
        LIMIT 20
        """
        
        popular_queries = execute_query(popular_queries_query, [], True)
        
        return create_response(200, {
            'popular_queries': popular_queries or [],
            'generated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo consultas populares: {str(e)}")
        return create_response(500, {'error': 'Error obteniendo consultas populares'})

def process_user_feedback(event):
    """Procesa feedback de usuario sobre respuestas del chat"""
    try:
        body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        
        required_fields = ['query_id', 'rating']
        for field in required_fields:
            if field not in body:
                return create_response(400, {'error': f'Campo requerido: {field}'})
        
        query_id = body['query_id']
        rating = body['rating']
        comment = body.get('comment', '')
        
        # Validar rating
        valid_ratings = ['muy_malo', 'malo', 'regular', 'bueno', 'muy_bueno']
        if rating not in valid_ratings:
            return create_response(400, {'error': 'Rating inválido'})
        
         
        
        # Actualizar satisfacción en la consulta original
        update_query = """
        UPDATE consultas_globales_sistema
        SET satisfaccion_usuario = %s
        WHERE id_consulta = %s
        """
        
        execute_query(update_query, [rating, query_id], False)
        
        # Si hay comentario, registrarlo por separado
        if comment:
            feedback_query = """
            INSERT INTO feedback_chat_detallado (
                id_feedback, id_consulta, comentario, fecha_feedback
            ) VALUES (UUID(), %s, %s, NOW())
            """
            
            execute_query(feedback_query, [query_id, comment], False)
        
        return create_response(200, {
            'message': 'Feedback registrado exitosamente',
            'query_id': query_id
        })
        
    except Exception as e:
        logger.error(f"Error procesando feedback: {str(e)}")
        return create_response(500, {'error': 'Error procesando feedback'})

def create_response(status_code, body):
    """Crea una respuesta HTTP estándar"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS'
        },
        'body': json.dumps(body, ensure_ascii=False, default=str)
    }

 