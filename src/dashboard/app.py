# app.py for DashboardMetricsFunction

import os
import json
import logging
import datetime
from decimal import Decimal

from common.db import (
    execute_query,
    get_connection,
    insert_audit_record
)

from common.headers import add_cors_headers

# Configure logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

def lambda_handler(event, context):
    """Main handler that routes to the appropriate dashboard metric functions"""
    try:
        http_method = event['httpMethod']
        path = event['path']
        
        # Handle OPTIONS requests for CORS preflight
        if http_method == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': add_cors_headers(),
                'body': ''
            }
        
        # Extract path parameter for metric type if present
        path_parts = path.split('/')
        if len(path_parts) > 2:
            metric_type = path_parts[2]
        else:
            metric_type = None
            
        # Main metrics dashboard - summary of all key metrics
        if http_method == 'GET' and path == '/dashboard/metrics':
            return get_dashboard_summary(event, context)
            
        # Specific metric categories
        elif http_method == 'GET' and path == '/dashboard/metrics/documents':
            return get_document_metrics(event, context)
            
        elif http_method == 'GET' and path == '/dashboard/metrics/users':
            return get_user_metrics(event, context)
            
        elif http_method == 'GET' and path == '/dashboard/metrics/processing':
            return get_processing_metrics(event, context)
            
        elif http_method == 'GET' and path == '/dashboard/metrics/classification':
            return get_classification_accuracy(event, context)
            
        elif http_method == 'GET' and path == '/dashboard/metrics/extraction':
            return get_extraction_confidence(event, context)
            
        elif http_method == 'GET' and path == '/dashboard/metrics/volume':
            return get_document_volume_trends(event, context)
            
        elif http_method == 'GET' and path == '/dashboard/metrics/timing':
            return get_processing_times(event, context)
            
        # elif http_method == 'GET' and path == '/dashboard/metrics/compliance':
        #     return get_compliance_status(event, context)
            
        elif http_method == 'GET' and path == '/dashboard/metrics/activity':
            return get_recent_activity(event, context)
            
        # If no route matches
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
    """Validates the user session and checks if they have required permissions"""
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

class DecimalEncoder(json.JSONEncoder):
    """Handle Decimal types in JSON serialization"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

def get_dashboard_summary(event, context):
    """Get a comprehensive summary of all key metrics for main dashboard"""
    try:
        # Validate session - require dashboard view permission
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Document counts by status and type
        doc_counts_query = """
        SELECT 
            COUNT(*) AS total_documents,
            SUM(CASE WHEN estado = 'borrador' THEN 1 ELSE 0 END) AS draft_count,
            SUM(CASE WHEN estado = 'publicado' THEN 1 ELSE 0 END) AS published_count,
            SUM(CASE WHEN estado = 'archivado' THEN 1 ELSE 0 END) AS archived_count,
            COUNT(DISTINCT id_tipo_documento) AS document_types_count
        FROM documentos 
        WHERE estado != 'eliminado'
        """
        doc_counts = execute_query(doc_counts_query)[0]
        
        # Documents by type breakdown
        doc_types_query = """
        SELECT 
            td.nombre_tipo,
            COUNT(*) AS count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE d.estado != 'eliminado'
        GROUP BY td.id_tipo_documento, td.nombre_tipo
        ORDER BY count DESC
        LIMIT 10
        """
        doc_types = execute_query(doc_types_query)
        
        # Document activity (created/modified) in last 30 days
        activity_query = """
        SELECT 
            DATE(fecha_creacion) AS date,
            COUNT(*) AS created_count,
            0 AS modified_count
        FROM documentos
        WHERE fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        AND estado != 'eliminado'
        GROUP BY DATE(fecha_creacion)
        
        UNION ALL
        
        SELECT 
            DATE(fecha_modificacion) AS date,
            0 AS created_count,
            COUNT(*) AS modified_count
        FROM documentos
        WHERE fecha_modificacion >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        AND estado != 'eliminado'
        GROUP BY DATE(fecha_modificacion)
        """
        activity_raw = execute_query(activity_query)
        
        # Process activity data into a unified format
        activity_by_date = {}
        for row in activity_raw:
            date_str = row['date'].isoformat()
            if date_str not in activity_by_date:
                activity_by_date[date_str] = {
                    'date': date_str,
                    'created_count': 0,
                    'modified_count': 0
                }
            activity_by_date[date_str]['created_count'] += row['created_count']
            activity_by_date[date_str]['modified_count'] += row['modified_count']
        
        activity_timeline = list(activity_by_date.values())
        activity_timeline.sort(key=lambda x: x['date'])
        
        # User metrics
        user_query = """
        SELECT 
            COUNT(*) AS total_users,
            SUM(CASE WHEN estado = 'activo' THEN 1 ELSE 0 END) AS active_users,
            SUM(CASE WHEN estado = 'inactivo' THEN 1 ELSE 0 END) AS inactive_users,
            SUM(CASE WHEN estado = 'bloqueado' THEN 1 ELSE 0 END) AS blocked_users,
            SUM(CASE WHEN ultimo_acceso >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS active_last_week,
            SUM(CASE WHEN ultimo_acceso >= DATE_SUB(CURDATE(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) AS active_last_month
        FROM usuarios
        """
        user_metrics = execute_query(user_query)[0]
        
        # Folder metrics
        folder_query = """
        SELECT 
            COUNT(*) AS total_folders,
            SUM(CASE WHEN carpeta_padre_id IS NULL THEN 1 ELSE 0 END) AS root_folders,
            MAX(LENGTH(ruta_completa) - LENGTH(REPLACE(ruta_completa, '/', ''))) AS max_depth
        FROM carpetas
        """
        folder_metrics = execute_query(folder_query)[0]
        
        # Processing metrics
        processing_query = """
        SELECT 
            COUNT(*) AS total_processed,
            SUM(CASE WHEN estado_analisis = 'procesado' THEN 1 ELSE 0 END) AS success_count,
            SUM(CASE WHEN estado_analisis = 'error' THEN 1 ELSE 0 END) AS error_count,
            AVG(confianza_clasificacion) AS avg_classification_confidence,
            AVG(tiempo_procesamiento) AS avg_processing_time,
            SUM(CASE WHEN requiere_verificacion = 1 AND verificado = 0 THEN 1 ELSE 0 END) AS pending_verification,
            SUM(CASE WHEN verificado = 1 THEN 1 ELSE 0 END) AS verified_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        """
        processing_metrics = execute_query(processing_query)[0]
        
        # Client metrics
        client_query = """
        SELECT 
            COUNT(*) AS total_clients,
            SUM(CASE WHEN estado = 'activo' THEN 1 ELSE 0 END) AS active_clients,
            SUM(CASE WHEN estado = 'inactivo' THEN 1 ELSE 0 END) AS inactive_clients,
            SUM(CASE WHEN estado = 'prospecto' THEN 1 ELSE 0 END) AS prospect_clients,
            SUM(CASE WHEN tipo_cliente = 'persona_fisica' THEN 1 ELSE 0 END) AS personal_clients,
            SUM(CASE WHEN tipo_cliente = 'empresa' THEN 1 ELSE 0 END) AS company_clients,
            SUM(CASE WHEN tipo_cliente = 'organismo_publico' THEN 1 ELSE 0 END) AS public_org_clients,
            COUNT(DISTINCT gestor_principal_id) AS active_managers
        FROM clientes
        """
        client_metrics = execute_query(client_query)[0]
        
        # Client document requests
        request_query = """
        SELECT 
            COUNT(*) AS total_requests,
            SUM(CASE WHEN estado = 'pendiente' THEN 1 ELSE 0 END) AS pending_requests,
            SUM(CASE WHEN estado = 'recordatorio_enviado' THEN 1 ELSE 0 END) AS reminder_sent,
            SUM(CASE WHEN estado = 'recibido' THEN 1 ELSE 0 END) AS received_requests,
            SUM(CASE WHEN estado = 'cancelado' THEN 1 ELSE 0 END) AS cancelled_requests,
            SUM(CASE WHEN fecha_limite < CURDATE() AND estado IN ('pendiente', 'recordatorio_enviado') THEN 1 ELSE 0 END) AS overdue_requests
        FROM documentos_solicitados
        """
        request_metrics = execute_query(request_query)[0]
        
        # Documents expiring soon
        expiring_query = """
        SELECT 
            SUM(CASE WHEN DATEDIFF(fecha_vencimiento, CURDATE()) <= 5 THEN 1 ELSE 0 END) AS expiring_5_days,
            SUM(CASE WHEN DATEDIFF(fecha_vencimiento, CURDATE()) <= 15 THEN 1 ELSE 0 END) AS expiring_15_days,
            SUM(CASE WHEN DATEDIFF(fecha_vencimiento, CURDATE()) <= 30 THEN 1 ELSE 0 END) AS expiring_30_days
        FROM (
            SELECT dc.id_cliente, d.id_documento, 
                   DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) as fecha_vencimiento
            FROM documentos_clientes dc
            JOIN documentos d ON dc.id_documento = d.id_documento
            JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
            JOIN tipos_documento_bancario tdb ON td.id_tipo_documento = tdb.id_tipo_documento
            JOIN categorias_bancarias cb ON tdb.id_categoria_bancaria = cb.id_categoria_bancaria
            WHERE d.estado = 'publicado' 
              AND cb.validez_en_dias IS NOT NULL
              AND DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) >= CURDATE()
              AND DATE_ADD(d.fecha_modificacion, INTERVAL cb.validez_en_dias DAY) <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)
        ) AS expiring_docs
        """
        expiring_docs = execute_query(expiring_query)[0]
        
        # Top users by document creation
        top_creators_query = """
        SELECT 
            u.nombre_usuario,
            COUNT(*) AS document_count
        FROM documentos d
        JOIN usuarios u ON d.creado_por = u.id_usuario
        WHERE d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        AND d.estado != 'eliminado'
        GROUP BY d.creado_por, u.nombre_usuario
        ORDER BY document_count DESC
        LIMIT 5
        """
        top_creators = execute_query(top_creators_query)
        
        # System storage metrics
        storage_query = """
        SELECT 
            COUNT(*) AS total_versions,
            SUM(tamano_bytes) AS total_storage_bytes,
            AVG(tamano_bytes) AS avg_file_size_bytes
        FROM versiones_documento
        """
        storage_metrics = execute_query(storage_query)[0]
        
        # Client document completeness
        client_doc_query = """
        SELECT 
            SUM(CASE WHEN estado_documental = 'completo' THEN 1 ELSE 0 END) AS complete_clients,
            SUM(CASE WHEN estado_documental = 'incompleto' THEN 1 ELSE 0 END) AS incomplete_clients,
            SUM(CASE WHEN estado_documental = 'pendiente_actualizacion' THEN 1 ELSE 0 END) AS pending_update_clients,
            SUM(CASE WHEN estado_documental = 'en_revision' THEN 1 ELSE 0 END) AS reviewing_clients
        FROM clientes
        WHERE estado = 'activo'
        """
        client_doc_metrics = execute_query(client_doc_query)[0]
        
        # Compile comprehensive summary
        summary = {
            "document_metrics": {
                "total_documents": doc_counts["total_documents"],
                "draft_documents": doc_counts["draft_count"],
                "published_documents": doc_counts["published_count"],
                "archived_documents": doc_counts["archived_count"],
                "document_types_count": doc_counts["document_types_count"],
                "document_types_breakdown": doc_types,
                "activity_timeline": activity_timeline
            },
            "user_metrics": {
                "total_users": user_metrics["total_users"],
                "active_users": user_metrics["active_users"],
                "inactive_users": user_metrics["inactive_users"],
                "blocked_users": user_metrics["blocked_users"],
                "active_last_week": user_metrics["active_last_week"],
                "active_last_month": user_metrics["active_last_month"],
                "top_creators": top_creators
            },
            "folder_metrics": {
                "total_folders": folder_metrics["total_folders"],
                "root_folders": folder_metrics["root_folders"],
                "max_folder_depth": folder_metrics["max_depth"]
            },
            "processing_metrics": {
                "total_processed": processing_metrics["total_processed"],
                "success_count": processing_metrics["success_count"],
                "error_count": processing_metrics["error_count"],
                "success_rate": (processing_metrics["success_count"] / processing_metrics["total_processed"] * 100) if processing_metrics["total_processed"] > 0 else 0,
                "error_rate": (processing_metrics["error_count"] / processing_metrics["total_processed"] * 100) if processing_metrics["total_processed"] > 0 else 0,
                "avg_classification_confidence": processing_metrics["avg_classification_confidence"] or 0,
                "avg_processing_time_ms": processing_metrics["avg_processing_time"] or 0,
                "pending_verification": processing_metrics["pending_verification"] or 0,
                "verified_count": processing_metrics["verified_count"] or 0
            },
            "client_metrics": {
                "total_clients": client_metrics["total_clients"],
                "active_clients": client_metrics["active_clients"],
                "inactive_clients": client_metrics["inactive_clients"],
                "prospect_clients": client_metrics["prospect_clients"],
                "personal_clients": client_metrics["personal_clients"],
                "company_clients": client_metrics["company_clients"],
                "public_org_clients": client_metrics["public_org_clients"],
                "active_managers": client_metrics["active_managers"],
                "document_completeness": {
                    "complete_clients": client_doc_metrics["complete_clients"] or 0,
                    "incomplete_clients": client_doc_metrics["incomplete_clients"] or 0,
                    "pending_update_clients": client_doc_metrics["pending_update_clients"] or 0,
                    "reviewing_clients": client_doc_metrics["reviewing_clients"] or 0
                }
            },
            "request_metrics": {
                "total_requests": request_metrics["total_requests"],
                "pending_requests": request_metrics["pending_requests"],
                "reminder_sent": request_metrics["reminder_sent"],
                "received_requests": request_metrics["received_requests"],
                "cancelled_requests": request_metrics["cancelled_requests"],
                "overdue_requests": request_metrics["overdue_requests"]
            },
            "compliance_metrics": {
                "documents_expiring_soon": {
                    "next_5_days": expiring_docs["expiring_5_days"] or 0,
                    "next_15_days": expiring_docs["expiring_15_days"] or 0,
                    "next_30_days": expiring_docs["expiring_30_days"] or 0
                }
            },
            "storage_metrics": {
                "total_versions": storage_metrics["total_versions"],
                "total_storage_bytes": storage_metrics["total_storage_bytes"] or 0,
                "total_storage_mb": (storage_metrics["total_storage_bytes"] or 0) / (1024 * 1024),
                "avg_file_size_bytes": storage_metrics["avg_file_size_bytes"] or 0,
                "avg_file_size_mb": (storage_metrics["avg_file_size_bytes"] or 0) / (1024 * 1024)
            }
        }
        
        # Log the dashboard access
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'comprehensive_summary'}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(summary, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving dashboard summary: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving dashboard summary: {str(e)}'})
        }
    
def get_document_metrics(event, context):
    """Get detailed document metrics"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Get query parameters for time range
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Default to last 30 days if not specified
        days = int(query_params.get('days', 30))
        if days <= 0:
            days = 30
        
        # Basic document counts
        doc_counts_query = """
        SELECT 
            COUNT(*) AS total_documents,
            SUM(CASE WHEN estado = 'borrador' THEN 1 ELSE 0 END) AS draft_count,
            SUM(CASE WHEN estado = 'publicado' THEN 1 ELSE 0 END) AS published_count,
            SUM(CASE WHEN estado = 'archivado' THEN 1 ELSE 0 END) AS archived_count,
            SUM(CASE WHEN fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY) THEN 1 ELSE 0 END) AS new_documents
        FROM documentos 
        WHERE estado != 'eliminado'
        """
        doc_counts = execute_query(doc_counts_query, (days,))[0]
        
        # Document count by type
        type_query = """
        SELECT td.nombre_tipo, COUNT(*) AS count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE d.estado != 'eliminado'
        GROUP BY td.nombre_tipo
        ORDER BY count DESC
        LIMIT 10
        """
        doc_by_type = execute_query(type_query)
        
        # Document trends over time
        trend_query = """
        SELECT 
            DATE(fecha_creacion) AS date,
            COUNT(*) AS count
        FROM documentos
        WHERE estado != 'eliminado' 
          AND fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DATE(fecha_creacion)
        ORDER BY date
        """
        doc_trend = execute_query(trend_query, (days,))
        
        # Documents pending review
        pending_query = """
        SELECT 
            COUNT(*) AS pending_count,
            SUM(CASE WHEN d.estado = 'borrador' THEN 1 ELSE 0 END) AS pending_draft,
            SUM(CASE WHEN a.requiere_verificacion = 1 AND a.verificado = 0 THEN 1 ELSE 0 END) AS pending_verification
        FROM documentos d
        LEFT JOIN analisis_documento_ia a ON d.id_documento = a.id_documento
        WHERE d.estado != 'eliminado'
        """
        pending_docs = execute_query(pending_query)[0]
        
        # Storage metrics
        storage_query = """
        SELECT 
            COALESCE(SUM(tamano_bytes), 0) AS total_storage_bytes,
            COUNT(*) AS total_versions,
            AVG(tamano_bytes) AS avg_document_size,
            COUNT(CASE WHEN fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY) THEN 1 END) AS new_versions
        FROM versiones_documento
        """
        storage_metrics = execute_query(storage_query, (days,))[0]
        
        # User activity metrics
        activity_query = """
        SELECT 
            COUNT(DISTINCT usuario_id) AS active_users,
            SUM(CASE WHEN accion = 'crear' AND entidad_afectada = 'documento' THEN 1 ELSE 0 END) AS documents_created,
            SUM(CASE WHEN accion = 'ver' AND entidad_afectada = 'documento' THEN 1 ELSE 0 END) AS document_views,
            SUM(CASE WHEN accion = 'descargar' AND entidad_afectada = 'documento' THEN 1 ELSE 0 END) AS document_downloads
        FROM registros_auditoria
        WHERE fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        """
        activity_metrics = execute_query(activity_query, (days,))[0]
        
        # AI processing metrics
        ai_metrics_query = """
        SELECT 
            COUNT(*) AS total_analyzed_documents,
            SUM(CASE WHEN fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY) THEN 1 ELSE 0 END) AS documents_analyzed_recently,
            SUM(CASE WHEN estado_analisis = 'procesado' THEN 1 ELSE 0 END) AS successfully_processed,
            SUM(CASE WHEN estado_analisis = 'error' THEN 1 ELSE 0 END) AS processing_errors,
            AVG(tiempo_procesamiento) AS avg_processing_time,
            AVG(confianza_clasificacion) AS avg_confidence_score
        FROM analisis_documento_ia
        """
        ai_metrics = execute_query(ai_metrics_query, (days,))[0]
        
        # Top active users
        top_users_query = """
        SELECT 
            ra.usuario_id,
            u.nombre_usuario,
            COUNT(*) AS activity_count
        FROM registros_auditoria ra
        JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE ra.fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY ra.usuario_id, u.nombre_usuario
        ORDER BY COUNT(*) DESC
        LIMIT 10
        """
        top_users = execute_query(top_users_query, (days,))
        
        # Document access by time of day
        access_by_hour_query = """
        SELECT 
            HOUR(fecha_hora) AS hour,
            COUNT(*) AS count
        FROM registros_auditoria
        WHERE accion = 'ver' 
            AND entidad_afectada = 'documento'
            AND fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY HOUR(fecha_hora)
        ORDER BY hour
        """
        access_by_hour = execute_query(access_by_hour_query, (days,))
        
        # Client metrics
        client_metrics_query = """
        SELECT
            COUNT(*) AS total_clients,
            SUM(CASE WHEN estado = 'activo' THEN 1 ELSE 0 END) AS active_clients,
            SUM(CASE WHEN fecha_alta >= DATE_SUB(CURDATE(), INTERVAL %s DAY) THEN 1 ELSE 0 END) AS new_clients
        FROM clientes
        """
        client_metrics = execute_query(client_metrics_query, (days,))[0]
        
        # Compile results
        result = {
            "document_counts": {
                "total": doc_counts["total_documents"],
                "draft": doc_counts["draft_count"],
                "published": doc_counts["published_count"],
                "archived": doc_counts["archived_count"],
                "new_in_period": doc_counts["new_documents"]
            },
            "storage_metrics": {
                "total_bytes": storage_metrics["total_storage_bytes"],
                "total_versions": storage_metrics["total_versions"],
                "avg_document_size": storage_metrics["avg_document_size"],
                "new_versions": storage_metrics["new_versions"]
            },
            "user_activity": {
                "active_users": activity_metrics["active_users"],
                "documents_created": activity_metrics["documents_created"],
                "document_views": activity_metrics["document_views"],
                "document_downloads": activity_metrics["document_downloads"]
            },
            "ai_processing": {
                "total_analyzed": ai_metrics["total_analyzed_documents"],
                "recently_analyzed": ai_metrics["documents_analyzed_recently"],
                "success_rate": (ai_metrics["successfully_processed"] / ai_metrics["total_analyzed_documents"]) * 100 if ai_metrics["total_analyzed_documents"] > 0 else 0,
                "avg_processing_time": ai_metrics["avg_processing_time"],
                "avg_confidence": ai_metrics["avg_confidence_score"]
            },
            "client_metrics": {
                "total_clients": client_metrics["total_clients"],
                "active_clients": client_metrics["active_clients"],
                "new_clients": client_metrics["new_clients"]
            },
            "documents_by_type": [
                {"type": doc["nombre_tipo"], "count": doc["count"]} for doc in doc_by_type
            ],
            "document_trend": [
                {"date": doc["date"].isoformat() if hasattr(doc["date"], "isoformat") else str(doc["date"]), 
                 "count": doc["count"]} for doc in doc_trend
            ],
            "pending_documents": {
                "total_pending": pending_docs["pending_count"],
                "pending_draft": pending_docs["pending_draft"],
                "pending_verification": pending_docs["pending_verification"]
            },
            "top_active_users": [
                {"user_id": user["usuario_id"], 
                 "username": user["nombre_usuario"],
                 "activity_count": user["activity_count"]} for user in top_users
            ],
            "document_access_by_hour": [
                {"hour": hour["hour"], 
                 "count": hour["count"]} for hour in access_by_hour
            ]
        }
            
        # Log the access
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'document_metrics', 'days': days}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(result, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving document metrics: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving document metrics: {str(e)}'})
        }
    
def get_user_metrics(event, context):
    """Get comprehensive user activity and metrics"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Get query parameters for time range
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Default to last 30 days if not specified
        days = int(query_params.get('days', 30))
        if days <= 0:
            days = 30
            
        # User counts and status
        user_counts_query = """
        SELECT 
            COUNT(*) AS total_users,
            SUM(CASE WHEN estado = 'activo' THEN 1 ELSE 0 END) AS active_users,
            SUM(CASE WHEN estado = 'inactivo' THEN 1 ELSE 0 END) AS inactive_users,
            SUM(CASE WHEN estado = 'bloqueado' THEN 1 ELSE 0 END) AS blocked_users,
            SUM(CASE WHEN fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY) THEN 1 ELSE 0 END) AS new_users,
            SUM(CASE WHEN ultimo_acceso >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS active_last_week,
            SUM(CASE WHEN ultimo_acceso >= DATE_SUB(CURDATE(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) AS active_last_month,
            SUM(CASE WHEN ultimo_acceso >= DATE_SUB(CURDATE(), INTERVAL 90 DAY) THEN 1 ELSE 0 END) AS active_last_quarter,
            SUM(CASE WHEN requiere_2fa = 1 THEN 1 ELSE 0 END) AS with_2fa
        FROM usuarios
        """
        user_counts = execute_query(user_counts_query, (days,))[0]
        
        # Most active users by actions
        active_users_query = """
        SELECT 
            u.id_usuario, 
            u.nombre_usuario, 
            u.nombre, 
            u.apellidos, 
            COUNT(*) AS action_count,
            COUNT(DISTINCT DATE(ra.fecha_hora)) AS active_days,
            MAX(ra.fecha_hora) AS last_activity
        FROM registros_auditoria ra
        JOIN usuarios u ON ra.usuario_id = u.id_usuario
        WHERE ra.fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY u.id_usuario, u.nombre_usuario, u.nombre, u.apellidos
        ORDER BY action_count DESC
        LIMIT 10
        """
        active_users = execute_query(active_users_query, (days,))
        
        # User activity by action type
        action_types_query = """
        SELECT 
            accion, 
            COUNT(*) AS action_count,
            COUNT(DISTINCT usuario_id) AS unique_users
        FROM registros_auditoria
        WHERE fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY accion
        ORDER BY action_count DESC
        """
        action_types = execute_query(action_types_query, (days,))
        
        # Login activity over time
        login_query = """
        SELECT 
            DATE(fecha_hora) AS date,
            COUNT(*) AS login_count,
            COUNT(DISTINCT usuario_id) AS unique_users
        FROM registros_auditoria
        WHERE accion = 'login'
          AND fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DATE(fecha_hora)
        ORDER BY date
        """
        login_activity = execute_query(login_query, (days,))
        
        # Current active sessions
        sessions_query = """
        SELECT 
            COUNT(*) AS active_sessions,
            COUNT(DISTINCT id_usuario) AS users_with_sessions,
            MIN(fecha_expiracion) AS nearest_expiration,
            MAX(fecha_expiracion) AS farthest_expiration,
            AVG(TIMESTAMPDIFF(MINUTE, fecha_inicio, fecha_expiracion)) AS avg_session_length_minutes
        FROM sesiones
        WHERE activa = TRUE
          AND fecha_expiracion > NOW()
        """
        sessions_data = execute_query(sessions_query)[0]
        
        # Device and browser statistics from user agent
        user_agent_query = """
        SELECT 
            CASE 
                WHEN user_agent LIKE '%%Mobile%%' THEN 'Mobile'
                WHEN user_agent LIKE '%%Tablet%%' THEN 'Tablet'
                ELSE 'Desktop'
            END AS device_type,
            COUNT(*) AS count
        FROM sesiones
        WHERE fecha_inicio >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY device_type
        """

        device_stats = execute_query(user_agent_query, (days,))
        
        browser_query = """
        SELECT 
            CASE 
                WHEN user_agent LIKE '%%Chrome%%' THEN 'Chrome'
                WHEN user_agent LIKE '%%Firefox%%' THEN 'Firefox'
                WHEN user_agent LIKE '%%Safari%%' THEN 'Safari'
                WHEN user_agent LIKE '%%Edge%%' THEN 'Edge'
                WHEN user_agent LIKE '%%MSIE%%' OR user_agent LIKE '%%Trident%%' THEN 'Internet Explorer'
                ELSE 'Other'
            END AS browser,
            COUNT(*) AS count
        FROM sesiones
        WHERE fecha_inicio >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY browser
        """
        
        browser_stats = execute_query(browser_query, (days,))
        
        # Login failure statistics
        login_failures_query = """
        SELECT 
            DATE(fecha_hora) AS date,
            COUNT(*) AS failure_count
        FROM registros_auditoria
        WHERE accion = 'login'
          AND resultado = 'error'
          AND fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DATE(fecha_hora)
        ORDER BY date
        """
        login_failures = execute_query(login_failures_query, (days,))
        
        # User roles distribution
        roles_query = """
        SELECT 
            r.nombre_rol,
            COUNT(DISTINCT ur.id_usuario) AS user_count
        FROM usuarios_roles ur
        JOIN roles r ON ur.id_rol = r.id_rol
        JOIN usuarios u ON ur.id_usuario = u.id_usuario
        WHERE u.estado = 'activo'
        GROUP BY r.id_rol, r.nombre_rol
        ORDER BY user_count DESC
        """
        roles_distribution = execute_query(roles_query)
        
        # User activity by hour of day
        hourly_activity_query = """
        SELECT 
            HOUR(fecha_hora) AS hour_of_day,
            COUNT(*) AS action_count
        FROM registros_auditoria
        WHERE fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY HOUR(fecha_hora)
        ORDER BY hour_of_day
        """
        hourly_activity = execute_query(hourly_activity_query, (days,))
        
        # User activity by day of week
        weekday_activity_query = """
        SELECT 
            DAYOFWEEK(fecha_hora) AS day_of_week,
            COUNT(*) AS action_count
        FROM registros_auditoria
        WHERE fecha_hora >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DAYOFWEEK(fecha_hora)
        ORDER BY day_of_week
        """
        weekday_activity = execute_query(weekday_activity_query, (days,))
        
        # User content contribution metrics
        content_creation_query = """
        SELECT 
            u.nombre_usuario,
            COUNT(DISTINCT d.id_documento) AS documents_created,
            COUNT(DISTINCT v.id_version) AS versions_created,
            SUM(v.tamano_bytes) AS total_bytes_contributed
        FROM documentos d
        JOIN usuarios u ON d.creado_por = u.id_usuario
        LEFT JOIN versiones_documento v ON v.id_documento = d.id_documento AND v.creado_por = u.id_usuario
        WHERE d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY u.id_usuario, u.nombre_usuario
        ORDER BY documents_created DESC
        LIMIT 10
        """
        content_creation = execute_query(content_creation_query, (days,))
        
        # User inactivity analysis
        inactive_users_query = """
        SELECT 
            COUNT(*) AS total_inactive,
            AVG(DATEDIFF(CURDATE(), ultimo_acceso)) AS avg_days_inactive,
            COUNT(CASE WHEN ultimo_acceso < DATE_SUB(CURDATE(), INTERVAL 30 DAY) THEN 1 END) AS inactive_30_days,
            COUNT(CASE WHEN ultimo_acceso < DATE_SUB(CURDATE(), INTERVAL 60 DAY) THEN 1 END) AS inactive_60_days,
            COUNT(CASE WHEN ultimo_acceso < DATE_SUB(CURDATE(), INTERVAL 90 DAY) THEN 1 END) AS inactive_90_days
        FROM usuarios
        WHERE estado = 'activo' AND ultimo_acceso IS NOT NULL
        """
        inactive_users = execute_query(inactive_users_query)[0]
        
        # New user registration trend
        user_registration_query = """
        SELECT 
            DATE(fecha_creacion) AS date,
            COUNT(*) AS new_users
        FROM usuarios
        WHERE fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DATE(fecha_creacion)
        ORDER BY date
        """
        user_registration = execute_query(user_registration_query, (days,))
        
        # Compile comprehensive results
        result = {
            "user_counts": {
                "total": user_counts["total_users"],
                "active": user_counts["active_users"],
                "inactive": user_counts["inactive_users"],
                "blocked": user_counts["blocked_users"],
                "new_in_period": user_counts["new_users"],
                "active_last_week": user_counts["active_last_week"],
                "active_last_month": user_counts["active_last_month"],
                "active_last_quarter": user_counts["active_last_quarter"],
                "with_2fa_enabled": user_counts["with_2fa"]
            },
            "most_active_users": [
                {
                    "user_id": user["id_usuario"],
                    "username": user["nombre_usuario"],
                    "name": f"{user['nombre']} {user['apellidos']}",
                    "action_count": user["action_count"],
                    "active_days": user["active_days"],
                    "last_activity": user["last_activity"].isoformat() if user["last_activity"] else None,
                    "activity_per_day": round(user["action_count"] / user["active_days"], 2) if user["active_days"] > 0 else 0
                } for user in active_users
            ],
            "action_distribution": [
                {
                    "action_type": action["accion"],
                    "count": action["action_count"],
                    "unique_users": action["unique_users"],
                    "percentage": round((action["action_count"] / sum(a["action_count"] for a in action_types)) * 100, 2)
                } for action in action_types
            ],
            "login_activity": [
                {
                    "date": date["date"].isoformat(),
                    "login_count": date["login_count"],
                    "unique_users": date["unique_users"]
                } for date in login_activity
            ],
            "login_failures": [
                {
                    "date": failure["date"].isoformat(),
                    "count": failure["failure_count"]
                } for failure in login_failures
            ],
            "session_metrics": {
                "active_sessions": sessions_data["active_sessions"],
                "users_with_sessions": sessions_data["users_with_sessions"],
                "nearest_expiration": sessions_data["nearest_expiration"].isoformat() if sessions_data["nearest_expiration"] else None,
                "farthest_expiration": sessions_data["farthest_expiration"].isoformat() if sessions_data["farthest_expiration"] else None,
                "avg_session_length_minutes": sessions_data["avg_session_length_minutes"]
            },
            "device_usage": [
                {
                    "device_type": device["device_type"],
                    "count": device["count"],
                    "percentage": round((device["count"] / sum(d["count"] for d in device_stats)) * 100, 2) if device_stats else 0
                } for device in device_stats
            ],
            "browser_usage": [
                {
                    "browser": browser["browser"],
                    "count": browser["count"],
                    "percentage": round((browser["count"] / sum(b["count"] for b in browser_stats)) * 100, 2) if browser_stats else 0
                } for browser in browser_stats
            ],
            "roles_distribution": [
                {
                    "role_name": role["nombre_rol"],
                    "user_count": role["user_count"],
                    "percentage": round((role["user_count"] / user_counts["active_users"]) * 100, 2) if user_counts["active_users"] > 0 else 0
                } for role in roles_distribution
            ],
            "hourly_activity": [
                {
                    "hour": hour["hour_of_day"],
                    "count": hour["action_count"]
                } for hour in hourly_activity
            ],
            "weekday_activity": [
                {
                    "day_of_week": day["day_of_week"],
                    "day_name": ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][day["day_of_week"] - 1],
                    "count": day["action_count"]
                } for day in weekday_activity
            ],
            "content_contribution": [
                {
                    "username": user["nombre_usuario"],
                    "documents_created": user["documents_created"],
                    "versions_created": user["versions_created"],
                    "total_bytes": user["total_bytes_contributed"],
                    "total_mb": round(user["total_bytes_contributed"] / (1024 * 1024), 2) if user["total_bytes_contributed"] else 0
                } for user in content_creation
            ],
            "inactivity_analysis": {
                "total_inactive_users": inactive_users["total_inactive"],
                "avg_days_inactive": inactive_users["avg_days_inactive"],
                "inactive_30_days": inactive_users["inactive_30_days"],
                "inactive_60_days": inactive_users["inactive_60_days"],
                "inactive_90_days": inactive_users["inactive_90_days"]
            },
            "user_registration": [
                {
                    "date": reg["date"].isoformat(),
                    "new_users": reg["new_users"]
                } for reg in user_registration
            ]
        }
        
        # Log the access
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'comprehensive_user_metrics', 'days': days}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(result, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving user metrics: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving user metrics: {str(e)}'})
        }
    
def get_processing_metrics(event, context):
    """Get document processing metrics for the admin dashboard"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Get query parameters for time range
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Default to last 30 days if not specified
        days = int(query_params.get('days', 30))
        if days <= 0:
            days = 30
        
        # Overall processing statistics
        process_stats_query = """
        SELECT 
            COUNT(*) AS total_processed,
            SUM(CASE WHEN estado_analisis = 'completado' THEN 1 ELSE 0 END) AS completed_count,
            SUM(CASE WHEN estado_analisis = 'error' THEN 1 ELSE 0 END) AS error_count,
            SUM(CASE WHEN estado_analisis = 'advertencia' THEN 1 ELSE 0 END) AS warning_count,
            AVG(tiempo_procesamiento) AS avg_processing_time,
            MAX(tiempo_procesamiento) AS max_processing_time,
            MIN(tiempo_procesamiento) AS min_processing_time
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        """
        process_stats = execute_query(process_stats_query, (days,))[0]
        
        # Processing by document type
        type_stats_query = """
        SELECT 
            a.tipo_documento,
            COUNT(*) AS count,
            SUM(CASE WHEN a.estado_analisis = 'completado' THEN 1 ELSE 0 END) AS success_count,
            SUM(CASE WHEN a.estado_analisis = 'error' THEN 1 ELSE 0 END) AS error_count,
            AVG(a.tiempo_procesamiento) AS avg_time
        FROM analisis_documento_ia a
        WHERE a.fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY a.tipo_documento
        ORDER BY count DESC
        """
        type_stats = execute_query(type_stats_query, (days,))
        
        # Processing trend over time
        trend_query = """
        SELECT 
            DATE(fecha_analisis) AS date,
            COUNT(*) AS total_count,
            SUM(CASE WHEN estado_analisis = 'completado' THEN 1 ELSE 0 END) AS success_count,
            SUM(CASE WHEN estado_analisis = 'error' THEN 1 ELSE 0 END) AS error_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DATE(fecha_analisis)
        ORDER BY date
        """
        process_trend = execute_query(trend_query, (days,))
        
        # Error types
        error_query = """
        SELECT 
            IFNULL(mensaje_error, 'Unknown error') AS mensaje_error,
            COUNT(*) AS error_count
        FROM analisis_documento_ia
        WHERE estado_analisis = 'error'
          AND fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY mensaje_error
        ORDER BY error_count DESC
        LIMIT 10
        """
        error_types = execute_query(error_query, (days,))
        
        # Add model versions statistics
        model_query = """
        SELECT 
            IFNULL(version_modelo, 'Unknown version') AS model_version,
            COUNT(*) AS doc_count,
            SUM(CASE WHEN estado_analisis = 'completado' THEN 1 ELSE 0 END) AS success_count,
            AVG(tiempo_procesamiento) AS avg_time
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY version_modelo
        ORDER BY doc_count DESC
        """
        model_stats = execute_query(model_query, (days,))
        
        # Compile results
        total_processed = process_stats["total_processed"] or 0
        success_count = process_stats["completed_count"] or 0
        
        result = {
            "processing_stats": {
                "total_processed": total_processed,
                "success_count": success_count,
                "error_count": process_stats["error_count"] or 0,
                "warning_count": process_stats["warning_count"] or 0,
                "success_rate": (success_count / total_processed * 100) if total_processed > 0 else 0,
                "avg_processing_time_ms": process_stats["avg_processing_time"] or 0,
                "max_processing_time_ms": process_stats["max_processing_time"] or 0,
                "min_processing_time_ms": process_stats["min_processing_time"] or 0
            },
            "processing_by_type": [
                {
                    "document_type": stat["tipo_documento"] or "Unknown type",
                    "count": stat["count"],
                    "success_count": stat["success_count"],
                    "error_count": stat["error_count"],
                    "success_rate": (stat["success_count"] / stat["count"] * 100) if stat["count"] > 0 else 0,
                    "avg_time_ms": stat["avg_time"] or 0
                } for stat in type_stats
            ],
            "processing_trend": [
                {
                    "date": date["date"].isoformat() if date["date"] else None,
                    "total": date["total_count"],
                    "success": date["success_count"],
                    "error": date["error_count"]
                } for date in process_trend
            ],
            "error_types": [
                {
                    "error_message": error["mensaje_error"],
                    "count": error["error_count"]
                } for error in error_types
            ],
            "model_versions": [
                {
                    "version": version["model_version"],
                    "count": version["doc_count"],
                    "success_count": version["success_count"],
                    "success_rate": (version["success_count"] / version["doc_count"] * 100) if version["doc_count"] > 0 else 0,
                    "avg_time_ms": version["avg_time"] or 0
                } for version in model_stats
            ]
        }
    
        # Log the access
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'processing_metrics', 'days': days}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(result, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving processing metrics: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving processing metrics: {str(e)}'})
        }  
    
def get_classification_accuracy(event, context):
    """Get classification accuracy metrics for the admin dashboard"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Get query parameters for time range
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Default to last 30 days if not specified
        days = int(query_params.get('days', 30))
        if days <= 0:
            days = 30
        
        # Overall classification accuracy
        accuracy_query = """
        SELECT 
            AVG(confianza_clasificacion) AS avg_confidence,
            COUNT(*) AS total_documents,
            SUM(CASE WHEN confianza_clasificacion >= 0.9 THEN 1 ELSE 0 END) AS high_confidence,
            SUM(CASE WHEN confianza_clasificacion >= 0.7 AND confianza_clasificacion < 0.9 THEN 1 ELSE 0 END) AS medium_confidence,
            SUM(CASE WHEN confianza_clasificacion < 0.7 THEN 1 ELSE 0 END) AS low_confidence,
            SUM(CASE WHEN verificado = 1 THEN 1 ELSE 0 END) AS verified_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        """
        accuracy_stats = execute_query(accuracy_query, (days,))[0]
        
        # Accuracy by document type
        type_accuracy_query = """
        SELECT 
            IFNULL(tipo_documento, 'Unknown type') AS tipo_documento,
            AVG(confianza_clasificacion) AS avg_confidence,
            COUNT(*) AS doc_count,
            SUM(CASE WHEN verificado = 1 THEN 1 ELSE 0 END) AS verified_count,
            SUM(CASE WHEN requiere_verificacion = 1 THEN 1 ELSE 0 END) AS requires_verification_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY tipo_documento
        ORDER BY avg_confidence DESC
        """
        type_accuracy = execute_query(type_accuracy_query, (days,))
        
        # Confidence distribution
        confidence_query = """
        SELECT 
            FLOOR(confianza_clasificacion * 10) / 10 AS confidence_range,
            COUNT(*) AS doc_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY FLOOR(confianza_clasificacion * 10) / 10
        ORDER BY confidence_range
        """
        confidence_dist = execute_query(confidence_query, (days,))
        
        # Confidence trend over time
        trend_query = """
        SELECT 
            DATE(fecha_analisis) AS date,
            AVG(confianza_clasificacion) AS avg_confidence,
            SUM(CASE WHEN verificado = 1 THEN 1 ELSE 0 END) AS verified_count,
            COUNT(*) AS total_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DATE(fecha_analisis)
        ORDER BY date
        """
        confidence_trend = execute_query(trend_query, (days,))
        
        # Add verification metrics
        verification_query = """
        SELECT 
            SUM(CASE WHEN requiere_verificacion = 1 THEN 1 ELSE 0 END) AS requires_verification,
            SUM(CASE WHEN verificado = 1 THEN 1 ELSE 0 END) AS verified,
            SUM(CASE WHEN requiere_verificacion = 1 AND verificado = 1 THEN 1 ELSE 0 END) AS required_and_verified,
            AVG(CASE WHEN verificado = 1 THEN confianza_clasificacion ELSE NULL END) AS verified_avg_confidence
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        """
        verification_stats = execute_query(verification_query, (days,))[0]
        
        # Extract and prepare data
        total_documents = accuracy_stats["total_documents"] or 0
        high_confidence = accuracy_stats["high_confidence"] or 0
        verified_count = accuracy_stats["verified_count"] or 0
        
        # Compile results
        result = {
            "classification_stats": {
                "avg_confidence": accuracy_stats["avg_confidence"] or 0,
                "total_documents": total_documents,
                "high_confidence_count": high_confidence,
                "medium_confidence_count": accuracy_stats["medium_confidence"] or 0,
                "low_confidence_count": accuracy_stats["low_confidence"] or 0,
                "manual_verification_count": verified_count,
                "high_confidence_percent": (high_confidence / total_documents * 100) if total_documents > 0 else 0,
                "verification_rate": (verified_count / total_documents * 100) if total_documents > 0 else 0
            },
            "verification_stats": {
                "requires_verification": verification_stats["requires_verification"] or 0,
                "verified": verification_stats["verified"] or 0,
                "required_and_verified": verification_stats["required_and_verified"] or 0,
                "verification_completion_rate": (verification_stats["verified"] / verification_stats["requires_verification"] * 100) 
                    if verification_stats["requires_verification"] and verification_stats["requires_verification"] > 0 else 0,
                "verified_avg_confidence": verification_stats["verified_avg_confidence"] or 0
            },
            "accuracy_by_type": [
                {
                    "document_type": type_acc["tipo_documento"],
                    "avg_confidence": type_acc["avg_confidence"] or 0,
                    "document_count": type_acc["doc_count"],
                    "verified_count": type_acc["verified_count"],
                    "requires_verification_count": type_acc["requires_verification_count"],
                    "verification_rate": (type_acc["verified_count"] / type_acc["doc_count"] * 100) if type_acc["doc_count"] > 0 else 0,
                    "verification_coverage": (type_acc["verified_count"] / type_acc["requires_verification_count"] * 100) 
                        if type_acc["requires_verification_count"] and type_acc["requires_verification_count"] > 0 else 0
                } for type_acc in type_accuracy
            ],
            "confidence_distribution": [
                {
                    "confidence_range": f"{dist['confidence_range']:.1f}" if dist['confidence_range'] is not None else "Unknown",
                    "document_count": dist["doc_count"]
                } for dist in confidence_dist
            ],
            "confidence_trend": [
                {
                    "date": trend["date"].isoformat() if trend["date"] else None,
                    "avg_confidence": trend["avg_confidence"] or 0,
                    "verified_count": trend["verified_count"] or 0,
                    "total_count": trend["total_count"] or 0,
                    "verification_rate": (trend["verified_count"] / trend["total_count"] * 100) if trend["total_count"] and trend["total_count"] > 0 else 0
                } for trend in confidence_trend
            ]
        }
        
        # Log the access
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'classification_metrics', 'days': days}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(result, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving classification metrics: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving classification metrics: {str(e)}'})
        }
    
def get_extraction_confidence(event, context):
    """Get extraction confidence metrics for document processing analysis"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Get query parameters for time range
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Default to last 30 days if not specified or invalid
        days = int(query_params.get('days', 30))
        if days <= 0:
            days = 30
            
        # Overall extraction confidence metrics
        confidence_query = """
        SELECT 
            AVG(d.confianza_extraccion) AS avg_confidence,
            COUNT(*) AS total_documents,
            SUM(CASE WHEN d.confianza_extraccion >= 0.9 THEN 1 ELSE 0 END) AS high_confidence,
            SUM(CASE WHEN d.confianza_extraccion >= 0.7 AND d.confianza_extraccion < 0.9 THEN 1 ELSE 0 END) AS medium_confidence,
            SUM(CASE WHEN d.confianza_extraccion < 0.7 THEN 1 ELSE 0 END) AS low_confidence,
            SUM(CASE WHEN d.validado_manualmente = 1 THEN 1 ELSE 0 END) AS manually_validated
        FROM documentos d
        WHERE d.confianza_extraccion IS NOT NULL
          AND d.fecha_modificacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        """
        confidence_stats = execute_query(confidence_query, (days,))
        
        if not confidence_stats:
            confidence_stats = [{
                "avg_confidence": 0,
                "total_documents": 0,
                "high_confidence": 0,
                "medium_confidence": 0,
                "low_confidence": 0,
                "manually_validated": 0
            }]
            
        confidence_data = confidence_stats[0]
        total_docs = confidence_data["total_documents"] or 0
            
        # Extraction by document type
        type_query = """
        SELECT 
            td.nombre_tipo,
            AVG(d.confianza_extraccion) AS avg_confidence,
            COUNT(*) AS doc_count,
            SUM(CASE WHEN d.validado_manualmente = 1 THEN 1 ELSE 0 END) AS validated_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE d.confianza_extraccion IS NOT NULL
          AND d.fecha_modificacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY td.nombre_tipo
        ORDER BY avg_confidence DESC
        """
        type_confidence = execute_query(type_query, (days,))
        
        # Entity extraction counts
        entity_query = """
        SELECT 
            JSON_UNQUOTE(JSON_EXTRACT(entity, '$.type')) AS entity_type,
            COUNT(*) AS entity_count,
            AVG(JSON_EXTRACT(entity, '$.confidence')) AS avg_confidence
        FROM (
            SELECT JSON_EXTRACT(entidades_detectadas, CONCAT('$[', numbers.n, ']')) AS entity
            FROM analisis_documento_ia a
            JOIN (
                SELECT 0 AS n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION
                SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9
            ) AS numbers
            WHERE a.entidades_detectadas IS NOT NULL 
              AND JSON_LENGTH(a.entidades_detectadas) > numbers.n
              AND a.fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        ) AS extracted_entities
        WHERE entity IS NOT NULL
        GROUP BY entity_type
        ORDER BY entity_count DESC
        LIMIT 10
        """
        
        entity_stats = []
        try:
            entity_stats = execute_query(entity_query, (days,))
        except Exception as entity_error:
            logger.warning(f"Error executing entity extraction query: {str(entity_error)}")
            
        # Extracted field quality assessment
        field_query = """
        SELECT 
            field_name,
            COUNT(*) AS field_count
        FROM (
            SELECT 
                JSON_UNQUOTE(json_keys.keys) AS field_name
            FROM documentos d
            JOIN JSON_TABLE(
                JSON_KEYS(d.datos_extraidos_ia),
                '$[*]' COLUMNS (keys VARCHAR(255) PATH '$')
            ) AS json_keys
            WHERE d.datos_extraidos_ia IS NOT NULL
              AND d.fecha_modificacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        ) AS extracted_fields
        GROUP BY field_name
        ORDER BY field_count DESC
        LIMIT 15
        """
        
        field_stats = []
        try:
            field_stats = execute_query(field_query, (days,))
        except Exception as field_error:
            logger.warning(f"Error executing field quality query: {str(field_error)}")
            # Fallback to a simpler query if the JSON functions aren't supported
            try:
                simple_field_query = """
                SELECT 
                    'datos_extraidos' AS field_name,
                    COUNT(*) AS field_count
                FROM documentos d
                WHERE d.datos_extraidos_ia IS NOT NULL
                  AND d.fecha_modificacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
                """
                field_stats = execute_query(simple_field_query, (days,))
            except Exception:
                pass
        
        # Compile results
        result = {
            "extraction_stats": {
                "avg_confidence": confidence_data["avg_confidence"] or 0,
                "total_documents": total_docs,
                "high_confidence_count": confidence_data["high_confidence"] or 0,
                "medium_confidence_count": confidence_data["medium_confidence"] or 0,
                "low_confidence_count": confidence_data["low_confidence"] or 0,
                "manually_validated_count": confidence_data["manually_validated"] or 0,
                "high_confidence_percent": (confidence_data["high_confidence"] / total_docs * 100) if total_docs > 0 else 0,
                "validation_rate": (confidence_data["manually_validated"] / total_docs * 100) if total_docs > 0 else 0
            },
            "extraction_by_type": [
                {
                    "document_type": type_conf["nombre_tipo"],
                    "avg_confidence": type_conf["avg_confidence"] or 0,
                    "document_count": type_conf["doc_count"] or 0,
                    "validated_count": type_conf["validated_count"] or 0,
                    "validation_rate": (type_conf["validated_count"] / type_conf["doc_count"] * 100) if type_conf.get("doc_count", 0) > 0 else 0
                } for type_conf in type_confidence
            ],
            "entity_extraction": [
                {
                    "entity_type": entity["entity_type"],
                    "count": entity["entity_count"] or 0,
                    "avg_confidence": entity["avg_confidence"] or 0
                } for entity in entity_stats if entity.get("entity_type")
            ],
            "extracted_fields": [
                {
                    "field_name": field["field_name"],
                    "count": field["field_count"] or 0
                } for field in field_stats if field.get("field_name")
            ],
            "time_range": {
                "days": days,
                "start_date": (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d"),
                "end_date": datetime.datetime.now().strftime("%Y-%m-%d")
            }
        }
            
        # Log the access
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'extraction_metrics', 'days': days}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(result, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving extraction metrics: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving extraction metrics: {str(e)}'})
        }

def get_document_volume_trends(event, context):
    """Get document volume trends over time"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Time range (default 90 days)
        days = int(query_params.get('days', 90))
        if days <= 0:
            days = 90
            
        # Grouping (day, week, month)
        grouping = query_params.get('grouping', 'day')
        if grouping not in ['day', 'week', 'month']:
            grouping = 'day'
        
        # Determine date grouping SQL
        if grouping == 'week':
            date_format = "YEARWEEK(fecha_creacion, 1)"
            period_label = "CONCAT(YEAR(fecha_creacion), '-W', WEEK(fecha_creacion, 1))"
        elif grouping == 'month':
            date_format = "DATE_FORMAT(fecha_creacion, '%Y-%m')"
            period_label = "DATE_FORMAT(fecha_creacion, '%Y-%m')"
        else:  # day
            date_format = "DATE(fecha_creacion)"
            period_label = "DATE(fecha_creacion)"
        
        # Volume by time period
        volume_trend_query = f"""
        SELECT 
            {period_label} AS period,
            COUNT(*) AS document_count
        FROM documentos
        WHERE fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
          AND estado != 'eliminado'
        GROUP BY {date_format}
        ORDER BY {date_format}
        """
        
        volume_trend = execute_query(volume_trend_query, (days,))
        
        # Document type distribution over time
        type_trend_query = f"""
        SELECT 
            {period_label} AS period,
            td.nombre_tipo AS document_type,
            COUNT(*) AS document_count
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        WHERE d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
          AND d.estado != 'eliminado'
        GROUP BY {date_format}, td.nombre_tipo
        ORDER BY {date_format}, document_count DESC
        """
        
        type_trend = execute_query(type_trend_query, (days,))
        
        # Processing volume trend
        processing_trend_query = f"""
        SELECT 
            {period_label} AS period,
            COUNT(*) AS processing_count,
            SUM(CASE WHEN estado_analisis = 'completado' THEN 1 ELSE 0 END) AS success_count,
            SUM(CASE WHEN estado_analisis = 'error' THEN 1 ELSE 0 END) AS error_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY {date_format}
        ORDER BY {date_format}
        """
        
        try:
            processing_trend = execute_query(processing_trend_query, (days,))
        except Exception as e:
            logger.warning(f"Error executing processing trend query: {str(e)}")
            processing_trend = []
        
        # Group type trends by period
        type_by_period = {}
        for entry in type_trend:
            period = entry["period"]
            if isinstance(period, datetime.date) or isinstance(period, datetime.datetime):
                period = period.isoformat()
                
            if period not in type_by_period:
                type_by_period[period] = []
                
            type_by_period[period].append({
                "document_type": entry["document_type"],
                "count": entry["document_count"]
            })
        
        # Format volume trend
        formatted_volume_trend = []
        for entry in volume_trend:
            period = entry["period"]
            if isinstance(period, (datetime.date, datetime.datetime)):
                period = period.isoformat()
            
            formatted_volume_trend.append({
                "period": period,
                "document_count": entry["document_count"]
            })
        
        # Format processing trend
        formatted_processing_trend = []
        for entry in processing_trend:
            period = entry["period"]
            if isinstance(period, (datetime.date, datetime.datetime)):
                period = period.isoformat()
            
            processing_count = entry["processing_count"] or 0
            success_count = entry["success_count"] or 0
            error_count = entry["error_count"] or 0
            
            formatted_processing_trend.append({
                "period": period,
                "processing_count": processing_count,
                "success_count": success_count,
                "error_count": error_count,
                "success_rate": (success_count / processing_count * 100) if processing_count > 0 else 0
            })
        
        # Get overall stats for summary
        overall_stats = {
            "total_documents": sum(entry["document_count"] for entry in volume_trend),
            "average_per_period": sum(entry["document_count"] for entry in volume_trend) / len(volume_trend) if volume_trend else 0,
            "processing_success_rate": (sum(entry.get("success_count", 0) for entry in processing_trend) / 
                                       sum(entry.get("processing_count", 0) for entry in processing_trend) * 100) 
                                       if processing_trend and sum(entry.get("processing_count", 0) for entry in processing_trend) > 0 else 0
        }
        
        # Compile results
        result = {
            "volume_trend": formatted_volume_trend,
            "type_distribution_by_period": [
                {
                    "period": period,
                    "types": types
                } for period, types in type_by_period.items()
            ],
            "processing_trend": formatted_processing_trend,
            "overall_stats": overall_stats,
            "time_range": {
                "days": days,
                "grouping": grouping,
                "start_date": (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d"),
                "end_date": datetime.datetime.now().strftime("%Y-%m-%d")
            }
        }
        
        # Log the access
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'volume_trends', 'days': days, 'grouping': grouping}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(result, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving document volume trends: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving document volume trends: {str(e)}'})
        }

def get_processing_times(event, context):
    """Get detailed processing time statistics for document analysis"""
    try:
        # Validate session and permissions
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response
        
        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Time range (default 30 days)
        days = int(query_params.get('days', 30))
        if days <= 0 or days > 365:  # Add a reasonable upper limit
            days = 30
        
        # Overall processing time statistics
        overall_query = """
        SELECT 
            AVG(tiempo_procesamiento) AS avg_time,
            MIN(tiempo_procesamiento) AS min_time,
            MAX(tiempo_procesamiento) AS max_time,
            STDDEV(tiempo_procesamiento) AS std_dev_time,
            COUNT(*) AS total_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
          AND estado_analisis = 'procesado'
          AND tiempo_procesamiento IS NOT NULL
        """
        
        overall_stats = execute_query(overall_query, (days,))
        if not overall_stats:
            overall_stats = [{"avg_time": 0, "min_time": 0, "max_time": 0, "std_dev_time": 0, "total_count": 0}]
        
        # Processing time by document type
        type_query = """
        SELECT 
            tipo_documento,
            AVG(tiempo_procesamiento) AS avg_time,
            MIN(tiempo_procesamiento) AS min_time,
            MAX(tiempo_procesamiento) AS max_time,
            COUNT(*) AS doc_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
          AND estado_analisis = 'procesado'
          AND tiempo_procesamiento IS NOT NULL
        GROUP BY tipo_documento
        ORDER BY avg_time DESC
        """
        
        type_stats = execute_query(type_query, (days,))
        
        # Processing time trend
        trend_query = """
        SELECT 
            DATE(fecha_analisis) AS date,
            AVG(tiempo_procesamiento) AS avg_time,
            COUNT(*) AS doc_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
          AND estado_analisis = 'procesado'
          AND tiempo_procesamiento IS NOT NULL
        GROUP BY DATE(fecha_analisis)
        ORDER BY date
        """
        
        time_trend = execute_query(trend_query, (days,))
        
        # Processing time distribution
        dist_query = """
        SELECT 
            CASE 
                WHEN tiempo_procesamiento < 1000 THEN '< 1 sec'
                WHEN tiempo_procesamiento < 5000 THEN '1-5 sec'
                WHEN tiempo_procesamiento < 10000 THEN '5-10 sec'
                WHEN tiempo_procesamiento < 30000 THEN '10-30 sec'
                WHEN tiempo_procesamiento < 60000 THEN '30-60 sec'
                ELSE '> 60 sec'
            END AS time_range,
            COUNT(*) AS doc_count
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
          AND estado_analisis = 'procesado'
          AND tiempo_procesamiento IS NOT NULL
        GROUP BY 
            CASE 
                WHEN tiempo_procesamiento < 1000 THEN '< 1 sec'
                WHEN tiempo_procesamiento < 5000 THEN '1-5 sec'
                WHEN tiempo_procesamiento < 10000 THEN '5-10 sec'
                WHEN tiempo_procesamiento < 30000 THEN '10-30 sec'
                WHEN tiempo_procesamiento < 60000 THEN '30-60 sec'
                ELSE '> 60 sec'
            END
        ORDER BY 
            CASE time_range
                WHEN '< 1 sec' THEN 1
                WHEN '1-5 sec' THEN 2
                WHEN '5-10 sec' THEN 3
                WHEN '10-30 sec' THEN 4
                WHEN '30-60 sec' THEN 5
                ELSE 6
            END
        """
        
        time_dist = execute_query(dist_query, (days,))
        
        # Processing by service
        service_query = """
        SELECT 
            procesado_por AS service,
            COUNT(*) AS doc_count,
            AVG(tiempo_procesamiento) AS avg_time
        FROM analisis_documento_ia
        WHERE fecha_analisis >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
          AND estado_analisis = 'procesado'
          AND tiempo_procesamiento IS NOT NULL
        GROUP BY procesado_por
        ORDER BY doc_count DESC
        """
        
        service_stats = execute_query(service_query, (days,))
        
        # Assemble results
        result = {
            "overall_stats": {
                "avg_processing_time_ms": overall_stats[0]["avg_time"] or 0,
                "min_processing_time_ms": overall_stats[0]["min_time"] or 0,
                "max_processing_time_ms": overall_stats[0]["max_time"] or 0,
                "std_dev_time_ms": overall_stats[0]["std_dev_time"] or 0,
                "total_documents": overall_stats[0]["total_count"] or 0
            },
            "processing_by_type": [
                {
                    "document_type": type_stat["tipo_documento"] or "unknown",
                    "avg_time_ms": type_stat["avg_time"] or 0,
                    "min_time_ms": type_stat["min_time"] or 0,
                    "max_time_ms": type_stat["max_time"] or 0,
                    "document_count": type_stat["doc_count"] or 0
                } for type_stat in type_stats
            ],
            "time_trend": [
                {
                    "date": trend["date"].isoformat() if trend["date"] else None,
                    "avg_time_ms": trend["avg_time"] or 0,
                    "document_count": trend["doc_count"] or 0
                } for trend in time_trend
            ],
            "time_distribution": [
                {
                    "time_range": dist["time_range"] or "unknown",
                    "document_count": dist["doc_count"] or 0
                } for dist in time_dist
            ],
            "processing_by_service": [
                {
                    "service": service["service"] or "unknown",
                    "document_count": service["doc_count"] or 0,
                    "avg_time_ms": service["avg_time"] or 0
                } for service in service_stats
            ]
        }
        
        # Log the access in audit
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'ver',
            'entidad_afectada': 'dashboard',
            'id_entidad_afectada': None,
            'detalles': json.dumps({'tipo': 'processing_times', 'days': days}),
            'resultado': 'éxito'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(result, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving processing time metrics: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error retrieving processing time metrics: {str(e)}'})
        }
    
def get_recent_activity(event, context):
    """Retrieves recent activity metrics for the dashboard"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.dashboard')
        if error_response:
            return error_response

        # Get query parameters for filtering
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Limit of activities to return
        limit = int(query_params.get('limit', 20))
        
        # Number of days to look back
        days = int(query_params.get('days', 7))
        
        # Filter by activity type
        activity_type = query_params.get('type')
        
        # Current date for calculations
        now = datetime.datetime.now()
        start_date = now - datetime.timedelta(days=days)
        
        # Build base query
        base_query = """
        SELECT 
            ra.id_registro,
            ra.fecha_hora,
            ra.usuario_id,
            u.nombre_usuario,
            ra.accion,
            ra.entidad_afectada,
            ra.id_entidad_afectada,
            ra.detalles,
            ra.resultado
        FROM 
            registros_auditoria ra
        JOIN 
            usuarios u ON ra.usuario_id = u.id_usuario
        WHERE 
            ra.fecha_hora >= %s
        """
        
        query_params = [start_date]
        
        # Add filter by activity type if provided
        if activity_type:
            base_query += " AND ra.accion = %s"
            query_params.append(activity_type)
        
        # Add order and limit
        base_query += " ORDER BY ra.fecha_hora DESC LIMIT %s"
        query_params.append(limit)
        
        # Execute query
        activities = execute_query(base_query, query_params)
        
        # Process activities to enhance with additional information
        enhanced_activities = []
        for activity in activities:
            # Format date
            if 'fecha_hora' in activity and activity['fecha_hora']:
                activity['fecha_hora'] = activity['fecha_hora'].isoformat()
            
            # Parse JSON details if present
            if 'detalles' in activity and activity['detalles']:
                try:
                    activity['detalles'] = json.loads(activity['detalles'])
                except:
                    pass
            
            # Add additional context based on entity type
            if activity['entidad_afectada'] == 'documento':
                if activity['id_entidad_afectada']:
                    doc_query = """
                    SELECT titulo, codigo_documento, id_tipo_documento
                    FROM documentos
                    WHERE id_documento = %s
                    """
                    doc_result = execute_query(doc_query, (activity['id_entidad_afectada'],))
                    if doc_result:
                        activity['entity_context'] = {
                            'titulo': doc_result[0]['titulo'],
                            'codigo': doc_result[0]['codigo_documento']
                        }
            
            elif activity['entidad_afectada'] == 'cliente':
                if activity['id_entidad_afectada']:
                    client_query = """
                    SELECT nombre_razon_social, codigo_cliente, tipo_cliente
                    FROM clientes
                    WHERE id_cliente = %s
                    """
                    client_result = execute_query(client_query, (activity['id_entidad_afectada'],))
                    if client_result:
                        activity['entity_context'] = {
                            'nombre': client_result[0]['nombre_razon_social'],
                            'codigo': client_result[0]['codigo_cliente']
                        }
            
            elif activity['entidad_afectada'] == 'carpeta':
                if activity['id_entidad_afectada']:
                    folder_query = """
                    SELECT nombre_carpeta, ruta_completa
                    FROM carpetas
                    WHERE id_carpeta = %s
                    """
                    folder_result = execute_query(folder_query, (activity['id_entidad_afectada'],))
                    if folder_result:
                        activity['entity_context'] = {
                            'nombre': folder_result[0]['nombre_carpeta'],
                            'ruta': folder_result[0]['ruta_completa']
                        }
            
            enhanced_activities.append(activity)
        
        # Get summary counts by activity type
        summary_query = """
        SELECT 
            accion,
            COUNT(*) as count
        FROM 
            registros_auditoria
        WHERE 
            fecha_hora >= %s
        GROUP BY 
            accion
        ORDER BY 
            count DESC
        """
        
        summary = execute_query(summary_query, [start_date])
        
        # Get most active users
        active_users_query = """
        SELECT 
            ra.usuario_id,
            u.nombre_usuario,
            COUNT(*) as activity_count
        FROM 
            registros_auditoria ra
        JOIN 
            usuarios u ON ra.usuario_id = u.id_usuario
        WHERE 
            ra.fecha_hora >= %s
        GROUP BY 
            ra.usuario_id, u.nombre_usuario
        ORDER BY 
            activity_count DESC
        LIMIT 5
        """
        
        active_users = execute_query(active_users_query, [start_date])
        
        # Get activity by day (for trend charts)
        trend_query = """
        SELECT 
            DATE(fecha_hora) as activity_date,
            COUNT(*) as count
        FROM 
            registros_auditoria
        WHERE 
            fecha_hora >= %s
        GROUP BY 
            DATE(fecha_hora)
        ORDER BY 
            activity_date
        """
        
        trend_data = execute_query(trend_query, [start_date])
        
        # Format date for trend data
        for day in trend_data:
            if 'activity_date' in day and day['activity_date']:
                day['activity_date'] = day['activity_date'].isoformat()
        
        # Prepare response
        response = {
            'activities': enhanced_activities,
            'summary': summary,
            'most_active_users': active_users,
            'trend_data': trend_data,
            'period': {
                'days': days,
                'start_date': start_date.isoformat(),
                'end_date': now.isoformat()
            }
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
    
    except Exception as e:
        logger.error(f"Error getting dashboard activity: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error getting dashboard activity: {str(e)}'})
        }