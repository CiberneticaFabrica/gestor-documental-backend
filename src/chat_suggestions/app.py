# src/chat_suggestions/app.py
import json
import logging
import os
from common.db import execute_query
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

def lambda_handler(event, context):
    """
    Handler para generar sugerencias inteligentes de consultas
    """
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        user_context = query_params.get('context', '')
        user_role = query_params.get('user_role', 'user')
        
        suggestions = generate_suggestions(user_context, user_role)
        
        return create_response(200, {
            'suggestions': suggestions,
            'context': user_context,
            'generated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error generando sugerencias: {str(e)}")
        return create_response(500, {'error': 'Error generando sugerencias'})

def generate_suggestions(context, user_role):
    """
    Genera sugerencias contextuales basadas en el rol del usuario y contexto
    """
    
    
    suggestions = []
    
    try:
        # Sugerencias basadas en patrones frecuentes
        patterns_query = """
        SELECT patron_pregunta, intent_asociado, frecuencia_uso
        FROM patrones_consultas_frecuentes
        WHERE activo = 1
        ORDER BY frecuencia_uso DESC
        LIMIT 8
        """
        
        patterns = execute_query(patterns_query, [], True)
        
        # Categorizar sugerencias por tipo
        suggestions_by_category = {
            'documentos_expiracion': [],
            'consultas_cliente': [],
            'estadisticas': [],
            'busquedas': []
        }
        
        for pattern in patterns:
            intent = pattern['intent_asociado']
            question = pattern['patron_pregunta']
            
            if intent == 'expiring_documents':
                suggestions_by_category['documentos_expiracion'].append({
                    'text': question,
                    'category': 'Documentos por Vencer',
                    'frequency': pattern['frecuencia_uso']
                })
            elif intent == 'client_documents':
                suggestions_by_category['consultas_cliente'].append({
                    'text': question,
                    'category': 'Consultas de Cliente',
                    'frequency': pattern['frecuencia_uso']
                })
            elif intent == 'count_query':
                suggestions_by_category['estadisticas'].append({
                    'text': question,
                    'category': 'Estadísticas',
                    'frequency': pattern['frecuencia_uso']
                })
            elif intent == 'search_documents':
                suggestions_by_category['busquedas'].append({
                    'text': question,
                    'category': 'Búsquedas',
                    'frequency': pattern['frecuencia_uso']
                })
        
        # Sugerencias específicas por rol
        if user_role == 'admin' or user_role == 'supervisor':
            suggestions.extend([
                {
                    'text': '¿Cuántos documentos se procesaron esta semana?',
                    'category': 'Administración',
                    'icon': 'chart-bar'
                },
                {
                    'text': '¿Qué clientes tienen documentación incompleta?',
                    'category': 'Supervisión',
                    'icon': 'exclamation-triangle'
                },
                {
                    'text': '¿Cuál es el estado de cumplimiento general?',
                    'category': 'Compliance',
                    'icon': 'shield-check'
                }
            ])
        
        # Sugerencias contextuales
        contextual_suggestions = get_contextual_suggestions(context)
        suggestions.extend(contextual_suggestions)
        
        # Combinar todas las categorías
        for category_suggestions in suggestions_by_category.values():
            suggestions.extend(category_suggestions[:2])  # Máximo 2 por categoría
        
        # Añadir sugerencias estáticas útiles
        static_suggestions = [
            {
                'text': '¿Qué documentos están por vencer en los próximos 30 días?',
                'category': 'Alertas',
                'icon': 'clock'
            },
            {
                'text': '¿Cuántos documentos subí hoy?',
                'category': 'Actividad Personal',
                'icon': 'upload'
            },
            {
                'text': 'Buscar documentos de Juan Pérez',
                'category': 'Búsqueda por Cliente',
                'icon': 'search'
            },
            {
                'text': '¿Qué tipos de documentos puedo subir?',
                'category': 'Ayuda',
                'icon': 'question-circle'
            }
        ]
        
        suggestions.extend(static_suggestions)
        
        # Limitar y ordenar
        suggestions = suggestions[:12]  # Máximo 12 sugerencias
        
        return suggestions
        
    except Exception as e:
        logger.error(f"Error obteniendo sugerencias de BD: {str(e)}")
        
        # Fallback a sugerencias estáticas si falla la BD
        return [
            {
                'text': '¿Qué documentos están próximos a expirar?',
                'category': 'Documentos',
                'icon': 'calendar'
            },
            {
                'text': '¿Cuántos documentos tengo?',
                'category': 'Estadísticas',
                'icon': 'file-alt'
            },
            {
                'text': 'Buscar documentos de un cliente',
                'category': 'Búsqueda',
                'icon': 'search'
            }
        ]

def get_contextual_suggestions(context):
    """
    Genera sugerencias basadas en el contexto actual del usuario
    """
    suggestions = []
    
    if not context:
        return suggestions
    
    context_lower = context.lower()
    
    # Sugerencias basadas en contexto temporal
    from datetime import datetime
    
    current_hour = datetime.now().hour
    
    if current_hour < 12:  # Mañana
        suggestions.append({
            'text': '¿Qué documentos llegaron ayer?',
            'category': 'Revisión Matutina',
            'icon': 'sun'
        })
    elif current_hour >= 17:  # Tarde
        suggestions.append({
            'text': '¿Qué documentos procesé hoy?',
            'category': 'Resumen del Día',
            'icon': 'moon'
        })
    
    # Sugerencias basadas en palabras clave del contexto
    if 'cliente' in context_lower:
        suggestions.append({
            'text': '¿Qué clientes necesitan actualizar documentos?',
            'category': 'Gestión de Clientes',
            'icon': 'users'
        })
    
    if 'vencimiento' in context_lower or 'expirar' in context_lower:
        suggestions.append({
            'text': '¿Qué documentos vencen esta semana?',
            'category': 'Vencimientos',
            'icon': 'calendar-times'
        })
    
    return suggestions

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