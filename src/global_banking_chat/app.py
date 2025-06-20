# ============================================================================
# LAMBDA CHAT GLOBAL - SISTEMA BANCARIO
# Versión reorganizada por bloques funcionales
# ============================================================================

import json
import logging
import os
import boto3
from datetime import datetime, timedelta
import re
from common.db import execute_query, get_connection, generate_uuid, register_global_chat_query
from common.headers import add_cors_headers

# ============================================================================
# CONFIGURACIÓN Y VARIABLES GLOBALES
# ============================================================================

# Configurar el logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Cliente Bedrock
bedrock_client = boto3.client('bedrock-runtime', region_name=os.environ.get('BEDROCK_REGION', 'us-east-1'))

# ============================================================================
# BLOQUE 1: HANDLER PRINCIPAL Y VALIDACIÓN
# ============================================================================

def lambda_handler(event, context):
    """
    Handler principal para el chat global del sistema bancario.
    """
    try:
        # Manejar solicitudes OPTIONS para CORS preflight
        if event['httpMethod'] == 'OPTIONS':
            return create_response(200, '', add_cors_headers())
        
        # Validar que sea POST
        if event['httpMethod'] != 'POST':
            return create_response(405, {'error': 'Método no permitido. Use POST.'})
        
        # Validar sesión
        user_id, error_response = validate_session(event)
        if error_response:
            return error_response
        
        start_time = datetime.utcnow()
        logger.info(f"Chat global - Usuario {user_id} - Evento recibido")
        
        # Parsear body del evento
        body = json.loads(event['body']) if event.get('body') else {}
            
        # Validar campos requeridos
        if 'question' not in body:
            return create_response(400, {'error': 'Campo requerido faltante: question'})
        
        question = body['question']
        context_data = body.get('context', '')
        
        logger.info(f"Usuario {user_id} pregunta: {question}")
        
        # Procesar consulta
        return process_chat_query(user_id, question, context_data, start_time)
        
    except Exception as e:
        logger.error(f"Error procesando consulta global: {str(e)}", exc_info=True)
        return create_response(500, {
            'error': 'Error interno del servidor',
            'details': str(e) if os.environ.get('DEBUG', 'false').lower() == 'true' else None
        })

def process_chat_query(user_id, question, context_data, start_time):
    """
    Procesa la consulta del chat paso a paso
    """
    # Analizar la pregunta y determinar qué datos necesitamos
    query_analysis = analyze_question(question, user_id)
    logger.info(f"Análisis de pregunta: {query_analysis}")
    
    # Obtener datos relevantes de la base de datos
    relevant_data = fetch_relevant_data(query_analysis, user_id)
    logger.info(f"Datos obtenidos: {list(relevant_data.keys())}")
    
    # Log detallado de los datos obtenidos
    log_data_details(relevant_data)
    
    # Extraer entidades para incluir en la respuesta
    entities = extract_entities_from_data(relevant_data, query_analysis)
    logger.info(f"Entidades extraídas: {json.dumps(entities, ensure_ascii=False)}")
    
    # Generar respuesta usando Bedrock
    logger.info("Llamando a Bedrock para generar respuesta...")
    response = generate_smart_response(question, relevant_data, context_data, query_analysis)
    logger.info(f"Respuesta de Bedrock recibida: {response[:100]}...")
    
    # Calcular tiempo de procesamiento
    processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
    
    # Registrar la consulta
    query_id = register_global_chat_query(
        user_id=user_id,
        question=question,
        answer=response,
        intent_detected=query_analysis.get('intent', 'unknown'),
        data_sources=query_analysis.get('data_sources', []),
        processing_time_ms=processing_time
    )
    
    logger.info(f"Consulta registrada con ID: {query_id} - Tiempo: {processing_time}ms")
    
    # Retornar respuesta
    return create_response(200, {
        'query_id': query_id,
        'question': question,
        'answer': response,
        'data_sources': query_analysis.get('data_sources', []),
        'entities': entities,
        'intent': query_analysis.get('intent', 'unknown'),
        'query_type': query_analysis.get('query_type', 'general'),
        'processing_time_ms': processing_time,
        'timestamp': datetime.utcnow().isoformat()
    })

def log_data_details(relevant_data):
    """Log detallado de los datos obtenidos"""
    for key, value in relevant_data.items():
        if isinstance(value, list):
            logger.info(f"  {key}: {len(value)} elementos")
        elif isinstance(value, dict):
            logger.info(f"  {key}: {json.dumps(value, ensure_ascii=False, default=str)[:200]}...")
        else:
            logger.info(f"  {key}: {value}")

# ============================================================================
# BLOQUE 2: AUTENTICACIÓN Y SEGURIDAD
# ============================================================================

def validate_session(event, required_permission=None):
    """
    Verifica la sesión del usuario
    """
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None, create_response(401, {'error': 'Token no proporcionado'})
    
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
        return None, create_response(401, {'error': 'Sesión inválida'})
    
    session = session_result[0]
    
    # Validaciones de sesión
    if not session['activa']:
        return None, create_response(401, {'error': 'Sesión inactiva'})
    
    if session['fecha_expiracion'] < datetime.now():
        return None, create_response(401, {'error': 'Sesión expirada'})
    
    if session['estado'] != 'activo':
        return None, create_response(401, {'error': 'Usuario inactivo'})
    
    user_id = session['id_usuario']
    
    # Si no se requiere un permiso específico, solo devolver el ID del usuario
    if not required_permission:
        return user_id, None
    
    # Verificar permisos si se requiere
    return validate_user_permission(user_id, required_permission)

def validate_user_permission(user_id, required_permission):
    """Valida permisos específicos del usuario"""
    perm_query = """
    SELECT COUNT(*) as has_permission
    FROM usuarios_roles ur
    JOIN roles_permisos rp ON ur.id_rol = rp.id_rol
    JOIN permisos p ON rp.id_permiso = p.id_permiso
    WHERE ur.id_usuario = %s AND p.codigo_permiso = %s
    """
    
    perm_result = execute_query(perm_query, (user_id, required_permission))
    
    if not perm_result or perm_result[0]['has_permission'] == 0:
        return user_id, create_response(403, {
            'error': f'No tiene el permiso requerido: {required_permission}'
        })
    
    return user_id, None

# ============================================================================
# BLOQUE 3: ANÁLISIS DE PREGUNTAS E INTENCIONES
# ============================================================================

def analyze_question(question, user_id):
    """
    Análisis mejorado de preguntas con mejor detección de intenciones
    """
    question_lower = question.lower().strip()
    
    analysis = {
        'intent': 'unknown',
        'entities': [],
        'time_range': None,
        'document_types': [],
        'client_info': None,
        'data_sources': [],
        'filters': {},
        'query_type': 'general',
        'specific_info_request': None
    }
    
    # NUEVA CATEGORÍA: INFORMACIÓN ESPECÍFICA DE DOCUMENTOS
    analysis = detect_specific_document_info(question_lower, analysis)
    
    # Si no es información específica, continuar con las demás categorías
    if analysis['intent'] == 'unknown':
        analysis = detect_standard_intents(question_lower, analysis)
    
    # Detección de nombres de clientes (si no se detectó ya en información específica)
    if not analysis['client_info']:
        analysis['client_info'] = extract_client_name(question)
    
    # Detección de rangos de tiempo
    analysis['time_range'] = extract_time_range(question_lower)
    
    # Si detectamos un cliente en un conteo, cambiar la intención
    if analysis['intent'] == 'count_query' and analysis['client_info']:
        analysis['intent'] = 'count_client_documents'
        analysis['data_sources'] = ['documentos', 'clientes', 'documentos_clientes']
    
    return analysis

def detect_specific_document_info(question_lower, analysis):
    """
    Detectar preguntas sobre información específica de documentos existentes
    """
    specific_info_patterns = get_specific_info_patterns()
    
    logger.info(f"Analizando pregunta para información específica: '{question_lower}'")
    
    for info_type, patterns in specific_info_patterns.items():
        logger.info(f"Probando patrones para {info_type}")
        for i, pattern in enumerate(patterns):
            logger.info(f"  Patrón {i+1}: {pattern}")
            matches = re.findall(pattern, question_lower, re.IGNORECASE)
            logger.info(f"  Matches encontrados: {matches}")
            
            if matches:
                if info_type.endswith('_expiration'):
                    # Para patrones de expiración, el match es un número de documento
                    document_number = matches[0].strip()
                    logger.info(f"  Número de documento encontrado: '{document_number}'")
                    
                    if is_valid_document_number(document_number):
                        analysis['intent'] = 'specific_document_info'
                        analysis['specific_info_request'] = info_type
                        analysis['document_number'] = document_number
                        analysis['data_sources'] = ['documentos_identificacion', 'documentos']
                        analysis['query_type'] = 'specific_info'
                        logger.info(f"✅ Detectada consulta de expiración: {info_type} para documento {document_number}")
                        return analysis
                    else:
                        logger.info(f"❌ Número de documento no válido: '{document_number}'")
                else:
                    # Para patrones de nombres, el match es un nombre de persona
                    potential_name = matches[0].strip()
                    logger.info(f"  Nombre potencial: '{potential_name}'")
                    
                    if is_valid_client_name(potential_name):
                        analysis['intent'] = 'specific_document_info'
                        analysis['specific_info_request'] = info_type
                        analysis['client_info'] = potential_name.title()
                        analysis['data_sources'] = ['documentos', 'clientes', 'documentos_clientes', 'documentos_identificacion']
                        analysis['query_type'] = 'specific_info'
                        logger.info(f"✅ Detectada solicitud de información específica: {info_type} para {analysis['client_info']}")
                        return analysis
                    else:
                        logger.info(f"❌ Nombre no válido: '{potential_name}'")
                        
        if analysis['intent'] == 'specific_document_info':
            break
    
    return analysis

def detect_standard_intents(question_lower, analysis):
    """
    Detecta intenciones estándar del sistema
    """
    # 1. DOCUMENTOS POR EXPIRAR
    if any(phrase in question_lower for phrase in [
        'próximos a expirar', 'próximos a vencer', 'están próximos', 
        'van a expirar', 'van a vencer', 'próximos vencimientos',
        'documentos expiran', 'documentos vencen', 'se vencen',
        'por vencer', 'están por vencer', 'documentos están por vencer',
        'vencen en', 'expiran en', 'próximos días'
    ]):
        analysis['intent'] = 'expiring_documents'
        analysis['data_sources'] = ['documentos_identificacion', 'documentos']
        analysis['query_type'] = 'list'
        
    # 2. DOCUMENTOS VENCIDOS
    elif any(phrase in question_lower for phrase in [
        'ya están vencidos', 'documentos vencidos', 'han vencido',
        'están vencidos', 'documentos caducados', 'ya vencieron'
    ]):
        analysis['intent'] = 'expired_documents'
        analysis['data_sources'] = ['documentos_identificacion', 'documentos']
        analysis['query_type'] = 'list'
        
    # 3. CONTEOS
    elif any(word in question_lower for word in ['cuántos', 'cuántas', 'cantidad', 'número', 'total']) and \
         any(word in question_lower for word in ['documentos', 'docs', 'cédulas', 'pasaportes', 'contratos']):
        analysis['intent'] = 'count_query'
        analysis['data_sources'] = ['documentos', 'clientes']
        analysis['query_type'] = 'count'
        
        # Detectar tipos específicos de documentos para conteo
        if 'cédulas' in question_lower or 'cedulas' in question_lower:
            analysis['document_types'] = ['cedula']
        elif 'pasaportes' in question_lower:
            analysis['document_types'] = ['pasaporte']
        elif 'contratos' in question_lower:
            analysis['document_types'] = ['contrato']
            
    # 4. DOCUMENTOS DE CLIENTE
    elif any(phrase in question_lower for phrase in [
        'documentos tiene', 'documentos de', 'documentos del',
        'qué documentos tiene', 'cuáles documentos'
    ]):
        analysis['intent'] = 'client_documents'
        analysis['data_sources'] = ['documentos', 'clientes', 'documentos_clientes']
        analysis['query_type'] = 'list'
        
    # 5. SUBIDAS RECIENTES
    elif any(word in question_lower for word in ['subí', 'cargué', 'agregué', 'subidos']) and \
         any(word in question_lower for word in ['ayer', 'hoy', 'semana', 'mes']):
        analysis['intent'] = 'recent_uploads'
        analysis['data_sources'] = ['documentos']
        analysis['query_type'] = 'list'
        
    # 6. ESTADO DE CLIENTE
    elif any(word in question_lower for word in ['estado', 'completitud', 'faltantes']):
        analysis['intent'] = 'client_status'
        analysis['data_sources'] = ['clientes']
        analysis['query_type'] = 'status'
        
    # 7. BÚSQUEDA POR TIPO DE DOCUMENTO
    elif any(phrase in question_lower for phrase in [
        'buscar documentos de tipo', 'documentos tipo', 
        'buscar tipo', 'listar tipo', 'mostrar tipo'
    ]):
        analysis['intent'] = 'search_by_type'
        analysis['data_sources'] = ['documentos', 'documentos_identificacion']
        analysis['query_type'] = 'search'

    # 8. DOCUMENTOS PENDIENTES DE CLIENTE
    elif any(word in question_lower for word in ['pendientes', 'falta', 'faltantes', 'necesita']) and \
         extract_client_name(question_lower):
        analysis['intent'] = 'client_pending_documents'
        analysis['data_sources'] = ['clientes', 'documentos_solicitados']
        analysis['query_type'] = 'pending'

        # Detectar el tipo específico
        if 'dni' in question_lower:
            analysis['document_types'] = ['dni', 'cedula']
        elif 'cédula' in question_lower or 'cedula' in question_lower:
            analysis['document_types'] = ['cedula']
        elif 'pasaporte' in question_lower:
            analysis['document_types'] = ['pasaporte']
    
    return analysis

def get_specific_info_patterns():
    """
    Patrones para detectar información específica de documentos
    """
    return {
        'cedula_number': [
            r'cu[aá]l\s+es\s+el?\s+(?:c[eé]dula|dni)\s+de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)\s*\??',
            r'cu[aá]l\s+es\s+la?\s+(?:c[eé]dula|dni)\s+de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)\s*\??',
            r'(?:dame|dime|mostrar|buscar)\s+(?:el?|la?)\s+(?:c[eé]dula|dni)\s+de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)',
            r'(?:n[uú]mero\s+de\s+)?(?:c[eé]dula|dni)\s+de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)',
            r'([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)\s+(?:c[eé]dula|dni)\s+(?:n[uú]mero|cu[aá]l)',
            r'(?:c[eé]dula|dni).*?de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)'
        ],
        'cedula_expiration': [
            r'cu[aá]ndo\s+(?:expira|vence)\s+(?:la?\s+)?(?:c[eé]dula|dni)\s+([\d\-]+)',
            r'(?:fecha\s+de\s+)?(?:expiraci[oó]n|vencimiento)\s+(?:de\s+)?(?:c[eé]dula|dni)\s+([\d\-]+)',
            r'(?:c[eé]dula|dni)\s+([\d\-]+)\s+(?:cu[aá]ndo\s+)?(?:expira|vence)',
            r'(?:expira|vence)\s+(?:c[eé]dula|dni)\s+([\d\-]+)'
        ],
        'passport_number': [
            r'cu[aá]l\s+es\s+el?\s+pasaporte\s+de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)\s*\??',
            r'(?:dame|dime)\s+(?:el?)\s+pasaporte\s+de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)',
            r'(?:n[uú]mero\s+de\s+pasaporte\s+de)\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)',
            r'([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)\s+pasaporte\s+(?:n[uú]mero|cu[aá]l)',
            r'pasaporte.*?de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)'
        ],
        'passport_expiration': [
            r'cu[aá]ndo\s+(?:expira|vence)\s+(?:el?\s+)?pasaporte\s+([\w\d\-]+)',
            r'(?:fecha\s+de\s+)?(?:expiraci[oó]n|vencimiento)\s+(?:del?\s+)?pasaporte\s+([\w\d\-]+)',
            r'pasaporte\s+([\w\d\-]+)\s+(?:cu[aá]ndo\s+)?(?:expira|vence)'
        ],
        'document_details': [
            r'(?:informaci[oó]n|detalles|datos)\s+(?:del?\s+)?(?:documento|cedula|dni|pasaporte)\s+de\s+([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)',
            r'([a-záéíóúñ]+(?:\s+[a-záéíóúñ]+)*)\s+(?:qu[eé]\s+documentos|informaci[oó]n|detalles)'
        ]
    }

def is_valid_document_number(document_number):
    """Valida que sea un formato de número de documento válido"""
    return (len(document_number) >= 3 and 
            any(char.isdigit() for char in document_number))

def is_valid_client_name(potential_name):
    """Valida que sea un nombre de cliente válido"""
    excluded_keywords = [
        'cuántos', 'cuántas', 'qué', 'cuál', 'tipo', 'documento', 'cedula', 'dni', 'pasaporte',
        'es el', 'es la', 'dame', 'dime', 'mostrar', 'buscar', 'número', 'información',
        'cuándo', 'expira', 'vence', 'fecha', 'cuando'
    ]
    
    has_keyword = any(keyword.lower() in potential_name.lower() for keyword in excluded_keywords)
    
    return (len(potential_name) > 3 and 
            not has_keyword and
            not re.match(r'^[\d\-]+$', potential_name))

def extract_client_name(question):
    """
    Extrae nombres de clientes de manera más precisa
    """
    # Primero, eliminar frases que NO son nombres
    question_clean = question
    exclude_phrases = [
        'tipo dni', 'tipo cédula', 'tipo pasaporte', 
        'documentos puedo', 'tipos de documentos',
        'qué tipos', 'cuáles tipos', 'cuándo expira',
        'cuando expira', 'fecha de', 'expira la', 'vence la'
    ]

    for phrase in exclude_phrases:
        question_clean = question_clean.lower().replace(phrase, '')
        
    # Patrones mejorados para detectar nombres
    patterns = [
        r'tiene\s+([A-ZÁÉÍÓÚ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)*)',
        r'de\s+([A-ZÁÉÍÓÚ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)*)',
        r'([A-ZÁÉÍÓÚ][a-záéíóúñ]+\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)(?:\s+(?:documentos|docs))',
        r'(?:tiene|para)\s+([A-ZÁÉÍÓÚ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)*)\?',
        r'(?:cédula|dni|cedula|pasaporte).*(?:de|del)\s+([A-ZÁÉÍÓÚ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)*)',
        r'([A-ZÁÉÍÓÚ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)*).*(?:cédula|dni|cedula|pasaporte)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, question_clean, re.IGNORECASE)
        if matches:
            client_name = matches[0].strip()
            
            if is_valid_client_name(client_name):
                return client_name
    
    return None

def extract_time_range(question_lower):
    """
    Extrae rangos de tiempo de la pregunta
    """
    if 'ayer' in question_lower:
        return 'yesterday'
    elif 'hoy' in question_lower:
        return 'today'
    elif 'semana' in question_lower:
        return 'week'
    elif 'mes' in question_lower:
        return 'month'
    elif 'próximos' in question_lower and 'días' in question_lower:
        days_match = re.search(r'(\d+)\s*días?', question_lower)
        if days_match:
            return f'next_{days_match.group(1)}_days'
        else:
            return 'next_30_days'
    elif 'días' in question_lower:
        days_match = re.search(r'(\d+)\s*días?', question_lower)
        if days_match:
            return f'next_{days_match.group(1)}_days'
    
    return None

# ============================================================================
# BLOQUE 4: OBTENCIÓN DE DATOS
# ============================================================================

def fetch_relevant_data(analysis, user_id):
    """
    Obtiene los datos relevantes de la base de datos
    """
    data = {}
    
    try:
        intent_handlers = {
            'expiring_documents': lambda: get_expiring_documents(analysis, user_id),
            'expired_documents': lambda: get_expired_documents(analysis, user_id),
            'client_documents': lambda: get_client_documents(analysis, user_id),
            'count_query': lambda: handle_count_query(analysis, user_id),
            'count_client_documents': lambda: handle_client_document_count(analysis, user_id),
            'recent_uploads': lambda: get_recent_uploads(analysis, user_id),
            'client_status': lambda: get_client_status(analysis, user_id),
            'system_info': lambda: get_system_info(analysis, user_id),
            'client_pending_documents': lambda: get_client_pending_documents(analysis, user_id)
        }
        
        intent = analysis['intent']
        
        if intent == 'specific_document_info':
            if analysis.get('document_number'):
                data['document_info'] = get_document_by_number(analysis, user_id)
            else:
                data['client_docs'] = get_client_documents(analysis, user_id)
        elif intent in intent_handlers:
            data[get_data_key_for_intent(intent)] = intent_handlers[intent]()
        
        # Siempre incluir contexto si no hay errores críticos
        if not any('error' in str(v) for v in data.values() if isinstance(v, dict)):
            data['context'] = get_user_context(user_id)
        
    except Exception as e:
        logger.error(f"Error obteniendo datos: {str(e)}", exc_info=True)
        data['error'] = str(e)
    
    return data

def get_data_key_for_intent(intent):
    """Mapea intenciones a claves de datos"""
    intent_to_key = {
        'expiring_documents': 'expiring_docs',
        'expired_documents': 'expired_docs',
        'client_documents': 'client_docs',
        'count_query': 'counts',
        'count_client_documents': 'counts',
        'recent_uploads': 'recent_docs',
        'client_status': 'client_status',
        'system_info': 'system_info',
        'client_pending_documents': 'client_pending_docs'
    }
    return intent_to_key.get(intent, 'data')

# ============================================================================
# BLOQUE 5: FUNCIONES DE CONSULTA DE DOCUMENTOS
# ============================================================================

def get_expiring_documents(analysis, user_id):
    """Obtiene documentos próximos a expirar"""
    try:
        # Determinar días hacia el futuro
        days = 30  # default
        if analysis.get('time_range') and analysis['time_range'].startswith('next_'):
            try:
                days = int(analysis['time_range'].split('_')[1])
            except:
                days = 30
        
        logger.info(f"Buscando documentos que expiran en los próximos {days} días")
        
        query = """
        SELECT 
            di.id_documento,
            d.titulo,
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
        WHERE di.fecha_expiracion BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL %s DAY)
        AND d.estado = 'publicado'
        AND (d.creado_por = %s OR EXISTS (
            SELECT 1 FROM permisos_carpetas pc 
            WHERE pc.id_carpeta = d.id_carpeta 
            AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (SELECT id_grupo FROM usuarios_grupos WHERE id_usuario = %s) AND pc.tipo_entidad = 'grupo')
            )
            AND pc.tipo_permiso IN ('lectura', 'escritura', 'administracion')
        ))
        ORDER BY di.fecha_expiracion ASC
        LIMIT 50
        """
        
        results = execute_query(query, [days, user_id, user_id, user_id], True)
        logger.info(f"Encontrados {len(results)} documentos próximos a expirar")
        return results or []
        
    except Exception as e:
        logger.error(f"Error obteniendo documentos por expirar: {str(e)}")
        return []

def get_expired_documents(analysis, user_id):
    """Obtiene documentos ya vencidos"""
    try:
        query = """
        SELECT 
            di.id_documento,
            d.titulo,
            di.tipo_documento,
            di.numero_documento,
            di.fecha_expiracion,
            di.nombre_completo,
            c.nombre_razon_social as cliente_nombre,
            c.id_cliente,
            ABS(DATEDIFF(di.fecha_expiracion, CURDATE())) as dias_vencido,
            'VENCIDO' as nivel_urgencia
        FROM documentos_identificacion di
        JOIN documentos d ON di.id_documento = d.id_documento
        LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
        LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
        WHERE di.fecha_expiracion < CURDATE()
        AND d.estado = 'publicado'
        AND (d.creado_por = %s OR EXISTS (
            SELECT 1 FROM permisos_carpetas pc 
            WHERE pc.id_carpeta = d.id_carpeta 
            AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (SELECT id_grupo FROM usuarios_grupos WHERE id_usuario = %s) AND pc.tipo_entidad = 'grupo')
            )
            AND pc.tipo_permiso IN ('lectura', 'escritura', 'administracion')
        ))
        ORDER BY di.fecha_expiracion DESC
        LIMIT 50
        """
        
        results = execute_query(query, [user_id, user_id, user_id], True)
        return results or []
        
    except Exception as e:
        logger.error(f"Error obteniendo documentos vencidos: {str(e)}")
        return []

def get_document_by_number(analysis, user_id):
    """Obtiene información específica de un documento por su número"""
    try:
        document_number = analysis.get('document_number')
        if not document_number:
            return {'error': 'No se especificó número de documento'}
        
        logger.info(f"Buscando documento con número: '{document_number}'")
        
        # Buscar documento por número
        query = """
        SELECT 
            di.id_documento,
            d.titulo,
            di.tipo_documento,
            di.numero_documento,
            di.fecha_expiracion,
            di.nombre_completo,
            c.nombre_razon_social as cliente_nombre,
            c.id_cliente,
            d.estado,
            d.fecha_creacion,
            CASE 
                WHEN di.fecha_expiracion IS NOT NULL AND di.fecha_expiracion < CURDATE() THEN 'VENCIDO'
                WHEN di.fecha_expiracion IS NOT NULL AND di.fecha_expiracion <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) THEN 'POR_VENCER'
                WHEN d.validado_manualmente = 1 THEN 'VALIDADO'
                ELSE 'NORMAL'
            END as estado_documento,
            CASE 
                WHEN di.fecha_expiracion IS NOT NULL THEN DATEDIFF(di.fecha_expiracion, CURDATE())
                ELSE NULL
            END as dias_hasta_expiracion
        FROM documentos_identificacion di
        JOIN documentos d ON di.id_documento = d.id_documento
        LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
        LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
        WHERE di.numero_documento = %s
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
        LIMIT 1
        """
        
        result = execute_query(query, [document_number, user_id, user_id, user_id], True)
        
        if result:
            document_info = result[0]
            logger.info(f"Documento encontrado: {document_info}")
            return {
                'document_found': True,
                'document_info': document_info,
                'search_number': document_number
            }
        else:
            logger.info(f"Documento con número '{document_number}' no encontrado")
            return {
                'document_found': False,
                'error': f"No se encontró documento con número '{document_number}'",
                'search_number': document_number
            }
        
    except Exception as e:
        logger.error(f"Error obteniendo documento por número: {str(e)}", exc_info=True)
        return {'error': str(e)}

def get_recent_uploads(analysis, user_id):
    """Obtiene documentos subidos recientemente"""
    try:
        # Determinar rango de fechas
        if analysis.get('time_range') == 'yesterday':
            date_condition = "DATE(d.fecha_creacion) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)"
        elif analysis.get('time_range') == 'today':
            date_condition = "DATE(d.fecha_creacion) = CURDATE()"
        elif analysis.get('time_range') == 'week':
            date_condition = "d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)"
        else:
            date_condition = "d.fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)"
        
        query = f"""
        SELECT 
            d.id_documento,
            d.codigo_documento,
            d.titulo,
            td.nombre_tipo,
            d.fecha_creacion,
            c.nombre_razon_social as cliente
        FROM documentos d
        JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
        LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
        LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
        WHERE {date_condition}
        AND d.creado_por = %s
        AND d.estado != 'eliminado'
        ORDER BY d.fecha_creacion DESC
        LIMIT 20
        """
        
        results = execute_query(query, [user_id], True)
        return results or []
        
    except Exception as e:
        logger.error(f"Error obteniendo documentos recientes: {str(e)}")
        return []

def get_client_status(analysis, user_id):
    """Obtiene estado de completitud de clientes"""
    try:
        if analysis.get('client_info'):
            # Estado específico de un cliente
            client_name = analysis['client_info']
            query = """
            SELECT 
                c.id_cliente,
                c.nombre_razon_social,
                c.estado_documental,
                c.documentos_pendientes
            FROM clientes c
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
        
    except Exception as e:
        logger.error(f"Error obteniendo estado de clientes: {str(e)}")
        return []

def get_system_info(analysis, user_id):
    """Obtiene información sobre el sistema según la pregunta"""
    try:
        question_lower = analysis.get('question_lower', '')
        
        if 'tipos de documentos' in question_lower:
            query = """
            SELECT 
                td.nombre_tipo,
                td.descripcion,
                COUNT(d.id_documento) as cantidad_actual
            FROM tipos_documento td
            LEFT JOIN documentos d ON td.id_tipo_documento = d.id_tipo_documento
            WHERE td.es_documento_bancario = 1
            GROUP BY td.id_tipo_documento, td.nombre_tipo, td.descripcion
            ORDER BY td.nombre_tipo
            """
            
            result = execute_query(query, [], True)
            return {
                'info_type': 'document_types',
                'data': result or []
            }
            
        return {'info_type': 'unknown', 'data': []}
        
    except Exception as e:
        logger.error(f"Error obteniendo información del sistema: {str(e)}")
        return {'error': str(e)}

def get_client_pending_documents(analysis, user_id):
    """Obtiene documentos pendientes de un cliente"""
    try:
        client_name = analysis.get('client_info')
        if not client_name:
            return {'error': 'No se especificó nombre de cliente'}
            
        # Buscar cliente primero
        client_query = """
        SELECT 
            c.id_cliente,
            c.nombre_razon_social,
            c.estado_documental,
            c.documentos_pendientes
        FROM clientes c
        WHERE c.nombre_razon_social LIKE %s
        LIMIT 1
        """
        
        search_pattern = f"%{client_name}%"
        client_result = execute_query(client_query, [search_pattern], True)
        
        if not client_result:
            return {'error': f"Cliente '{client_name}' no encontrado"}
            
        client = client_result[0]
        
        # Buscar documentos solicitados pendientes
        pending_query = """
        SELECT 
            ds.id_solicitud,
            td.nombre_tipo,
            ds.fecha_solicitud,
            ds.fecha_limite,
            ds.estado,
            DATEDIFF(ds.fecha_limite, CURDATE()) as dias_restantes
        FROM documentos_solicitados ds
        JOIN tipos_documento td ON ds.id_tipo_documento = td.id_tipo_documento
        WHERE ds.id_cliente = %s
        AND ds.estado = 'pendiente'
        ORDER BY ds.fecha_limite ASC
        """
        
        pending_docs = execute_query(pending_query, [client['id_cliente']], True) or []
        
        return {
            'client_info': client,
            'pending_documents': pending_docs,
            'total_pending': len(pending_docs)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo documentos pendientes: {str(e)}")
        return {'error': str(e)}

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
        
    except Exception as e:
        logger.error(f"Error obteniendo contexto: {str(e)}")
    
    return context

# ============================================================================
# BLOQUE 6: FUNCIONES DE CONTEO Y ESTADÍSTICAS
# ============================================================================

def handle_count_query(analysis, user_id):
    """Maneja consultas de conteo"""
    try:
        # CONTEO ESPECÍFICO POR TIPO DE DOCUMENTO
        if analysis.get('document_types'):
            return handle_document_type_count(analysis, user_id)
        
        # CONTEO GENERAL DEL USUARIO
        else:
            return get_document_counts(analysis, user_id)
            
    except Exception as e:
        logger.error(f"Error en conteo de documentos: {str(e)}")
        return {'error': str(e)}

def handle_document_type_count(analysis, user_id):
    """Cuenta documentos por tipo específico"""
    try:
        doc_types = analysis['document_types']
        
        if 'cedula' in doc_types:
            query = """
            SELECT 
                COUNT(DISTINCT di.id_documento) as total_cedulas,
                COUNT(CASE WHEN d.estado = 'publicado' THEN 1 END) as cedulas_activas,
                COUNT(CASE WHEN di.fecha_expiracion < CURDATE() THEN 1 END) as cedulas_vencidas
            FROM documentos_identificacion di
            JOIN documentos d ON di.id_documento = d.id_documento
            WHERE di.tipo_documento = 'cedula'
            AND (d.creado_por = %s OR EXISTS (
                SELECT 1 FROM permisos_carpetas pc 
                WHERE pc.id_carpeta = d.id_carpeta 
                AND (
                    (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                    (pc.id_entidad IN (SELECT id_grupo FROM usuarios_grupos WHERE id_usuario = %s) AND pc.tipo_entidad = 'grupo')
                )
                AND pc.tipo_permiso IN ('lectura', 'escritura', 'administracion')
            ))
            """
            
            result = execute_query(query, [user_id, user_id, user_id], True)
            if result:
                return {'document_type_count': result[0], 'type': 'cedula'}
        
        return {'error': 'Tipo de documento no soportado'}
        
    except Exception as e:
        logger.error(f"Error contando documentos por tipo: {str(e)}")
        return {'error': str(e)}

def handle_client_document_count(analysis, user_id):
    """Conteo para cliente específico"""
    try:
        client_name = analysis['client_info']
        logger.info(f"Buscando conteo para cliente: '{client_name}'")
        
        query = """
        SELECT 
            c.id_cliente,
            c.nombre_razon_social,
            COUNT(d.id_documento) as total_documentos,
            COUNT(CASE WHEN d.estado = 'publicado' THEN 1 END) as documentos_publicados,
            COUNT(CASE WHEN d.validado_manualmente = 1 THEN 1 END) as documentos_validados,
            COUNT(CASE WHEN di.fecha_expiracion IS NOT NULL AND di.fecha_expiracion <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) THEN 1 END) as documentos_por_vencer
        FROM clientes c
        LEFT JOIN documentos_clientes dc ON c.id_cliente = dc.id_cliente
        LEFT JOIN documentos d ON dc.id_documento = d.id_documento 
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
        LEFT JOIN documentos_identificacion di ON d.id_documento = di.id_documento
        WHERE c.nombre_razon_social LIKE %s
        GROUP BY c.id_cliente, c.nombre_razon_social
        ORDER BY 
            CASE 
                WHEN c.nombre_razon_social = %s THEN 1
                WHEN c.nombre_razon_social LIKE %s THEN 2
                ELSE 3
            END
        LIMIT 1
        """
        
        search_pattern = f"%{client_name}%"
        exact_match = client_name
        starts_with = f"{client_name}%"
        
        result = execute_query(query, [user_id, user_id, user_id, search_pattern, exact_match, starts_with], True)
        
        if result:
            logger.info(f"Conteo encontrado para cliente: {result[0]}")
            return {'client_count': result[0]}
        else:
            logger.info(f"Cliente '{client_name}' no encontrado para conteo")
            return {'error': f"Cliente '{client_name}' no encontrado"}
            
    except Exception as e:
        logger.error(f"Error en conteo de cliente: {str(e)}", exc_info=True)
        return {'error': str(e)}

def get_document_counts(analysis, user_id):
    """Obtiene conteos generales de documentos del usuario"""
    try:
        counts = {}
        
        # Conteo general (solo documentos que el usuario puede ver)
        query = """
        SELECT 
            COUNT(*) as total_documentos,
            COUNT(CASE WHEN DATE(fecha_creacion) = CURDATE() THEN 1 END) as hoy,
            COUNT(CASE WHEN DATE(fecha_creacion) = DATE_SUB(CURDATE(), INTERVAL 1 DAY) THEN 1 END) as ayer,
            COUNT(CASE WHEN fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 END) as esta_semana
        FROM documentos d
        WHERE d.estado != 'eliminado'
        AND (d.creado_por = %s OR EXISTS (
            SELECT 1 FROM permisos_carpetas pc 
            WHERE pc.id_carpeta = d.id_carpeta 
            AND (
                (pc.id_entidad = %s AND pc.tipo_entidad = 'usuario') OR
                (pc.id_entidad IN (SELECT id_grupo FROM usuarios_grupos WHERE id_usuario = %s) AND pc.tipo_entidad = 'grupo')
            )
            AND pc.tipo_permiso IN ('lectura', 'escritura', 'administracion')
        ))
        """
        
        result = execute_query(query, [user_id, user_id, user_id], True)
        if result:
            counts.update(result[0])
            logger.info(f"Conteos generales: {counts}")
        
        # Si el usuario pregunta específicamente por "hoy"
        if analysis.get('time_range') == 'today':
            counts['focus'] = 'hoy'
        
        return counts
        
    except Exception as e:
        logger.error(f"Error obteniendo conteos: {str(e)}")
        return {'error': str(e)}

# ============================================================================
# BLOQUE 7: EXTRACCIÓN DE ENTIDADES Y FORMATEO
# ============================================================================

def extract_entities_from_data(data, analysis):
    """Extrae entidades relevantes de los datos para incluir en la respuesta"""
    entities = {
        'document_ids': [],
        'client_ids': [],
        'client_names': [],
        'document_types': [],
        'urgency_levels': []
    }
    
    try:
        # Extraer de documentos próximos a expirar
        if 'expiring_docs' in data and data['expiring_docs']:
            extract_entities_from_documents(data['expiring_docs'], entities)
        
        # Extraer de documentos vencidos
        if 'expired_docs' in data and data['expired_docs']:
            extract_entities_from_documents(data['expired_docs'], entities, is_expired=True)
        
        # Extraer de documentos de cliente
        if 'client_docs' in data and isinstance(data['client_docs'], dict):
            extract_entities_from_client_docs(data['client_docs'], entities)
        
        # Extraer de conteos de cliente
        if 'counts' in data and isinstance(data['counts'], dict):
            extract_entities_from_counts(data['counts'], entities)
        
        # Agregar nombre del cliente si está en el análisis
        if analysis.get('client_info'):
            entities['client_names'].append(analysis['client_info'])
        
        # Limpiar duplicados
        for key in entities:
            if isinstance(entities[key], list):
                entities[key] = list(set(entities[key]))
                
    except Exception as e:
        logger.error(f"Error extrayendo entidades: {str(e)}")
    
    return entities

def extract_entities_from_documents(documents, entities, is_expired=False):
    """Extrae entidades de una lista de documentos"""
    for doc in documents:
        if doc.get('id_documento'):
            entities['document_ids'].append(doc['id_documento'])
        if doc.get('id_cliente'):
            entities['client_ids'].append(doc['id_cliente'])
        if doc.get('cliente_nombre'):
            entities['client_names'].append(doc['cliente_nombre'])
        if doc.get('tipo_documento'):
            entities['document_types'].append(doc['tipo_documento'])
        if is_expired:
            entities['urgency_levels'].append('VENCIDO')
        elif doc.get('nivel_urgencia'):
            entities['urgency_levels'].append(doc['nivel_urgencia'])

def extract_entities_from_client_docs(client_docs, entities):
    """Extrae entidades de documentos de cliente"""
    if 'documents' in client_docs:
        for doc in client_docs['documents']:
            if doc.get('id_documento'):
                entities['document_ids'].append(doc['id_documento'])
        
        # Información del cliente
        if 'client_info' in client_docs:
            client_info = client_docs['client_info']
            if client_info.get('id_cliente'):
                entities['client_ids'].append(client_info['id_cliente'])
            if client_info.get('nombre_razon_social'):
                entities['client_names'].append(client_info['nombre_razon_social'])

def extract_entities_from_counts(counts, entities):
    """Extrae entidades de datos de conteo"""
    if 'client_count' in counts:
        client_count = counts['client_count']
        if client_count.get('id_cliente'):
            entities['client_ids'].append(client_count['id_cliente'])
        if client_count.get('nombre_razon_social'):
            entities['client_names'].append(client_count['nombre_razon_social'])

# ============================================================================
# BLOQUE 8: GENERACIÓN DE RESPUESTAS CON BEDROCK
# ============================================================================

def generate_smart_response(question, data, context="", analysis=None):
    """
    Genera una respuesta inteligente usando los datos obtenidos y Bedrock
    """
    try:
        # Verificar si hay errores en los datos
        error_found = check_data_errors(data)
        if error_found:
            logger.info(f"Error encontrado en datos: {error_found}")
        
        # Preparar el contexto de datos para Bedrock
        data_context = format_data_for_bedrock(data, analysis)
        logger.info(f"Contexto de datos preparado: {data_context[:500]}...")
        
        # Generar prompt según el tipo de consulta
        prompt = generate_prompt_for_analysis(question, data_context, analysis)
        
        # Llamar a Bedrock
        return call_bedrock_api(prompt)
        
    except Exception as e:
        logger.error(f"Error consultando Bedrock: {str(e)}", exc_info=True)
        return "Ocurrió un error al procesar tu consulta. Por favor, intenta de nuevo."

def check_data_errors(data):
    """Verifica si hay errores en los datos"""
    for key, value in data.items():
        if isinstance(value, dict) and 'error' in value:
            return value['error']
        elif isinstance(value, str) and 'error' in value.lower():
            return value
    return None

def generate_prompt_for_analysis(question, data_context, analysis):
    """Genera el prompt apropiado según el análisis"""
    if analysis and analysis.get('intent') == 'specific_document_info':
        return generate_specific_document_prompt(question, data_context, analysis)
    else:
        return generate_standard_prompt(question, data_context)

def generate_specific_document_prompt(question, data_context, analysis):
    """Genera prompt para consultas de información específica de documentos"""
    if analysis.get('document_number'):
        # Consulta por número de documento
        return f"""Eres un asistente bancario experto en gestión documental.

DATOS DISPONIBLES:
{data_context}

PREGUNTA DEL USUARIO:
{question}

TIPO DE CONSULTA: Información específica por número de documento
INFORMACIÓN SOLICITADA: {analysis.get('specific_info_request', 'desconocida')}
NÚMERO DE DOCUMENTO: {analysis.get('document_number', 'no especificado')}

INSTRUCCIONES CRÍTICAS PARA CONSULTAS POR NÚMERO:
1. Si se encontró el documento, responde con la información específica solicitada
2. Para expiración: responde con la fecha exacta y estado (vencido/vigente/por vencer)
3. Si NO se encontró el documento, responde: "No se encontró documento con número [número]"
4. Responde de forma directa y específica
5. NO agregues información adicional no solicitada

EJEMPLOS DE RESPUESTAS CORRECTAS:
- "La cédula 8-823-2320 expira el 2025-12-15 (vence en 200 días)"
- "La cédula 8-823-2320 venció el 2024-11-20 (vencida hace 30 días)"
- "El pasaporte PA123456 expira el 2026-03-10 (vigente por 285 días)"
- Si no se encuentra: "No se encontró documento con número 8-823-2320"

Respuesta:"""
    else:
        # Consulta por cliente
        return f"""Eres un asistente bancario experto en gestión documental.

DATOS DISPONIBLES:
{data_context}

PREGUNTA DEL USUARIO:
{question}

TIPO DE CONSULTA: Información específica de documento
INFORMACIÓN SOLICITADA: {analysis.get('specific_info_request', 'desconocida')}
CLIENTE: {analysis.get('client_info', 'no especificado')}

INSTRUCCIONES CRÍTICAS PARA INFORMACIÓN ESPECÍFICA:
1. Si hay documentos del cliente, busca y extrae ÚNICAMENTE la información solicitada
2. Para cédula/DNI: busca el número de documento en los datos de identificación
3. Para pasaporte: busca el número de pasaporte en los datos de identificación  
4. Si NO encuentras la información específica en los datos, responde: "No encontré información para esta consulta"
5. Responde SOLO con la información solicitada de forma directa: "El DNI de [Cliente] es: [número]"
6. NO agregues información adicional no solicitada
7. Si encuentras múltiples documentos del mismo tipo, lista todos los números encontrados

EJEMPLOS DE RESPUESTAS CORRECTAS:
- "El DNI de Beatriz Santos es: 4-114-121"  
- "El pasaporte de Giorgio Saita es: PA0106480"
- "Los números de cédula encontrados para Ana María son: 8-727-1234 y 4-998-567"
- Si no hay datos: "No encontré información para esta consulta"

Respuesta:"""

def generate_standard_prompt(question, data_context):
    """Genera prompt estándar para consultas generales"""
    return f"""Eres un asistente bancario experto en gestión documental.

DATOS DISPONIBLES:
{data_context}

PREGUNTA DEL USUARIO:
{question}

INSTRUCCIONES CRÍTICAS:
1. Si hay datos relevantes, responde ÚNICAMENTE basándote en esos datos
2. Si NO hay datos o hay errores, responde: "No encontré información para esta consulta"
3. Sé CONCISO y DIRECTO - máximo 3-4 líneas para conteos simples
4. Para listas de documentos, usa formato numerado SOLO si hay más de 1 elemento
5. Para conteos, responde SOLO el número y concepto: "X tiene Y documentos"
6. NO agregues información adicional del usuario ni estadísticas generales
7. Mantén un tono profesional pero directo

EJEMPLOS EXACTOS:
- Conteo simple: "Giorgio Saita tiene 7 documentos en total"
- Documentos por vencer organizados: 
  "Documentos próximos a expirar:
  
  1. Cliente: Giorgio Saita
     1) Cédula - Giorgio Saita
        Número: 8-999-1234
        Expira: 2025-06-01 (4 días)
        Urgencia: CRÍTICO
  
  2. Cliente: Ana María Castro  
     1) Pasaporte - Ana M. Castro
        Número: PA123456
        Expira: 2025-06-15 (18 días)
        Urgencia: PRÓXIMO"
- Sin datos: "No encontré información para esta consulta"

Respuesta:"""

def call_bedrock_api(prompt):
    """Llama a la API de Bedrock con el prompt generado"""
    # Configurar parámetros para el modelo
    model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-haiku-20240307-v1:0')
    
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 800,
        "temperature": 0.05,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }
    
    logger.info(f"Llamando a Bedrock con modelo: {model_id}")
    
    # Llamar a Bedrock
    response = bedrock_client.invoke_model(
        modelId=model_id,
        body=json.dumps(body),
        contentType='application/json'
    )
    
    # Procesar respuesta
    response_body = json.loads(response['body'].read())
    logger.info(f"Respuesta de Bedrock recibida: {json.dumps(response_body, ensure_ascii=False)[:500]}...")
    
    if 'content' in response_body and response_body['content']:
        answer = response_body['content'][0]['text'].strip()
        logger.info(f"Respuesta extraída: {answer}")
        return answer
    else:
        logger.error("Respuesta inesperada de Bedrock")
        return "Lo siento, no pude procesar tu consulta en este momento."

# ============================================================================
# BLOQUE 9: FORMATEO DE DATOS PARA BEDROCK
# ============================================================================

def format_data_for_bedrock(data, analysis):
    """
    Formatea los datos para Bedrock de manera más clara y concisa
    """
    formatted = []
    
    # Verificar errores primero
    for key, value in data.items():
        if isinstance(value, dict) and 'error' in value:
            formatted.append(f"ERROR: {value['error']}")
            return "\n".join(formatted)
    
    # Formatear según el tipo de datos disponibles
    if 'document_info' in data:
        formatted.extend(format_document_info(data['document_info']))
    
    if 'client_docs' in data:
        formatted.extend(format_client_documents(data['client_docs']))
    
    if 'expiring_docs' in data:
        formatted.extend(format_expiring_documents(data['expiring_docs']))
    
    if 'expired_docs' in data:
        formatted.extend(format_expired_documents(data['expired_docs']))
    
    if 'counts' in data:
        formatted.extend(format_counts_data(data['counts']))
    
    if 'recent_docs' in data:
        formatted.extend(format_recent_documents(data['recent_docs']))
    
    if 'system_info' in data:
        formatted.extend(format_system_info(data['system_info']))
    
    if 'client_pending_docs' in data:
        formatted.extend(format_pending_documents(data['client_pending_docs']))
    
    # Si no hay datos formateados
    if not formatted:
        formatted.append("No se encontraron datos relevantes para esta consulta.")
    
    return "\n".join(formatted)

def format_document_info(document_info):
    """Formatea información específica de documento por número"""
    formatted = []
    
    if not document_info.get('error'):
        search_number = document_info.get('search_number', 'N/A')
        
        if document_info.get('document_found'):
            document = document_info.get('document_info', {})
            formatted.append(f"INFORMACIÓN DEL DOCUMENTO {search_number}:")
            formatted.append(f"Tipo: {document.get('tipo_documento', 'N/A')}")
            formatted.append(f"Número: {document.get('numero_documento', 'N/A')}")
            formatted.append(f"Nombre: {document.get('nombre_completo', 'N/A')}")
            if document.get('cliente_nombre'):
                formatted.append(f"Cliente: {document['cliente_nombre']}")
            formatted.append(f"Estado: {document.get('estado_documento', 'N/A')}")
            
            # INFORMACIÓN DE EXPIRACIÓN
            if document.get('fecha_expiracion'):
                formatted.append(f"Fecha de expiración: {document['fecha_expiracion']}")
                if document.get('dias_hasta_expiracion') is not None:
                    dias = document['dias_hasta_expiracion']
                    if dias < 0:
                        formatted.append(f"Estado: VENCIDO (hace {abs(dias)} días)")
                    elif dias == 0:
                        formatted.append(f"Estado: VENCE HOY")
                    else:
                        formatted.append(f"Estado: Vence en {dias} días")
            else:
                formatted.append("Fecha de expiración: No disponible")
            
            if document.get('fecha_creacion'):
                formatted.append(f"Fecha de creación: {document['fecha_creacion']}")
        else:
            formatted.append(f"DOCUMENTO NO ENCONTRADO:")
            formatted.append(f"Número buscado: {search_number}")
            formatted.append(f"Error: {document_info.get('error', 'Documento no encontrado')}")
        
        formatted.append("")
    
    return formatted

def format_client_documents(client_docs):
    """Formatea documentos de cliente"""
    formatted = []
    
    if not client_docs.get('error'):
        client_info = client_docs.get('client_info', {})
        documents = client_docs.get('documents', [])
        
        client_name = client_info.get('nombre_razon_social', 'Cliente')
        formatted.append(f"DOCUMENTOS DE {client_name.upper()}:")
        formatted.append(f"Total: {len(documents)} documentos")
        
        if documents:
            # Agrupar por tipo de documento Y mostrar información de identificación
            docs_by_type = {}
            for doc in documents:
                doc_type = doc.get('nombre_tipo', 'Otros')
                if doc_type not in docs_by_type:
                    docs_by_type[doc_type] = []
                docs_by_type[doc_type].append(doc)
            
            # Mostrar agrupados por tipo con toda la información disponible
            for doc_type, docs in docs_by_type.items():
                formatted.append(f"\n{doc_type}:")
                for i, doc in enumerate(docs, 1):
                    formatted.append(f"  {i}. {doc.get('titulo', 'Sin título')}")
                    formatted.append(f"     Estado: {doc.get('estado', 'N/A')}")
                    
                    # INFORMACIÓN DE IDENTIFICACIÓN CRÍTICA
                    if doc.get('numero_documento'):
                        formatted.append(f"     Número: {doc['numero_documento']}")
                    if doc.get('tipo_documento'):
                        formatted.append(f"     Tipo ID: {doc['tipo_documento']}")
                    if doc.get('nombre_completo'):
                        formatted.append(f"     Nombre completo: {doc['nombre_completo']}")
                    if doc.get('fecha_expiracion'):
                        formatted.append(f"     Fecha expiración: {doc['fecha_expiracion']}")
                    if doc.get('estado_documento'):
                        formatted.append(f"     Situación: {doc['estado_documento']}")
        
        formatted.append("")
    
    return formatted

def format_expiring_documents(expiring_docs):
    """Formatea documentos próximos a expirar"""
    formatted = []
    
    if expiring_docs:
        formatted.append("DOCUMENTOS PRÓXIMOS A EXPIRAR:")
        
        # Agrupar documentos por cliente
        docs_by_client = group_documents_by_client(expiring_docs)
        
        # Formatear por cliente
        for client_num, (client_key, client_data) in enumerate(docs_by_client.items(), 1):
            formatted.append(f"\n{client_num}. Cliente: {client_data['nombre']}")
            
            # Ordenar documentos del cliente por fecha de expiración
            client_docs = sorted(client_data['documentos'], 
                               key=lambda x: x.get('fecha_expiracion', ''))
            
            for doc_num, doc in enumerate(client_docs, 1):
                formatted.append(f"   {doc_num}) {doc.get('tipo_documento', 'Documento')} - {doc.get('nombre_completo', 'N/A')}")
                formatted.append(f"      Número: {doc.get('numero_documento', 'N/A')}")
                formatted.append(f"      Expira: {doc.get('fecha_expiracion', 'N/A')} ({doc.get('dias_restantes', '?')} días)")
                formatted.append(f"      Urgencia: {doc.get('nivel_urgencia', 'N/A')}")
        
        formatted.append("")
    
    return formatted

def format_expired_documents(expired_docs):
    """Formatea documentos vencidos"""
    formatted = []
    
    if expired_docs:
        formatted.append("DOCUMENTOS VENCIDOS:")
        
        # Agrupar documentos por cliente
        docs_by_client = group_documents_by_client(expired_docs)
        
        # Formatear por cliente
        for client_num, (client_key, client_data) in enumerate(docs_by_client.items(), 1):
            formatted.append(f"\n{client_num}. Cliente: {client_data['nombre']}")
            
            for doc_num, doc in enumerate(client_data['documentos'], 1):
                formatted.append(f"   {doc_num}) {doc.get('tipo_documento', 'Documento')} - {doc.get('nombre_completo', 'N/A')}")
                formatted.append(f"      Número: {doc.get('numero_documento', 'N/A')}")
                formatted.append(f"      Venció: {doc.get('fecha_expiracion', 'N/A')} (hace {doc.get('dias_vencido', '?')} días)")
        
        formatted.append("")
    
    return formatted

def format_counts_data(counts):
    """Formatea datos de conteo"""
    formatted = []
    
    # Conteo por cliente específico
    if 'client_count' in counts:
        client_count = counts['client_count']
        client_name = client_count.get('nombre_razon_social', 'Cliente')
        formatted.append(f"RESUMEN DE DOCUMENTOS - {client_name.upper()}:")
        formatted.append(f"├─ Total: {client_count.get('total_documentos', 0)} documentos")
        formatted.append(f"├─ Publicados: {client_count.get('documentos_publicados', 0)}")
        formatted.append(f"├─ Validados: {client_count.get('documentos_validados', 0)}")
        formatted.append(f"└─ Por vencer (30 días): {client_count.get('documentos_por_vencer', 0)}")
    
    # Conteo por tipo de documento
    elif 'document_type_count' in counts:
        type_count = counts['document_type_count']
        doc_type = counts.get('type', 'documentos')
        formatted.append(f"CONTEO DE {doc_type.upper()}S:")
        if 'total_cedulas' in type_count:
            formatted.append(f"├─ Total: {type_count.get('total_cedulas', 0)}")
            formatted.append(f"├─ Activas: {type_count.get('cedulas_activas', 0)}")
            formatted.append(f"└─ Vencidas: {type_count.get('cedulas_vencidas', 0)}")
    
    # Conteo general
    else:
        formatted.append("ESTADÍSTICAS GENERALES:")
        if 'total_documentos' in counts:
            formatted.append(f"├─ Total: {counts['total_documentos']} documentos")
        if 'hoy' in counts and counts.get('focus') == 'hoy':
            formatted.append(f"└─ Subidos hoy: {counts['hoy']}")
        elif 'hoy' in counts:
            formatted.append(f"├─ Subidos hoy: {counts['hoy']}")
        if 'ayer' in counts:
            formatted.append(f"└─ Subidos ayer: {counts['ayer']}")
    
    formatted.append("")
    return formatted

def format_recent_documents(recent_docs):
    """Formatea documentos recientes"""
    formatted = []
    
    if recent_docs:
        formatted.append("DOCUMENTOS RECIENTES:")
        
        # Agrupar por fecha
        docs_by_date = {}
        for doc in recent_docs:
            fecha = doc.get('fecha_creacion', 'Sin fecha')
            # Extraer solo la fecha (sin hora)
            fecha_corta = fecha.split('T')[0] if 'T' in str(fecha) else str(fecha)
            
            if fecha_corta not in docs_by_date:
                docs_by_date[fecha_corta] = []
            
            docs_by_date[fecha_corta].append(doc)
        
        # Mostrar agrupados por fecha
        for fecha, docs in sorted(docs_by_date.items(), reverse=True):
            formatted.append(f"\n{fecha}:")
            
            # Agrupar por cliente dentro de cada fecha
            docs_by_client = {}
            for doc in docs:
                client = doc.get('cliente', 'Sin cliente')
                if client not in docs_by_client:
                    docs_by_client[client] = []
                docs_by_client[client].append(doc)
            
            for client, client_docs in docs_by_client.items():
                if client != 'Sin cliente':
                    formatted.append(f"  Cliente: {client}")
                    for doc in client_docs:
                        formatted.append(f"    - {doc.get('nombre_tipo', 'Tipo')}: {doc.get('titulo', 'Sin título')}")
                else:
                    for doc in client_docs:
                        formatted.append(f"  - {doc.get('nombre_tipo', 'Tipo')}: {doc.get('titulo', 'Sin título')}")
        
        formatted.append("")
    
    return formatted

def format_system_info(system_info):
    """Formatea información del sistema"""
    formatted = []
    
    if isinstance(system_info, dict):
        info_type = system_info.get('info_type')
        info_data = system_info.get('data', [])
        
        if info_type == 'document_types' and info_data:
            formatted.append("TIPOS DE DOCUMENTOS DISPONIBLES EN EL SISTEMA:")
            
            # Agrupar por si tienen documentos o no
            con_docs = [t for t in info_data if t.get('cantidad_actual', 0) > 0]
            sin_docs = [t for t in info_data if t.get('cantidad_actual', 0) == 0]
            
            if con_docs:
                formatted.append("\nTipos con documentos registrados:")
                for tipo in con_docs:
                    formatted.append(f"  • {tipo.get('nombre_tipo', 'N/A')} ({tipo.get('cantidad_actual', 0)} documentos)")
                    if tipo.get('descripcion'):
                        formatted.append(f"    {tipo['descripcion']}")
            
            if sin_docs:
                formatted.append("\nTipos disponibles sin documentos aún:")
                for tipo in sin_docs:
                    formatted.append(f"  • {tipo.get('nombre_tipo', 'N/A')}")
                    if tipo.get('descripcion'):
                        formatted.append(f"    {tipo['descripcion']}")
        
        formatted.append("")
    
    return formatted

def format_pending_documents(pending_docs):
    """Formatea documentos pendientes"""
    formatted = []
    
    if isinstance(pending_docs, dict) and not pending_docs.get('error'):
        client_info = pending_docs.get('client_info', {})
        pending = pending_docs.get('pending_documents', [])
        
        client_name = client_info.get('nombre_razon_social', 'Cliente')
        formatted.append(f"DOCUMENTOS PENDIENTES DE {client_name.upper()}:")
        formatted.append(f"Estado documental: {client_info.get('estado_documental', 'N/A')}")
        formatted.append(f"Total pendientes: {len(pending)}")
        
        if pending:
            # Agrupar por urgencia
            urgentes = [d for d in pending if d.get('dias_restantes', 999) <= 7]
            proximos = [d for d in pending if 7 < d.get('dias_restantes', 999) <= 30]
            otros = [d for d in pending if d.get('dias_restantes', 999) > 30]
            
            if urgentes:
                formatted.append("\nURGENTES (vencen en 7 días o menos):")
                for doc in urgentes:
                    formatted.append(f"  - {doc.get('nombre_tipo', 'Documento')}")
                    formatted.append(f"    Solicitado: {doc.get('fecha_solicitud', 'N/A')}")
                    formatted.append(f"    Vence: {doc.get('fecha_limite', 'N/A')} ({doc.get('dias_restantes', '?')} días)")
            
            if proximos:
                formatted.append("\nPRÓXIMOS (vencen en 8-30 días):")
                for doc in proximos:
                    formatted.append(f"  - {doc.get('nombre_tipo', 'Documento')}")
                    formatted.append(f"    Vence: {doc.get('fecha_limite', 'N/A')} ({doc.get('dias_restantes', '?')} días)")
            
            if otros:
                formatted.append("\nOTROS:")
                for doc in otros:
                    formatted.append(f"  - {doc.get('nombre_tipo', 'Documento')}")
                    formatted.append(f"    Vence: {doc.get('fecha_limite', 'N/A')}")
        
        formatted.append("")
    
    return formatted

def group_documents_by_client(documents):
    """Agrupa documentos por cliente"""
    docs_by_client = {}
    for doc in documents:
        client_name = doc.get('cliente_nombre', 'Sin cliente asignado')
        client_id = doc.get('id_cliente', 'sin_id')
        
        # Crear clave única para el cliente
        client_key = f"{client_id}_{client_name}"
        
        if client_key not in docs_by_client:
            docs_by_client[client_key] = {
                'nombre': client_name,
                'id': client_id,
                'documentos': []
            }
        
        docs_by_client[client_key]['documentos'].append(doc)
    
    return docs_by_client

# ============================================================================
# BLOQUE 10: UTILIDADES Y HELPERS
# ============================================================================

def create_response(status_code, body, headers=None):
    """Crea una respuesta HTTP estándar"""
    if headers is None:
        headers = add_cors_headers({'Content-Type': 'application/json'})
    
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': json.dumps(body, ensure_ascii=False, default=str) if isinstance(body, dict) else body
    }
        

def get_client_documents(analysis, user_id):
    """Obtiene documentos de un cliente específico"""
    try:
        if not analysis.get('client_info'):
            return {'error': 'No se especificó nombre de cliente'}
        
        client_name = analysis['client_info']
        logger.info(f"Buscando documentos para cliente: '{client_name}'")
        
        # Primero buscar el cliente
        client_query = """
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
        
        client_result = execute_query(client_query, [search_pattern, exact_match, starts_with], True)
        
        if not client_result:
            logger.info(f"Cliente '{client_name}' no encontrado")
            return {'error': f"Cliente '{client_name}' no encontrado"}
        
        client = client_result[0]
        client_id = client['id_cliente']
        logger.info(f"Cliente encontrado: {client['nombre_razon_social']} (ID: {client_id})")
        
        # Obtener documentos del cliente CON INFORMACIÓN DE IDENTIFICACIÓN
        docs_query = """
        SELECT 
            d.id_documento,
            d.codigo_documento,
            d.titulo,
            td.nombre_tipo,
            d.estado,
            d.fecha_creacion,
            di.numero_documento,
            di.fecha_expiracion,
            di.tipo_documento,
            di.nombre_completo,
            CASE 
                WHEN di.fecha_expiracion IS NOT NULL AND di.fecha_expiracion < CURDATE() THEN 'VENCIDO'
                WHEN di.fecha_expiracion IS NOT NULL AND di.fecha_expiracion <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) THEN 'POR_VENCER'
                WHEN d.validado_manualmente = 1 THEN 'VALIDADO'
                ELSE 'NORMAL'
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
        LIMIT 20
        """
        
        documents = execute_query(docs_query, [client_id, user_id, user_id, user_id], True) or []
        logger.info(f"Encontrados {len(documents)} documentos para el cliente")
        
        return {
            'client_info': client,
            'documents': documents,
            'total_documents': len(documents)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo documentos del cliente: {str(e)}", exc_info=True)
        return {'error': str(e)}