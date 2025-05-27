# src/global_banking_chat/app.py
import json
import logging
import os
import boto3
from datetime import datetime, timedelta
import re
from common.db import execute_query, get_connection, generate_uuid, register_global_chat_query,get_client_documents_by_name,get_expiring_documents_for_chat
# Configurar el logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Cliente Bedrock
bedrock_client = boto3.client('bedrock-runtime')

def lambda_handler(event, context):
    """
    Handler principal para el chat global del sistema bancario.
    
    Evento esperado:
    {
        "question": "¿Qué documentos están próximos a expirar?",
        "user_id": "uuid-del-usuario",
        "context": "optional-context"
    }
    """
    try:
        # Log del evento recibido
        logger.info(f"Evento recibido: {json.dumps(event)}")
        
        # Parsear evento si viene de API Gateway
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
            
        # Validar campos requeridos
        if 'question' not in body:
            return create_response(400, {'error': 'Campo requerido faltante: question'})
        
        question = body['question']
        user_id = body.get('user_id', 'anonymous')
        context = body.get('context', '')
        
        # Analizar la pregunta y determinar qué datos necesitamos
        query_analysis = analyze_question(question, user_id)
        
        # Obtener datos relevantes de la base de datos
        relevant_data = fetch_relevant_data(query_analysis, user_id)
        
        # Generar respuesta usando Bedrock
        response = generate_smart_response(question, relevant_data, context)
        
        # Registrar la consulta
        query_id = register_global_query(question, response, user_id, query_analysis)
        
        # Retornar respuesta
        return create_response(200, {
            'query_id': query_id,
            'question': question,
            'answer': response,
            'data_sources': query_analysis.get('data_sources', []),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error procesando consulta global: {str(e)}")
        return create_response(500, {'error': 'Error interno del servidor'})

def analyze_question(question, user_id):
    """
    Analiza la pregunta para determinar qué tipo de consulta es y qué datos necesita.
    """
    question_lower = question.lower()
    
    analysis = {
        'intent': 'unknown',
        'entities': [],
        'time_range': None,
        'document_types': [],
        'client_info': None,
        'data_sources': [],
        'filters': {}
    }
    
    # Detectar intenciones principales
    if any(word in question_lower for word in ['próximos', 'expirar', 'vencer', 'caducar']):
        analysis['intent'] = 'expiring_documents'
        analysis['data_sources'] = ['documentos_identificacion', 'documentos']
        
    elif any(word in question_lower for word in ['documentos tiene', 'documentos de']):
        analysis['intent'] = 'client_documents'
        analysis['data_sources'] = ['documentos', 'clientes', 'documentos_clientes']
        
    elif any(word in question_lower for word in ['subí', 'cargué', 'agregué']) and any(word in question_lower for word in ['ayer', 'hoy', 'semana']):
        analysis['intent'] = 'recent_uploads'
        analysis['data_sources'] = ['documentos']
        
    elif any(word in question_lower for word in ['cuántos', 'cantidad', 'número']):
        analysis['intent'] = 'count_query'
        analysis['data_sources'] = ['documentos']
        
    elif any(word in question_lower for word in ['estado', 'completitud', 'faltantes']):
        analysis['intent'] = 'client_status'
        analysis['data_sources'] = ['clientes', 'vista_cliente_cache']
        
    elif any(word in question_lower for word in ['búsqueda', 'buscar', 'encontrar']):
        analysis['intent'] = 'search_documents'
        analysis['data_sources'] = ['documentos', 'analisis_documento_ia']
    
    # Detectar rangos de tiempo
    if 'ayer' in question_lower:
        analysis['time_range'] = 'yesterday'
    elif 'hoy' in question_lower:
        analysis['time_range'] = 'today'
    elif 'semana' in question_lower:
        analysis['time_range'] = 'week'
    elif 'mes' in question_lower:
        analysis['time_range'] = 'month'
    elif 'próximos' in question_lower and 'días' in question_lower:
        # Extraer número de días
        days_match = re.search(r'(\d+)\s*días?', question_lower)
        if days_match:
            analysis['time_range'] = f'next_{days_match.group(1)}_days'
        else:
            analysis['time_range'] = 'next_30_days'
    
    # Detectar tipos de documento
    doc_types = {
        'cédula': 'cedula',
        'dni': 'cedula', 
        'pasaporte': 'pasaporte',
        'contrato': 'contrato',
        'extracto': 'extracto',
        'nómina': 'nomina',
        'kyc': 'formulario_kyc'
    }
    
    for keyword, doc_type in doc_types.items():
        if keyword in question_lower:
            analysis['document_types'].append(doc_type)
    
    # Detectar nombres de clientes (buscar patrones como "documentos de Juan" o "Marco Rosas")
    # Patrón para nombres: "de [Nombre]" o "[Nombre Apellido]"
    name_patterns = [
        r'(?:de|tiene)\s+([A-ZÁÉÍÓÚ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)*)',
        r'\b([A-ZÁÉÍÓÚ][a-záéíóúñ]+\s+[A-ZÁÉÍÓÚ][a-záéíóúñ]+)\b'
    ]
    
    for pattern in name_patterns:
        matches = re.findall(pattern, question, re.IGNORECASE)
        if matches:
            analysis['client_info'] = matches[0].strip()
            break
    
    logger.info(f"Análisis de pregunta: {analysis}")
    return analysis

def fetch_relevant_data(analysis, user_id):
    """
    Obtiene los datos relevantes de la base de datos según el análisis de la pregunta.
    """
    
    
    data = {}
    
    try:
        if analysis['intent'] == 'expiring_documents':
            data['expiring_docs'] = get_expiring_documents(analysis, user_id)
            
        elif analysis['intent'] == 'client_documents':
            data['client_docs'] = get_client_documents(analysis, user_id)
            
        elif analysis['intent'] == 'recent_uploads':
            data['recent_docs'] = get_recent_uploads(analysis, user_id)
            
        elif analysis['intent'] == 'count_query':
            data['counts'] = get_document_counts(analysis, user_id)
            
        elif analysis['intent'] == 'client_status':
            data['client_status'] = get_client_status(analysis, user_id)
            
        elif analysis['intent'] == 'search_documents':
            data['search_results'] = search_documents(analysis, user_id)
        
        # Siempre incluir datos de contexto general
        data['context'] = get_user_context(user_id)
        
    except Exception as e:
        logger.error(f"Error obteniendo datos: {str(e)}")
        data['error'] = str(e)
    
    return data

def get_expiring_documents(analysis, user_id):
    """Obtiene documentos próximos a expirar"""
     
    
    # Determinar días hacia el futuro
    days = 30  # default
    if analysis['time_range'] and analysis['time_range'].startswith('next_'):
        try:
            days = int(analysis['time_range'].split('_')[1])
        except:
            days = 30
    
    query = """
    SELECT 
        di.id_documento,
        d.titulo,
        di.tipo_documento,
        di.numero_documento,
        di.fecha_expiracion,
        di.nombre_completo,
        c.nombre_razon_social as cliente_nombre,
        DATEDIFF(di.fecha_expiracion, CURDATE()) as dias_restantes
    FROM documentos_identificacion di
    JOIN documentos d ON di.id_documento = d.id_documento
    LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
    LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
    WHERE di.fecha_expiracion BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL %s DAY)
    AND d.estado = 'publicado'
    ORDER BY di.fecha_expiracion ASC
    LIMIT 50
    """
    
    results = execute_query(query, [days], True)
    return results or []

def get_client_documents(analysis, user_id):
    """Obtiene documentos de un cliente específico"""
     
    
    if not analysis.get('client_info'):
        return []
    
    client_name = analysis['client_info']
    
    # Buscar documentos del cliente por nombre
    query = """
    SELECT 
        d.id_documento,
        d.codigo_documento,
        d.titulo,
        td.nombre_tipo,
        d.fecha_creacion,
        d.estado,
        c.nombre_razon_social,
        di.numero_documento,
        di.fecha_expiracion
    FROM documentos d
    JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
    LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
    LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
    LEFT JOIN documentos_identificacion di ON d.id_documento = di.id_documento
    WHERE (
        c.nombre_razon_social LIKE %s
        OR di.nombre_completo LIKE %s
    )
    ORDER BY d.fecha_creacion DESC
    LIMIT 20
    """
    
    search_pattern = f"%{client_name}%"
    results = execute_query(query, [search_pattern, search_pattern], True)
    return results or []

def get_recent_uploads(analysis, user_id):
    """Obtiene documentos subidos recientemente"""
     
    
    # Determinar rango de fechas
    if analysis['time_range'] == 'yesterday':
        date_condition = "DATE(d.fecha_creacion) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)"
    elif analysis['time_range'] == 'today':
        date_condition = "DATE(d.fecha_creacion) = CURDATE()"
    elif analysis['time_range'] == 'week':
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
        u.nombre_usuario as subido_por,
        c.nombre_razon_social as cliente
    FROM documentos d
    JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
    LEFT JOIN usuarios u ON d.creado_por = u.id_usuario
    LEFT JOIN documentos_clientes dc ON d.id_documento = dc.id_documento
    LEFT JOIN clientes c ON dc.id_cliente = c.id_cliente
    WHERE {date_condition}
    AND d.creado_por = %s
    ORDER BY d.fecha_creacion DESC
    LIMIT 20
    """
    
    results = execute_query(query, [user_id], True)
    return results or []

def get_document_counts(analysis, user_id):
    """Obtiene conteos de documentos"""
     
    
    counts = {}
    
    # Conteo general
    query = """
    SELECT 
        COUNT(*) as total_documentos,
        COUNT(CASE WHEN DATE(fecha_creacion) = CURDATE() THEN 1 END) as hoy,
        COUNT(CASE WHEN DATE(fecha_creacion) = DATE_SUB(CURDATE(), INTERVAL 1 DAY) THEN 1 END) as ayer,
        COUNT(CASE WHEN fecha_creacion >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 END) as esta_semana
    FROM documentos 
    WHERE creado_por = %s
    """
    
    result = execute_query(query, [user_id], True)
    if result:
        counts.update(result[0])
    
    # Conteo por tipo
    type_query = """
    SELECT 
        td.nombre_tipo,
        COUNT(*) as cantidad
    FROM documentos d
    JOIN tipos_documento td ON d.id_tipo_documento = td.id_tipo_documento
    WHERE d.creado_por = %s
    GROUP BY td.nombre_tipo
    ORDER BY cantidad DESC
    """
    
    type_results = execute_query(type_query, [user_id], True)
    counts['por_tipo'] = type_results or []
    
    return counts

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

def generate_smart_response(question, data, context=""):
    """
    Genera una respuesta inteligente usando los datos obtenidos y Bedrock.
    """
    try:
        # Preparar el contexto de datos para Bedrock
        data_context = format_data_for_bedrock(data)
        
        # Prompt optimizado para consultas bancarias globales
        prompt = f"""Eres un asistente bancario experto que ayuda a los usuarios con consultas sobre el sistema de gestión documental.

            DATOS DISPONIBLES:
            {data_context}

            PREGUNTA DEL USUARIO:
            {question}

            INSTRUCCIONES:
            1. Responde basándote ÚNICAMENTE en los datos proporcionados arriba
            2. Si no hay datos suficientes, di claramente "No encontré información para responder esta consulta"
            3. Sé específico con números, fechas y nombres cuando estén disponibles
            4. Organiza la información de manera clara y profesional
            5. Si hay documentos próximos a vencer, menciona las fechas específicas
            6. Para consultas de conteo, proporciona números exactos
            7. Mantén un tono profesional pero amigable

            CONTEXTO ADICIONAL:
            {context}

            Respuesta:"""

        # Configurar parámetros para el modelo
        model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-haiku-20240307-v1:0')
        
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2000,
            "temperature": 0.3,  # Temperatura baja para respuestas más precisas
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        # Llamar a Bedrock
        response = bedrock_client.invoke_model(
            modelId=model_id,
            body=json.dumps(body),
            contentType='application/json'
        )
        
        # Procesar respuesta
        response_body = json.loads(response['body'].read())
        
        if 'content' in response_body and response_body['content']:
            answer = response_body['content'][0]['text'].strip()
            logger.info(f"Respuesta de Bedrock: {answer}")
            return answer
        else:
            logger.error("Respuesta inesperada de Bedrock")
            return "Lo siento, no pude procesar tu consulta en este momento."
            
    except Exception as e:
        logger.error(f"Error consultando Bedrock: {str(e)}")
        return f"Ocurrió un error al procesar tu consulta. Por favor, intenta de nuevo."

def format_data_for_bedrock(data):
    """
    Formatea los datos obtenidos de la BD en un formato legible para Bedrock.
    """
    formatted = []
    
    if 'expiring_docs' in data and data['expiring_docs']:
        formatted.append("DOCUMENTOS PRÓXIMOS A EXPIRAR:")
        for doc in data['expiring_docs']:
            formatted.append(f"- {doc.get('tipo_documento', 'Documento')} de {doc.get('nombre_completo', 'N/A')}")
            formatted.append(f"  Número: {doc.get('numero_documento', 'N/A')}")
            formatted.append(f"  Expira: {doc.get('fecha_expiracion', 'N/A')} ({doc.get('dias_restantes', '?')} días restantes)")
            if doc.get('cliente_nombre'):
                formatted.append(f"  Cliente: {doc['cliente_nombre']}")
            formatted.append("")
    
    if 'client_docs' in data and data['client_docs']:
        formatted.append("DOCUMENTOS DEL CLIENTE:")
        for doc in data['client_docs']:
            formatted.append(f"- {doc.get('nombre_tipo', 'Documento')}: {doc.get('titulo', 'Sin título')}")
            formatted.append(f"  Código: {doc.get('codigo_documento', 'N/A')}")
            formatted.append(f"  Estado: {doc.get('estado', 'N/A')}")
            formatted.append(f"  Fecha: {doc.get('fecha_creacion', 'N/A')}")
            if doc.get('numero_documento'):
                formatted.append(f"  Número: {doc['numero_documento']}")
            formatted.append("")
    
    if 'recent_docs' in data and data['recent_docs']:
        formatted.append("DOCUMENTOS RECIENTES:")
        for doc in data['recent_docs']:
            formatted.append(f"- {doc.get('nombre_tipo', 'Documento')}: {doc.get('titulo', 'Sin título')}")
            formatted.append(f"  Fecha: {doc.get('fecha_creacion', 'N/A')}")
            if doc.get('cliente'):
                formatted.append(f"  Cliente: {doc['cliente']}")
            formatted.append("")
    
    if 'counts' in data:
        counts = data['counts']
        formatted.append("ESTADÍSTICAS DE DOCUMENTOS:")
        if 'total_documentos' in counts:
            formatted.append(f"- Total de documentos: {counts['total_documentos']}")
        if 'hoy' in counts:
            formatted.append(f"- Documentos subidos hoy: {counts['hoy']}")
        if 'ayer' in counts:
            formatted.append(f"- Documentos subidos ayer: {counts['ayer']}")
        if 'esta_semana' in counts:
            formatted.append(f"- Documentos esta semana: {counts['esta_semana']}")
        
        if 'por_tipo' in counts and counts['por_tipo']:
            formatted.append("- Distribución por tipo:")
            for tipo in counts['por_tipo']:
                formatted.append(f"  * {tipo.get('nombre_tipo', 'N/A')}: {tipo.get('cantidad', 0)}")
        formatted.append("")
    
    if 'client_status' in data and data['client_status']:
        formatted.append("ESTADO DE CLIENTES:")
        for status in data['client_status']:
            if 'estado_documental' in status:
                formatted.append(f"- Estado {status['estado_documental']}: {status.get('cantidad', 0)} clientes")
            else:
                formatted.append(f"- Cliente: {status.get('nombre_razon_social', 'N/A')}")
                formatted.append(f"  Estado documental: {status.get('estado_documental', 'N/A')}")
                formatted.append("")
    
    if 'search_results' in data and data['search_results']:
        formatted.append("RESULTADOS DE BÚSQUEDA:")
        for doc in data['search_results']:
            formatted.append(f"- {doc.get('nombre_tipo', 'Documento')}: {doc.get('titulo', 'Sin título')}")
            if doc.get('nombre_razon_social'):
                formatted.append(f"  Cliente: {doc['nombre_razon_social']}")
            if doc.get('numero_documento'):
                formatted.append(f"  Número: {doc['numero_documento']}")
            formatted.append(f"  Fecha: {doc.get('fecha_creacion', 'N/A')}")
            formatted.append("")
    
    if 'context' in data and data['context']:
        ctx = data['context']
        if 'user' in ctx:
            user = ctx['user']
            formatted.append(f"USUARIO ACTUAL: {user.get('nombre', '')} {user.get('apellidos', '')}")
        if 'stats' in ctx:
            stats = ctx['stats']
            formatted.append(f"Tienes {stats.get('total_docs', 0)} documentos en total, {stats.get('docs_hoy', 0)} subidos hoy.")
    
    if not formatted:
        formatted.append("No se encontraron datos relevantes para esta consulta.")
    
    return "\n".join(formatted)

def register_global_query(question, answer, user_id, analysis):
    """
    Registra la consulta global en la base de datos usando la función optimizada.
    """
    try:
        
        
        query_id = register_global_chat_query(
            user_id=user_id,
            question=question,
            answer=answer,
            intent_detected=analysis.get('intent', 'unknown'),
            data_sources=analysis.get('data_sources', [])
        )
        
        return query_id
        
    except Exception as e:
        logger.error(f"Error registrando consulta global: {str(e)}")
        return generate_uuid()

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

def get_client_documents(analysis, user_id):
    """
    Obtiene documentos de un cliente específico, usando una función optimizada si existe.
    """
     

    if not analysis.get('client_info'):
        logger.info("No se proporcionó información de cliente en el análisis.")
        return []

    client_name = analysis['client_info']

    try:
        result, error = get_client_documents_by_name(client_name, user_id, limit=20)
        if error:
            logger.warning(f"No se encontraron documentos para el cliente: {client_name}")
            return []
        return result or []

    except Exception as e:
        logger.error(f"Error obteniendo documentos del cliente '{client_name}': {str(e)}")
        return []

def get_expiring_documents(analysis, user_id):
    """
    Obtiene documentos próximos a expirar usando lógica optimizada.
    """
     

    try:
        # Determinar cuántos días hacia adelante buscar
        days = 30
        if analysis.get('time_range') and analysis['time_range'].startswith('next_'):
            try:
                days = int(re.search(r'next_(\d+)', analysis['time_range']).group(1))
            except Exception as e:
                logger.warning(f"No se pudo interpretar el rango de días: {analysis['time_range']}. Usando 30 días por defecto.")
                days = 30

        results = get_expiring_documents_for_chat(days_ahead=days, user_id=user_id, limit=50)
        return results or []

    except Exception as e:
        logger.error(f"Error al obtener documentos por expirar: {str(e)}")
        return []
