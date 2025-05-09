def add_cors_headers(headers=None):
    """Añade encabezados CORS a las respuestas de la API"""
    if headers is None:
        headers = {}
    
    cors_headers = {
        'Access-Control-Allow-Origin': '*',  # O restringe a tu dominio específico
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
        'Access-Control-Allow-Credentials': 'true'
    }
    
    # Combinar con los encabezados existentes
    return {**headers, **cors_headers}