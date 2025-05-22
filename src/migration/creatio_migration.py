# src/migration/creatio_migration.py
import os
import json
import uuid
import boto3
import pymysql
import logging
import requests
import datetime
from urllib.parse import urljoin

# Configure logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Database configuration
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")

# Creatio configuration
CREATIO_INSTANCE = "571043-demo.creatio.com"
CREATIO_USER = "Administrator 1"
CREATIO_PASSWORD = "Administrator 1!"
CREATIO_BASE_URL = f"https://{CREATIO_INSTANCE}"

def get_db_connection():
    """Creates a connection to the database"""
    try:
        connection = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            db=DB_NAME,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=60
        )
        return connection
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}")
        raise

def execute_query(query, params=None, fetch=True):
    """Execute a SQL query and return results"""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
            if fetch:
                return cursor.fetchall()
            else:
                connection.commit()
                return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error executing query: {str(e)}")
        connection.rollback()
        raise
    finally:
        connection.close()

def generate_uuid():
    """Generate a UUID"""
    return str(uuid.uuid4())

def authenticate_creatio():
    """Authenticate with Creatio and get cookies and CSRF token"""
    auth_url = urljoin(CREATIO_BASE_URL, "/ServiceModel/AuthService.svc/Login")
    
    auth_data = {
        "UserName": CREATIO_USER,
        "UserPassword": CREATIO_PASSWORD
    }
    
    try:
        response = requests.post(auth_url, json=auth_data)
        
        if response.status_code != 200 or not response.json().get("Code", 0) == 0:
            logger.error(f"Authentication failed: {response.text}")
            raise Exception("Failed to authenticate with Creatio")
        
        # Get BPMCSRF cookie
        cookies = response.cookies
        csrf_token = None
        
        for cookie in cookies:
            if cookie.name == "BPMCSRF":
                csrf_token = cookie.value
                break
        
        if not csrf_token:
            raise Exception("BPMCSRF token not found in response cookies")
            
        return cookies, csrf_token
        
    except Exception as e:
        logger.error(f"Error authenticating with Creatio: {str(e)}")
        raise

def get_contacts_from_creatio(cookies, csrf_token, limit=50):
    """Get contacts from Creatio with type=Client"""
    # Define the URL for the Contact endpoint
    contacts_url = urljoin(CREATIO_BASE_URL, "/0/odata/Contact")
    
    # Set headers with CSRF token
    headers = {
        "Content-Type": "application/json",
        "BPMCSRF": csrf_token,
        "ForceUseSession": "true"
    }
    
    # Define query parameters to filter by TypeId (client type)
    # 00783ef6-f36b-1410-a883-16d83cab0980 is the TypeId for clients
    params = {
        "$filter": "Type/Id eq '00783ef6-f36b-1410-a883-16d83cab0980'",
        "$top": limit
    }
    
    try:
        response = requests.get(contacts_url, headers=headers, cookies=cookies, params=params)
        
        if response.status_code != 200:
            logger.error(f"Failed to get contacts: {response.text}")
            raise Exception(f"Failed to get contacts. Status code: {response.status_code}")
        
        return response.json().get("value", [])
    
    except Exception as e:
        logger.error(f"Error getting contacts from Creatio: {str(e)}")
        raise

def map_creatio_contact_to_client(contact):
    """Map Creatio contact fields to document manager client fields"""
    # Determine client type based on Creatio contact fields
    tipo_cliente = "persona_fisica"  # Default
    
    # Create a structured data_contacto field
    datos_contacto = {
        "email": contact.get("Email", ""),
        "telefono": contact.get("MobilePhone", ""),
        "direccion": contact.get("Address", "")
    }
    
    # Determine risk level (simplified logic)
    nivel_riesgo = "bajo"  # Default
    credit_score = contact.get("labCredScore", 0)
    if credit_score:
        if credit_score < 500:
            nivel_riesgo = "alto"
        elif credit_score < 650:
            nivel_riesgo = "medio"
    
    # Map to client object
    cliente = {
        "tipo_cliente": tipo_cliente,
        "nombre_razon_social": contact.get("Name", ""),
        "documento_identificacion": contact.get("INN", "") or contact.get("labIDNumber", ""),
        "estado": "activo",
        "segmento": contact.get("SocialStatusId", None),
        "segmento_bancario": "retail",  # Default
        "nivel_riesgo": nivel_riesgo,
        "datos_contacto": datos_contacto,
        "preferencias_comunicacion": {
            "canal_preferido": "email" if not contact.get("DoNotUseEmail", True) else "telefono"
        },
        "metadata_personalizada": {
            "creatio_id": contact.get("Id"),
            "credit_score": credit_score,
            "age": contact.get("Age", 0),
            "birth_date": contact.get("BirthDate"),
            "country_id": contact.get("CountryId"),
            "city_id": contact.get("CityId")
        }
    }
    
    return cliente

def check_client_exists(documento_identificacion):
    """Check if a client already exists by documento_identificacion"""
    if not documento_identificacion:
        return None
        
    query = """
    SELECT id_cliente, codigo_cliente, nombre_razon_social 
    FROM clientes 
    WHERE documento_identificacion = %s
    """
    
    results = execute_query(query, (documento_identificacion,))
    
    if results and len(results) > 0:
        return results[0]
    
    return None

def check_migration_exists(creatio_id):
    """Check if a migration record already exists for this Creatio contact"""
    query = """
    SELECT id, gestor_cliente_id 
    FROM migration 
    WHERE creatio_contact_id = %s
    """
    
    results = execute_query(query, (creatio_id,))
    
    if results and len(results) > 0:
        return results[0]
    
    return None

def create_client(client_data):
    """Create a new client in the document manager"""
    # Generate client ID
    client_id = generate_uuid()
    
    # Generate client code (simplified)
    now = datetime.datetime.now()
    date_part = now.strftime("%Y%m%d")
    
    tipo_prefix = {
        'persona_fisica': 'PF',
        'empresa': 'EM',
        'organismo_publico': 'OP'
    }[client_data['tipo_cliente']]
    
    # Get sequence for the code
    seq_query = """
    SELECT COUNT(*) as seq
    FROM clientes
    WHERE tipo_cliente = %s AND DATE(fecha_alta) = CURDATE()
    """
    
    seq_result = execute_query(seq_query, (client_data['tipo_cliente'],))
    sequence = (seq_result[0]['seq'] + 1) if seq_result else 1
    
    # Format final code
    codigo_cliente = f"{tipo_prefix}-{date_part}-{sequence:04d}"
    
    # Insert client
    insert_query = """
    INSERT INTO clientes (
        id_cliente, codigo_cliente, tipo_cliente, nombre_razon_social,
        documento_identificacion, fecha_alta, estado, segmento,
        datos_contacto, preferencias_comunicacion,
        metadata_personalizada, segmento_bancario, nivel_riesgo
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    
    execute_query(insert_query, (
        client_id, 
        codigo_cliente, 
        client_data['tipo_cliente'], 
        client_data['nombre_razon_social'],
        client_data['documento_identificacion'], 
        now, 
        client_data['estado'], 
        client_data['segmento'],
        json.dumps(client_data['datos_contacto']), 
        json.dumps(client_data['preferencias_comunicacion']),
        json.dumps(client_data['metadata_personalizada']), 
        client_data['segmento_bancario'], 
        client_data['nivel_riesgo']
    ), fetch=False)
    
    return client_id, codigo_cliente

def update_client(client_id, client_data):
    """Update an existing client in the document manager"""
    # Build the update query dynamically
    update_fields = []
    update_params = []
    
    # Fields to update
    if 'nombre_razon_social' in client_data:
        update_fields.append("nombre_razon_social = %s")
        update_params.append(client_data['nombre_razon_social'])
    
    if 'estado' in client_data:
        update_fields.append("estado = %s")
        update_params.append(client_data['estado'])
    
    if 'segmento' in client_data:
        update_fields.append("segmento = %s")
        update_params.append(client_data['segmento'])
    
    if 'segmento_bancario' in client_data:
        update_fields.append("segmento_bancario = %s")
        update_params.append(client_data['segmento_bancario'])
    
    if 'nivel_riesgo' in client_data:
        update_fields.append("nivel_riesgo = %s")
        update_params.append(client_data['nivel_riesgo'])
    
    if 'datos_contacto' in client_data:
        update_fields.append("datos_contacto = %s")
        update_params.append(json.dumps(client_data['datos_contacto']))
    
    if 'preferencias_comunicacion' in client_data:
        update_fields.append("preferencias_comunicacion = %s")
        update_params.append(json.dumps(client_data['preferencias_comunicacion']))
    
    if 'metadata_personalizada' in client_data:
        update_fields.append("metadata_personalizada = %s")
        update_params.append(json.dumps(client_data['metadata_personalizada']))
    
    # Add last activity date
    update_fields.append("fecha_ultima_actividad = %s")
    update_params.append(datetime.datetime.now().date())
    
    # Add client_id to params
    update_params.append(client_id)
    
    # Execute update query
    update_query = f"""
    UPDATE clientes
    SET {', '.join(update_fields)}
    WHERE id_cliente = %s
    """
    
    execute_query(update_query, update_params, fetch=False)
    
    return client_id

def create_migration_record(creatio_id, client_id, status="exitoso", details=None):
    """Create a record in the migration table"""
    migration_id = generate_uuid()
    
    insert_query = """
    INSERT INTO migration (
        id, creatio_contact_id, gestor_cliente_id, 
        fecha_migracion, estado_migracion, detalles
    ) VALUES (%s, %s, %s, %s, %s, %s)
    """
    
    execute_query(insert_query, (
        migration_id,
        creatio_id,
        client_id,
        datetime.datetime.now(),
        status,
        json.dumps(details) if details else None
    ), fetch=False)
    
    return migration_id

def lambda_handler(event, context):
    """Main Lambda handler function"""
    try:
        # Get the number of contacts to migrate from event
        limit = 10  # Default
        
        if 'body' in event:
            try:
                body = json.loads(event['body'])
                if 'limit' in body:
                    limit = int(body['limit'])
            except:
                pass
        elif 'limit' in event:
            limit = int(event['limit'])
        
        # Authenticate with Creatio
        logger.info(f"Authenticating with Creatio instance {CREATIO_INSTANCE}")
        cookies, csrf_token = authenticate_creatio()
        
        # Get contacts from Creatio
        logger.info(f"Fetching {limit} contacts from Creatio")
        contacts = get_contacts_from_creatio(cookies, csrf_token, limit)
        
        # Process each contact
        results = {
            "total_contacts": len(contacts),
            "created": 0,
            "updated": 0,
            "errors": 0,
            "details": []
        }
        
        for contact in contacts:
            try:
                creatio_id = contact.get("Id")
                if not creatio_id:
                    logger.warning(f"Contact missing ID: {contact}")
                    results["errors"] += 1
                    results["details"].append({
                        "status": "error", 
                        "message": "Contact missing ID",
                        "creatio_data": contact
                    })
                    continue
                
                # Check if this contact has already been migrated
                existing_migration = check_migration_exists(creatio_id)
                if existing_migration:
                    # Contact already migrated, update the client
                    logger.info(f"Contact {creatio_id} already migrated. Updating client {existing_migration['gestor_cliente_id']}")
                    
                    # Map Creatio data to client data
                    client_data = map_creatio_contact_to_client(contact)
                    
                    # Update the client
                    update_client(existing_migration['gestor_cliente_id'], client_data)
                    
                    results["updated"] += 1
                    results["details"].append({
                        "status": "updated", 
                        "creatio_id": creatio_id,
                        "client_id": existing_migration['gestor_cliente_id']
                    })
                    continue
                
                # Map Creatio data to client data
                client_data = map_creatio_contact_to_client(contact)
                
                # Check if a client with this documento_identificacion already exists
                existing_client = check_client_exists(client_data['documento_identificacion'])
                
                if existing_client:
                    # Client exists, update it
                    logger.info(f"Updating existing client {existing_client['id_cliente']} for Creatio contact {creatio_id}")
                    client_id = update_client(existing_client['id_cliente'], client_data)
                    
                    # Create migration record
                    create_migration_record(creatio_id, existing_client['id_cliente'])
                    
                    results["updated"] += 1
                    results["details"].append({
                        "status": "updated", 
                        "creatio_id": creatio_id,
                        "client_id": existing_client['id_cliente']
                    })
                else:
                    # Create new client
                    logger.info(f"Creating new client for Creatio contact {creatio_id}")
                    client_id, client_code = create_client(client_data)
                    
                    # Create migration record
                    create_migration_record(creatio_id, client_id)
                    
                    results["created"] += 1
                    results["details"].append({
                        "status": "created", 
                        "creatio_id": creatio_id,
                        "client_id": client_id,
                        "client_code": client_code
                    })
                    
            except Exception as e:
                logger.error(f"Error processing contact {contact.get('Id')}: {str(e)}")
                results["errors"] += 1
                results["details"].append({
                    "status": "error", 
                    "creatio_id": contact.get("Id"),
                    "message": str(e)
                })
        
        logger.info(f"Migration completed: {results['created']} created, {results['updated']} updated, {results['errors']} errors")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(results)
        }
        
    except Exception as e:
        logger.error(f"Error in Lambda handler: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': str(e)})
        }