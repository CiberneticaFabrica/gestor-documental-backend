import os
import json
import logging
import requests
import datetime
import boto3
from uuid import uuid4

from common.db import (
    execute_query,
    get_connection,
    generate_uuid,
    insert_audit_record
)

from common.headers import add_cors_headers

# Configure logger
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Creatio API details
CREATIO_INSTANCE = "571043-demo.creatio.com"
CREATIO_USERNAME = "Administrator 1"
CREATIO_PASSWORD = "Administrator 1!"
CLIENT_TYPE_ID = "00783ef6-f36b-1410-a883-16d83cab0980"

def lambda_handler(event, context):
    """Main handler that directs to the corresponding functions"""
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
        
        # Migration routes
        if http_method == 'POST' and path == '/migration':
            return start_migration(event, context)
        elif http_method == 'GET' and path == '/migration/status':
            return check_migration_status(event, context)
                 
        # If no route is found, return 404
        return {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Route not found'})
        }
        
    except Exception as e:
        logger.error(f"Error in main dispatcher: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }

def validate_session(event, required_permission=None):
    """Validates the session and checks for permissions"""
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None, {'statusCode': 401, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'Token not provided'})}
    
    session_token = auth_header.split(' ')[1]
    
    # Check if the session exists and is active
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

def authenticate_with_creatio():
    """Authenticate with Creatio CRM and return the authentication cookies"""
    try:
        logger.info("Authenticating with Creatio...")
        url = f"https://{CREATIO_INSTANCE}/ServiceModel/AuthService.svc/Login"
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        data = {
            'UserName': CREATIO_USERNAME, 
            'UserPassword': CREATIO_PASSWORD
        }
        
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code != 200:
            logger.error(f"Creatio authentication failed: {response.status_code} - {response.text}")
            return None
        
        # Extract the BPMCSRF cookie
        cookies = response.cookies
        
        # Check if authentication was successful in the response body
        response_json = response.json()
        if not response_json.get('Code', 0) == 0:
            logger.error(f"Creatio authentication failed: {response_json}")
            return None
            
        logger.info("Creatio authentication successful")
        return cookies
        
    except Exception as e:
        logger.error(f"Error authenticating with Creatio: {str(e)}")
        return None

def get_creatio_contacts(cookies, count=10):
    """Get client contacts from Creatio"""
    try:
        logger.info(f"Getting {count} client contacts from Creatio...")
        
        # Extract BPMCSRF token from cookies
        csrf_token = cookies.get('BPMCSRF')
        
        # Prepare headers with CSRF token
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'BPMCSRF': csrf_token
        }
        
        # Fields to select from Creatio
        select_fields = [
            "Id", "Name", "TypeId", "Email", "MobilePhone", "Phone", 
            "INN", "Address", "Notes", "BirthDate", "PlaceOfBirth", 
            "labClientCode", "ClientTypeId", "labFATCAId", "labSolvencyId",
            "labCredScore", "labIsNonGrata", "CountryId", "CityId", "Zip",
            "GivenName", "Surname", "MiddleName"
        ]

        # NUEVA LÓGICA: Calcular cuántos contactos ya fueron migrados
        migrated_count_query = """
        SELECT COUNT(*) as migrated_count
        FROM contactos_migrados_creatio
        """
        
        try:
            migrated_result = execute_query(migrated_count_query)
            skip_count = migrated_result[0]['migrated_count'] if migrated_result else 0
            logger.info(f"Found {skip_count} already migrated contacts, skipping them")
        except Exception as e:
            logger.warning(f"Could not check migrated contacts count: {str(e)}, starting from beginning")
            skip_count = 0
        
        # Build the OData query
        url = f"https://{CREATIO_INSTANCE}/0/odata/Contact"
        params = {
            '$filter': f"Type/Id eq {CLIENT_TYPE_ID}",
            '$select': ",".join(select_fields),
            '$top': count,                  # Cantidad solicitada
            '$skip': skip_count,            # Saltar los ya migrados
            '$orderby': 'CreatedOn asc'     # Orden consistente
        }

        logger.info(f"Querying Creatio with $top={count}, $skip={skip_count}")
        
        # Make the request
        response = requests.get(url, headers=headers, cookies=cookies, params=params)
        
        if response.status_code != 200:
            logger.error(f"Failed to get contacts: {response.status_code} - {response.text}")
            return None
            
        data = response.json()
        contacts = data.get('value', [])
        
        logger.info(f"Retrieved {len(contacts)} contacts from Creatio")
        return contacts
        
    except Exception as e:
        logger.error(f"Error getting Creatio contacts: {str(e)}")
        return None

def map_cliente_tipo(creatio_client_type):
    """Map Creatio client type to our system's client type"""
    # Default to 'persona_fisica' if no mapping is found
    tipo_mapping = {
        # Add any specific mappings here
        # 'creatio_type_id': 'sistema_tipo'
    }
    
    return tipo_mapping.get(creatio_client_type, 'persona_fisica')

def map_cliente_segmento(creatio_client_type_id):
    """Map Creatio client type to our system's client segment"""
    # Mapping for client segments based on Creatio's client type IDs
    # These are example IDs - adjust according to actual Creatio configuration

    #ejemplo de mapeo
    # 'creatio_type_id': 'sistema_segmento'
    # segmento_mapping = {
    #     "00783ef6-f36b-1410-a883-16d83cab0980": "banca_personal",  # Cliente Personal
    #     "60733efc-f36b-1410-a883-16d83cab0980": "banca_personal",  # Contact
    #     "ebf50f5c-a351-4d8e-ad31-5e49939f034c": "banca_corporativa",  # Cliente Corporativo
    #     "bc04b305-8012-4a51-a9fe-392aabbc1607": "banca_institucional",  # Cliente Institucional
    #     "d80949d6-f36b-1410-a883-16d83cab0980": "banca_comercial",  # Cliente Comercial
    #     "69e26a87-8dd0-46c6-9335-7d7aa2c67e5f": "banca_pyme",  # Cliente PYME
    # }
    
    # # If there's a direct mapping, use it
    # if creatio_client_type_id and creatio_client_type_id in segmento_mapping:
    #     return segmento_mapping[creatio_client_type_id]
    
    # # Fallback logic based on ID pattern if it's a valid GUID
    # if creatio_client_type_id and len(creatio_client_type_id) >= 36:
    #     # If it looks like a business-related ID format
    #     if "f36b" in creatio_client_type_id:
    #         return "banca_comercial"
    
    # Default fallback 
    return "retail"

def map_cliente_segmento_bancario(creatio_fatca_id, creatio_solvency_id=None, cred_score=None, client_code=None):
    # """Map Creatio data to our system's banking segment"""
    # # Valid segment values: 'retail', 'premium', 'privada', 'empresas', 'corporativa', 'institucional'
    
    # # Check if client has a special client code prefix
    # if client_code:
    #     if client_code.startswith("CORP-"):
    #         return "corporativa"
    #     if client_code.startswith("PRIV-"):
    #         return "privada"
    #     if client_code.startswith("PREM-"):
    #         return "premium"
    #     if client_code.startswith("EMP-"):
    #         return "empresas"
    #     if client_code.startswith("INST-"):
    #         return "institucional"
    
    # # Check FATCA status
    # if creatio_fatca_id and creatio_fatca_id != "00000000-0000-0000-0000-000000000000":
    #     # Mapping of FATCA IDs to segments
    #     fatca_mapping = {
    #         # These are example IDs - update with actual FATCA category IDs from Creatio
    #         "d2588358-d33e-472a-95c0-e3d9c4e95ce2": "premium",  # High net worth individuals
    #         "a7fd3e58-da96-4b0b-9521-0689c3f8d0a1": "privada",  # Private banking clients
    #         "57b3ec75-f6e4-4cad-a5b8-d814f3d1e2b9": "corporativa"  # Corporate clients
    #     }
        
    #     if creatio_fatca_id in fatca_mapping:
    #         return fatca_mapping[creatio_fatca_id]
        
    #     # If it's a valid FATCA ID but not in our mapping, assume premium
    #     return "premium"
    
    # # Check solvency ID if FATCA didn't determine segment
    # if creatio_solvency_id and creatio_solvency_id != "00000000-0000-0000-0000-000000000000":
    #     # Higher solvency indicates better financial standing
    #     return "premium"
    
    # # Check credit score if available
    # if cred_score is not None:
    #     if cred_score >= 750:
    #         return "premium"
    #     elif cred_score >= 700:
    #         return "privada"
    
    # Default to retail
    return "retail"

def map_cliente_nivel_riesgo(creatio_is_non_grata, creatio_cred_score=None, fatca_id=None, solvency_id=None):
    """Map Creatio risk indicators to our system's risk level"""
    # Valid risk levels: 'bajo', 'medio', 'alto', 'muy_alto'
    
    # Highest priority: "Non grata" clients are always highest risk
    if creatio_is_non_grata:
        return 'muy_alto'
    
    # Check FATCA status - certain FATCA categories might indicate higher risk
    if fatca_id and fatca_id != "00000000-0000-0000-0000-000000000000" or fatca_id is not None:
        # These are example IDs - update with actual high-risk FATCA category IDs
        high_risk_fatca_ids = [
            "b2af6c8d-e45f-4a92-b7d1-43ce482c9efe",  # Foreign PEPs
            "7e28d3a5-6b19-4fc9-8e27-b91de6a7c3f1"   # High-risk jurisdictions
        ]
        
        if fatca_id in high_risk_fatca_ids:
            return 'alto'
    
    # Credit score based mapping
    if creatio_cred_score is not None:
        if creatio_cred_score < 580:
            return 'muy_alto'
        elif creatio_cred_score < 650:
            return 'alto'
        elif creatio_cred_score < 720:
            return 'medio'
        else:
            return 'bajo'
    
    # Solvency check if credit score is unavailable
    if solvency_id and solvency_id != "00000000-0000-0000-0000-000000000000" or solvency_id is not None:
        # These are example IDs - update with actual solvency category IDs
        solvency_risk_mapping = {
            "3f5a9e7c-8b2d-42e1-9d63-a12bc4e56f78": "bajo",     # High solvency
            "6d8c2b1a-e4f7-4935-a876-9c3d5e2a1b0f": "medio",    # Medium solvency
            "9e2a7f3b-5c8d-46e9-b1a2-d7c4e8f9a0b3": "alto"      # Low solvency
        }
        
        if solvency_id in solvency_risk_mapping:
            return solvency_risk_mapping[solvency_id]
    
    # Default risk level if we can't determine from available data
    return 'medio'

def process_contact(contact, user_id, cookies):
    """Process a single contact from Creatio and create or update in our system"""

    # Initialize migration_id at the beginning
    migration_id = None
    
    try:
        logger.info(f"Processing contact: {contact['Name']} (ID: {contact['Id']})")

        # NUEVA VALIDACIÓN: Verificar si el contacto ya fue migrado
        creatio_contact_id = contact['Id']
        
        migration_check_query = """
        SELECT id_cliente, fecha_migracion, nombre_contacto
        FROM contactos_migrados_creatio
        WHERE creatio_contact_id = %s
        """
        
        existing_migration = execute_query(migration_check_query, (creatio_contact_id,))
        
        if existing_migration:
            logger.info(f"Contact {contact['Name']} (ID: {creatio_contact_id}) already migrated. Skipping.")
            return {
                "status": "skipped", 
                "client_id": existing_migration[0]['id_cliente'],
                "migration_id": None,
                "message": f"Contact already migrated on {existing_migration[0]['fecha_migracion']}",
                "documents_processed": {"documents_processed": 0, "documents_created": 0, "documents_updated": 0, "documents_error": 0}
            }
    
        # Check if the contact already exists in our system by document ID (INN)
        documento_identificacion = contact.get('INN', '')
        if not documento_identificacion:
            logger.warning(f"Contact {contact['Id']} has no identification document number, skipping")
            return {"status": "skipped", "reason": "missing_identification"}
        
        # Check if client exists
        check_query = """
        SELECT id_cliente, codigo_cliente, estado
        FROM clientes
        WHERE documento_identificacion = %s
        """
        
        existing_client = execute_query(check_query, (documento_identificacion,))

        # Extract more data for accurate mappings
        creatio_client_type_id = contact.get('TypeId')
        creatio_fatca_id = contact.get('labFATCAId')
        creatio_solvency_id = contact.get('labSolvencyId')
        creatio_cred_score = contact.get('labCredScore')
        creatio_is_non_grata = contact.get('labIsNonGrata', False)
        creatio_client_code = contact.get('labClientCode', '')
        
        # Map contact data to our client model
        client_data = {
            'tipo_cliente': 'persona_fisica',
            'nombre_razon_social': contact.get('Name', ''),
            'documento_identificacion': documento_identificacion,
            'datos_contacto': {
                'email': contact.get('Email', ''),
                'telefono': contact.get('MobilePhone', '') or contact.get('Phone', ''),
                'direccion': contact.get('Address', '')
            },
            'preferencias_comunicacion': {
                "idioma": "español", 
                "canal_preferido": "email", 
                "horario_preferido": "mañana"
            },
            'segmento': map_cliente_segmento(creatio_client_type_id),
            'segmento_bancario': map_cliente_segmento_bancario(
                creatio_fatca_id, 
                creatio_solvency_id, 
                creatio_cred_score, 
                creatio_client_code
            ),
            'nivel_riesgo': map_cliente_nivel_riesgo(
                creatio_is_non_grata, 
                creatio_cred_score, 
                creatio_fatca_id, 
                creatio_solvency_id
            ),
            'estado': 'activo',
            'estado_documental': 'incompleto',
            'anotaciones_especiales': contact.get('Notes', ''),
            'clasificacion_fatca': 'no_aplica'  # Default value, adjust based on actual data
        }
        
        # Add additional metadata
        client_data['metadata_personalizada'] = {
            'creatio_id': contact['Id'],
            'creatio_client_code': contact.get('labClientCode', ''),
            'birth_date': contact.get('BirthDate', ''),
            'place_of_birth': contact.get('PlaceOfBirth', ''),
            'given_name': contact.get('GivenName', ''),
            'surname': contact.get('Surname', ''),
            'middle_name': contact.get('MiddleName', '')
        }
        
        # Get creatio_id for migration records
        creatio_id = contact['Id']
        
        # Check if a migration record already exists for this contact
        migration_check_query = """
        SELECT id FROM migration WHERE creatio_contact_id = %s
        """
        existing_migration = execute_query(migration_check_query, (creatio_id,))
        
        if existing_client:
            # Client exists, update it
            client_id = existing_client[0]['id_cliente']
            
            # Update client
            update_fields = []
            update_params = []
            
            for field, value in client_data.items():
                if field in ['datos_contacto', 'preferencias_comunicacion', 'metadata_personalizada']:
                    update_fields.append(f"{field} = %s")
                    update_params.append(json.dumps(value))
                else:
                    update_fields.append(f"{field} = %s")
                    update_params.append(value)
            
            # Add client_id to params
            update_params.append(client_id)
            
            # Build and execute update query
            update_query = f"""
            UPDATE clientes
            SET {', '.join(update_fields)}, fecha_ultima_actividad = CURRENT_TIMESTAMP
            WHERE id_cliente = %s
            """
            
            execute_query(update_query, update_params, fetch=False)

            # NUEVO: Registrar migración exitosa de contacto (si no existe)
            contact_migration_check = """
            SELECT id FROM contactos_migrados_creatio WHERE creatio_contact_id = %s
            """
            existing_contact_migration = execute_query(contact_migration_check, (creatio_id,))
            
            if not existing_contact_migration:
                contact_migration_id = generate_uuid()
                contact_migration_query = """
                INSERT INTO contactos_migrados_creatio (
                    id, creatio_contact_id, id_cliente, nombre_contacto
                ) VALUES (%s, %s, %s, %s)
                """
                
                try:
                    execute_query(contact_migration_query, (
                        contact_migration_id,
                        creatio_id,
                        client_id,
                        client_data['nombre_razon_social']
                    ), fetch=False)
                    
                    logger.info(f"Contact migration record created for existing client {client_data['nombre_razon_social']}")
                except Exception as contact_migration_error:
                    logger.warning(f"Could not create contact migration record: {str(contact_migration_error)}")
            
            # Handle migration record - update if exists, otherwise insert
            migration_details = json.dumps({
                'action': 'update', 
                'timestamp': datetime.datetime.now().isoformat()
            })
            
            if existing_migration:
                # Update existing migration record
                migration_update_query = """
                UPDATE migration 
                SET gestor_cliente_id = %s, 
                    estado_migracion = 'exitoso',
                    detalles = %s,
                    fecha_migracion = CURRENT_TIMESTAMP
                WHERE creatio_contact_id = %s
                """
                
                migration_update_params = (
                    client_id,
                    migration_details,
                    creatio_id
                )
                
                execute_query(migration_update_query, migration_update_params, fetch=False)
                migration_id = existing_migration[0]['id']
            else:
                # Insert new migration record
                migration_id = generate_uuid()
                migration_query = """
                INSERT INTO migration (
                    id, creatio_contact_id, gestor_cliente_id, estado_migracion, detalles
                ) VALUES (%s, %s, %s, %s, %s)
                """
                
                migration_params = (
                    migration_id,
                    creatio_id,
                    client_id,
                    'exitoso',
                    migration_details
                )
                
                execute_query(migration_query, migration_params, fetch=False)
            
            # Process documents from Creatio after updating the client
            documents_result = fetch_and_process_creatio_documents(client_id, creatio_id, cookies, user_id)     
            
            logger.info(f"Updated client with ID: {client_id}")
            return {
                "status": "updated", 
                "client_id": client_id,
                "migration_id": migration_id,
                "documents_processed": documents_result
            }
            
        else:
            # Client doesn't exist, create it
            client_id = generate_uuid()
            
            # Generate code based on client type
            now = datetime.datetime.now()
            date_part = now.strftime("%Y%m%d")

            tipo_prefix = {
                'persona_fisica': 'PF',
                'empresa': 'EM',
                'organismo_publico': 'OP'
            }[client_data['tipo_cliente']]

            # Generate unique code with UUID - retry until unique
            max_attempts = 100  # Very unlikely to need this many attempts
            codigo_cliente = None

            for attempt in range(max_attempts):
                # Generate 4-character UUID suffix
                uuid_suffix = str(uuid4()).replace('-', '')[:4].upper()
                
                # Create proposed code
                proposed_code = f"{tipo_prefix}-{date_part}-{uuid_suffix}"
                
                # Check if this code already exists
                check_query = """
                SELECT COUNT(*) as count 
                FROM clientes 
                WHERE codigo_cliente = %s
                """
                
                check_result = execute_query(check_query, (proposed_code,))
                
                if check_result[0]['count'] == 0:
                    # Code is unique!
                    codigo_cliente = proposed_code
                    break
                else:
                    # Extremely rare case - UUID collision, try again
                    logger.warning(f"UUID collision detected: {proposed_code}, retrying (attempt {attempt + 1})")

            if codigo_cliente is None:
                # This should never happen, but just in case
                raise Exception(f"Could not generate unique client code after {max_attempts} attempts")
            
            # Insert client - FIX: Ensure the number of columns matches the number of values
            insert_query = """
            INSERT INTO clientes (
                id_cliente, codigo_cliente, tipo_cliente, nombre_razon_social,
                documento_identificacion, fecha_alta, estado, segmento,
                gestor_principal_id, datos_contacto, preferencias_comunicacion, segmento_bancario, nivel_riesgo,
                fecha_ultima_revision_kyc, proxima_revision_kyc, estado_documental,
                anotaciones_especiales, clasificacion_fatca, metadata_personalizada
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """
            
            # Default dates
            fecha_ultima_revision_kyc = now.date()
            proxima_revision_kyc = (now + datetime.timedelta(days=365)).date()
            
            # Let's verify the number of parameters matches the placeholders
            insert_params = (
                client_id,                                 # 1
                codigo_cliente,                           # 2
                client_data['tipo_cliente'],              # 3
                client_data['nombre_razon_social'],       # 4
                client_data['documento_identificacion'],  # 5
                now,                                      # 6
                client_data['estado'],                    # 7
                client_data['segmento'],                  # 8
                user_id,                                  # 9 - gestor_principal_id
                json.dumps(client_data['datos_contacto']), # 10
                json.dumps(client_data['preferencias_comunicacion']), # 11
                client_data['segmento_bancario'],         # 12
                client_data['nivel_riesgo'],              # 13
                fecha_ultima_revision_kyc,                # 14
                proxima_revision_kyc,                     # 15
                client_data['estado_documental'],         # 16
                client_data['anotaciones_especiales'],    # 17
                client_data['clasificacion_fatca'],       # 18
                json.dumps(client_data['metadata_personalizada']) # 19
            )
            
            # Verify we have the same number of params as placeholders
            assert len(insert_params) == insert_query.count("%s"), "Mismatch in parameter count"
            
            execute_query(insert_query, insert_params, fetch=False)

            # NUEVO: Registrar migración exitosa de contacto
            contact_migration_id = generate_uuid()
            contact_migration_query = """
            INSERT INTO contactos_migrados_creatio (
                id, creatio_contact_id, id_cliente, nombre_contacto
            ) VALUES (%s, %s, %s, %s)
            """
            
            try:
                execute_query(contact_migration_query, (
                    contact_migration_id,
                    creatio_id,
                    client_id,
                    client_data['nombre_razon_social']
                ), fetch=False)
                
                logger.info(f"Contact migration record created for {client_data['nombre_razon_social']}")
            except Exception as contact_migration_error:
                logger.warning(f"Could not create contact migration record: {str(contact_migration_error)}")
            
            # Generate relevant client structures
            # call_generar_solicitudes(client_id, user_id)
            call_crear_estructura_carpetas(client_id, user_id)
            
            # Insert migration record
            migration_id = generate_uuid()
            migration_query = """
            INSERT INTO migration (
                id, creatio_contact_id, gestor_cliente_id, estado_migracion, detalles
            ) VALUES (%s, %s, %s, %s, %s)
            """
            
            migration_params = (
                migration_id,
                creatio_id,
                client_id,
                'exitoso',
                json.dumps({'action': 'create', 'timestamp': datetime.datetime.now().isoformat()})
            )
            
            execute_query(migration_query, migration_params, fetch=False)

            # Process documents from Creatio after creating the client
            documents_result = fetch_and_process_creatio_documents(client_id, creatio_id, cookies, user_id)
               
            logger.info(f"Created new client with ID: {client_id}")
            return {
                "status": "created", 
                "client_id": client_id, 
                "codigo_cliente": codigo_cliente,
                "migration_id": migration_id,
                "documents_processed": documents_result
            }
            
    except Exception as e:
        logger.error(f"Error processing contact {contact.get('Id', 'unknown')}: {str(e)}")
        
        # Register migration error
        try:
            creatio_id = contact.get('Id', 'unknown')
            
            # Check if a migration record already exists for this contact
            migration_check_query = """
            SELECT id FROM migration WHERE creatio_contact_id = %s
            """
            existing_migration = execute_query(migration_check_query, (creatio_id,))
            
            error_details = json.dumps({
                'error': str(e), 
                'timestamp': datetime.datetime.now().isoformat()
            })
            
            if existing_migration:
                # Update existing migration record
                migration_update_query = """
                UPDATE migration 
                SET estado_migracion = 'error',
                    detalles = %s,
                    fecha_migracion = CURRENT_TIMESTAMP
                WHERE creatio_contact_id = %s
                """
                
                migration_update_params = (
                    error_details,
                    creatio_id
                )
                
                execute_query(migration_update_query, migration_update_params, fetch=False)
                migration_id = existing_migration[0]['id']
            else:
                # Insert new migration record
                migration_id = generate_uuid()
                migration_query = """
                INSERT INTO migration (
                    id, creatio_contact_id, gestor_cliente_id, estado_migracion, detalles
                ) VALUES (%s, %s, %s, %s, %s)
                """
                
                migration_params = (
                    migration_id,
                    creatio_id,
                    '00000000-0000-0000-0000-000000000000',  # Empty client ID instead of None
                    'error',
                    error_details
                )
                
                execute_query(migration_query, migration_params, fetch=False)
            
            return {
                "status": "error", 
                "error": str(e),
                "migration_id": migration_id
            }
            
        except Exception as err:
            logger.error(f"Error registering migration failure: {str(err)}")
            # If we get here, we couldn't even create a migration record
            return {"status": "error", "error": str(e)}

# ESTAS SON LAS FUNCIONES CORRECTAS - ASEGÚRATE DE QUE ESTÉN ASÍ:
def call_generar_solicitudes(cliente_id, user_id):
    """Llama al procedimiento que genera solicitudes documentales para un cliente"""
    query = "CALL generar_solicitudes_documentos_cliente(%s, %s)"
    return execute_query(query, (cliente_id, user_id), fetch=False)
        
def call_crear_estructura_carpetas(cliente_id, user_id):
    """Llama al procedimiento que crea la estructura de carpetas para un cliente"""
    query = "CALL crear_estructura_carpetas_cliente(%s, %s)"
    return execute_query(query, (cliente_id, user_id), fetch=False)

def start_migration(event, context):
    """Start migration from Creatio to our system"""
    try:
        # Validate session (requires admin permission)
        user_id, error_response = validate_session(event, 'admin.migracion')
        if error_response:
            return error_response
        
        # Get request body
        body = json.loads(event['body'])
        
        # Validate required fields
        if 'count' not in body:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Missing required field: count'})
            }
        
        # Get count of contacts to migrate
        count = int(body.get('count', 10))
        
        # Validate count
        if count <= 0 or count > 100:
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Count must be between 1 and 100'})
            }
        
        # Authenticate with Creatio
        cookies = authenticate_with_creatio()
        if not cookies:
            return {
                'statusCode': 500,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Failed to authenticate with Creatio'})
            }
        
        # Get contacts from Creatio
        contacts = get_creatio_contacts(cookies, count)
        if contacts is None:
            return {
                'statusCode': 500,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Failed to get contacts from Creatio'})
            }
        
        if not contacts:
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'message': 'No contacts found to migrate'})
            }
        
        # Process contacts
        results = []
        for contact in contacts:
            result = process_contact(contact, user_id, cookies)
            results.append({
                'creatio_id': contact['Id'],
                'name': contact['Name'],
                'result': result
            })
        
        # Create summary
        created = sum(1 for r in results if r['result']['status'] == 'created')
        updated = sum(1 for r in results if r['result']['status'] == 'updated')
        errors = sum(1 for r in results if r['result']['status'] == 'error')
        skipped = sum(1 for r in results if r['result']['status'] == 'skipped')

        # Calculate document stats
        docs_processed = sum(r['result'].get('documents_processed', {}).get('documents_processed', 0) for r in results if 'documents_processed' in r['result'])
        docs_created = sum(r['result'].get('documents_processed', {}).get('documents_created', 0) for r in results if 'documents_processed' in r['result'])
        docs_updated = sum(r['result'].get('documents_processed', {}).get('documents_updated', 0) for r in results if 'documents_processed' in r['result'])
        docs_error = sum(r['result'].get('documents_processed', {}).get('documents_error', 0) for r in results if 'documents_processed' in r['result'])
        
        summary = {
            'total_contacts': len(contacts),
            'processed': len(results),
            'created': created,
            'updated': updated,
            'errors': errors,
            'skipped': skipped,
            'documents': {
                'total_processed': docs_processed,
                'created': docs_created,
                'updated': docs_updated,
                'errors': docs_error
            }
        }
        
        # Audit log entry
        audit_data = {
            'fecha_hora': datetime.datetime.now(),
            'usuario_id': user_id,
            'direccion_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0'),
            'accion': 'migracion',
            'entidad_afectada': 'clientes',
            'id_entidad_afectada': 'creatio',
            'detalles': json.dumps(summary),
            'resultado': 'éxito' if errors == 0 else 'parcial'
        }
        
        insert_audit_record(audit_data)
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'message': 'Migration completed',
                'summary': summary,
                'details': results
            })
        }
        
    except Exception as e:
        logger.error(f"Error starting migration: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error starting migration: {str(e)}'})
        }

def check_migration_status(event, context):
    """Check the status of migrations"""
    try:
        # Validate session
        user_id, error_response = validate_session(event, 'admin.migracion')
        if error_response:
            return error_response
        
        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Pagination
        page = int(query_params.get('page', 1))
        page_size = int(query_params.get('limit', 10))
        
        # Filters
        status = query_params.get('status')
        client_id = query_params.get('client_id')
        creatio_id = query_params.get('creatio_id')
        date_from = query_params.get('date_from')
        date_to = query_params.get('date_to')
        
        # Build query
        query = """
        SELECT m.id, m.creatio_contact_id, m.gestor_cliente_id, 
               m.fecha_migracion, m.estado_migracion, m.detalles,
               c.nombre_razon_social, c.codigo_cliente
        FROM migration m
        LEFT JOIN clientes c ON m.gestor_cliente_id = c.id_cliente
        """
        
        count_query = "SELECT COUNT(*) as total FROM migration m"
        
        where_clauses = []
        params = []
        
        # Add filters if provided
        if status:
            where_clauses.append("m.estado_migracion = %s")
            params.append(status)
        
        if client_id:
            where_clauses.append("m.gestor_cliente_id = %s")
            params.append(client_id)
        
        if creatio_id:
            where_clauses.append("m.creatio_contact_id = %s")
            params.append(creatio_id)
        
        if date_from:
            where_clauses.append("m.fecha_migracion >= %s")
            params.append(date_from)
        
        if date_to:
            where_clauses.append("m.fecha_migracion <= %s")
            params.append(date_to)
        
        # Add WHERE clause if filters exist
        if where_clauses:
            where_clause = " WHERE " + " AND ".join(where_clauses)
            query += where_clause
            count_query += where_clause
        
        # Add ordering and pagination
        query += " ORDER BY m.fecha_migracion DESC LIMIT %s OFFSET %s"
        params.extend([page_size, (page - 1) * page_size])
        
        # Execute queries
        migrations = execute_query(query, params)
        count_result = execute_query(count_query, params[:-2] if params else [])
        
        total = count_result[0]['total'] if count_result else 0
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        
        # Process results
        for migration in migrations:
            # Convert datetime to string
            if 'fecha_migracion' in migration and migration['fecha_migracion']:
                migration['fecha_migracion'] = migration['fecha_migracion'].isoformat()
            
            # Parse JSON details
            if 'detalles' in migration and migration['detalles']:
                try:
                    migration['detalles'] = json.loads(migration['detalles'])
                except:
                    pass
        
        # Get summary stats
        stats_query = """
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN estado_migracion = 'exitoso' THEN 1 ELSE 0 END) as exitosos,
            SUM(CASE WHEN estado_migracion = 'error' THEN 1 ELSE 0 END) as errores,
            SUM(CASE WHEN estado_migracion = 'pendiente' THEN 1 ELSE 0 END) as pendientes
        FROM migration
        """
        
        stats_result = execute_query(stats_query)
        stats = stats_result[0] if stats_result else {}
        
        # Create response
        response = {
            'migrations': migrations,
            'pagination': {
                'total': total,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages
            },
            'statistics': stats
        }
        
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Error checking migration status: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f'Error checking migration status: {str(e)}'})
        }










def fetch_and_process_creatio_documents(client_id, creatio_contact_id, cookies, user_id):
    """
    Fetches documents from Creatio for a contact and processes them in our system.
    
    Args:
        client_id: ID of the client in our system
        creatio_contact_id: ID of the contact in Creatio
        cookies: Authentication cookies for Creatio API
        user_id: ID of the user performing the action
    
    Returns:
        A summary of the documents processed
    """
    try:
        logger.info(f"Fetching documents for Creatio contact: {creatio_contact_id}")
        
        # Extract CSRF token from cookies
        csrf_token = cookies.get('BPMCSRF')
        
        # Prepare headers with CSRF token
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'BPMCSRF': csrf_token
        }
        
        # Build the OData query to get contact files
        url = f"https://{CREATIO_INSTANCE}/0/odata/ContactFile"
        params = {
            '$filter': f"Contact/Id eq {creatio_contact_id}"
        }
        
        # Make the request to get files
        response = requests.get(url, headers=headers, cookies=cookies, params=params)
        
        if response.status_code != 200:
            logger.error(f"Failed to get contact files: {response.status_code} - {response.text}")
            return {
                'status': 'error',
                'message': f"Failed to get contact files: {response.status_code}",
                'documents_processed': 0
            }
            
        data = response.json()
        files = data.get('value', [])
        
        if not files:
            logger.info(f"No documents found for contact {creatio_contact_id}")
            return {
                'status': 'success',
                'message': "No documents found for this contact",
                'documents_processed': 0
            }
        
        logger.info(f"Found {len(files)} documents for contact {creatio_contact_id}")
        
        # Process each file
        processed_files = []
        for file in files:
            file_result = process_creatio_file(file, client_id, cookies, user_id, headers)
            processed_files.append(file_result)
        
        # Create summary
        created = sum(1 for f in processed_files if f.get('action') == 'created')
        updated = sum(1 for f in processed_files if f.get('action') == 'updated')
        skipped = sum(1 for f in processed_files if f.get('status') == 'skipped') 
        errors = sum(1 for f in processed_files if f.get('status') == 'error')
        
        return {
            'status': 'success',
            'message': f"Processed {len(processed_files)} documents",
            'documents_processed': len(processed_files),
            'documents_created': created,
            'documents_updated': updated,
            'documents_skipped': skipped,
            'documents_error': errors,
            'documents_details': processed_files
        }
        
    except Exception as e:
        logger.error(f"Error fetching and processing Creatio documents: {str(e)}")
        return {
            'status': 'error',
            'message': f"Error processing documents: {str(e)}",
            'documents_processed': 0
        }

def process_creatio_file(file, client_id, cookies, user_id, headers):
    """
    Process a single file from Creatio - download and create/update in our system
    
    Args:
        file: File metadata from Creatio
        client_id: ID of the client in our system
        cookies: Authentication cookies for Creatio API
        user_id: ID of the user performing the action
        headers: Request headers with CSRF token
    
    Returns:
        Status of the file processing
    """
    try:
        file_id = file.get('Id')
        file_name = file.get('Name')
        file_size = file.get('Size')
        file_type = file.get('TypeId')
        content_type = file.get('Data@odata.mediaContentType', 'application/octet-stream')
        
        logger.info(f"Processing file: {file_name} (ID: {file_id})")

        # NUEVA VALIDACIÓN: Verificar si el archivo ya fue migrado
        migration_check_query = """
        SELECT id_documento, fecha_migracion
        FROM documentos_migrados_creatio
        WHERE creatio_file_id = %s
        """
        
        existing_migration = execute_query(migration_check_query, (file_id,))
        
        if existing_migration:
            logger.info(f"File {file_name} (ID: {file_id}) already migrated. Skipping.")
            return {
                'status': 'skipped',
                'creatio_file_id': file_id,
                'file_name': file_name,
                'document_id': existing_migration[0]['id_documento'],
                'message': f"File already migrated on {existing_migration[0]['fecha_migracion']}"
            }
        
        # Check if document already exists in our system
        # We'll use the Creatio file ID as a reference
        check_query = """
        SELECT id_documento, version_actual
        FROM documentos
        WHERE metadatos->>'$.origen_externo' = 'creatio' 
        AND metadatos->>'$.id_externo' = %s
        """
        
        existing_doc = execute_query(check_query, (file_id,))
        existing_doc_id = existing_doc[0]['id_documento'] if existing_doc else None
        
        # Download the file from Creatio
        file_url = f"https://{CREATIO_INSTANCE}/0/odata/ContactFile/{file_id}/Data"
        file_response = requests.get(file_url, headers=headers, cookies=cookies)
        
        if file_response.status_code != 200:
            logger.error(f"Failed to download file: {file_response.status_code} - {file_response.text}")
            return {
                'status': 'error',
                'creatio_file_id': file_id,
                'file_name': file_name,
                'message': f"Failed to download file: {file_response.status_code}"
            }
        
        # Create a temporary file to store the content
        temp_file_path = f"/tmp/{file_id}_{file_name}"
        with open(temp_file_path, 'wb') as f:
            f.write(file_response.content)
        
        # Create or update document in our system, passing the Creatio file ID
        if existing_doc_id:
            # Document exists - update with a new version
            result = create_document_from_file_improved(
                temp_file_path, 
                client_id, 
                user_id, 
                content_type=None, 
                external_file_id=file_id,  # Pass Creatio file ID
                parent_document_id=existing_doc_id
            )
            action = 'updated'
        else:
            # Document doesn't exist - create new
            result = create_document_from_file_improved(
                temp_file_path, 
                client_id, 
                user_id, 
                content_type=None,
                external_file_id=file_id  # Pass Creatio file ID
            )
            action = 'created'
            
            # If document was created successfully, store the reference to Creatio ID
            # in the document metadata
            if result.get('id_documento'):
                store_creatio_reference(result.get('id_documento'), file_id, 'creatio')
        
        # Remove temporary file
        os.remove(temp_file_path)
        
        return {
            'status': 'success',
            'action': action,
            'creatio_file_id': file_id,
            'file_name': file_name,
            'document_id': result.get('id_documento'),
            'upload_url': result.get('upload_url')
        }
    
    except Exception as e:
        logger.error(f"Error processing Creatio file {file.get('Name', 'unknown')}: {str(e)}")
        return {
            'status': 'error',
            'creatio_file_id': file.get('Id'),
            'file_name': file.get('Name'),
            'message': f"Error processing file: {str(e)}"
        }

def create_document_from_file(file_path, client_id, user_id, content_type, external_file_id=None, parent_document_id=None):
    """
    Creates a document using the existing create_document method and uploads the file
    
    Args:
        file_path: Path to the temporary file
        client_id: ID of the client in our system
        user_id: ID of the user performing the action
        content_type: MIME type of the file
        external_file_id: ID of the file in Creatio for example (optional)
        parent_document_id: ID of the parent document if this is an update
    
    Returns:
        Result of document creation including the upload URL
    """
    try:
        # Extract filename from path
        filename = os.path.basename(file_path)
        
        # Build request body
        request_body = {
            'id_cliente': client_id,
            'filename': filename,
            'content_type': content_type,
        }
        
        # Add optional fields
        if parent_document_id:
            request_body['parent_document_id'] = parent_document_id
        
        # NEW: Add Creatio file ID if provided
        if external_file_id:
            request_body['external_file_id'] = external_file_id
        
        # Create mock event with required data
        mock_event = {
            'body': json.dumps(request_body),
            'requestContext': {
                'identity': {
                    'sourceIp': '127.0.0.1'  # Internal operation
                }
            },
            'headers': {
                'Authorization': f'Bearer system_migration_{user_id}'  # Special token format to identify system operations
            }
        }
        
        # Call create_document to get presigned URL
        # result = create_document(mock_event, None)
        result = create_document_internal(id_cliente=client_id, 
                                          filename=filename, 
                                          content_type=content_type, 
                                          parent_document_id=parent_document_id, 
                                          external_file_id=external_file_id, 
                                          user_id=user_id)
        
        # Check if document creation was successful
        if not result.get('success', False):
            logger.error(f"Failed to create document: {result.get('error', 'Unknown error')}")
            return {
                'status': 'error',
                'message': f"Failed to create document: {result.get('error', 'Unknown error')}"
            }
        
        # Extract document info from successful result
        doc_id = result.get('id_documento')
        upload_url = result.get('upload_url')
        upload_fields = result.get('upload_fields')

        if not all([doc_id, upload_url, upload_fields]):
            logger.error("Invalid response from create_document_internal")
            return {
                'status': 'error',
                'message': "Invalid response from document creation"
            }
        
        logger.info(f"Document created with ID: {doc_id}, proceeding with file upload")

        
        # Upload the file using the presigned URL
        try:
            with open(file_path, 'rb') as file_content:
                # Prepare form data
                form_data = upload_fields.copy()
                
                # Add the file as the last field
                files = {'file': (filename, file_content, content_type)}

                logger.info(f"Uploading file {filename} to S3...")
                
                # Upload to S3
                upload_response = requests.post(
                    upload_url, 
                    data=form_data,
                    files=files,
                    timeout=360  # 6 minute timeout for large files
                )
                
                if upload_response.status_code not in [200, 201, 204]:
                    logger.error(f"Failed to upload file to S3: {upload_response.status_code} - {upload_response.text}")
                    return {
                        'status': 'error',
                        'id_documento': doc_id,
                        'message': f"Failed to upload file to S3: {upload_response.status_code}"
                    }
                
                logger.info(f"Successfully uploaded file {filename} to S3")
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return {
                'status': 'error',
                'id_documento': doc_id,
                'message': f"File not found: {file_path}"
            }
        except requests.exceptions.Timeout:
            logger.error(f"Timeout uploading file {filename}")
            return {
                'status': 'error',
                'id_documento': doc_id,
                'message': f"Timeout uploading file {filename}"
            }
        except Exception as upload_err:
            logger.error(f"Error uploading file to S3: {str(upload_err)}")
            return {
                'status': 'error',
                'id_documento': doc_id,
                'message': f"Error uploading file to S3: {str(upload_err)}"
            }
        
        return {
            'status': 'success',
            'id_documento': doc_id,
            'upload_url': upload_url,
            'upload_fields': upload_fields,
            'creatio_file_id': external_file_id  # Return for reference
        }
        
    except Exception as e:
        logger.error(f"Error in create_document_from_file: {str(e)}")
        return {
            'status': 'error',
            'message': f"Error creating document: {str(e)}"
        }

def store_creatio_reference(document_id, creatio_id, source_system):
    """
    Stores a reference to the original document ID in the external system
    by updating the metadatos JSON field in the documentos table
    
    Args:
        document_id: ID of the document in our system
        creatio_id: ID of the document in Creatio
        source_system: Name of the source system ('creatio')
    """
    try:
        # First, get the current metadatos value
        query = """
        SELECT metadatos
        FROM documentos
        WHERE id_documento = %s
        """
        
        result = execute_query(query, (document_id,))
        
        if not result:
            logger.error(f"Document {document_id} not found when storing Creatio reference")
            return
        
        # Parse existing metadatos or initialize empty dict
        current_metadata = {}
        if result[0]['metadatos']:
            try:
                current_metadata = json.loads(result[0]['metadatos'])
            except json.JSONDecodeError:
                current_metadata = {}
        
        # Add Creatio reference information
        current_metadata['origen_externo'] = source_system
        current_metadata['id_externo'] = creatio_id
        current_metadata['creatio_file_id'] = creatio_id  # Store explicitly as creatio_file_id too
        current_metadata['fecha_sincronizacion'] = datetime.datetime.now().isoformat()
        
        # Update the document with the new metadatos
        update_query = """
        UPDATE documentos
        SET metadatos = %s
        WHERE id_documento = %s
        """
        
        execute_query(update_query, (json.dumps(current_metadata), document_id), fetch=False)
        
        logger.info(f"Stored reference between document {document_id} and Creatio file {creatio_id}")
        
    except Exception as e:
        logger.error(f"Error storing Creatio reference: {str(e)}")

def create_document_internal(id_cliente, filename, content_type='application/octet-stream', 
                           parent_document_id=None, external_file_id=None, user_id=None):
    """
    Genera una URL prefirmada para subir un archivo directamente a S3 con los metadatos
    necesarios. Versión interna sin validación de sesión para uso en procesos del sistema.
    
    Args:
        id_cliente: ID del cliente
        filename: Nombre del archivo
        content_type: Tipo de contenido del archivo
        parent_document_id: ID del documento padre (para nuevas versiones)
        external_file_id: ID del archivo externo (ej. de Creatio)
        user_id: ID del usuario del sistema (opcional, para auditoría)
    
    Returns:
        dict: Resultado con URL de carga o error
    """
    try:
        # Generate document ID (use parent_document_id if this is a new version)
        doc_id = parent_document_id if parent_document_id else generate_uuid()
       
        # Initialize S3 client
        import boto3
        from botocore.config import Config
       
        # Configuración de reintentos para servicios AWS
        retry_config = Config(
            retries={
                'max_attempts': 3,
                'mode': 'standard'
            }
        )
       
        s3_client = boto3.client('s3', config=retry_config)
       
        # Definir el bucket y la ruta en S3
        upload_bucket = 'gestor-documental-bancario-documents-input'
        folder_prefix = "incoming"
        s3_key = f"{folder_prefix}/{doc_id}/{filename}"
       
        # Prepare S3 metadata fields
        s3_fields = {
            'Content-Type': content_type,
            'x-amz-meta-client-id': id_cliente,
            'x-amz-meta-document-id': doc_id,
            'x-amz-meta-is-new-version': 'true' if parent_document_id else 'false'
        }
        
        # Prepare S3 conditions
        s3_conditions = [
            ['content-length-range', 1, 50 * 1024 * 1024],  # Increased to 50MB for system uploads
            ['eq', '$Content-Type', content_type],
            ['eq', '$x-amz-meta-client-id', id_cliente],
            ['eq', '$x-amz-meta-document-id', doc_id],
            ['eq', '$x-amz-meta-is-new-version', 'true' if parent_document_id else 'false']
        ]
        
        # Add Creatio file ID to metadata if provided
        if external_file_id:
            s3_fields['x-amz-meta-external-file-id'] = external_file_id
            s3_conditions.append(['eq', '$x-amz-meta-external-file-id', external_file_id])
       
        # Generar URL prefirmada para carga directa a S3 con metadatos
        presigned_post = s3_client.generate_presigned_post(
            Bucket=upload_bucket,
            Key=s3_key,
            Fields=s3_fields,
            Conditions=s3_conditions,
            ExpiresIn=3600  # 1 hora para procesos internos
        )
       
        # Preparar respuesta con instrucciones y URL para carga
        upload_instructions = {
            'success': True,
            'message': 'URL generada exitosamente para proceso interno.',
            'id_documento': doc_id,
            'upload_url': presigned_post['url'],
            'upload_fields': presigned_post['fields'],
            'metadata': {
                'client-id': id_cliente,
                'document-id': doc_id,
                'is-new-version': 'true' if parent_document_id else 'false',
                'external-file-id': external_file_id
            },
            'ruta_s3': f"{folder_prefix}/{doc_id}/",
            'expira_en': 3600
        }
       
        # Registrar en auditoría si se proporciona user_id
        if user_id:
            try:
                audit_data = {
                    'fecha_hora': datetime.datetime.now(),
                    'usuario_id': user_id,
                    'direccion_ip': '0.0.0.0',  # Proceso interno
                    'accion': 'generar_url_carga_interno' + ('_nueva_version' if parent_document_id else ''),
                    'entidad_afectada': 'documento',
                    'id_entidad_afectada': doc_id,
                    'detalles': json.dumps({
                        'id_cliente': id_cliente,
                        'filename': filename,
                        'content_type': content_type,
                        'is_new_version': bool(parent_document_id),
                        'external_file_id': external_file_id,
                        'proceso': 'interno'
                    }),
                    'resultado': 'éxito'
                }
               
                insert_audit_record(audit_data)
            except Exception as audit_error:
                logger.warning(f"Error al registrar auditoría (no crítico): {str(audit_error)}")
       
        return upload_instructions
       
    except Exception as e:
        logger.error(f"Error al crear documento interno: {str(e)}")
        return {
            'success': False,
            'error': f'Error al crear documento: {str(e)}'
        }








# Función mejorada para crear documentos con Content-Type correcto
def create_document_from_file_improved(file_path, client_id, user_id, content_type=None, external_file_id=None, parent_document_id=None):
    """
    Creates a document with improved Content-Type handling
    """
    try:
        # Extract filename from path
        filename = os.path.basename(file_path)
        
        # Determine content type if not provided
        if not content_type:
            content_type = get_content_type_from_filename(filename)
        
        # Validate that the detected content type is reasonable
        if content_type == 'application/octet-stream':
            # Try to detect from file magic numbers if possible
            detected_type = detect_content_type_from_file(file_path)
            if detected_type and detected_type != 'application/octet-stream':
                content_type = detected_type
        
        logger.info(f"Creating document for file: {filename} with content-type: {content_type}")
        
        # Call the internal function
        result = create_document_internal(
            id_cliente=client_id, 
            filename=filename, 
            content_type=content_type, 
            parent_document_id=parent_document_id, 
            external_file_id=external_file_id, 
            user_id=user_id
        )
        
        # Check if document creation was successful
        if not result.get('success', False):
            logger.error(f"Failed to create document: {result.get('error', 'Unknown error')}")
            return {
                'status': 'error',
                'message': f"Failed to create document: {result.get('error', 'Unknown error')}"
            }
        
        # Extract document info from successful result
        doc_id = result.get('id_documento')
        upload_url = result.get('upload_url')
        upload_fields = result.get('upload_fields')

        if not all([doc_id, upload_url, upload_fields]):
            logger.error("Invalid response from create_document_internal")
            return {
                'status': 'error',
                'message': "Invalid response from document creation"
            }
        
        logger.info(f"Document created with ID: {doc_id}, uploading with content-type: {content_type}")
        
        # Upload the file with explicit content type
        try:
            with open(file_path, 'rb') as file_content:
                # Ensure Content-Type is set correctly in the form data
                form_data = upload_fields.copy()
                
                # Override Content-Type if it was set incorrectly
                if 'Content-Type' in form_data:
                    form_data['Content-Type'] = content_type
                
                # Log the form data for debugging
                logger.info(f"Upload form data: {form_data}")
                
                # Prepare files with explicit content type
                files = {'file': (filename, file_content, content_type)}
                
                logger.info(f"Uploading file {filename} to S3 with Content-Type: {content_type}")
                
                # Upload to S3
                upload_response = requests.post(
                    upload_url, 
                    data=form_data,
                    files=files,
                    timeout=360
                )
                
                if upload_response.status_code not in [200, 201, 204]:
                    logger.error(f"Failed to upload file to S3: {upload_response.status_code} - {upload_response.text}")
                    return {
                        'status': 'error',
                        'id_documento': doc_id,
                        'message': f"Failed to upload file to S3: {upload_response.status_code}"
                    }
                
                logger.info(f"Successfully uploaded file {filename} to S3")
                
        except Exception as upload_err:
            logger.error(f"Error uploading file to S3: {str(upload_err)}")
            return {
                'status': 'error',
                'id_documento': doc_id,
                'message': f"Error uploading file to S3: {str(upload_err)}"
            }
        
        return {
            'status': 'success',
            'id_documento': doc_id,
            'filename': filename,
            'content_type': content_type,
            'creatio_file_id': external_file_id,
            'message': f"Document {filename} created and uploaded successfully with content-type {content_type}"
        }
        
    except Exception as e:
        logger.error(f"Error in create_document_from_file_improved: {str(e)}")
        return {
            'status': 'error',
            'message': f"Error creating document: {str(e)}"
        }
    
# Mejorar la función get_content_type_from_filename para ser más precisa
def get_content_type_from_filename(filename):
    """
    Determina el tipo de contenido basado en la extensión del archivo.
    Prioriza mimetypes.guess_type() pero tiene fallbacks confiables.
    """
    import mimetypes
    
    # Inicializar mimetypes si no está inicializado
    if not mimetypes.inited:
        mimetypes.init()
    
    # Intentar primero con mimetypes
    content_type, encoding = mimetypes.guess_type(filename)
    
    if content_type and content_type != 'application/octet-stream':
        return content_type
    
    # Fallbacks más específicos para extensiones comunes
    if '.' not in filename:
        return 'application/octet-stream'
    
    extension = filename.lower().split('.')[-1]
    
    # Mapeo específico y confiable
    content_type_map = {
        # Imágenes
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'bmp': 'image/bmp',
        'tiff': 'image/tiff',
        'tif': 'image/tiff',
        'webp': 'image/webp',
        'svg': 'image/svg+xml',
        'ico': 'image/x-icon',
        
        # Documentos
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'odt': 'application/vnd.oasis.opendocument.text',
        'ods': 'application/vnd.oasis.opendocument.spreadsheet',
        'odp': 'application/vnd.oasis.opendocument.presentation',
        
        # Texto
        'txt': 'text/plain',
        'csv': 'text/csv',
        'json': 'application/json',
        'xml': 'application/xml',
        'html': 'text/html',
        'htm': 'text/html',
        'css': 'text/css',
        'js': 'application/javascript',
        
        # Archivos comprimidos
        'zip': 'application/zip',
        'rar': 'application/vnd.rar',
        '7z': 'application/x-7z-compressed',
        'tar': 'application/x-tar',
        'gz': 'application/gzip',
        'bz2': 'application/x-bzip2',
        
        # Audio
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'ogg': 'audio/ogg',
        'flac': 'audio/flac',
        
        # Video
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime',
        'wmv': 'video/x-ms-wmv',
        'mkv': 'video/x-matroska'
    }
    
    detected_type = content_type_map.get(extension, 'application/octet-stream')
    
    # Log para debugging
    logger.info(f"Content type detection for '{filename}': extension='{extension}' -> '{detected_type}'")
    
    return detected_type

def detect_content_type_from_file(file_path):
    """
    Detecta el content type leyendo los primeros bytes del archivo (magic numbers)
    """
    try:
        with open(file_path, 'rb') as f:
            # Leer los primeros 512 bytes
            header = f.read(512)
        
        # Patrones de magic numbers para tipos comunes
        magic_patterns = {
            b'\x89PNG\r\n\x1a\n': 'image/png',
            b'\xff\xd8\xff': 'image/jpeg',
            b'GIF87a': 'image/gif',
            b'GIF89a': 'image/gif',
            b'%PDF': 'application/pdf',
            b'PK\x03\x04': 'application/zip',  # También para docx, xlsx, etc.
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'application/msword',  # Doc files
            b'BM': 'image/bmp',
            b'RIFF': 'image/webp',  # Necesita verificación adicional
        }
        
        # Verificar patrones
        for pattern, content_type in magic_patterns.items():
            if header.startswith(pattern):
                # Verificación especial para RIFF (puede ser WebP o otros)
                if pattern == b'RIFF' and b'WEBP' in header[:20]:
                    return 'image/webp'
                elif pattern == b'RIFF':
                    continue  # No es WebP, seguir buscando
                
                logger.info(f"Detected content type from magic numbers: {content_type}")
                return content_type
        
        return None
        
    except Exception as e:
        logger.warning(f"Could not detect content type from file magic: {str(e)}")
        return None