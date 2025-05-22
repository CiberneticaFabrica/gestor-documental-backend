# src/migration/migration_status.py
import os
import json
import logging
import pymysql
import datetime

from common.headers import add_cors_headers

# Configure logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Database configuration
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")

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

def get_migration_status():
    """Get summary statistics about migration status"""
    stats_query = """
    SELECT 
        estado_migracion, 
        COUNT(*) as count,
        MIN(fecha_migracion) as first_migration,
        MAX(fecha_migracion) as last_migration
    FROM migration
    GROUP BY estado_migracion
    """
    
    stats = execute_query(stats_query)
    
    # Get recent migrations
    recent_query = """
    SELECT 
        m.id, 
        m.creatio_contact_id, 
        m.gestor_cliente_id,
        m.fecha_migracion,
        m.estado_migracion,
        c.nombre_razon_social as client_name,
        c.documento_identificacion
    FROM migration m
    JOIN clientes c ON m.gestor_cliente_id = c.id_cliente
    ORDER BY m.fecha_migracion DESC
    LIMIT 10
    """
    
    recent = execute_query(recent_query)
    
    # Format dates for JSON
    for stat in stats:
        if stat.get("first_migration"):
            stat["first_migration"] = stat["first_migration"].isoformat()
        if stat.get("last_migration"):
            stat["last_migration"] = stat["last_migration"].isoformat()
    
    for rec in recent:
        if rec.get("fecha_migracion"):
            rec["fecha_migracion"] = rec["fecha_migracion"].isoformat()
    
    return {
        "statistics": stats,
        "recent_migrations": recent
    }

def lambda_handler(event, context):
    """Handle migration status requests"""
    try:
        # Check if this is a GET request for migration status
        if event['httpMethod'] == 'OPTIONS':
            # Handle CORS preflight request
            return {
                'statusCode': 200,
                'headers': add_cors_headers(),
                'body': ''
            }
        
        if event['httpMethod'] == 'GET' and event['path'] == '/migration/status':
            # Get migration status
            status = get_migration_status()
            
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps(status, default=str)
            }
        
        # If not a valid request, return 404
        return {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Route not found'})
        }
        
    except Exception as e:
        logger.error(f"Error in Lambda handler: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': str(e)})
        }