import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

load_dotenv()

def create_database():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', '')
        )
        
        cursor = connection.cursor()
        
        # Create database
        database_name = os.getenv('MYSQL_DATABASE', 'ndu_certilog')
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name}")
        print(f"✅ Database '{database_name}' created or already exists")
        
        cursor.close()
        connection.close()
        return True
        
    except Error as e:
        print(f"❌ Error creating database: {e}")
        return False

if __name__ == '__main__':
    create_database()