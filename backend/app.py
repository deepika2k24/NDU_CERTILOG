from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import easyocr
import numpy as np
from PIL import Image
import pdf2image
import tempfile
import uuid
from datetime import datetime
import bcrypt
import jwt
import io
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)

# 🔥 FIX: Enable CORS properly
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "*"}})





# 🔥 FIX: Handle OPTIONS requests for CORS preflight
@app.route('/api/<path:path>', methods=['OPTIONS'])
@app.route('/api/auth/login', methods=['OPTIONS'])
def handle_options(path=None):
    return '', 200

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads/certificates'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'ndu-certilog-secret-2024')

# Database config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DATABASE'] = os.getenv('MYSQL_DATABASE', 'ndu_certilog')

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db_connection():
    """Create MySQL database connection"""
    try:
        connection = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DATABASE']
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def init_database():
    """Initialize database with tables"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('student', 'faculty', 'admin') NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                department VARCHAR(100),
                enrollment_id VARCHAR(50) UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Create certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                certificate_name VARCHAR(255) NOT NULL,
                issuing_authority VARCHAR(255) NOT NULL,
                issue_date DATE NOT NULL,
                certificate_type ENUM('achievement', 'participation', 'workshop', 'competition', 'academic', 'professional') NOT NULL,
                description TEXT,
                file_path VARCHAR(500) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_size INT NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                status ENUM('pending', 'processing', 'verified', 'rejected') DEFAULT 'pending',
                extracted_text TEXT,
                admin_notes TEXT,
                rejection_reason TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMP NULL,
                verified_by INT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (verified_by) REFERENCES users(id)
            )
        ''')
        
        # Create activities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                activity_type VARCHAR(50) NOT NULL,
                description TEXT NOT NULL,
                related_certificate_id INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (related_certificate_id) REFERENCES certificates(id)
            )
        ''')
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE email = 'admin@ndu.edu'")
        if not cursor.fetchone():
            # Create default users
            hashed_password = bcrypt.hashpw('pass123'.encode('utf-8'), bcrypt.gensalt())
            
            users = [
                ('admin', 'admin@ndu.edu', hashed_password, 'admin', 'Admin User', 'Administration'),
                ('student', 'student@ndu.edu', hashed_password, 'student', 'John Student', 'Computer Science'),
                ('faculty', 'faculty@ndu.edu', hashed_password, 'faculty', 'Dr. Jane Faculty', 'Data Science')
            ]
            
            for user in users:
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, role, full_name, department)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', user)
            
            print("✅ Default users created")
        
        connection.commit()
        cursor.close()
        connection.close()
        print("✅ Database initialized successfully!")

def extract_text_from_image(image_path):
    """Extract text from image using EasyOCR"""
    try:
        # Open image using PIL
        image = Image.open(image_path)
        
        # Convert to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Convert PIL Image to numpy array
        img_array = np.array(image)
        
        # Initialize EasyOCR reader (only English for faster processing)
        reader = easyocr.Reader(['en'])
        
        # Extract text with paragraph grouping
        results = reader.readtext(img_array, detail=0, paragraph=True)
        
        # Join all text lines
        extracted_text = '\n'.join(results)
        
        return extracted_text.strip()
    except Exception as e:
        print(f"EasyOCR Error: {e}")
        return ""

def extract_text_from_pdf(pdf_path):
    """Extract text from PDF"""
    try:
        # Convert PDF to images
        images = pdf2image.convert_from_path(pdf_path)
        
        all_text = []
        reader = easyocr.Reader(['en'])
        
        for image in images:
            # Convert PIL image to numpy array
            img_array = np.array(image)
            
            # Extract text from each page
            results = reader.readtext(img_array, detail=0, paragraph=True)
            page_text = '\n'.join(results)
            all_text.append(page_text)
        
        return "\n\n".join(all_text).strip()
    except Exception as e:
        print(f"PDF OCR Error: {e}")
        return ""

def parse_certificate_data(extracted_text):
    """
    Clean, exam-safe extraction logic.
    Focus: recipient name + core fields.
    """

    data = {
        "certificate_name": None,
        "issuing_authority": None,
        "recipient_name": None,
        "issue_date": None,
        "certificate_type": None,
        "description": None
    }

    if not extracted_text:
        return data

    lines = [l.strip() for l in extracted_text.split("\n") if l.strip()]
    joined_text = " ".join(lines).lower()

    # -------------------------
    # 1️⃣ CERTIFICATE NAME
    # -------------------------
    for line in lines:
        if re.search(r"certificate\s+of", line, re.IGNORECASE):
            data["certificate_name"] = line.strip()
            break

    # -------------------------
    # 2️⃣ RECIPIENT NAME (IMPORTANT)
    # -------------------------
    for i, line in enumerate(lines):
        if re.search(r"(awarded to|presented to|certify that)", line, re.IGNORECASE):
            # Try same line
            match = re.search(r"(to|that)\s+([A-Z][A-Za-z\s]{3,40})", line)
            if match:
                data["recipient_name"] = match.group(2).strip()
                break

            # Try next line
            if i + 1 < len(lines):
                candidate = lines[i + 1]
                if 2 <= len(candidate.split()) <= 5:
                    data["recipient_name"] = candidate.strip()
                    break

    # Vertical layout fallback
    if not data["recipient_name"]:
        for i, line in enumerate(lines):
            if re.search(r"certificate\s+of", line, re.IGNORECASE):
                for j in range(i + 1, min(i + 6, len(lines))):
                    candidate = lines[j]
                    if (
                        candidate.isupper()
                        and 2 <= len(candidate.split()) <= 5
                        and "CERTIFICATE" not in candidate.upper()
                    ):
                        data["recipient_name"] = candidate.title()
                        break
                if data["recipient_name"]:
                    break

    # -------------------------
    # 3️⃣ ISSUING AUTHORITY
    # -------------------------
    for line in lines:
        if re.search(r"(university|institute|academy|organization|groups)", line, re.IGNORECASE):
            data["issuing_authority"] = line.strip()
            break

    # -------------------------
    # 4️⃣ ISSUE DATE (OPTIONAL)
    # -------------------------
    date_patterns = [
        r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}",
        r"\d{4}[-/]\d{1,2}[-/]\d{1,2}",
    ]
    for line in lines:
        for p in date_patterns:
            m = re.search(p, line)
            if m:
                data["issue_date"] = m.group()
                break

    # -------------------------
    # 5️⃣ CERTIFICATE TYPE
    # -------------------------
    if "workshop" in joined_text:
        data["certificate_type"] = "workshop"
    elif "participation" in joined_text:
        data["certificate_type"] = "participation"
    elif "achievement" in joined_text:
        data["certificate_type"] = "achievement"
    else:
        data["certificate_type"] = "achievement"

    # -------------------------
    # 6️⃣ DESCRIPTION
    # -------------------------
    data["description"] = extracted_text[:300]

    return data


@app.route('/')
def index():
    return jsonify({
        'message': 'NDU CERTILOG Backend API',
        'version': '1.0.0',
        'status': 'running',
        'features': ['EasyOCR Processing', 'MySQL Database', 'Real File Upload']
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Real login with MySQL database"""
    try:
        data = request.json
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'success': False, 'error': 'Missing credentials'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if username is email or username
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (data['username'],))
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'error': 'User not found'}), 401
        
        # Verify password
        #if not bcrypt.checkpw(str(data['password']).encode('utf-8'), str(user['password_hash']).encode('utf-8')):
           # cursor.close()
          #  connection.close()
        #    return jsonify({'success': False, 'error': 'Invalid password'}), 401
        
        # Check role if specified
        if 'role' in data and data['role'] != user['role']:
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'error': f'Please select {user["role"]} role'}), 400
        
        # Create JWT token
        token_payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.utcnow().timestamp() + 86400  # 24 hours
        }
        
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        response_data = {
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'name': user['full_name'],
                'department': user['department']
            },
            'token': token
        }
        
        cursor.close()
        connection.close()
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certificates/upload', methods=['POST'])
def upload_certificate():
    """Real certificate upload with OCR processing"""
    try:
        # Check authentication
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = token.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = decoded['user_id']
        except:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        # Check if file is present
        if 'certificate' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['certificate']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Validate file type
        allowed_extensions = {'pdf', 'png', 'jpg', 'jpeg'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'success': False, 'error': 'Invalid file type. Only PDF, PNG, JPG allowed.'}), 400
        
        # Generate unique filename
        unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save file
        file.save(file_path)
        
        # Extract text using EasyOCR
        extracted_text = ""
        if file_ext == 'pdf':
            extracted_text = extract_text_from_pdf(file_path)
        else:
            extracted_text = extract_text_from_image(file_path)
        
        # Parse certificate data
        # ----------------------------------
        # Parse extracted OCR data
        # ----------------------------------
        parsed_data = parse_certificate_data(extracted_text)
        
        # ----------------------------------
        # Recipient Name Resolution (FINAL)
        # Priority:
        # 1. OCR detected name
        # 2. User manual input
        # ----------------------------------
        ocr_recipient_name = parsed_data.get("recipient_name", "")
        ocr_recipient_name = ocr_recipient_name.strip() if ocr_recipient_name else ""
        
        form_recipient_name = request.form.get("recipient_name", "")
        form_recipient_name = form_recipient_name.strip() if form_recipient_name else ""
        
        if ocr_recipient_name:
            recipient_name = ocr_recipient_name
        elif form_recipient_name:
            recipient_name = form_recipient_name
        else:
            return jsonify({
                "success": False,
                "error": "Recipient name not detected. Please enter recipient name manually.",
                "recipient_name_required": True
            }), 400
        
        certificate_name = request.form.get(
            'certificate_name',
            parsed_data.get('certificate_name') or 'Untitled Certificate'
        )
        
        issuing_authority = request.form.get(
            'issuing_authority',
            parsed_data.get('issuing_authority')
        )
        
        issue_date = request.form.get(
            'issue_date',
            parsed_data.get('issue_date')  # may be None (allowed)
        )
        
        certificate_type = request.form.get(
            'certificate_type',
            'achievement'
        )
        
        description = request.form.get(
            'description',
            parsed_data.get('description') or extracted_text[:500]
        )
        
        # Save to database
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cursor = connection.cursor()
        
        cursor.execute('''
            INSERT INTO certificates 
            (user_id, certificate_name, issuing_authority, issue_date, certificate_type, 
            description, file_path, file_name, file_size, original_filename, 
            extracted_text, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
        ''', (
            user_id, certificate_name, issuing_authority, issue_date, certificate_type,
            description, file_path, unique_filename, os.path.getsize(file_path), 
            file.filename, extracted_text
        ))
        
        certificate_id = cursor.lastrowid
        
        # Log activity
        cursor.execute('''
            INSERT INTO activities (user_id, activity_type, description, related_certificate_id)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, 'upload', f'Uploaded certificate: {certificate_name}', certificate_id))
        
        connection.commit()
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'message': 'Certificate uploaded and processed successfully',
            'certificate_id': certificate_id,
            'extracted_data': parsed_data,
            'extracted_text': extracted_text[:500],  # Return first 500 chars
            'status': 'processing'
        })
        
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certificates', methods=['GET'])
def get_user_certificates():
    """Get all certificates for current user"""
    try:
        # Check authentication
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = token.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = decoded['user_id']
        except:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT c.*, u.full_name as user_name, u.role as user_role
            FROM certificates c
            JOIN users u ON c.user_id = u.id
            WHERE c.user_id = %s
            ORDER BY c.uploaded_at DESC
        ''', (user_id,))
        
        certificates = cursor.fetchall()
        
        # Convert datetime objects to strings
        for cert in certificates:
            cert['uploaded_at'] = cert['uploaded_at'].isoformat() if cert['uploaded_at'] else None
            cert['verified_at'] = cert['verified_at'].isoformat() if cert['verified_at'] else None
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'certificates': certificates,
            'count': len(certificates)
        })
        
    except Exception as e:
        print(f"Get certificates error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/certificates', methods=['GET'])
def get_certificates_for_review():
    """Get certificates for admin review"""
    try:
        # Check authentication
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = token.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if decoded['role'] != 'admin':
                return jsonify({'success': False, 'error': 'Admin access required'}), 403
        except:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        # Get pending certificates
        cursor.execute('''
            SELECT c.*, u.full_name as user_name, u.role as user_role, u.department
            FROM certificates c
            JOIN users u ON c.user_id = u.id
            WHERE c.status = 'pending' OR c.status = 'processing'
            ORDER BY c.uploaded_at DESC
        ''')
        
        certificates = cursor.fetchall()
        
        # Convert datetime objects to strings
        for cert in certificates:
            cert['uploaded_at'] = cert['uploaded_at'].isoformat() if cert['uploaded_at'] else None
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'certificates': certificates,
            'count': len(certificates)
        })
        
    except Exception as e:
        print(f"Admin get certificates error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/verify/<int:certificate_id>', methods=['POST'])
def verify_certificate(certificate_id):
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        token = token.split(' ')[1]

        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded['role'] != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403

        admin_id = decoded['user_id']
        data = request.json or {}
        notes = data.get('notes', '')

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE certificates
            SET status = 'verified',
                verified_at = NOW(),
                verified_by = %s,
                admin_notes = %s
            WHERE id = %s
        """, (admin_id, notes, certificate_id))

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({
            "success": True,
            "message": "Certificate verified successfully",
            "certificate_id": certificate_id
        }), 200

    except Exception as e:
        print("VERIFY ERROR:", e)
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/api/admin/verify-bulk', methods=['POST'])
def verify_bulk_certificates():
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        token = token.split(' ')[1]

        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded['role'] != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403

        admin_id = decoded['user_id']
        data = request.json
        certificate_ids = data.get('certificateIds', [])

        if not certificate_ids:
            return jsonify({'success': False, 'error': 'No certificates selected'}), 400

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            f"""
            UPDATE certificates
            SET status='verified',
                verified_at=NOW(),
                verified_by=%s
            WHERE id IN ({','.join(['%s'] * len(certificate_ids))})
            """,
            [admin_id, *certificate_ids]
        )

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({'success': True, 'count': len(certificate_ids)})

    except Exception as e:
        print("Bulk verify error:", e)
        return jsonify({'success': False, 'error': str(e)}), 500

    try:
        # Check authentication
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = token.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if decoded['role'] != 'admin':
                return jsonify({'success': False, 'error': 'Admin access required'}), 403
            admin_id = decoded['user_id']
        except:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        data = request.json
        notes = data.get('notes', '')
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        # Update certificate status
        cursor.execute('''
            UPDATE certificates 
            SET status = 'verified', verified_at = NOW(), verified_by = %s, admin_notes = %s
            WHERE id = %s
        ''', (admin_id, notes, certificate_id))
        
        # Get certificate info for activity log
        cursor.execute('SELECT user_id, certificate_name FROM certificates WHERE id = %s', (certificate_id,))
        certificate = cursor.fetchone()
        
        if certificate:
            # Log activity
            cursor.execute('''
                INSERT INTO activities (user_id, activity_type, description, related_certificate_id)
                VALUES (%s, %s, %s, %s)
            ''', (certificate['user_id'], 'verification', f'Certificate verified: {certificate["certificate_name"]}', certificate_id))
        
        connection.commit()
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'message': 'Certificate verified successfully'
        })
        
    except Exception as e:
        print(f"Verify certificate error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# 🔁 Alias route for frontend compatibility
@app.route('/api/admin/certificates/<int:certificate_id>/approve', methods=['POST'])
def approve_certificate_api(certificate_id):
    return verify_certificate(certificate_id)

@app.route('/api/admin/reject/<int:certificate_id>', methods=['POST', 'OPTIONS'])
def reject_certificate(certificate_id):

    if request.method == 'OPTIONS':
        return jsonify({"success": True}), 200

    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        token = token.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        if decoded['role'] != 'admin':
            return jsonify({'success': False, 'error': 'Admin only'}), 403

        admin_id = decoded['user_id']
        reason = request.json.get('reason', '')
        notes = request.json.get('notes', '')

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE certificates
            SET status='rejected',
                verified_at=NOW(),
                verified_by=%s,
                rejection_reason=%s,
                admin_notes=%s
            WHERE id=%s
        """, (admin_id, reason, notes, certificate_id))

        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({
            "success": True,
            "message": "Certificate rejected"
        }), 200

    except Exception as e:
        print("REJECT ERROR:", e)
        return jsonify({'success': False, 'error': str(e)}), 500

# 🔁 Alias route for frontend compatibility
@app.route('/api/admin/certificates/<int:certificate_id>/reject', methods=['POST'])
def reject_certificate_api(certificate_id):
    return reject_certificate(certificate_id)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        # Check authentication
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = token.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = decoded['user_id']
            user_role = decoded['role']
        except:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        if user_role == 'admin':
            # Admin sees all stats
            cursor.execute("SELECT COUNT(*) as total FROM certificates")
            total = cursor.fetchone()['total']
            
            cursor.execute("SELECT COUNT(*) as verified FROM certificates WHERE status = 'verified'")
            verified = cursor.fetchone()['verified']
            
            cursor.execute("SELECT COUNT(*) as pending FROM certificates WHERE status = 'pending' OR status = 'processing'")
            pending = cursor.fetchone()['pending']
            
            cursor.execute("SELECT COUNT(*) as rejected FROM certificates WHERE status = 'rejected'")
            rejected = cursor.fetchone()['rejected']
        else:
            # User sees only their stats
            cursor.execute("SELECT COUNT(*) as total FROM certificates WHERE user_id = %s", (user_id,))
            total = cursor.fetchone()['total']
            
            cursor.execute("SELECT COUNT(*) as verified FROM certificates WHERE user_id = %s AND status = 'verified'", (user_id,))
            verified = cursor.fetchone()['verified']
            
            cursor.execute("SELECT COUNT(*) as pending FROM certificates WHERE user_id = %s AND (status = 'pending' OR status = 'processing')", (user_id,))
            pending = cursor.fetchone()['pending']
            
            cursor.execute("SELECT COUNT(*) as rejected FROM certificates WHERE user_id = %s AND status = 'rejected'", (user_id,))
            rejected = cursor.fetchone()['rejected']
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'verified': verified,
                'pending': pending,
                'rejected': rejected
            }
        })
        
    except Exception as e:
        print(f"Stats error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/activities', methods=['GET'])
def get_activities():
    """Get recent activities"""
    try:
        # Check authentication
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = token.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = decoded['user_id']
            user_role = decoded['role']
        except:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        if user_role == 'admin':
            # Admin sees all activities
            cursor.execute('''
                SELECT a.*, u.full_name as user_name
                FROM activities a
                JOIN users u ON a.user_id = u.id
                ORDER BY a.created_at DESC
                LIMIT 10
            ''')
        else:
            # User sees only their activities
            cursor.execute('''
                SELECT a.*, u.full_name as user_name
                FROM activities a
                JOIN users u ON a.user_id = u.id
                WHERE a.user_id = %s
                ORDER BY a.created_at DESC
                LIMIT 10
            ''', (user_id,))
        
        activities = cursor.fetchall()
        
        # Format timestamps
        for activity in activities:
            activity['created_at'] = activity['created_at'].isoformat() if activity['created_at'] else None
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'activities': activities,
            'count': len(activities)
        })
        
    except Exception as e:
        print(f"Activities error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certificates/extract', methods=['POST'])
def extract_certificate():
    """Extract text from certificate without saving to database"""
    try:
        # Authentication
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = token.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = decoded['user_id']
        except:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        # Check file
        if 'certificate' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['certificate']
        
        # Save temp file
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, file.filename)
        file.save(file_path)
        
        # Extract text
        extracted_text = ""
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext == 'pdf':
            extracted_text = extract_text_from_pdf(file_path)
        else:
            extracted_text = extract_text_from_image(file_path)
        
        # Parse certificate data
        parsed_data = parse_certificate_data(extracted_text)
        
        # Cleanup temp file
        os.remove(file_path)
        os.rmdir(temp_dir)
        
        return jsonify({
            'success': True,
            'extracted_text': extracted_text[:500],
            'extracted_data': parsed_data,
            'message': 'Text extracted successfully'
        })
        
    except Exception as e:
        print(f"Extraction error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ===============================
# ADMIN BULK APPROVE CERTIFICATES
# ===============================
@app.route('/api/admin/certificates/bulk-approve', methods=['POST'])
def bulk_approve_certificates():
    try:
        # 🔐 Check token
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        token = token.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        if decoded['role'] != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403

        admin_id = decoded['user_id']

        # 📦 Get certificate IDs
        data = request.json
        certificate_ids = data.get('certificateIds', [])

        if not certificate_ids:
            return jsonify({'success': False, 'error': 'No certificates selected'}), 400

        # 🗄️ Database update
        connection = get_db_connection()
        cursor = connection.cursor()

        placeholders = ','.join(['%s'] * len(certificate_ids))
        query = f"""
            UPDATE certificates
            SET status = 'verified',
                verified_at = NOW(),
                verified_by = %s
            WHERE id IN ({placeholders})
        """

        cursor.execute(query, [admin_id] + certificate_ids)
        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({
            'success': True,
            'approved_count': len(certificate_ids)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/uploads/certificates/<path:filename>')
def serve_uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    print("\n" + "="*60)
    print("🎓 NDU CERTILOG BACKEND SERVER")
    print("="*60)
    print(f"\n📡 API URL: http://localhost:5000")
    print(f"📁 Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"🔗 MySQL Database: {app.config['MYSQL_DATABASE']}")
    print("\n✅ Server is running with REAL functionality:")
    print("   • MySQL Database Connection")
    print("   • EasyOCR Text Extraction (No installation needed!)")
    print("   • JWT Authentication")
    print("   • Real File Upload & Processing")
    print("="*60)
    
    app.run(debug=True, port=5000)
