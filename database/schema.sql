-- Create database
CREATE DATABASE IF NOT EXISTS ndu_certilog;
USE ndu_certilog;

-- Users table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('student', 'faculty', 'admin') NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    department VARCHAR(100),
    enrollment_id VARCHAR(50) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Certificates table
CREATE TABLE certificates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    certificate_name VARCHAR(255) NOT NULL,
    issuing_authority VARCHAR(255) NOT NULL,
    issue_date DATE NOT NULL,
    certificate_type ENUM('achievement', 'participation', 'workshop', 'competition', 'academic', 'professional') NOT NULL,
    description TEXT,
    file_path VARCHAR(500) NOT NULL,
    status ENUM('pending', 'processing', 'verified', 'rejected') DEFAULT 'pending',
    extracted_text TEXT,
    admin_notes TEXT,
    rejection_reason TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP NULL,
    verified_by INT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (verified_by) REFERENCES users(id)
);

-- Activity log table
CREATE TABLE activities (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    activity_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    related_certificate_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (related_certificate_id) REFERENCES certificates(id)
);

-- Insert sample data
INSERT INTO users (username, email, password_hash, role, full_name, department) VALUES
('student', 'student@ndu.edu', '$2b$12$hashhashhashhashhashhash', 'student', 'John Student', 'Computer Science'),
('faculty', 'faculty@ndu.edu', '$2b$12$hashhashhashhashhashhash', 'faculty', 'Dr. Jane Faculty', 'Data Science'),
('admin', 'admin@ndu.edu', '$2b$12$hashhashhashhashhashhash', 'admin', 'Admin User', 'Administration');

-- Insert sample certificates
INSERT INTO certificates (user_id, certificate_name, issuing_authority, issue_date, certificate_type, description, file_path, status) VALUES
(1, 'Python Programming Certificate', 'Coding Academy', '2024-01-15', 'achievement', 'Certificate of completion for Python Programming Course', 'uploads/cert1.jpg', 'verified'),
(1, 'Machine Learning Workshop', 'AI Research Institute', '2024-01-10', 'workshop', 'Workshop on Machine Learning Fundamentals', 'uploads/cert2.jpg', 'pending'),
(2, 'Research Paper Award', 'International Conference', '2023-11-30', 'academic', 'Best Research Paper Award 2023', 'uploads/cert3.jpg', 'verified');