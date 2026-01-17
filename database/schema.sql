CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    usn VARCHAR(20),              -- only for students
    email VARCHAR(100) NOT NULL UNIQUE,
    role ENUM('student','faculty','admin') NOT NULL,
    department VARCHAR(50),
    program VARCHAR(50),
    semester INT,                 -- only for students
    status ENUM('Active','Inactive') DEFAULT 'Active'
);

