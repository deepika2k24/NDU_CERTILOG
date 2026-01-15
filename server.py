import http.server
import socketserver
import os

# Change to frontend directory
os.chdir('frontend')

PORT = 8001  # Changed port

Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("\n" + "="*50)
    print("NDU CERTILOG Server Started!")
    print("="*50)
    print(f"\nOpen in browser: http://localhost:{PORT}")
    print("\nDEMO LOGIN CREDENTIALS:")
    print("-" * 40)
    print("STUDENT:    student@ndu.edu / pass123")
    print("FACULTY:    faculty@ndu.edu / pass123")
    print("ADMIN:      admin@ndu.edu / pass123")
    print("-" * 40)
    print("\nAvailable Pages:")
    print("   * Login:        http://localhost:{PORT}/".format(PORT=PORT))
    print("   * Dashboard:    http://localhost:{PORT}/dashboard.html".format(PORT=PORT))
    print("   * Upload:       http://localhost:{PORT}/upload.html".format(PORT=PORT))
    print("   * Review:       http://localhost:{PORT}/review.html".format(PORT=PORT))
    print("\nPress Ctrl+C to stop server")
    print("="*50)
    
    httpd.serve_forever()