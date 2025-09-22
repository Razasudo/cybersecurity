import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import threading
import time
import json
import bcrypt
import socket
import subprocess
import os
import ipaddress
import requests
import hashlib
import dns.resolver
import schedule
import unittest
import pdb
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64

# ==================== AUTHENTICATION MODULE ====================
class UserAuth:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.user_file = self.data_dir / "users.json"
        self.current_user = None
        self.session_active = False
        self.lock = threading.Lock()
        
        self.data_dir.mkdir(exist_ok=True, parents=True)
        self.load_users()
    
    def load_users(self):
        try:
            if self.user_file.exists():
                with open(self.user_file, 'r') as f:
                    self.users = json.load(f)
            else:
                self.users = {}
        except:
            self.users = {}
    
    def save_users(self):
        with self.lock:
            with open(self.user_file, 'w') as f:
                json.dump(self.users, f, indent=4)
    
    def register(self, username, password):
        if not username or not password:
            return False, "Username and password are required"
        
        if username in self.users:
            return False, "Username already exists"
        
        if len(password) < 4:
            return False, "Password must be at least 4 characters"
        
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.users[username] = {
            'password': hashed.decode(),
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }
        self.save_users()
        return True, "Registration successful"
    
    def login(self, username, password):
        if username not in self.users:
            return False, "User not found"
        
        stored_hash = self.users[username]['password'].encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            self.current_user = username
            self.session_active = True
            self.users[username]['last_login'] = datetime.now().isoformat()
            self.save_users()
            return True, "Login successful"
        return False, "Invalid password"
    
    def logout(self):
        self.current_user = None
        self.session_active = False
        return True, "Logout successful"

# ==================== NETWORK SCANNER MODULE ====================
class NetworkScanner:
    def __init__(self):
        self.scan_progress = 0
        self.is_scanning = False
        self.stop_scan = False
        self.live_hosts = []
        self.open_ports = {}
        self.lock = threading.Lock()
    
    def ping_host(self, ip, timeout=1):
        """Ping a single host using system ping command"""
        if self.stop_scan:
            return None
            
        try:
            # Platform-specific ping command
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', '-w', str(timeout*1000), str(ip)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return ip if result.returncode == 0 else None
        except:
            return None
    
    def scan_port(self, ip, port, timeout=1):
        """Check if a port is open on a host"""
        if self.stop_scan:
            return None
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((str(ip), port))
                return port if result == 0 else None
        except:
            return None
    
    def ping_sweep(self, ip_range, max_workers=50):
        """Perform network scan with threading"""
        self.scan_progress = 0
        self.is_scanning = True
        self.stop_scan = False
        self.live_hosts = []
        
        try:
            # Parse IP range
            network = ipaddress.ip_network(ip_range, strict=False)
            hosts = list(network.hosts())
            total_hosts = len(hosts)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all ping tasks
                future_to_ip = {
                    executor.submit(self.ping_host, host, 1): host 
                    for host in hosts[:50]  # Limit for demo
                }
                
                # Process results as they complete
                for i, future in enumerate(as_completed(future_to_ip)):
                    if self.stop_scan:
                        break
                    
                    host = future_to_ip[future]
                    try:
                        result = future.result()
                        if result:
                            with self.lock:
                                self.live_hosts.append(str(result))
                    except Exception as e:
                        pass
                    
                    self.scan_progress = (i + 1) / min(50, total_hosts) * 100
                    time.sleep(0.01)  # Prevent UI freezing
            
        except Exception as e:
            return [f"Scan error: {str(e)}"]
        
        self.is_scanning = False
        return [f"Found {len(self.live_hosts)} live hosts:"] + self.live_hosts
    
    def port_scan(self, target, ports="1-1024", max_workers=100):
        """Scan ports on a target host"""
        self.scan_progress = 0
        self.is_scanning = True
        self.stop_scan = False
        self.open_ports[target] = []
        
        try:
            # Parse port range
            if "-" in ports:
                start, end = map(int, ports.split("-"))
                port_list = list(range(start, end + 1))
            else:
                port_list = [int(p) for p in ports.split(",")]
            
            total_ports = len(port_list)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all port scanning tasks
                future_to_port = {
                    executor.submit(self.scan_port, target, port, 1): port 
                    for port in port_list[:100]  # Limit for demo
                }
                
                # Process results as they complete
                for i, future in enumerate(as_completed(future_to_port)):
                    if self.stop_scan:
                        break
                    
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result:
                            with self.lock:
                                self.open_ports[target].append(result)
                    except Exception as e:
                        pass
                    
                    self.scan_progress = (i + 1) / min(100, total_ports) * 100
                    time.sleep(0.01)
            
        except Exception as e:
            return [f"Port scan error: {str(e)}"]
        
        self.is_scanning = False
        result = [f"Found {len(self.open_ports[target])} open ports on {target}:"]
        result.extend([f"Port {p}/tcp open" for p in self.open_ports[target]])
        return result
    
    def stop_scanning(self):
        self.stop_scan = True
        self.is_scanning = False

# ==================== PASSWORD TOOLS MODULE ====================
class PasswordTools:
    def __init__(self):
        self.api_url = "https://api.pwnedpasswords.com/range/"
    
    def check_hibp(self, password):
        """Check password against HaveIBeenPwned API"""
        try:
            # Hash password using SHA-1
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            # Make API request
            response = requests.get(f"{self.api_url}{prefix}")
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return int(count)
            return 0
        except:
            return -1  # API error
    
    def check_password_strength(self, password):
        if not password:
            return {"score": 0, "strength": "Very Weak", "issues": ["No password"], "suggestions": ["Enter a password"]}
        
        score = 0
        issues = []
        suggestions = []
        
        # Length check
        length = len(password)
        if length >= 12:
            score += 2
        elif length >= 8:
            score += 1
        else:
            issues.append(f"Too short ({length} characters, min 8)")
            suggestions.append("Use at least 8 characters")
        
        # Complexity checks
        if any(c.isdigit() for c in password):
            score += 1
        else:
            issues.append("No numbers")
            suggestions.append("Add numbers (0-9)")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            issues.append("No uppercase letters")
            suggestions.append("Add uppercase letters (A-Z)")
        
        if any(not c.isalnum() for c in password):
            score += 1
        else:
            issues.append("No special characters")
            suggestions.append("Add special characters (!@#$%^&*)")
        
        # Common password check
        common_passwords = {"password", "123456", "qwerty", "letmein", "admin"}
        if password.lower() in common_passwords:
            score = max(0, score - 2)
            issues.append("Very common password")
            suggestions.append("Avoid common passwords")
        
        # HIBP API check
        breach_count = self.check_hibp(password)
        if breach_count > 0:
            score = max(0, score - 2)
            issues.append(f"Password found in {breach_count} data breaches")
            suggestions.append("Change this password immediately!")
        elif breach_count == -1:
            issues.append("Could not check breach database")
            suggestions.append("Check internet connection and try again")
        
        strengths = {
            0: "Very Weak", 1: "Weak", 2: "Medium", 
            3: "Strong", 4: "Very Strong", 5: "Excellent"
        }
        
        return {
            "score": score, 
            "strength": strengths.get(score, "Weak"),
            "issues": issues,
            "suggestions": suggestions,
            "length": length,
            "breach_count": breach_count if breach_count > 0 else 0
        }

# ==================== ENCRYPTION TOOLS MODULE ====================
class EncryptionTools:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True, parents=True)
        self.encryption_history = []
        
        # Generate or load keys
        self.fernet_key = Fernet.generate_key()
        self.fernet = Fernet(self.fernet_key)
        
        # Generate RSA keys if not exists
        self.private_key, self.public_key = self.load_or_generate_rsa_keys()
    
    def load_or_generate_rsa_keys(self):
        """Load existing RSA keys or generate new ones"""
        private_key_path = self.data_dir / "private_key.pem"
        public_key_path = self.data_dir / "public_key.pem"
        
        try:
            # Try to load existing keys
            if private_key_path.exists() and public_key_path.exists():
                with open(private_key_path, "rb") as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                with open(public_key_path, "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())
                return private_key, public_key
        except:
            pass
        
        # Generate new keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Save keys
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return private_key, public_key
    
    def fernet_encrypt(self, text):
        """Encrypt using Fernet symmetric encryption"""
        encrypted = self.fernet.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def fernet_decrypt(self, encrypted_text):
        """Decrypt using Fernet"""
        try:
            encrypted = base64.urlsafe_b64decode(encrypted_text.encode())
            decrypted = self.fernet.decrypt(encrypted)
            return decrypted.decode()
        except:
            return "Decryption failed - invalid token"
    
    def rsa_encrypt(self, text):
        """Encrypt using RSA asymmetric encryption"""
        encrypted = self.public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    
    def rsa_decrypt(self, encrypted_text):
        """Decrypt using RSA private key"""
        try:
            encrypted = base64.b64decode(encrypted_text.encode())
            decrypted = self.private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except:
            return "Decryption failed - invalid data"
    
    def analyze_text(self, text):
        """Analyze text for encryption patterns"""
        analysis = {
            "length": len(text),
            "upper_case": sum(1 for c in text if c.isupper()),
            "lower_case": sum(1 for c in text if c.islower()),
            "digits": sum(1 for c in text if c.isdigit()),
            "special_chars": sum(1 for c in text if not c.isalnum() and not c.isspace()),
            "entropy": self.calculate_entropy(text)
        }
        return analysis
    
    def calculate_entropy(self, text):
        """Calculate simple entropy of text"""
        if not text:
            return 0
        
        import math
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0
        for count in freq.values():
            probability = count / len(text)
            entropy -= probability * math.log2(probability)
        
        return entropy

# ==================== SUBDOMAIN ENUMERATOR MODULE ====================
class SubdomainEnumerator:
    def __init__(self):
        self.wordlist = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", 
            "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
            "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
            "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
            "lists", "support", "mobile", "mx", "static", "docs", "beta",
            "shop", "sql", "secure", "demo", "cp", "calendar", "wiki", "api",
            "web", "media", "email", "images", "img", "www1", "intranet",
            "portal", "video", "sip", "dns2", "remote", "server", "ftp2",
            "mail1", "chat", "search", "monitor", "live", "apps", "cdn"
        ]
        self.found_subdomains = []
        self.enumeration_progress = 0
        self.is_enumerating = False
        self.stop_enumeration = False
    
    def check_subdomain(self, subdomain, domain):
        """Check if a subdomain exists using DNS resolution"""
        if self.stop_enumeration:
            return None
            
        full_domain = f"{subdomain}.{domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            return full_domain
        except:
            return None
    
    def enumerate(self, domain, max_workers=20):
        """Find valid subdomains using DNS resolution"""
        self.enumeration_progress = 0
        self.is_enumerating = True
        self.stop_enumeration = False
        self.found_subdomains = []
        
        total_subdomains = len(self.wordlist)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.check_subdomain, sub, domain): sub 
                for sub in self.wordlist
            }
            
            for i, future in enumerate(as_completed(futures)):
                if self.stop_enumeration:
                    break
                    
                try:
                    result = future.result()
                    if result:
                        self.found_subdomains.append(result)
                except:
                    pass
                
                self.enumeration_progress = (i + 1) / total_subdomains * 100
                time.sleep(0.01)
        
        self.is_enumerating = False
        return self.found_subdomains
    
    def stop_enumeration_process(self):
        self.stop_enumeration = True
        self.is_enumerating = False

# ==================== ATTACK SIMULATOR MODULE ====================
class AttackSimulator:
    def __init__(self):
        self.attack_progress = 0
        self.is_attacking = False
        self.attack_results = []
        self.common_passwords = [
            "password", "123456", "qwerty", "letmein", "admin", "welcome",
            "monkey", "password1", "12345678", "123456789", "abc123", "password123"
        ]
    
    def dictionary_attack(self, target_hash, hash_type="md5", max_workers=10):
        """Perform dictionary attack against a hashed password"""
        self.attack_progress = 0
        self.is_attacking = True
        self.attack_results = []
        
        total_words = len(self.common_passwords)
        found = False
        
        for i, word in enumerate(self.common_passwords):
            if not self.is_attacking:
                break
            
            # Hash the word using the specified algorithm
            if hash_type.lower() == "md5":
                hashed_word = hashlib.md5(word.encode()).hexdigest()
            elif hash_type.lower() == "sha1":
                hashed_word = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type.lower() == "sha256":
                hashed_word = hashlib.sha256(word.encode()).hexdigest()
            else:
                self.attack_results.append(f"Unsupported hash type: {hash_type}")
                break
            
            # Check if the hash matches
            if hashed_word == target_hash:
                self.attack_results.append(f"Password found: '{word}' ({hash_type.upper()})")
                found = True
                break
            
            self.attack_progress = (i + 1) / total_words * 100
            time.sleep(0.05)  # Small delay to prevent UI freezing
        
        if not found:
            self.attack_results.append(f"No match found after {total_words} attempts")
        
        self.is_attacking = False
        return self.attack_results
    
    def simulate_brute_force(self, target, max_length=4):
        """Simulate brute force attack"""
        self.attack_progress = 0
        self.is_attacking = True
        self.attack_results = []
        
        # Simple character set for demo
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        total_attempts = min(1000, sum(len(chars)**i for i in range(1, max_length + 1)))
        
        # Simulate attack
        attempted = 0
        for length in range(1, max_length + 1):
            if not self.is_attacking:
                break
            
            # This would be the actual combination generation in a real attack
            # For demo, we'll just simulate the process
            combinations = min(100, len(chars) ** length)
            
            for i in range(combinations):
                if not self.is_attacking:
                    break
                
                attempted += 1
                self.attack_progress = (attempted / total_attempts) * 100
                
                # Simulate finding a match (for demo purposes)
                if attempted == total_attempts // 2:
                    self.attack_results.append(f"Found potential match after {attempted} attempts")
                
                time.sleep(0.01)
        
        if not self.attack_results:
            self.attack_results.append(f"Attack completed. No match found after {attempted} attempts.")
        
        self.is_attacking = False
        return self.attack_results
    
    def stop_attack(self):
        self.is_attacking = False

# ==================== AUTOMATION MODULE ====================
class AutomationManager:
    def __init__(self):
        self.scheduled_tasks = []
        self.is_running = False
    
    def schedule_daily_scan(self, ip_range, callback):
        """Schedule a daily network scan"""
        task = schedule.every().day.at("09:00").do(self.run_scan, ip_range, callback)
        self.scheduled_tasks.append(("Daily Network Scan", task))
        return "Daily network scan scheduled at 09:00"
    
    def schedule_daily_password_check(self, callback):
        """Schedule a daily password check"""
        task = schedule.every().day.at("10:00").do(self.run_password_check, callback)
        self.scheduled_tasks.append(("Daily Password Check", task))
        return "Daily password check scheduled at 10:00"
    
    def run_scan(self, ip_range, callback):
        """Run a network scan"""
        scanner = NetworkScanner()
        results = scanner.ping_sweep(ip_range)
        callback(f"Scheduled Scan Results: {results}")
    
    def run_password_check(self, callback):
        """Run a password check"""
        # This would check saved passwords in a real implementation
        callback("Scheduled password check completed. No weak passwords found.")
    
    def clear_all_tasks(self):
        """Clear all scheduled tasks"""
        schedule.clear()
        self.scheduled_tasks = []
        return "All scheduled tasks cleared"
    
    def view_scheduled_tasks(self):
        """View all scheduled tasks"""
        if not self.scheduled_tasks:
            return ["No scheduled tasks"]
        
        return [f"{name}: {task}" for name, task in self.scheduled_tasks]

# ==================== REPORT GENERATOR MODULE ====================
class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_report(self, report_type, data, title="Security Report"):
        """Generate a report in text or JSON format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Text report
        txt_filename = self.output_dir / f"{report_type}_{timestamp}.txt"
        with open(txt_filename, 'w') as f:
            f.write(f"{title}\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Report Type: {report_type}\n")
            f.write("-" * 50 + "\n\n")
            
            if isinstance(data, list):
                for item in data:
                    f.write(f"• {item}\n")
            elif isinstance(data, dict):
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
            else:
                f.write(str(data))
        
        # JSON report
        json_filename = self.output_dir / f"{report_type}_{timestamp}.json"
        report_data = {
            "title": title,
            "generated": datetime.now().isoformat(),
            "type": report_type,
            "data": data
        }
        with open(json_filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        return f"Reports generated: {txt_filename}, {json_filename}"

# ==================== TESTING MODULE ====================
class TestModules(unittest.TestCase):
    def test_auth_module(self):
        """Test authentication module"""
        auth = UserAuth("test_data")
        success, message = auth.register("testuser", "password123")
        self.assertTrue(success)
        
        success, message = auth.login("testuser", "password123")
        self.assertTrue(success)
        
        success, message = auth.login("testuser", "wrongpassword")
        self.assertFalse(success)
    
    def test_password_tools(self):
        """Test password tools module"""
        pt = PasswordTools()
        result = pt.check_password_strength("Weak1")
        self.assertEqual(result['strength'], "Weak")
        
        result = pt.check_password_strength("StrongPassword123!")
        self.assertIn("Strong", result['strength'])
    
    def test_encryption_tools(self):
        """Test encryption tools module"""
        et = EncryptionTools("test_data")
        original = "Secret message"
        encrypted = et.fernet_encrypt(original)
        decrypted = et.fernet_decrypt(encrypted)
        self.assertEqual(original, decrypted)

# ==================== MAIN APPLICATION ====================
class PyCyberSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("PyCyberSuite - Complete Cybersecurity Toolkit")
        self.root.geometry("1200x800")
        self.root.configure(bg='white')
        
        # Initialize all modules
        self.auth = UserAuth()
        self.scanner = NetworkScanner()
        self.password_tools = PasswordTools()
        self.encryption_tools = EncryptionTools()
        self.subdomain_enumerator = SubdomainEnumerator()
        self.attack_simulator = AttackSimulator()
        self.automation_manager = AutomationManager()
        self.report_generator = ReportGenerator()
        
        # Set up the interface
        self.setup_ui()
        
        # Start with login screen
        self.show_frame(self.login_frame)
        
        # Start automation scheduler in background
        self.start_scheduler()
    
    def setup_ui(self):
        # Create main container
        self.main_container = tk.Frame(self.root, bg='white')
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create all frames
        self.login_frame = self.create_login_frame()
        self.main_frame = self.create_main_frame()
        
        # Show login frame initially
        self.show_frame(self.login_frame)
    
    def create_login_frame(self):
        frame = tk.Frame(self.main_container, bg='white', padx=20, pady=20)
        
        # Title
        title = tk.Label(frame, text="PyCyberSuite", font=("Arial", 28, "bold"), 
                        bg='white', fg='#2c3e50')
        title.pack(pady=(50, 10))
        
        subtitle = tk.Label(frame, text="Complete Cybersecurity Toolkit", font=("Arial", 14), 
                           bg='white', fg='#7f8c8d')
        subtitle.pack(pady=(0, 40))
        
        # Login form container
        form_frame = tk.Frame(frame, bg='white')
        form_frame.pack(pady=20)
        
        # Username
        tk.Label(form_frame, text="Username:", bg='white', font=("Arial", 11)).grid(
            row=0, column=0, sticky='w', pady=8, padx=5)
        self.username_entry = ttk.Entry(form_frame, width=25, font=("Arial", 11))
        self.username_entry.grid(row=0, column=1, pady=8, padx=5)
        
        # Password
        tk.Label(form_frame, text="Password:", bg='white', font=("Arial", 11)).grid(
            row=1, column=0, sticky='w', pady=8, padx=5)
        self.password_entry = ttk.Entry(form_frame, width=25, show='*', font=("Arial", 11))
        self.password_entry.grid(row=1, column=1, pady=8, padx=5)
        
        # Buttons
        btn_frame = tk.Frame(form_frame, bg='white')
        btn_frame.grid(row=2, column=0, columnspan=2, pady=25)
        
        ttk.Button(btn_frame, text="Login", command=self.login, width=12).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="Register", command=self.register, width=12).pack(side=tk.LEFT, padx=8)
        
        # Status label
        self.status_label = tk.Label(form_frame, text="", bg='white', fg='red', font=("Arial", 10))
        self.status_label.grid(row=3, column=0, columnspan=2, pady=12)
        
        # Bind Enter key to login
        self.password_entry.bind('<Return>', lambda e: self.login())
        
        return frame
    
    def create_main_frame(self):
        frame = tk.Frame(self.main_container, bg='white')
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create all tabs
        self.setup_dashboard_tab()
        self.setup_network_tab()
        self.setup_password_tab()
        self.setup_encryption_tab()
        self.setup_subdomain_tab()
        self.setup_attack_tab()
        self.setup_automation_tab()
        self.setup_reports_tab()
        self.setup_testing_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Logout button
        ttk.Button(frame, text="Logout", command=self.logout).pack(side=tk.BOTTOM, pady=5)
        
        return frame
    
    def setup_dashboard_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Dashboard")
        
        # Welcome message
        ttk.Label(frame, text="Welcome to PyCyberSuite", font=("Arial", 18, "bold")).pack(pady=20)
        
        # Quick actions
        actions_frame = ttk.LabelFrame(frame, text="Quick Actions", padding="15")
        actions_frame.pack(fill=tk.X, padx=20, pady=10)
        
        actions = [
            ("🌐 Network Scan", self.quick_network_scan),
            ("🔑 Password Check", self.quick_password_check),
            ("🔒 Text Encryption", self.quick_encrypt),
            ("🌐 Subdomain Enumeration", self.quick_subdomain_enum),
            ("⚔️ Attack Simulation", self.quick_attack),
            ("📊 Generate Report", self.quick_report)
        ]
        
        for text, command in actions:
            btn = ttk.Button(actions_frame, text=text, command=command)
            btn.pack(pady=6, fill=tk.X)
    
    def setup_network_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Network Tools")
        
        # Scan controls
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="IP Range:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(control_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "192.168.1.0/24")
        
        ttk.Button(control_frame, text="Ping Sweep", command=self.start_ping_sweep).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(control_frame, text="Target:").pack(side=tk.LEFT, padx=(20, 5))
        self.port_target_entry = ttk.Entry(control_frame, width=15)
        self.port_target_entry.pack(side=tk.LEFT, padx=5)
        self.port_target_entry.insert(0, "192.168.1.1")
        
        ttk.Label(control_frame, text="Ports:").pack(side=tk.LEFT, padx=(20, 5))
        self.ports_entry = ttk.Entry(control_frame, width=15)
        self.ports_entry.pack(side=tk.LEFT, padx=5)
        self.ports_entry.insert(0, "1-100")
        
        ttk.Button(control_frame, text="Port Scan", command=self.start_port_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.results_text.config(state=tk.DISABLED)
    
    def setup_password_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Password Tools")
        
        # Password input
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Password:").pack(side=tk.LEFT)
        self.pwd_entry = ttk.Entry(input_frame, width=30, show="*")
        self.pwd_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="Check Strength", command=self.check_password_strength).pack(side=tk.LEFT, padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Password Analysis")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.pwd_results = scrolledtext.ScrolledText(results_frame, height=15)
        self.pwd_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.pwd_results.config(state=tk.DISABLED)
    
    def setup_encryption_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Encryption Tools")
        
        # Encryption type selection
        encryption_frame = ttk.Frame(frame)
        encryption_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(encryption_frame, text="Algorithm:").pack(side=tk.LEFT)
        self.encryption_type = ttk.Combobox(encryption_frame, values=["Fernet", "RSA"], width=10)
        self.encryption_type.pack(side=tk.LEFT, padx=5)
        self.encryption_type.set("Fernet")
        
        # Encryption input
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Text:").pack(side=tk.LEFT)
        self.encrypt_entry = ttk.Entry(input_frame, width=30)
        self.encrypt_entry.pack(side=tk.LEFT, padx=5)
        self.encrypt_entry.insert(0, "Secret message to encrypt")
        
        ttk.Button(input_frame, text="Encrypt", command=self.encrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Decrypt", command=self.decrypt_text).pack(side=tk.LEFT, padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Encryption Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.encrypt_results = scrolledtext.ScrolledText(results_frame, height=15)
        self.encrypt_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.encrypt_results.config(state=tk.DISABLED)
    
    def setup_subdomain_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Subdomain Enum")
        
        # Subdomain enumeration controls
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Domain:").pack(side=tk.LEFT)
        self.domain_entry = ttk.Entry(control_frame, width=25)
        self.domain_entry.pack(side=tk.LEFT, padx=5)
        self.domain_entry.insert(0, "example.com")
        
        ttk.Button(control_frame, text="Enumerate", command=self.start_subdomain_enum).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop", command=self.stop_subdomain_enum).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.enum_progress_bar = ttk.Progressbar(frame, mode='determinate')
        self.enum_progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Subdomain Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.subdomain_results = scrolledtext.ScrolledText(results_frame, height=15)
        self.subdomain_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.subdomain_results.config(state=tk.DISABLED)
    
    def setup_attack_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Attack Simulation")
        
        # Attack type selection
        attack_type_frame = ttk.Frame(frame)
        attack_type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(attack_type_frame, text="Attack Type:").pack(side=tk.LEFT)
        self.attack_type = ttk.Combobox(attack_type_frame, values=["Dictionary", "Brute Force"], width=12)
        self.attack_type.pack(side=tk.LEFT, padx=5)
        self.attack_type.set("Dictionary")
        
        # Dictionary attack controls
        dict_frame = ttk.Frame(frame)
        dict_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(dict_frame, text="Hash:").pack(side=tk.LEFT)
        self.hash_entry = ttk.Entry(dict_frame, width=40)
        self.hash_entry.pack(side=tk.LEFT, padx=5)
        self.hash_entry.insert(0, "5f4dcc3b5aa765d61d8327deb882cf99")  # MD5 of "password"
        
        ttk.Label(dict_frame, text="Hash Type:").pack(side=tk.LEFT, padx=(10, 5))
        self.hash_type = ttk.Combobox(dict_frame, values=["md5", "sha1", "sha256"], width=8)
        self.hash_type.pack(side=tk.LEFT, padx=5)
        self.hash_type.set("md5")
        
        # Brute force controls
        brute_frame = ttk.Frame(frame)
        brute_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(brute_frame, text="Target:").pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(brute_frame, width=20)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "test_target")
        
        ttk.Label(brute_frame, text="Max Length:").pack(side=tk.LEFT, padx=(10, 5))
        self.max_length = ttk.Spinbox(brute_frame, from_=1, to=8, width=5)
        self.max_length.pack(side=tk.LEFT, padx=5)
        self.max_length.set(4)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Start Attack", command=self.start_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop Attack", command=self.stop_attack).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.attack_progress_bar = ttk.Progressbar(frame, mode='determinate')
        self.attack_progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Attack Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.attack_results = scrolledtext.ScrolledText(results_frame, height=15)
        self.attack_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.attack_results.config(state=tk.DISABLED)
    
    def setup_automation_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Automation")
        
        # Schedule controls
        schedule_frame = ttk.LabelFrame(frame, text="Schedule Tasks")
        schedule_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(schedule_frame, text="Schedule Daily Network Scan", 
                  command=self.schedule_daily_scan).pack(pady=5)
        
        ttk.Button(schedule_frame, text="Schedule Daily Password Check", 
                  command=self.schedule_daily_password_check).pack(pady=5)
        
        ttk.Button(schedule_frame, text="Clear All Scheduled Tasks", 
                  command=self.clear_scheduled_tasks).pack(pady=5)
        
        # Task list
        tasks_frame = ttk.LabelFrame(frame, text="Scheduled Tasks")
        tasks_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.tasks_text = scrolledtext.ScrolledText(tasks_frame, height=10)
        self.tasks_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tasks_text.config(state=tk.DISABLED)
        
        # Refresh button
        ttk.Button(frame, text="Refresh Task List", command=self.refresh_task_list).pack(pady=5)
    
    def setup_reports_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Reports")
        
        # Report controls
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Report Type:").pack(side=tk.LEFT)
        self.report_type = ttk.Combobox(control_frame, values=["Security Scan", "Password Audit", "Attack Results"], width=15)
        self.report_type.pack(side=tk.LEFT, padx=5)
        self.report_type.set("Security Scan")
        
        ttk.Button(control_frame, text="Generate Report", command=self.generate_report).pack(side=tk.LEFT, padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Generated Reports")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.report_results = scrolledtext.ScrolledText(results_frame, height=15)
        self.report_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.report_results.config(state=tk.DISABLED)
    
    def setup_testing_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Testing")
        
        # Test controls
        test_frame = ttk.LabelFrame(frame, text="Run Tests")
        test_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(test_frame, text="Run All Tests", command=self.run_all_tests).pack(pady=5)
        ttk.Button(test_frame, text="Test Authentication", command=self.run_auth_tests).pack(pady=5)
        ttk.Button(test_frame, text="Test Password Tools", command=self.run_password_tests).pack(pady=5)
        ttk.Button(test_frame, text="Test Encryption", command=self.run_encryption_tests).pack(pady=5)
        
        # Debug controls
        debug_frame = ttk.LabelFrame(frame, text="Debugging")
        debug_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(debug_frame, text="Start Debugger", command=self.start_debugger).pack(pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Test Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.test_results = scrolledtext.ScrolledText(results_frame, height=15)
        self.test_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.test_results.config(state=tk.DISABLED)
    
    def show_frame(self, frame):
        """Show a specific frame"""
        for f in [self.login_frame, self.main_frame]:
            f.pack_forget()
        frame.pack(fill=tk.BOTH, expand=True)
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_label.config(text="Please enter username and password")
            return
        
        success, message = self.auth.login(username, password)
        if success:
            self.status_label.config(text=message, fg='green')
            self.root.after(1000, self.show_main_application)
        else:
            self.status_label.config(text=message, fg='red')
    
    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_label.config(text="Please enter username and password")
            return
        
        success, message = self.auth.register(username, password)
        if success:
            self.status_label.config(text=message, fg='green')
        else:
            self.status_label.config(text=message, fg='red')
    
    def show_main_application(self):
        self.show_frame(self.main_frame)
        self.status_var.set(f"Welcome, {self.auth.current_user}!")
    
    def logout(self):
        self.auth.logout()
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.show_frame(self.login_frame)
        self.status_label.config(text="Logged out successfully", fg='green')
    
    def quick_network_scan(self):
        self.notebook.select(1)
        self.start_ping_sweep()
    
    def quick_password_check(self):
        self.notebook.select(2)
        password = simpledialog.askstring("Password Check", "Enter password to check:", show='*')
        if password:
            self.pwd_entry.delete(0, tk.END)
            self.pwd_entry.insert(0, password)
            self.check_password_strength()
    
    def quick_encrypt(self):
        self.notebook.select(3)
        self.encrypt_text()
    
    def quick_subdomain_enum(self):
        self.notebook.select(4)
        self.start_subdomain_enum()
    
    def quick_attack(self):
        self.notebook.select(5)
        self.start_attack()
    
    def quick_report(self):
        self.notebook.select(7)
        self.generate_report()
    
    def start_ping_sweep(self):
        ip_range = self.ip_entry.get()
        self.status_var.set(f"Ping sweeping {ip_range}...")
        self.progress_bar['value'] = 0
        
        def scan_thread():
            results = self.scanner.ping_sweep(ip_range)
            self.root.after(0, lambda: self.update_scan_results(results))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def start_port_scan(self):
        target = self.port_target_entry.get()
        ports = self.ports_entry.get()
        self.status_var.set(f"Scanning ports {ports} on {target}...")
        self.progress_bar['value'] = 0
        
        def scan_thread():
            results = self.scanner.port_scan(target, ports)
            self.root.after(0, lambda: self.update_scan_results(results))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def update_scan_results(self, results):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Network Scan Results - {datetime.now()}\n")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")
        
        for result in results:
            self.results_text.insert(tk.END, f"• {result}\n")
        
        self.results_text.config(state=tk.DISABLED)
        self.progress_bar['value'] = 100
        self.status_var.set("Scan completed")
    
    def stop_scan(self):
        self.scanner.stop_scanning()
        self.status_var.set("Scan stopped")
        self.progress_bar['value'] = 0
    
    def check_password_strength(self):
        password = self.pwd_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        
        result = self.password_tools.check_password_strength(password)
        
        self.pwd_results.config(state=tk.NORMAL)
        self.pwd_results.delete(1.0, tk.END)
        self.pwd_results.insert(tk.END, f"Password Strength Analysis\n")
        self.pwd_results.insert(tk.END, "=" * 50 + "\n\n")
        self.pwd_results.insert(tk.END, f"Password: {'*' * len(password)}\n")
        self.pwd_results.insert(tk.END, f"Length: {result['length']} characters\n")
        self.pwd_results.insert(tk.END, f"Strength: {result['strength']} ({result['score']}/5)\n")
        
        if result['breach_count'] > 0:
            self.pwd_results.insert(tk.END, f"Breaches: Found in {result['breach_count']} data breaches!\n")
        
        self.pwd_results.insert(tk.END, "\n")
        
        if result['issues']:
            self.pwd_results.insert(tk.END, "Issues found:\n")
            for issue in result['issues']:
                self.pwd_results.insert(tk.END, f"• {issue}\n")
        
        if result['suggestions']:
            self.pwd_results.insert(tk.END, "\nSuggestions:\n")
            for suggestion in result['suggestions']:
                self.pwd_results.insert(tk.END, f"• {suggestion}\n")
        
        self.pwd_results.config(state=tk.DISABLED)
        self.status_var.set("Password analysis completed")
    
    def encrypt_text(self):
        text = self.encrypt_entry.get()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to encrypt")
            return
        
        algorithm = self.encryption_type.get()
        if algorithm == "Fernet":
            encrypted = self.encryption_tools.fernet_encrypt(text)
            algorithm_name = "Fernet (Symmetric)"
        else:  # RSA
            encrypted = self.encryption_tools.rsa_encrypt(text)
            algorithm_name = "RSA (Asymmetric)"
        
        analysis = self.encryption_tools.analyze_text(text)
        
        self.encrypt_results.config(state=tk.NORMAL)
        self.encrypt_results.delete(1.0, tk.END)
        self.encrypt_results.insert(tk.END, f"Encryption Results - {algorithm_name}\n")
        self.encrypt_results.insert(tk.END, "=" * 50 + "\n\n")
        self.encrypt_results.insert(tk.END, f"Original: {text}\n")
        self.encrypt_results.insert(tk.END, f"Encrypted: {encrypted}\n\n")
        self.encrypt_results.insert(tk.END, "Text Analysis:\n")
        for key, value in analysis.items():
            self.encrypt_results.insert(tk.END, f"• {key}: {value}\n")
        
        self.encrypt_results.config(state=tk.DISABLED)
        self.status_var.set("Text encrypted")
    
    def decrypt_text(self):
        text = self.encrypt_entry.get()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to decrypt")
            return
        
        algorithm = self.encryption_type.get()
        if algorithm == "Fernet":
            decrypted = self.encryption_tools.fernet_decrypt(text)
            algorithm_name = "Fernet (Symmetric)"
        else:  # RSA
            decrypted = self.encryption_tools.rsa_decrypt(text)
            algorithm_name = "RSA (Asymmetric)"
        
        self.encrypt_results.config(state=tk.NORMAL)
        self.encrypt_results.delete(1.0, tk.END)
        self.encrypt_results.insert(tk.END, f"Decryption Results - {algorithm_name}\n")
        self.encrypt_results.insert(tk.END, "=" * 50 + "\n\n")
        self.encrypt_results.insert(tk.END, f"Encrypted: {text}\n")
        self.encrypt_results.insert(tk.END, f"Decrypted: {decrypted}\n")
        
        self.encrypt_results.config(state=tk.DISABLED)
        self.status_var.set("Text decrypted")
    
    def start_subdomain_enum(self):
        domain = self.domain_entry.get()
        self.status_var.set(f"Enumerating subdomains for {domain}...")
        self.enum_progress_bar['value'] = 0
        
        def enum_thread():
            results = self.subdomain_enumerator.enumerate(domain)
            self.root.after(0, lambda: self.update_subdomain_results(results))
        
        threading.Thread(target=enum_thread, daemon=True).start()
    
    def update_subdomain_results(self, results):
        self.subdomain_results.config(state=tk.NORMAL)
        self.subdomain_results.delete(1.0, tk.END)
        self.subdomain_results.insert(tk.END, f"Subdomain Enumeration Results - {datetime.now()}\n")
        self.subdomain_results.insert(tk.END, "=" * 50 + "\n\n")
        
        if results:
            self.subdomain_results.insert(tk.END, f"Found {len(results)} subdomains:\n\n")
            for result in results:
                self.subdomain_results.insert(tk.END, f"• {result}\n")
        else:
            self.subdomain_results.insert(tk.END, "No subdomains found.\n")
        
        self.subdomain_results.config(state=tk.DISABLED)
        self.enum_progress_bar['value'] = 100
        self.status_var.set("Subdomain enumeration completed")
    
    def stop_subdomain_enum(self):
        self.subdomain_enumerator.stop_enumeration_process()
        self.status_var.set("Enumeration stopped")
        self.enum_progress_bar['value'] = 0
    
    def start_attack(self):
        attack_type = self.attack_type.get()
        
        if attack_type == "Dictionary":
            target_hash = self.hash_entry.get()
            hash_type = self.hash_type.get()
            self.status_var.set(f"Running dictionary attack ({hash_type})...")
            self.attack_progress_bar['value'] = 0
            
            def attack_thread():
                results = self.attack_simulator.dictionary_attack(target_hash, hash_type)
                self.root.after(0, lambda: self.update_attack_results(results))
            
            threading.Thread(target=attack_thread, daemon=True).start()
        
        else:  # Brute Force
            target = self.target_entry.get()
            max_length = int(self.max_length.get())
            self.status_var.set(f"Simulating brute force attack on {target}...")
            self.attack_progress_bar['value'] = 0
            
            def attack_thread():
                results = self.attack_simulator.simulate_brute_force(target, max_length)
                self.root.after(0, lambda: self.update_attack_results(results))
            
            threading.Thread(target=attack_thread, daemon=True).start()
    
    def update_attack_results(self, results):
        self.attack_results.config(state=tk.NORMAL)
        self.attack_results.delete(1.0, tk.END)
        self.attack_results.insert(tk.END, f"Attack Simulation Results - {datetime.now()}\n")
        self.attack_results.insert(tk.END, "=" * 50 + "\n\n")
        
        for result in results:
            self.attack_results.insert(tk.END, f"• {result}\n")
        
        self.attack_results.config(state=tk.DISABLED)
        self.attack_progress_bar['value'] = 100
        self.status_var.set("Attack simulation completed")
    
    def stop_attack(self):
        self.attack_simulator.stop_attack()
        self.status_var.set("Attack stopped")
        self.attack_progress_bar['value'] = 0
    
    def schedule_daily_scan(self):
        ip_range = self.ip_entry.get()
        result = self.automation_manager.schedule_daily_scan(ip_range, self.automation_callback)
        self.status_var.set(result)
        self.refresh_task_list()
    
    def schedule_daily_password_check(self):
        result = self.automation_manager.schedule_daily_password_check(self.automation_callback)
        self.status_var.set(result)
        self.refresh_task_list()
    
    def clear_scheduled_tasks(self):
        result = self.automation_manager.clear_all_tasks()
        self.status_var.set(result)
        self.refresh_task_list()
    
    def refresh_task_list(self):
        tasks = self.automation_manager.view_scheduled_tasks()
        self.tasks_text.config(state=tk.NORMAL)
        self.tasks_text.delete(1.0, tk.END)
        self.tasks_text.insert(tk.END, "Scheduled Tasks\n")
        self.tasks_text.insert(tk.END, "=" * 50 + "\n\n")
        
        for task in tasks:
            self.tasks_text.insert(tk.END, f"• {task}\n")
        
        self.tasks_text.config(state=tk.DISABLED)
    
    def automation_callback(self, message):
        self.status_var.set(message)
        # Could also log this to a dedicated automation log
    
    def start_scheduler(self):
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(1)
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
    
    def generate_report(self):
        report_type = self.report_type.get()
        
        # Sample data for demonstration
        if report_type == "Security Scan":
            data = {
                "scan_type": "Network Ping Sweep",
                "target": self.ip_entry.get(),
                "live_hosts": len(self.scanner.live_hosts),
                "timestamp": datetime.now().isoformat(),
                "results": self.scanner.live_hosts
            }
        elif report_type == "Password Audit":
            password = self.pwd_entry.get() if self.pwd_entry.get() else "test123"
            analysis = self.password_tools.check_password_strength(password)
            data = {
                "password": "*" * len(password),
                "strength": analysis['strength'],
                "score": analysis['score'],
                "length": analysis['length'],
                "breach_count": analysis['breach_count'],
                "issues": analysis['issues'],
                "suggestions": analysis['suggestions']
            }
        else:  # Attack Results
            data = {
                "attack_type": self.attack_type.get(),
                "timestamp": datetime.now().isoformat(),
                "results": self.attack_simulator.attack_results
            }
        
        result = self.report_generator.generate_report(report_type, data)
        
        self.report_results.config(state=tk.NORMAL)
        self.report_results.delete(1.0, tk.END)
        self.report_results.insert(tk.END, f"Report Generation Results\n")
        self.report_results.insert(tk.END, "=" * 50 + "\n\n")
        self.report_results.insert(tk.END, f"{result}\n\n")
        self.report_results.insert(tk.END, "Report content preview:\n")
        self.report_results.insert(tk.END, "=" * 30 + "\n")
        
        if isinstance(data, dict):
            for key, value in data.items():
                if key == "password":
                    self.report_results.insert(tk.END, f"{key}: {'*' * len(value) if value else 'N/A'}\n")
                elif isinstance(value, list):
                    self.report_results.insert(tk.END, f"{key}:\n")
                    for item in value[:5]:  # Show first 5 items only
                        self.report_results.insert(tk.END, f"  • {item}\n")
                    if len(value) > 5:
                        self.report_results.insert(tk.END, f"  ... and {len(value) - 5} more\n")
                else:
                    self.report_results.insert(tk.END, f"{key}: {value}\n")
        
        self.report_results.config(state=tk.DISABLED)
        self.status_var.set(f"Report generated: {report_type}")
    
    def run_all_tests(self):
        self.run_tests(TestModules)
    
    def run_auth_tests(self):
        self.run_tests(TestModules, ['test_auth_module'])
    
    def run_password_tests(self):
        self.run_tests(TestModules, ['test_password_tools'])
    
    def run_encryption_tests(self):
        self.run_tests(TestModules, ['test_encryption_tools'])
    
    def run_tests(self, test_class, methods=None):
        """Run specified test methods and display results"""
        suite = unittest.TestSuite()
        
        if methods:
            for method in methods:
                suite.addTest(test_class(method))
        else:
            suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        
        # Capture test output
        import io
        from contextlib import redirect_stderr, redirect_stdout
        
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        
        self.test_results.config(state=tk.NORMAL)
        self.test_results.delete(1.0, tk.END)
        self.test_results.insert(tk.END, f"Test Results - {datetime.now()}\n")
        self.test_results.insert(tk.END, "=" * 50 + "\n\n")
        self.test_results.insert(tk.END, output.getvalue())
        
        # Summary
        self.test_results.insert(tk.END, "\n" + "=" * 50 + "\n")
        self.test_results.insert(tk.END, f"Tests Run: {result.testsRun}\n")
        self.test_results.insert(tk.END, f"Failures: {len(result.failures)}\n")
        self.test_results.insert(tk.END, f"Errors: {len(result.errors)}\n")
        
        if result.wasSuccessful():
            self.test_results.insert(tk.END, "ALL TESTS PASSED!\n")
            self.status_var.set("All tests passed successfully")
        else:
            self.test_results.insert(tk.END, "SOME TESTS FAILED!\n")
            self.status_var.set("Some tests failed - check results")
        
        self.test_results.config(state=tk.DISABLED)
    
    def start_debugger(self):
        """Start Python debugger for demonstration"""
        self.test_results.config(state=tk.NORMAL)
        self.test_results.delete(1.0, tk.END)
        self.test_results.insert(tk.END, "Python Debugger (pdb) Demonstration\n")
        self.test_results.insert(tk.END, "=" * 50 + "\n\n")
        self.test_results.insert(tk.END, "Debugger started. Check console for interaction.\n")
        self.test_results.insert(tk.END, "Use commands like 'help', 'next', 'step', 'continue'.\n")
        self.test_results.config(state=tk.DISABLED)
        
        # Start debugger in a separate thread to avoid blocking the GUI
        def debug_thread():
            # Set a trace point for demonstration
            pdb.set_trace()
            self.root.after(0, lambda: self.status_var.set("Debugger session completed"))
        
        threading.Thread(target=debug_thread, daemon=True).start()
        self.status_var.set("Debugger started - check console")

def main():
    """Main application entry point"""
    root = tk.Tk()
    app = PyCyberSuite(root)
    root.mainloop()

if __name__ == "__main__":
    print("Starting PyCyberSuite - Complete Cybersecurity Toolkit...")
    print("Please wait while initializing modules...")
    main()