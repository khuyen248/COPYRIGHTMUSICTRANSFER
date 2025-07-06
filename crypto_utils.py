import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.backends import default_backend
import logging
import pyDes

class CryptoManager:
    """Handles all cryptographic operations for the secure music transmission system"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self._generate_rsa_keys()
        
    def _generate_rsa_keys(self):
        """Generate RSA 2048-bit key pair"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            logging.info("RSA 2048-bit key pair generated successfully")
        except Exception as e:
            logging.error(f"RSA key generation failed: {str(e)}")
            raise
    
    def get_public_key_pem(self):
        """Get public key in PEM format for transmission"""
        try:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode('utf-8')
        except Exception as e:
            logging.error(f"Public key serialization failed: {str(e)}")
            raise
    
    def load_public_key_from_pem(self, pem_data):
        """Load public key from PEM format"""
        try:
            if isinstance(pem_data, str):
                pem_data = pem_data.encode('utf-8')
            public_key = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend()
            )
            # Extra validation: check key size
            if hasattr(public_key, 'key_size') and public_key.key_size != 2048:
                logging.error(f"Loaded public key is not 2048 bits, got {public_key.key_size} bits")
                raise ValueError("Receiver public key must be 2048 bits (RSA)")
            return public_key
        except Exception as e:
            logging.error(f"Public key loading failed: {str(e)}. PEM: {pem_data[:40]}...")
            raise
    
    def generate_session_key(self):
        """Generate 192-bit (24 bytes) session key for Triple DES"""
        return os.urandom(24)
    
    def generate_des_key(self):
        """Generate 64-bit (8 bytes) key for DES"""
        return os.urandom(8)
    
    def generate_iv(self):
        """Generate 64-bit (8 bytes) IV for DES/Triple DES"""
        return os.urandom(8)
    
    def encrypt_with_rsa_oaep(self, data, public_key):
        """Encrypt data using RSA with OAEP padding and SHA-512"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            # Extra validation: check key size
            if hasattr(public_key, 'key_size') and public_key.key_size != 2048:
                logging.error(f"Encryption public key is not 2048 bits, got {public_key.key_size} bits")
                raise ValueError("Encryption public key must be 2048 bits (RSA)")
            ciphertext = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            logging.error(f"RSA OAEP encryption failed: {str(e)}. Data len: {len(data)} bytes. Public key: {getattr(public_key, 'key_size', 'unknown')} bits.")
            raise
    
    def decrypt_with_rsa_oaep(self, ciphertext):
        """Decrypt data using RSA with OAEP padding and SHA-512"""
        try:
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            logging.error(f"RSA OAEP decryption failed: {str(e)}")
            raise
    
    def sign_with_rsa_sha512(self, data):
        """Sign data using RSA with SHA-512"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return signature
        except Exception as e:
            logging.error(f"RSA SHA-512 signing failed: {str(e)}")
            raise
    
    def verify_rsa_sha512_signature(self, data, signature, public_key):
        """Verify RSA signature with SHA-512"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            # Fix: If public_key is a string (PEM), load it
            if isinstance(public_key, str):
                public_key = self.load_public_key_from_pem(public_key)
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return True
        except Exception as e:
            logging.error(f"RSA SHA-512 signature verification failed: {str(e)}")
            return False
    
    def encrypt_with_triple_des(self, data, key, iv):
        """Encrypt data using Triple DES in CBC mode"""
        try:
            # Ensure key is 24 bytes for Triple DES
            if len(key) != 24:
                raise ValueError("Triple DES key must be 24 bytes")
            
            # Pad data to be multiple of 8 bytes (DES block size)
            padding_length = 8 - (len(data) % 8)
            if padding_length != 8:
                data += bytes([padding_length] * padding_length)
            else:
                data += bytes([8] * 8)
            
            cipher = Cipher(
                TripleDES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            return ciphertext
        except Exception as e:
            logging.error(f"Triple DES encryption failed: {str(e)}")
            raise
    
    def decrypt_with_triple_des(self, ciphertext, key, iv):
        """Decrypt data using Triple DES in CBC mode"""
        try:
            if len(key) != 24:
                raise ValueError("Triple DES key must be 24 bytes")
            
            cipher = Cipher(
                TripleDES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_data[-1]
            if padding_length > 8:
                raise ValueError("Invalid padding")
            
            data = padded_data[:-padding_length]
            return data
        except Exception as e:
            logging.error(f"Triple DES decryption failed: {str(e)}")
            raise
    
    def encrypt_with_des(self, data, key, iv):
        """Encrypt data using DES in CBC mode (dùng pyDes)"""
        try:
            if len(key) != 8:
                raise ValueError("DES key must be 8 bytes")
            if len(iv) != 8:
                raise ValueError("DES IV must be 8 bytes")
            # Pad data to 8 bytes
            padding_length = 8 - (len(data) % 8)
            data += bytes([padding_length] * padding_length)
            des = pyDes.des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_NORMAL)
            return des.encrypt(data)
        except Exception as e:
            logging.error(f"DES encryption failed: {str(e)}")
            raise

    def decrypt_with_des(self, ciphertext, key, iv):
        """Decrypt data using DES in CBC mode (dùng pyDes)"""
        try:
            if len(key) != 8:
                raise ValueError("DES key must be 8 bytes")
            if len(iv) != 8:
                raise ValueError("DES IV must be 8 bytes")
            des = pyDes.des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_NORMAL)
            data = des.decrypt(ciphertext)
            padding_length = data[-1]
            if padding_length > 8:
                raise ValueError("Invalid padding")
            return data[:-padding_length]
        except Exception as e:
            logging.error(f"DES decryption failed: {str(e)}")
            raise
    
    def calculate_sha512_hash(self, data):
        """Calculate SHA-512 hash of data"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            hash_obj = hashlib.sha512()
            hash_obj.update(data)
            return hash_obj.hexdigest()
        except Exception as e:
            logging.error(f"SHA-512 hashing failed: {str(e)}")
            raise
    
    def encode_base64(self, data):
        """Encode data to base64 string"""
        try:
            return base64.b64encode(data).decode('utf-8')
        except Exception as e:
            logging.error(f"Base64 encoding failed: {str(e)}")
            raise
    
    def decode_base64(self, data):
        """Decode base64 string to bytes"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return base64.b64decode(data)
        except Exception as e:
            logging.error(f"Base64 decoding failed: {str(e)}")
            raise
    
    def create_secure_package(self, file_bytes, meta_dict, receiver_public_key):
        """
        Tạo gói tin mã hóa và ký số đúng đặc tả:
        - Mã hóa file bằng Triple DES
        - Mã hóa metadata bằng DES
        - Ký metadata bằng RSA/SHA-512
        - Mã hóa session key bằng RSA OAEP
        - Tính hash SHA-512(IV || ciphertext)
        - Trả về dict đúng format
        """
        # 1. Sinh khóa và IV
        session_key = self.generate_session_key()  # 24 bytes cho Triple DES
        des_key = self.generate_des_key()          # 8 bytes cho DES
        iv = self.generate_iv()                    # 8 bytes cho DES/3DES

        # 2. Mã hóa file bằng Triple DES
        cipher_bytes = self.encrypt_with_triple_des(file_bytes, session_key, iv)

        # 3. Mã hóa metadata bằng DES
        import json
        meta_json = json.dumps(meta_dict, ensure_ascii=False).encode('utf-8')
        meta_cipher = self.encrypt_with_des(meta_json, des_key, iv)

        # 4. Ký metadata (dạng json) bằng RSA/SHA-512
        sig = self.sign_with_rsa_sha512(meta_json)

        # 5. Mã hóa session key (Triple DES) bằng RSA OAEP
        session_key_package = session_key + des_key  # Gửi cả 2 khóa
        encrypted_session_key = self.encrypt_with_rsa_oaep(session_key_package, receiver_public_key)

        # 6. Tính hash SHA-512(IV || ciphertext)
        hash_input = iv + cipher_bytes
        hash_hex = self.calculate_sha512_hash(hash_input)

        # 7. Đóng gói
        package = {
            "iv": self.encode_base64(iv),
            "cipher": self.encode_base64(cipher_bytes),
            "meta": self.encode_base64(meta_cipher),
            "hash": hash_hex,
            "sig": self.encode_base64(sig),
            "key": self.encode_base64(encrypted_session_key)
        }
        return package

    def verify_and_decrypt_package(self, package, sender_public_key=None):
        """
        Giải mã, xác thực, kiểm tra toàn vẹn gói tin nhận được đúng đặc tả:
        - Giải mã session key bằng RSA OAEP
        - Giải mã file bằng Triple DES
        - Giải mã metadata bằng DES
        - Kiểm tra hash SHA-512(IV || ciphertext)
        - Kiểm tra chữ ký metadata
        - Trả về (file_bytes, meta_dict) nếu hợp lệ, lỗi thì raise Exception
        """
        # 1. Giải mã session key
        iv = self.decode_base64(package["iv"])
        cipher_bytes = self.decode_base64(package["cipher"])
        meta_cipher = self.decode_base64(package["meta"])
        sig = self.decode_base64(package["sig"])
        encrypted_session_key = self.decode_base64(package["key"])
        hash_hex = package["hash"]

        session_key_package = self.decrypt_with_rsa_oaep(encrypted_session_key)
        session_key = session_key_package[:24]
        des_key = session_key_package[24:32]

        # 2. Kiểm tra hash
        hash_input = iv + cipher_bytes
        calc_hash = self.calculate_sha512_hash(hash_input)
        if calc_hash != hash_hex:
            raise Exception("Integrity check failed: hash mismatch")

        # 3. Giải mã file
        file_bytes = self.decrypt_with_triple_des(cipher_bytes, session_key, iv)

        # 4. Giải mã metadata
        meta_json = self.decrypt_with_des(meta_cipher, des_key, iv)
        import json
        meta_dict = json.loads(meta_json.decode('utf-8'))

        # 5. Kiểm tra chữ ký
        if sender_public_key is not None:
            if not self.verify_rsa_sha512_signature(meta_json, sig, sender_public_key):
                raise Exception("Signature verification failed")

        return file_bytes, meta_dict
