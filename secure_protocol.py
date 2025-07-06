import json
import logging
from crypto_utils import CryptoManager

class SecureProtocol:
    """
    Implements the secure protocol for music file transmission.
    Đảm bảo đúng đặc tả:
    - Mã hóa file: Triple DES
    - Metadata: DES
    - Ký số: RSA/SHA-512
    - Trao khóa: RSA 1024-bit OAEP SHA-512
    - Kiểm tra toàn vẹn: SHA-512(IV || ciphertext)
    """
    def __init__(self, crypto_manager):
        self.crypto = crypto_manager

    def create_secure_package(self, file_content, metadata, receiver_public_key_pem):
        """
        Đóng gói gói tin bảo mật đúng đặc tả.
        - file_content: bytes
        - metadata: dict (vd: {'filename': ..., 'copyright': ...})
        - receiver_public_key_pem: PEM string
        """
        receiver_public_key = self.crypto.load_public_key_from_pem(receiver_public_key_pem)
        return self.crypto.create_secure_package(file_content, metadata, receiver_public_key)

    def verify_and_decrypt_package(self, package, sender_public_key=None):
        """
        Giải mã, xác thực, kiểm tra toàn vẹn gói tin nhận được đúng đặc tả.
        - package: dict (nhận từ phía gửi)
        - sender_public_key: public key của sender (PEM hoặc object), nếu cần xác thực chữ ký
        """
        return self.crypto.verify_and_decrypt_package(package, sender_public_key)

    def create_handshake_message(self, message_type):
        """
        Tạo handshake message đúng format:
        - 'hello': {'message': 'Hello!', 'timestamp': ...}
        - 'ready': {'message': 'Ready!', 'timestamp': ..., 'public_key': ...}
        """
        if message_type == "hello":
            return {"message": "Hello!", "timestamp": self._get_timestamp()}
        elif message_type == "ready":
            return {
                "message": "Ready!",
                "timestamp": self._get_timestamp(),
                "public_key": self.crypto.get_public_key_pem()
            }
        else:
            raise ValueError("Invalid handshake message type")

    def create_ack_message(self, success=True, details=None):
        """
        Tạo ACK/NACK đúng format:
        - ACK: {'status': 'ACK', 'message': ..., 'timestamp': ..., 'details': ...}
        - NACK: {'status': 'NACK', 'message': ..., 'error': ..., 'timestamp': ...}
        """
        if success:
            return {
                "status": "ACK",
                "message": "File received and verified successfully",
                "timestamp": self._get_timestamp(),
                "details": details or {}
            }
        else:
            return {
                "status": "NACK",
                "message": "File verification failed",
                "error": details or "Unknown error",
                "timestamp": self._get_timestamp()
            }

    def _get_timestamp(self):
        import time
        return int(time.time())
