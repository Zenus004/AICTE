import base64
import os

import cv2
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class ImageSteganography:
    def __init__(self):
        self.delimiter = "$$END$$"  # Message end marker

    def generate_key(self, password: str) -> bytes:
        """Generate encryption key from password using PBKDF2."""
        salt = b'salt_123'  # In production, use random salt and store it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_message(self, message: str, password: str) -> bytes:
        """Encrypt the message using Fernet encryption."""
        key = self.generate_key(password)
        f = Fernet(key)
        return f.encrypt(message.encode())

    def decrypt_message(self, encrypted_message: bytes, password: str) -> str:
        """Decrypt the message using Fernet encryption."""
        key = self.generate_key(password)
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode()

    def can_encode_message(self, image: np.ndarray, message_length: int) -> bool:
        """Check if the image is large enough to encode the message."""
        max_bytes = (image.shape[0] * image.shape[1] * 3) // 8
        return message_length + len(self.delimiter) <= max_bytes

    def encode_message(self, image_path: str, message: str, password: str) -> bool:
        """Encode an encrypted message into an image."""
        try:
            # Read the image
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Image not found or invalid format")

            # Encrypt the message
            encrypted_message = self.encrypt_message(message, password)
            message_to_hide = encrypted_message + self.delimiter.encode()

            if not self.can_encode_message(img, len(message_to_hide)):
                raise ValueError("Message too large for this image")

            # Convert message to binary
            binary_message = ''.join(format(byte, '08b') for byte in message_to_hide)

            # Flatten the image and modify LSBs
            data_idx = 0
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(3):
                        if data_idx < len(binary_message):
                            img[i, j, k] = (img[i, j, k] & 254) | int(binary_message[data_idx])
                            data_idx += 1

            # Save the encoded image as PNG (lossless format)
            output_path = "encoded_" + os.path.splitext(os.path.basename(image_path))[0] + ".png"
            cv2.imwrite(output_path, img)
            print(f"Encoded image saved as: {output_path}")
            return True

        except Exception as e:
            print(f"Error during encoding: {str(e)}")
            return False

    def decode_message(self, image_path: str, password: str) -> str:
        """Decode and decrypt a message from an image."""
        try:
            # Read the image
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Image not found or invalid format")

            binary_message = ""
            decoded_bytes = bytearray()

            # Extract LSBs
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(3):
                        binary_message += str(img[i, j, k] & 1)
                        if len(binary_message) >= 8:
                            decoded_bytes.append(int(binary_message[:8], 2))
                            binary_message = binary_message[8:]

                            # Check for delimiter
                            if decoded_bytes.endswith(self.delimiter.encode()):
                                encrypted_message = bytes(decoded_bytes[:-len(self.delimiter)])
                                # Check if the token is bytes
                                if not isinstance(encrypted_message, bytes):
                                    raise TypeError("Extracted token is not bytes.")

                                # Decrypt and return the message
                                return self.decrypt_message(encrypted_message, password)

            raise ValueError("No hidden message found")

        except Exception as e:
            print(f"Error during decoding: {str(e)}")
            return ""


def main():
    stego = ImageSteganography()

    while True:
        print("\nImage Steganography Menu:")
        print("1. Encode message")
        print("2. Decode message")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            image_path = input("Enter image path: ").strip()

            # Check if image exists
            if not os.path.exists(image_path):
                print("Error: Image file does not exist. Check the path and try again.")
                continue

            message = input("Enter secret message: ")
            password = input("Enter password: ")

            if stego.encode_message(image_path, message, password):
                print("Message encoded successfully!")
            else:
                print("Failed to encode message.")

        elif choice == '2':
            image_path = input("Enter image path: ").strip()

            # Check if image exists
            if not os.path.exists(image_path):
                print("Error: Image file does not exist. Check the path and try again.")
                continue

            password = input("Enter password: ")

            decoded_message = stego.decode_message(image_path, password)
            if decoded_message:
                print(f"Decoded message: {decoded_message}")
            else:
                print("Failed to decode message.")

        elif choice == '3':
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
