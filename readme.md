# Secure Data Hiding in Images Using Steganography

## 📌 Introduction
With the rise of digital communication, ensuring data security and privacy has become a major concern. This project combines **steganography** and **encryption** to securely hide secret messages within images, making them undetectable while maintaining image quality.

## 🔥 Features
- **Dual-layer security** – Encrypts messages before hiding them in images.
- **Lossless Data Hiding** – Ensures minimal distortion to the image.
- **Password Protection** – Uses a secure key derived from a password.
- **Stealth & Security** – Makes messages resistant to detection and tampering.
- **User-friendly Interface** – Simple command-line menu for encoding and decoding messages.

## 🛠️ Technologies Used
- **Programming Language**: Python
- **Libraries**:
    - `OpenCV` – For image processing
    - `NumPy` – For array operations
    - `Cryptography` (Fernet, PBKDF2HMAC) – For encryption and secure key derivation
    - `Base64` – For safe encoding of cryptographic keys
    - `OS` – For file handling

## 🚀 Installation & Setup
### Prerequisites
Make sure you have Python installed. Then, install the required dependencies:
```sh
pip install opencv-python numpy cryptography
```

### Running the Project
1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/Image-Steganography.git
   cd Image-Steganography
   ```
2. Run the script:
   ```sh
   python steganography.py
   ```

## 📷 How It Works
### Encoding a Message
1. Choose an image file.
2. Enter the secret message.
3. Provide a password for encryption.
4. The encrypted message is embedded into the image, and a new **encoded image** is saved.

### Decoding a Message
1. Select the encoded image.
2. Enter the correct password.
3. The hidden message is extracted and decrypted.

## 🛡️ Security Mechanism
- **PBKDF2HMAC**: Derives a secure encryption key from the user-provided password.
- **Fernet Encryption**: Ensures confidentiality before embedding the message in an image.
- **Least Significant Bit (LSB) Encoding**: Hides message bits in image pixels without noticeable distortion.

## 🏆 Future Enhancements
- **Support for Multiple File Types** – Extend steganography to audio and video.
- **AI-powered Steganalysis Resistance** – Improve stealth against detection algorithms.
- **Cross-Platform Application** – Develop GUI and mobile versions.

## 🤝 Contributing
Contributions are welcome! Feel free to fork the repository and submit a pull request.
