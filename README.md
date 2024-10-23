# File Storage System Hybrid Crypto
Creating a Secure File Storage Using Hybrid Cryptography project involves combining symmetric and asymmetric encryption to ensure secure file storage and transmission. The following steps will guide you through setting up the project and include code snippets in Python using the PyCryptodome library for cryptography.

**1. Project Planning and Requirements**

**Objective:** Securely store files by encrypting the file content using symmetric encryption (AES) and encrypting the symmetric key using asymmetric encryption (RSA).
**Key Features:**
File encryption and decryption using hybrid cryptography.
Secure key exchange using RSA.
File integrity check using hashing (SHA-256).
Integration with cloud storage for file uploads (e.g., AWS S3, Google Cloud Storage).
**Technology Stack:**
**Programming Language:** Python.
**Cryptographic Libraries:** PyCryptodome.
**Cloud Storage:** AWS S3 (or any cloud provider).
**Authentication:** Optional user login mechanism.

**2. Set Up Development Environment**

**Install necessary Python packages:**
```bash
pip install pycryptodome boto3
Install AWS CLI and configure it if you plan to use AWS S3 for cloud storage:
```

```bash
pip install awscli
aws configure
```

**3. Hybrid Cryptography Workflow**

**Symmetric Encryption (AES):** Used to encrypt the file data.
**Asymmetric Encryption (RSA):** Used to encrypt the AES key.
**Hashing (SHA-256):** Used to verify file integrity after decryption.

**4. Code Implementation**

**A. Generate RSA Keys**
RSA keys are used to securely encrypt and decrypt the AES key.

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_rsa_keys():
    # Generate a new RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save the keys to files
    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("RSA Key Pair Generated")

generate_rsa_keys()
```

**B. Symmetric File Encryption (AES)**
Encrypt the file content using AES and encrypt the AES key using RSA.

```python
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import sha256

def encrypt_file(file_path, public_key_path):
    # Read file data
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Generate a random AES key
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    # Encrypt the AES key with RSA public key
    with open(public_key_path, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Save the encrypted file
    with open(file_path + ".enc", 'wb') as enc_file:
        enc_file.write(cipher_aes.nonce)
        enc_file.write(encrypted_aes_key)
        enc_file.write(tag)
        enc_file.write(ciphertext)

    print(f"File '{file_path}' encrypted successfully.")

encrypt_file("example.txt", "public.pem")
```

**C. File Decryption**
Decrypt the file by decrypting the AES key using the RSA private key, then decrypt the file data using the AES key.

```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_file(file_path_enc, private_key_path):
    with open(file_path_enc, 'rb') as enc_file:
        nonce = enc_file.read(16)
        encrypted_aes_key = enc_file.read(256)
        tag = enc_file.read(16)
        ciphertext = enc_file.read()

    # Decrypt the AES key with RSA private key
    with open(private_key_path, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt the file data using AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Save the decrypted file
    with open(file_path_enc.replace(".enc", ".dec"), 'wb') as dec_file:
        dec_file.write(decrypted_data)

    print(f"File '{file_path_enc}' decrypted successfully.")

decrypt_file("example.txt.enc", "private.pem")
```

**D. File Integrity Check (SHA-256 Hashing)**
After decryption, verify file integrity by comparing hashes of the original and decrypted files.

```python
def calculate_file_hash(file_path):
    hash_sha256 = sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)

    return hash_sha256.hexdigest()
```

**Compare original and decrypted file hashes**
```
original_hash = calculate_file_hash("example.txt")
decrypted_hash = calculate_file_hash("example.txt.dec")

if original_hash == decrypted_hash:
    print("File integrity verified. Hashes match.")
else:
    print("File integrity compromised. Hashes do not match.")
**E. Upload Encrypted File to Cloud Storage (AWS S3)**
Use boto3 to upload the encrypted file to AWS S3.
```

```python
import boto3

def upload_to_s3(file_name, bucket_name):
    s3 = boto3.client('s3')
    try:
        s3.upload_file(file_name, bucket_name, file_name)
        print(f"File '{file_name}' uploaded to S3 bucket '{bucket_name}'.")
    except Exception as e:
        print(f"Failed to upload file: {str(e)}")

upload_to_s3("example.txt.enc", "my-secure-bucket")
**F. Download Encrypted File from Cloud Storage**
Download the encrypted file back from AWS S3.
```

```python
def download_from_s3(file_name, bucket_name):
    s3 = boto3.client('s3')
    try:
        s3.download_file(bucket_name, file_name, file_name)
        print(f"File '{file_name}' downloaded from S3 bucket '{bucket_name}'.")
    except Exception as e:
        print(f"Failed to download file: {str(e)}")

download_from_s3("example.txt.enc", "my-secure-bucket")
```

**5. Testing and Validation**

**Test Encryption and Decryption:** Run the encryption and decryption processes and verify that the file is encrypted and decrypted correctly.
**Integrity Check:** Ensure that the file integrity is maintained by comparing the original and decrypted file hashes.
**Cloud Storage Integration:** Upload and download files to/from AWS S3 and verify that the process works smoothly.

**6. Security Considerations**

**Encryption Key Protection:** Ensure the RSA private key is securely stored and not exposed.
**Data in Transit and Rest:** Use HTTPS for communication with the cloud (e.g., S3) to ensure secure data transmission.
**User Authentication:** Implement user authentication if the system is used in a multi-user environment.

**7. Enhancements**

**User Authentication:** Add login functionality for multiple users using JWT tokens for authentication and authorization.
**GUI:** Create a web or desktop interface using frameworks like Flask (for web) or Tkinter (for desktop) to make the system more user-friendly.
**Cloud Storage Alternatives:** Integrate with other cloud storage providers like Google Cloud Storage or Azure Blob Storage.

By following these steps and implementing the code snippets provided, you can create a Secure File Storage System using Hybrid Cryptography with encryption, decryption, and cloud integration features.
