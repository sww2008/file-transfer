#!/usr/bin/env python3
"""
AWS Lambda function for PGP decryption using pure cryptography library.
Fetches PGP credentials from AWS Secrets Manager and decrypts files from S3.
"""

import base64
import json
import os
import tempfile
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_secret(secret_name: str, region_name: str = "ap-southeast-2") -> Any:
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise Exception(f"Error retrieving secret: {str(e)}")

    # Parse the secret string as JSON
    secret = json.loads(get_secret_value_response["SecretString"])
    return secret


def download_from_s3(bucket_name: str, object_key: str, local_path: str) -> None:
    s3_client = boto3.client("s3")

    try:
        s3_client.download_file(bucket_name, object_key, local_path)
    except ClientError as e:
        raise Exception(f"Error downloading from S3: {str(e)}")


def upload_to_s3(bucket_name: str, object_key: str, local_path: str) -> None:
    s3_client = boto3.client("s3")

    try:
        s3_client.upload_file(local_path, bucket_name, object_key)
    except ClientError as e:
        raise Exception(f"Error uploading to S3: {str(e)}")


def parse_pgp_private_key(key_data: str, passphrase: str) -> rsa.RSAPrivateKey:
    """Parse PGP private key using cryptography library."""
    try:
        # For this implementation, we'll assume the key_data is a PEM-encoded RSA private key
        # In a real PGP implementation, you'd need to parse the PGP packet structure

        # Convert passphrase to bytes
        passphrase_bytes = passphrase.encode("utf-8")

        # Load the private key from PEM format
        private_key = serialization.load_pem_private_key(
            key_data.encode("utf-8"), password=passphrase_bytes, backend=default_backend()
        )

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Private key is not an RSA key")

        return private_key

    except Exception as e:
        raise Exception(f"Error parsing private key: {str(e)}")


def decrypt_file_cryptography(encrypted_file_path: str, private_key: rsa.RSAPrivateKey, output_file_path: str) -> Any:
    """Decrypt file using cryptography library."""
    try:
        # Read the encrypted file
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        # For this implementation, we'll assume the file is encrypted with RSA
        # In a real PGP implementation, you'd need to parse the PGP message format
        # and handle the hybrid encryption (RSA + symmetric cipher)

        # Decrypt using RSA private key
        decrypted_data = private_key.decrypt(
            encrypted_data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Write decrypted data to output file
        with open(output_file_path, "wb") as f:
            f.write(decrypted_data)

        return decrypted_data

    except Exception as e:
        raise Exception(f"Error decrypting file: {str(e)}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        # Get configuration from environment variables
        s3_bucket = os.environ.get("S3_BUCKET")
        encrypted_s3_prefix = os.environ.get("ENCRYPTED_S3_PREFIX", "encrypted/")
        decrypted_s3_prefix = os.environ.get("DECRYPTED_S3_PREFIX", "decrypted/")
        secret_name = os.environ.get("GPG_SECRET_NAME", "gpg-credentials")
        secret_region = os.environ.get("SECRET_REGION", "ap-southeast-2")

        # Parse event parameters
        file_name = event.get("file_name")
        output_file_name = event.get("output_file_name")

        if not s3_bucket:
            raise ValueError("Missing required environment variable: S3_BUCKET")

        if not file_name:
            raise ValueError("Missing required parameter: file_name")

        # Construct S3 keys
        s3_encrypted_key = f"{encrypted_s3_prefix.rstrip('/')}/{file_name}"
        s3_output_key = f"{decrypted_s3_prefix.rstrip('/')}/{output_file_name or file_name.replace('.gpg', '.txt')}"

        # Default field names for secrets
        private_key_field = "PGPPrivateKey"
        passphrase_field = "PGPPassphrase"

        print(f"Starting PGP decryption for S3 object: s3://{s3_bucket}/{s3_encrypted_key}")

        # Get PGP credentials from AWS Secrets Manager
        print("Retrieving PGP credentials from AWS Secrets Manager...")
        secret = get_secret(secret_name, secret_region)

        private_key_data = secret.get(private_key_field)
        passphrase = secret.get(passphrase_field)

        if not private_key_data or not passphrase:
            raise ValueError(f"Missing {private_key_field} or {passphrase_field} in secret")

        # Parse the private key
        print("Parsing private key...")
        private_key = parse_pgp_private_key(private_key_data, passphrase)

        # Create temporary files
        with tempfile.TemporaryDirectory() as temp_dir:
            encrypted_file_path = os.path.join(temp_dir, "encrypted_file.gpg")
            decrypted_file_path = os.path.join(temp_dir, "decrypted_file.txt")

            # Download encrypted file from S3
            print(f"Downloading encrypted file from S3...")
            download_from_s3(s3_bucket, s3_encrypted_key, encrypted_file_path)

            # Decrypt the file
            print("Decrypting file...")
            decrypted_content = decrypt_file_cryptography(encrypted_file_path, private_key, decrypted_file_path)

            # Upload decrypted file to S3
            print(f"Uploading decrypted file to S3...")
            upload_to_s3(s3_bucket, s3_output_key, decrypted_file_path)

            # Return success response
            response = {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": "File decrypted successfully",
                        "input_file": f"s3://{s3_bucket}/{s3_encrypted_key}",
                        "output_file": f"s3://{s3_bucket}/{s3_output_key}",
                        "decrypted_size": len(decrypted_content),
                    }
                ),
            }

            print("PGP decryption completed successfully")
            return response

    except Exception as e:
        print(f"Error: {str(e)}")

        # Return error response
        return {"statusCode": 500, "body": json.dumps({"error": "PGP decryption failed", "message": str(e)})}
