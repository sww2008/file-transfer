#!/usr/bin/env python3
"""
AWS Lambda function for PGP decryption using pgpy library.
Fetches PGP credentials from AWS Secrets Manager and decrypts files from S3.
"""

import json
import os
import tempfile
import warnings
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError
from pgpy import PGPKey, PGPMessage

# Suppress cryptography deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")


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


def decrypt_file_pgpy(encrypted_file_path: str, private_key_data: str, passphrase: str, output_file_path: str) -> Any:
    """Decrypt PGP file using pgpy library with memory optimization and error handling."""
    try:
        # Parse the private key
        private_key, _ = PGPKey.from_blob(private_key_data)

        # Unlock the private key with passphrase
        with private_key.unlock(passphrase):
            # Read the encrypted file
            with open(encrypted_file_path, "rb") as f:
                encrypted_data = f.read()

            print(f"Encrypted file size: {len(encrypted_data)} bytes")

            # Try different approaches to handle the PGP message
            try:
                # Method 1: Direct message parsing
                message = PGPMessage.from_blob(encrypted_data)
                print("Successfully parsed PGP message")
                
                # Decrypt the message
                decrypted_message = private_key.decrypt(message)
                print("Successfully decrypted message")
                
            except Exception as parse_error:
                print(f"Direct parsing failed: {str(parse_error)}")
                
                # Method 2: Try to handle as raw data
                try:
                    # Create a new message from raw data
                    message = PGPMessage()
                    message.parse(encrypted_data)
                    print("Successfully parsed using alternative method")
                    
                    # Decrypt the message
                    decrypted_message = private_key.decrypt(message)
                    print("Successfully decrypted using alternative method")
                    
                except Exception as alt_error:
                    print(f"Alternative parsing failed: {str(alt_error)}")
                    
                    # Method 3: Try to extract data directly
                    try:
                        # Look for literal data packets
                        from pgpy.packet.types import LiteralData
                        
                        # Try to find literal data in the message
                        message = PGPMessage.from_blob(encrypted_data)
                        
                        # Get the raw message data
                        if hasattr(message, 'message') and message.message:
                            decrypted_data = message.message
                        else:
                            # Try to extract from packets
                            for packet in message:
                                if isinstance(packet, LiteralData):
                                    decrypted_data = packet.data
                                    break
                            else:
                                raise Exception("No literal data found in message")
                        
                        decrypted_message = type('DecryptedMessage', (), {'message': decrypted_data})()
                        print("Successfully extracted data using packet inspection")
                        
                    except Exception as extract_error:
                        print(f"Packet extraction failed: {str(extract_error)}")
                        raise Exception(f"All decryption methods failed. Last error: {str(extract_error)}")

            # Write decrypted data to output file
            with open(output_file_path, "wb") as f:
                f.write(decrypted_message.message)

            print(f"Decrypted data size: {len(decrypted_message.message)} bytes")

            # Clear variables to free memory
            del encrypted_data
            del message
            
            return decrypted_message.message

    except Exception as e:
        print(f"Decryption error details: {str(e)}")
        print(f"Error type: {type(e)}")
        raise Exception(f"Error decrypting file with PGPy: {str(e)}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        # Get configuration from environment variables
        s3_bucket = os.environ.get("S3_BUCKET")
        encrypted_s3_prefix = os.environ.get("ENCRYPTED_S3_PREFIX", "encrypted/")
        decrypted_s3_prefix = os.environ.get("DECRYPTED_S3_PREFIX", "decrypted/")
        secret_name = os.environ.get("GPG_SECRET_NAME", "gpg-credentials")
        secret_region = os.environ.get("SECRET_REGION", "ap-southeast-2")

        # Handle S3 event structure
        if "Records" in event:
            # S3 event structure
            records = event["Records"]
            if not records:
                raise ValueError("No records found in S3 event")
            
            s3_record = records[0]
            if "s3" not in s3_record:
                raise ValueError("Invalid S3 event structure")
            
            # Extract bucket and object key from S3 event
            bucket_name = s3_record["s3"]["bucket"]["name"]
            object_key = s3_record["s3"]["object"]["key"]
            
            # Use bucket from event if S3_BUCKET env var not set
            if not s3_bucket:
                s3_bucket = bucket_name
            
            # Extract file name from object key
            file_name = os.path.basename(object_key)
            
            # Use the full object key as the encrypted key
            s3_encrypted_key = object_key
            s3_output_key = f"{decrypted_s3_prefix.rstrip('/')}/{file_name.replace('.gpg', '.txt')}"
            
        else:
            # Direct parameter structure (backward compatibility)
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

        # Create temporary files
        with tempfile.TemporaryDirectory() as temp_dir:
            encrypted_file_path = os.path.join(temp_dir, "encrypted_file.gpg")
            decrypted_file_path = os.path.join(temp_dir, "decrypted_file.txt")

            # Download encrypted file from S3
            print(f"Downloading encrypted file from S3...")
            download_from_s3(s3_bucket, s3_encrypted_key, encrypted_file_path)

            # Decrypt the file using PGPy
            print("Decrypting file with PGPy...")
            decrypted_content = decrypt_file_pgpy(encrypted_file_path, private_key_data, passphrase, decrypted_file_path)

            # Clear sensitive data from memory
            del private_key_data
            del passphrase

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
