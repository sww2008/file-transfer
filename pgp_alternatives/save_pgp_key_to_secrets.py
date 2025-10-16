#!/usr/bin/env python3
"""
Script to save PGP private key from .asc file to AWS Secrets Manager.
This script reads a PGP private key file and stores it securely in AWS Secrets Manager.
"""

import json
import os
import sys
from typing import Dict, Any

import boto3
from botocore.exceptions import ClientError


def read_private_key_file(key_file_path: str) -> str:
    """Read the private key from .asc file."""
    try:
        with open(key_file_path, 'r') as f:
            private_key_data = f.read()
        return private_key_data
    except FileNotFoundError:
        raise Exception(f"Private key file not found: {key_file_path}")
    except Exception as e:
        raise Exception(f"Error reading private key file: {str(e)}")


def save_to_secrets_manager(
    secret_name: str,
    private_key_data: str,
    passphrase: str,
    region_name: str = "ap-southeast-2",
    description: str = "PGP credentials for file decryption"
) -> None:
    """Save PGP credentials to AWS Secrets Manager."""
    
    # Create secrets manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)
    
    # Prepare the secret data
    secret_data = {
        "PGPPrivateKey": private_key_data,
        "PGPPassphrase": passphrase
    }
    
    try:
        # Try to update existing secret first
        try:
            client.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(secret_data),
                Description=description
            )
            print(f"✅ Successfully updated existing secret: {secret_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                # Secret doesn't exist, create new one
                client.create_secret(
                    Name=secret_name,
                    Description=description,
                    SecretString=json.dumps(secret_data)
                )
                print(f"✅ Successfully created new secret: {secret_name}")
            else:
                raise e
                
    except ClientError as e:
        raise Exception(f"Error saving to Secrets Manager: {str(e)}")


def main():
    """Main function to handle command line arguments and save PGP key."""
    
    if len(sys.argv) < 3:
        print("Usage: python save_pgp_key_to_secrets.py <private_key_file.asc> <passphrase> [secret_name] [region]")
        print("Example: python save_pgp_key_to_secrets.py my_key.asc mypassphrase gpg-credentials ap-southeast-2")
        sys.exit(1)
    
    # Parse command line arguments
    key_file_path = sys.argv[1]
    passphrase = sys.argv[2]
    secret_name = sys.argv[3] if len(sys.argv) > 3 else "gpg-credentials"
    region_name = sys.argv[4] if len(sys.argv) > 4 else "ap-southeast-2"
    
    try:
        print(f"Reading private key from: {key_file_path}")
        private_key_data = read_private_key_file(key_file_path)
        
        print(f"Saving to AWS Secrets Manager...")
        print(f"  Secret Name: {secret_name}")
        print(f"  Region: {region_name}")
        
        save_to_secrets_manager(
            secret_name=secret_name,
            private_key_data=private_key_data,
            passphrase=passphrase,
            region_name=region_name
        )
        
        print("\n🎉 PGP credentials saved successfully!")
        print(f"\nTo use in your Lambda function, set these environment variables:")
        print(f"  GPG_SECRET_NAME={secret_name}")
        print(f"  SECRET_REGION={region_name}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
