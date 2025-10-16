#!/usr/bin/env python3
"""
Interactive script to save PGP private key to AWS Secrets Manager.
This version prompts for input instead of using command line arguments.
"""

import json
import os
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
    """Interactive main function."""
    
    print("🔐 PGP Private Key to AWS Secrets Manager")
    print("=" * 50)
    
    # Get input from user
    key_file_path = input("Enter path to your .asc private key file: ").strip()
    if not key_file_path:
        print("❌ Private key file path is required")
        return
    
    passphrase = input("Enter the passphrase for your private key: ").strip()
    if not passphrase:
        print("❌ Passphrase is required")
        return
    
    secret_name = input("Enter secret name (default: gpg-credentials): ").strip()
    if not secret_name:
        secret_name = "gpg-credentials"
    
    region_name = input("Enter AWS region (default: ap-southeast-2): ").strip()
    if not region_name:
        region_name = "ap-southeast-2"
    
    try:
        print(f"\n📖 Reading private key from: {key_file_path}")
        private_key_data = read_private_key_file(key_file_path)
        
        print(f"💾 Saving to AWS Secrets Manager...")
        print(f"  Secret Name: {secret_name}")
        print(f"  Region: {region_name}")
        
        save_to_secrets_manager(
            secret_name=secret_name,
            private_key_data=private_key_data,
            passphrase=passphrase,
            region_name=region_name
        )
        
        print("\n🎉 PGP credentials saved successfully!")
        print(f"\n📋 To use in your Lambda function, set these environment variables:")
        print(f"  GPG_SECRET_NAME={secret_name}")
        print(f"  SECRET_REGION={region_name}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")


if __name__ == "__main__":
    main()
