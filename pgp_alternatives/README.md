# PGP Decryption Lambda Alternatives

This folder contains two different implementations for PGP decryption in AWS Lambda:

## Files

- `lambda_pgp_decrypt_gnupg.py` - Uses `python-gnupg` library
- `lambda_pgp_decrypt_pgpy.py` - Uses `pgpy` library
- `requirements_gnupg.txt` - Dependencies for GNUPG version
- `requirements_pgpy.txt` - Dependencies for PGPy version
- `save_pgp_key_to_secrets.py` - Command-line script to save PGP key to AWS Secrets Manager
- `save_pgp_key_interactive.py` - Interactive script to save PGP key to AWS Secrets Manager

## Setting up PGP Private Key in AWS Secrets Manager

### Method 1: Using the Interactive Script (Recommended)

```bash
python save_pgp_key_interactive.py
```

This will prompt you for:
- Path to your `.asc` private key file
- Passphrase for the private key
- Secret name (default: `gpg-credentials`)
- AWS region (default: `ap-southeast-2`)

### Method 2: Using Command Line Arguments

```bash
python save_pgp_key_to_secrets.py my_private_key.asc mypassphrase gpg-credentials ap-southeast-2
```

### Method 3: Manual AWS CLI

```bash
# Create the secret manually
aws secretsmanager create-secret \
    --name gpg-credentials \
    --description "PGP credentials for file decryption" \
    --secret-string '{"PGPPrivateKey":"-----BEGIN PGP PRIVATE KEY BLOCK-----\n...","PGPPassphrase":"your_passphrase"}'
```

## Prerequisites

1. **AWS Credentials**: Make sure your AWS credentials are configured
2. **Private Key File**: You need your PGP private key in `.asc` format
3. **Passphrase**: The passphrase for your private key
4. **IAM Permissions**: Your AWS user/role needs `secretsmanager:CreateSecret` and `secretsmanager:UpdateSecret` permissions

## Lambda Environment Variables

Set these environment variables in your Lambda function:

- `GPG_SECRET_NAME` (default: `gpg-credentials`)
- `SECRET_REGION` (default: `ap-southeast-2`)
- `S3_BUCKET` (required)
- `ENCRYPTED_S3_PREFIX` (default: `encrypted/`)
- `DECRYPTED_S3_PREFIX` (default: `decrypted/`)

## Lambda IAM Permissions

Your Lambda execution role needs these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:region:account:secret:gpg-credentials*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::your-bucket-name/*"
        }
    ]
}
```

## Usage

Both Lambda functions expect an event with this structure:

```json
{
    "file_name": "encrypted_file.gpg",
    "output_file_name": "decrypted_file.txt"
}
```

## Library Comparison

| Feature                  | python-gnupg             | pgpy                |
| ------------------------ | ------------------------ | ------------------- |
| **Reliability**          | ⭐⭐⭐⭐⭐                    | ⭐⭐⭐⭐                |
| **Package Size**         | Large (needs GPG binary) | Small (pure Python) |
| **PGP Support**          | Complete                 | Good                |
| **Lambda Compatibility** | Requires GPG layer       | Native              |
| **Maintenance**          | Well-maintained          | Active development  |

## Recommendations

- **Use `python-gnupg`** for production environments where reliability is critical
- **Use `pgpy`** for Lambda environments where package size matters
- **Use `cryptography`** (original) only for simple RSA encryption, not full PGP
