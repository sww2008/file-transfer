# PGP Decryption Lambda Function

AWS Lambda function for PGP decryption using pure cryptography library. This function fetches PGP credentials from AWS Secrets Manager and decrypts files from S3.

## Features

- PGP file decryption using cryptography library
- AWS Secrets Manager integration for credential management
- S3 integration for file storage
- Comprehensive error handling
- Security best practices

## Prerequisites

- Python 3.13+
- AWS CLI configured
- GPG installed on the system
- Required AWS permissions for Secrets Manager and S3

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `S3_BUCKET` | S3 bucket name for file storage | Yes | - |
| `ENCRYPTED_S3_PREFIX` | S3 prefix for encrypted files | No | `encrypted/` |
| `DECRYPTED_S3_PREFIX` | S3 prefix for decrypted files | No | `decrypted/` |
| `GPG_SECRET_NAME` | AWS Secrets Manager secret name | No | `gpg-credentials` |
| `SECRET_REGION` | AWS region for secrets | No | `ap-southeast-2` |

## AWS Secrets Manager Configuration

The secret should contain the following JSON structure:

```json
{
  "PGPPrivateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----...",
  "PGPPassphrase": "your-passphrase"
}
```

## Usage

### Lambda Event Structure

```json
{
  "file_name": "encrypted-file.gpg",
  "output_file_name": "decrypted-file.txt"
}
```

### Response Structure

**Success Response:**
```json
{
  "statusCode": 200,
  "body": {
    "message": "File decrypted successfully",
    "input_file": "s3://bucket/encrypted/file.gpg",
    "output_file": "s3://bucket/decrypted/file.txt",
    "decrypted_size": 1024
  }
}
```

**Error Response:**
```json
{
  "statusCode": 500,
  "body": {
    "error": "PGP decryption failed",
    "message": "Error details"
  }
}
```

## Development

### Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Testing

Run the test suite:
```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ -v --cov=lambda_pgp_decrypt_cryptography --cov-report=html
```

### Code Quality

Format code:
```bash
black lambda_pgp_decrypt_cryptography.py
isort lambda_pgp_decrypt_cryptography.py
```

Lint code:
```bash
flake8 lambda_pgp_decrypt_cryptography.py
```

Type checking:
```bash
mypy lambda_pgp_decrypt_cryptography.py
```

Security scan:
```bash
bandit -r lambda_pgp_decrypt_cryptography.py
safety check
```

## CI/CD Pipeline

The repository includes a GitHub Actions workflow that provides:

- **Testing**: Automated test execution with coverage reporting
- **Code Quality**: Linting, formatting, and type checking
- **Security**: Security scanning with Bandit and Safety
- **Build**: Lambda deployment package creation and artifact upload

### Build Artifacts

The workflow creates downloadable Lambda packages:

- **Commit-specific packages**: `lambda-deployment-package-{commit-sha}` (30 days retention)
- **Latest packages**: `lambda-deployment-package-latest` (90 days retention, main branch only)

Each package includes:
- `lambda-deployment-package.zip`: Ready-to-deploy Lambda package
- `package-info.txt`: Build information and metadata

## Deployment

### Download Lambda Package

1. **From GitHub Actions**:
   - Go to the Actions tab in your GitHub repository
   - Select the latest successful workflow run
   - Download the `lambda-deployment-package.zip` artifact
   - Extract the package info from `package-info.txt`

2. **Deploy to AWS Lambda**:
   ```bash
   aws lambda update-function-code \
     --function-name your-function-name \
     --zip-file fileb://lambda-deployment-package.zip
   aws lambda update-function-configuration \
     --function-name your-function-name \
     --runtime python3.13 \
     --architectures x86_64
   ```

### Manual Build (Local)

If you need to build locally:
```bash
pip install -r requirements.txt -t ./package
cp lambda_pgp_decrypt_cryptography.py ./package/
cd package
zip -r ../lambda-deployment-package.zip .
```

## Security Considerations

- PGP private keys are stored securely in AWS Secrets Manager
- Temporary files are properly cleaned up
- GPG operations run in isolated environments
- All secrets are handled with proper error handling

## Troubleshooting

### Common Issues

1. **GPG not found**: Ensure GPG is installed on the Lambda runtime
2. **Permission denied**: Check AWS IAM permissions for Secrets Manager and S3
3. **Key import failed**: Verify the private key format and passphrase
4. **Timeout errors**: Check file size and network connectivity

### Logs

Monitor CloudWatch logs for detailed error information and debugging.

## License

This project is licensed under the MIT License.
