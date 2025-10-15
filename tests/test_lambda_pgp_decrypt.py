"""
Test suite for the PGP decryption Lambda function.
"""

import pytest
import json
import os
import tempfile
from unittest.mock import Mock, patch, mock_open
import boto3
from botocore.exceptions import ClientError

# Import the lambda function
from lambda_pgp_decrypt_cryptography import (
    lambda_handler,
    get_secret,
    download_from_s3,
    upload_to_s3,
    parse_pgp_private_key,
    decrypt_file_cryptography
)


class TestLambdaHandler:
    """Test cases for the main lambda_handler function."""
    
    @patch.dict(os.environ, {
        'S3_BUCKET': 'test-bucket',
        'GPG_SECRET_NAME': 'test-secret',
        'SECRET_REGION': 'ap-southeast-2'
    })
    @patch('lambda_pgp_decrypt_cryptography.get_secret')
    @patch('lambda_pgp_decrypt_cryptography.download_from_s3')
    @patch('lambda_pgp_decrypt_cryptography.upload_to_s3')
    @patch('lambda_pgp_decrypt_cryptography.decrypt_file_cryptography')
    def test_lambda_handler_success(self, mock_decrypt, mock_upload, mock_download, mock_get_secret):
        """Test successful lambda execution."""
        # Setup mocks
        mock_get_secret.return_value = {
            'PGPPrivateKey': 'test-private-key',
            'PGPPassphrase': 'test-passphrase'
        }
        mock_decrypt.return_value = b'decrypted content'
        
        # Test event
        event = {
            'file_name': 'test.gpg',
            'output_file_name': 'test.txt'
        }
        context = Mock()
        
        # Execute
        result = lambda_handler(event, context)
        
        # Assertions
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['message'] == 'File decrypted successfully'
        assert 'input_file' in body
        assert 'output_file' in body
        assert body['decrypted_size'] == 16
        
        # Verify function calls
        mock_get_secret.assert_called_once()
        mock_download.assert_called_once()
        mock_decrypt.assert_called_once()
        mock_upload.assert_called_once()
    
    @patch.dict(os.environ, {
        'S3_BUCKET': 'test-bucket',
        'GPG_SECRET_NAME': 'test-secret'
    })
    def test_lambda_handler_missing_file_name(self):
        """Test lambda handler with missing file_name parameter."""
        event = {}
        context = Mock()
        
        result = lambda_handler(event, context)
        
        assert result['statusCode'] == 500
        body = json.loads(result['body'])
        assert 'error' in body
        assert 'file_name' in body['message']
    
    @patch.dict(os.environ, {})
    def test_lambda_handler_missing_s3_bucket(self):
        """Test lambda handler with missing S3_BUCKET environment variable."""
        event = {'file_name': 'test.gpg'}
        context = Mock()
        
        result = lambda_handler(event, context)
        
        assert result['statusCode'] == 500
        body = json.loads(result['body'])
        assert 'error' in body
        assert 'S3_BUCKET' in body['message']


class TestGetSecret:
    """Test cases for the get_secret function."""
    
    @patch('boto3.session.Session')
    def test_get_secret_success(self, mock_session):
        """Test successful secret retrieval."""
        # Setup mock
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            'SecretString': '{"PGPPrivateKey": "test-key", "PGPPassphrase": "test-pass"}'
        }
        
        # Execute
        result = get_secret('test-secret', 'us-east-1')
        
        # Assertions
        assert result['PGPPrivateKey'] == 'test-key'
        assert result['PGPPassphrase'] == 'test-pass'
        mock_client.get_secret_value.assert_called_once_with(SecretId='test-secret')
    
    @patch('boto3.session.Session')
    def test_get_secret_client_error(self, mock_session):
        """Test secret retrieval with client error."""
        # Setup mock
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.get_secret_value.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException'}}, 'GetSecretValue'
        )
        
        # Execute and assert
        with pytest.raises(Exception) as exc_info:
            get_secret('test-secret')
        
        assert 'Error retrieving secret' in str(exc_info.value)


class TestS3Operations:
    """Test cases for S3 download and upload functions."""
    
    @patch('boto3.client')
    def test_download_from_s3_success(self, mock_boto_client):
        """Test successful S3 download."""
        mock_s3_client = Mock()
        mock_boto_client.return_value = mock_s3_client
        
        download_from_s3('test-bucket', 'test-key', '/tmp/test-file')
        
        mock_s3_client.download_file.assert_called_once_with(
            'test-bucket', 'test-key', '/tmp/test-file'
        )
    
    @patch('boto3.client')
    def test_download_from_s3_error(self, mock_boto_client):
        """Test S3 download with error."""
        mock_s3_client = Mock()
        mock_boto_client.return_value = mock_s3_client
        mock_s3_client.download_file.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchKey'}}, 'GetObject'
        )
        
        with pytest.raises(Exception) as exc_info:
            download_from_s3('test-bucket', 'test-key', '/tmp/test-file')
        
        assert 'Error downloading from S3' in str(exc_info.value)
    
    @patch('boto3.client')
    def test_upload_to_s3_success(self, mock_boto_client):
        """Test successful S3 upload."""
        mock_s3_client = Mock()
        mock_boto_client.return_value = mock_s3_client
        
        upload_to_s3('test-bucket', 'test-key', '/tmp/test-file')
        
        mock_s3_client.upload_file.assert_called_once_with(
            '/tmp/test-file', 'test-bucket', 'test-key'
        )


class TestPGPOperations:
    """Test cases for PGP-related functions."""
    
    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    def test_parse_pgp_private_key_success(self, mock_temp_file, mock_subprocess):
        """Test successful PGP private key parsing."""
        # Setup mocks
        mock_file = Mock()
        mock_file.name = '/tmp/test-key.asc'
        mock_temp_file.return_value.__enter__.return_value = mock_file
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = 'exported key data'
        
        result = parse_pgp_private_key('private key data', 'passphrase')
        
        assert result == 'exported key data'
        mock_subprocess.assert_called_once()
    
    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    def test_parse_pgp_private_key_failure(self, mock_temp_file, mock_subprocess):
        """Test PGP private key parsing with failure."""
        # Setup mocks
        mock_file = Mock()
        mock_file.name = '/tmp/test-key.asc'
        mock_temp_file.return_value.__enter__.return_value = mock_file
        mock_subprocess.return_value.returncode = 1
        mock_subprocess.return_value.stderr = 'GPG error'
        
        with pytest.raises(Exception) as exc_info:
            parse_pgp_private_key('private key data', 'passphrase')
        
        assert 'Failed to export private key' in str(exc_info.value)
    
    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    @patch('os.makedirs')
    @patch('os.chmod')
    def test_decrypt_file_cryptography_success(self, mock_chmod, mock_makedirs, 
                                               mock_temp_file, mock_subprocess):
        """Test successful file decryption."""
        # Setup mocks
        mock_file = Mock()
        mock_file.name = '/tmp/test-key.asc'
        mock_temp_file.return_value.__enter__.return_value = mock_file
        
        # Mock subprocess calls (import and decrypt)
        mock_subprocess.side_effect = [
            Mock(returncode=0),  # Import key
            Mock(returncode=0)   # Decrypt file
        ]
        
        with patch('builtins.open', mock_open(read_data=b'decrypted content')):
            result = decrypt_file_cryptography(
                '/tmp/encrypted.gpg',
                'private key data',
                'passphrase',
                '/tmp/decrypted.txt'
            )
        
        assert result == b'decrypted content'
        assert mock_subprocess.call_count == 2
    
    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    @patch('os.makedirs')
    @patch('os.chmod')
    def test_decrypt_file_cryptography_timeout(self, mock_chmod, mock_makedirs,
                                               mock_temp_file, mock_subprocess):
        """Test file decryption with timeout."""
        # Setup mocks
        mock_file = Mock()
        mock_file.name = '/tmp/test-key.asc'
        mock_temp_file.return_value.__enter__.return_value = mock_file
        mock_subprocess.side_effect = subprocess.TimeoutExpired('gpg', 60)
        
        with pytest.raises(Exception) as exc_info:
            decrypt_file_cryptography(
                '/tmp/encrypted.gpg',
                'private key data',
                'passphrase',
                '/tmp/decrypted.txt'
            )
        
        assert 'GPG decryption timed out' in str(exc_info.value)


class TestIntegration:
    """Integration test cases."""
    
    @patch.dict(os.environ, {
        'S3_BUCKET': 'test-bucket',
        'GPG_SECRET_NAME': 'test-secret',
        'SECRET_REGION': 'ap-southeast-2'
    })
    @patch('lambda_pgp_decrypt_cryptography.get_secret')
    @patch('lambda_pgp_decrypt_cryptography.download_from_s3')
    @patch('lambda_pgp_decrypt_cryptography.upload_to_s3')
    @patch('lambda_pgp_decrypt_cryptography.decrypt_file_cryptography')
    def test_full_workflow_success(self, mock_decrypt, mock_upload, mock_download, mock_get_secret):
        """Test the complete workflow with all components."""
        # Setup comprehensive mocks
        mock_get_secret.return_value = {
            'PGPPrivateKey': '-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'PGPPassphrase': 'test-passphrase'
        }
        mock_decrypt.return_value = b'This is decrypted content'
        
        # Test event with all parameters
        event = {
            'file_name': 'encrypted-file.gpg',
            'output_file_name': 'decrypted-file.txt'
        }
        context = Mock()
        
        # Execute
        result = lambda_handler(event, context)
        
        # Verify success
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['message'] == 'File decrypted successfully'
        assert 's3://test-bucket/encrypted/encrypted-file.gpg' in body['input_file']
        assert 's3://test-bucket/decrypted/decrypted-file.txt' in body['output_file']
        assert body['decrypted_size'] == 25
        
        # Verify all functions were called
        mock_get_secret.assert_called_once_with('test-secret', 'ap-southeast-2')
        mock_download.assert_called_once()
        mock_decrypt.assert_called_once()
        mock_upload.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__])
