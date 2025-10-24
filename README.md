# AWS IAM Roles Anywhere Credential Helper

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=alert_status&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=reliability_rating&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=sqale_rating&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=coverage&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)

A pure Java library for AWS IAM Roles Anywhere credential provisioning, eliminating the need for external credential helper tools.

## Overview

AWS IAM Roles Anywhere allows workloads outside of AWS to obtain temporary AWS credentials using X.509 certificates. While AWS provides an [official credential helper tool](https://github.com/aws/rolesanywhere-credential-helper), this library offers several advantages:

- **Zero Dependencies**: No external tools required - everything is embedded in your Java application
- **Native Integration**: Works seamlessly with AWS SDK v2 credential providers
- **Spring Boot Support**: Auto-configuration for Spring Boot applications
- **Production Ready**: Comprehensive test coverage and async credential refresh support

## Key Features

- ✅ Support for both PKCS#1 and PKCS#8 private key formats
- ✅ X.509 certificate chain validation
- ✅ Automatic credential refresh with async support
- ✅ Spring Boot starter with auto-configuration
- ✅ Built on AWS SDK v2 and Apache HTTP Client
- ✅ Comprehensive test suite with mock AWS server

## Quick Start

### Maven Dependencies

Add the appropriate dependency to your `pom.xml`:

**Core Library (for standalone usage):**
```xml
<dependency>
    <groupId>in.neuw</groupId>
    <artifactId>aws-iam-roles-anywhere-core</artifactId>
    <version>0.5.7</version>
</dependency>
```

**Spring Boot Starter (recommended for Spring Boot apps):**
```xml
<dependency>
    <groupId>in.neuw</groupId>
    <artifactId>aws-iam-roles-anywhere-starter</artifactId>
    <version>0.5.7</version>
</dependency>
```

### Basic Usage

#### Using the Core Library

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import software.amazon.awssdk.services.s3.S3Client;

// Configure properties
AwsRolesAnywhereProperties properties = new AwsRolesAnywhereProperties();
properties.setRoleArn("arn:aws:iam::123456789012:role/MyRole");
properties.setProfileArn("arn:aws:rolesanywhere:us-east-1:123456789012:profile/uuid");
properties.setTrustAnchorArn("arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/uuid");
properties.setRegion("us-east-1");
properties.setDurationSeconds(3600);
properties.setEncodedX509Certificate("BASE64_ENCODED_CERTIFICATE");
properties.setEncodedPrivateKey("BASE64_ENCODED_PRIVATE_KEY");

// Create credentials provider using builder
IAMRolesAnywhereSessionsCredentialsProvider credentialsProvider = 
    new IAMRolesAnywhereSessionsCredentialsProvider.Builder(properties, new ObjectMapper())
        .prefetch(true)
        .asyncCredentialUpdateEnabled(false)
        .build();

// Use with AWS SDK
S3Client s3Client = S3Client.builder()
    .credentialsProvider(credentialsProvider)
    .build();
```

#### Using the Spring Boot Starter

**application.yml:**
```yaml
aws:
  iam:
    rolesanywhere:
      region: us-east-1
      role-arn: arn:aws:iam::123456789012:role/MyRole
      profile-arn: arn:aws:rolesanywhere:us-east-1:123456789012:profile/uuid
      trust-anchor-arn: arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/uuid
      encoded-x509-certificate: BASE64_ENCODED_CERTIFICATE
      encoded-private-key: BASE64_ENCODED_PRIVATE_KEY
      duration-seconds: 3600
      prefetch: true
      async-credential-update-enabled: true
```

**Java Configuration:**
```java
@Configuration
public class AwsConfig {
    
    @Bean
    public S3Client s3Client(AwsCredentialsProvider credentialsProvider) {
        return S3Client.builder()
            .credentialsProvider(credentialsProvider)
            .build();
    }
}
```

## Configuration Reference

### Required Properties

| Property                 | Description                                   | Example                                                          |
|--------------------------|-----------------------------------------------|------------------------------------------------------------------|
| `roleArn`                | ARN of the IAM role to assume                 | `arn:aws:iam::123456789012:role/MyRole`                          |
| `profileArn`             | ARN of the Roles Anywhere profile             | `arn:aws:rolesanywhere:us-east-1:123456789012:profile/uuid`      |
| `trustAnchorArn`         | ARN of the trust anchor                       | `arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/uuid` |
| `region`                 | AWS region                                    | `us-east-1`                                                      |
| `encodedX509Certificate` | Base64 encoded X.509 certificate              | `LS0tLS1CRUdJTi...`                                              |
| `encodedPrivateKey`      | Base64 encoded private key (PKCS#1 or PKCS#8) | `LS0tLS1CRUdJTi...`                                              |

### Optional Properties

| Property                       | Default | Description                                     |
|--------------------------------|---------|-------------------------------------------------|
| `durationSeconds`              | `3600`  | Credential validity duration (900-3600 seconds) |
| `roleSessionName`              | `null`  | Custom session name for the assumed role        |
| `prefetch`                     | `true`  | Enable credential pre-fetching                  |
| `asyncCredentialUpdateEnabled` | `false` | Enable asynchronous credential refresh          |

## Certificate Setup

For certificate generation and setup, refer to the [roles-anywhere-openssl repository](https://github.com/krnbr/roles-anywhere-openssl).

### Supported Formats

- **Private Keys**: PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) and PKCS#8 (`-----BEGIN PRIVATE KEY-----`)
- **Certificates**: X.509 PEM format (`-----BEGIN CERTIFICATE-----`)
- **Certificate Chains**: Multiple certificates concatenated in PEM format

## Project Structure

- **`core/`** - Core credential provider implementation
- **`starter/`** - Spring Boot auto-configuration
- **`tests/`** - Comprehensive test suite

Run tests with: `mvn clean verify`

## Troubleshooting

### Common Issues

**Certificate/Key Format Errors**
- Ensure certificates are in PEM format with proper headers (`-----BEGIN CERTIFICATE-----`)
- Verify private keys are either PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) or PKCS#8 (`-----BEGIN PRIVATE KEY-----`)
- Check that Base64 encoding doesn't include line breaks or whitespace

**Credential Refresh Issues**
- Enable async credential refresh for long-running applications
- Verify network connectivity to AWS Roles Anywhere endpoints
- Check IAM role trust relationships and policies

**Spring Boot Integration**
- Ensure properties are correctly prefixed with `aws.iam.rolesanywhere`
- Verify auto-configuration is not excluded

## Version History

| Version | AWS SDK v2 | Spring Boot | Notes                              |
|---------|------------|-------------|------------------------------------|
| 0.5.7   | 2.34.0     | 3.5.7       | Latest stable release              |
| 0.5.6   | 2.34.0     | 3.5.6       | Latest stable release              |
| 0.5.5   | 2.32.27    | 3.5.5       | Better Exception Handling features |
| 0.5.4   | 2.32.7     | 3.5.4       | No major or minor changes          |
| 0.5.3   | 2.31.68    | 3.5.3       | No major or minor changes          |
| 0.5.2   | 2.31.66    | 3.5.2       | Bug fixes and dependency updates   |
| 0.5.1   | 2.31.65    | 3.5.1       | Performance improvements           |
| 0.5     | 2.31.63    | 3.5.0       | **PKCS#8 support added**           |
| 0.4.5.1 | 2.31.50    | 3.5.0       | Property validation enhancements   |
| 0.4.5   | 2.31.50    | 3.5.0       | Spring Boot 3.5.0 support          |
| 0.4.4   | 2.31.50    | 3.4.6       | Stability improvements             |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.


