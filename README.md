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
    <version>0.7.14</version>
</dependency>
```

**Spring Boot Starter (recommended for Spring Boot apps):**
```xml
<dependency>
    <groupId>in.neuw</groupId>
    <artifactId>aws-iam-roles-anywhere-starter</artifactId>
    <version>0.7.14</version>
</dependency>
```

### Basic Usage

#### Using the Core Library

```java
import tools.jackson.databind.json.JsonMapper;
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
                new IAMRolesAnywhereSessionsCredentialsProvider.Builder(properties, new JsonMapper())
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

## Logging

Without logging config the logs won't show up at all in the console.

For logging configuration, when just using the core library, you may use the following logback.xml example for reference:

```xml
<configuration>
    <!-- Keep Apache HTTP logs minimal -->
    <logger name="org.apache.http" level="WARN"/>
    <logger name="org.apache.http.wire" level="OFF"/>
    <logger name="org.apache.http.headers" level="OFF"/>
    <logger name="in.neuw.aws" level="DEBUG"/> <!-- or INFO, etc. -->

    <!-- Ensure other logs appear -->
    <root level="DEBUG"> <!-- or INFO, DEBUG, WARN, ERROR -->
        <appender-ref ref="STDOUT"/>
    </root>

    <!-- Console Appender (if missing) -->
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
</configuration>
```

For logging configuration when using the starter, it is relatively straight forward, and spring boot will automatically help in there.

```
# example config for enabling debug logging for aws-iam-roles-anywhere-starter
logger.in.neuw.aws=DEBUG
```

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

| Version | Core's JDK<br/> Runtime | Starter's JDK<br/>Runtime | AWS SDK v2 | Spring Boot | Notes                                                                                                                                        |
|---------|-------------------------|---------------------------|------------|-------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| 0.7.14  | 8                       | 17                        | 2.42.41    | 3.5.14      | newer version of dependent libraries supported. JDK 8 for core and Starter is JDK 17, with jackson 2                                         |
| 0.7.13  | 8                       | 17                        | 2.42.25    | 3.5.13      | newer version of dependent libraries supported. JDK 8 for core and Starter is JDK 17, with jackson 2                                         |
| 0.7.12  | 8                       | 17                        | 2.42.16    | 3.5.12      | newer version of dependent libraries supported. JDK 8 for core and Starter is JDK 17, with jackson 2                                         |
| 0.7.11  | 8                       | 17                        | 2.41.33    | 3.5.11      | newer version of dependent libraries supported. JDK 8 for core and Starter is JDK 17, with jackson 2                                         |
| 0.7.10  | 8                       | 17                        | 2.41.14    | 3.5.10      | newer version of dependent libraries supported. JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8    |
| 0.7.9   | 8                       | 17                        | 2.40.12    | 3.5.9       | newer version of dependent libraries supported. JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8    |
| 0.7.8   | 8                       | 17                        | 2.40.4     | 3.5.8       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.7   | 8                       | 17                        | 2.40.4     | 3.5.7       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.6   | 8                       | 17                        | 2.40.4     | 3.5.6       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.5   | 8                       | 17                        | 2.40.4     | 3.5.5       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.4   | 8                       | 17                        | 2.40.4     | 3.5.4       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.3   | 8                       | 17                        | 2.40.4     | 3.5.3       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.2   | 8                       | 17                        | 2.40.4     | 3.5.2       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.1   | 8                       | 17                        | 2.40.4     | 3.5.1       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
| 0.7.0   | 8                       | 17                        | 2.40.4     | 3.5.0       | Support for JDK 8 for core and Starter is JDK 17, with jackson 2 - jackson 3 does not work with JDK 8                                        |
|         |                         |                           |            |             |                                                                                                                                              |

### Encoding Certificate and Key Files

The library requires Base64-encoded certificate and private key values. Here's how to encode your PEM files:

#### Using Command Line (Linux/macOS)

**Encode a certificate:**
```bash
base64 -i certificate.pem
```

**Encode a private key:**
```bash
base64 -i private-key.key
```

#### Using Java

```java
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class FileEncoder {
    public static String encodeFile(String filePath) throws Exception {
        byte[] fileContent = Files.readAllBytes(Paths.get(filePath));
        return Base64.getEncoder().encodeToString(fileContent);
    }

    public static void main(String[] args) throws Exception {
        String encodedCert = encodeFile("certificate.pem");
        String encodedKey = encodeFile("private-key.key");

        System.out.println("Encoded Certificate:");
        System.out.println(encodedCert);
        System.out.println("\nEncoded Private Key:");
        System.out.println(encodedKey);
    }
}
```

#### Important Notes

- The encoded values should **not** contain line breaks when used in the configuration
- Keep the encoded private key secure - treat it with the same care as the original key file
- The PEM files must contain the proper headers (`-----BEGIN CERTIFICATE-----`, etc.) before encoding
- For certificate chains, complete chain needs to be encoded.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.


