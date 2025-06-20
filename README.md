### AWS roles anywhere Credential Helper(100% programmatic)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=alert_status&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=reliability_rating&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=sqale_rating&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=neuw_aws-iam-roles-anywhere&metric=coverage&token=c504fc27486350af3da99abb8f023932fe4caab3)](https://sonarcloud.io/summary/new_code?id=neuw_aws-iam-roles-anywhere)

AWS roles anywhere is a great IAM service that was launched in July 2022.

AWS provides a [tool](https://github.com/aws/rolesanywhere-credential-helper) to fetch temporary credentials by providing the certificate and key.

That tool is great, but needs extra config for an application to rely on an external tool.
That tool cannot be shipped along with the code.

This library removes the requirement of that external utility/ tool to load temporary credentials.

The Structure of the library is quite straight forward: -

➬ A parent pom! Maintains the common most versions of libraries.

➬ A core library—based on AWS SDK, and uses APACHE http client for http call.

➬ A Spring Boot starter library that provides AutoConfiguration and uses core library underneath.

### ➬ Important Instructions for the setting-up certificates, encoding file content, etc.

Refer the [repository](https://github.com/krnbr/roles-anywhere-openssl) for the generation of the ca, certificates, etc.

➬ The code only supports the PKCS1 format as of today!

➬ In future iterations, can try to include PKCS8 as well, but not supported yet! 

### Project Structure

- Core - The core logic sits here.
- Starter - The Spring boot custom starter code is here.
- Tests - The tests for the complete repo are placed in here. run `mvn clean verify` at root of repo!

### ➬ The initial BETA version has been made available over maven here:-

The core:-

```
<dependency>
    <groupId>in.neuw</groupId>
    <artifactId>aws-iam-roles-anywhere-core</artifactId>
    <version>0.5</version>
</dependency>
```

The Starter:-

```
<dependency>
    <groupId>in.neuw</groupId>
    <artifactId>aws-iam-roles-anywhere-starter</artifactId>
    <version>0.5</version>
</dependency>
```

### Versions

| Parent / Core Version | Starter Version | AWS SDK v2 Version | Spring Boot Version |                                   Notes                                    |
|-----------------------|-----------------|:------------------:|:-------------------:|:--------------------------------------------------------------------------:|
| 0.4.1                 | 0.4.1           |       2.31.9       |        3.4.3        |                                                                            |
| 0.4.2                 | 0.4.2           |      2.31.21       |        3.4.4        |                                                                            |
| 0.4.3                 | 0.4.3           |      2.31.29       |        3.4.5        |                                                                            |
| 0.4.4                 | 0.4.4           |      2.31.50       |        3.4.6        |                                                                            |
| 0.4.5                 | 0.4.5           |      2.31.50       |        3.5.0        |                                                                            |
| 0.4.5.1               | 0.4.5.1         |      2.31.50       |        3.5.0        |             Minor change related to Validations of properties              |
| 0.5                   | 0.5             |      2.31.63       |        3.5.0        | Support for the PKCS8 along with PKCS1, changed AWS SDK version to 2.31.63 |
| 0.5.1                 | 0.5.1           |      2.31.65       |        3.5.1        |               AWS SDK version to 2.31.65 & Spring Boot 3.5.1               |
| 0.5.2                 | 0.5.2           |      2.31.66       |        3.5.2        |               AWS SDK version to 2.31.66 & Spring Boot 3.5.2               |


