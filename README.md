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

Structure of the library is quite straight forward:-

➬ A parent pom! Maintains the common most versions of libraries.

➬ A core library - based on AWS SDK, and uses APACHE http client for http call.

➬ A Spring Boot starter library that provides AutoConfiguration and uses core library underneath.

The initial BETA version has been made available over maven here:-

```
<dependency>
    <groupId>in.neuw</groupId>
    <artifactId>aws-iam-roles-anywhere-core</artifactId>
    <version>0.4-2.31.50</version>
</dependency>
```

### Versions

| Parent / Core Version | Starter Version | AWS SDK v2 Version | Spring Boot Version |
|-----------------------|-----------------|:------------------:|:-------------------:|
| 0.4.1                 | 0.4.1           |       2.31.9       |        3.4.3        |
| 0.4.2                 | 0.4.2           |      2.31.21       |        3.4.4        |
| 0.4.3                 | 0.4.3           |      2.31.29       |        3.4.5        |
| 0.4.4                 | 0.4.4           |      2.31.50       |        3.4.6        |
| 0.4.5                 | 0.4.5           |      3.31.50       |        3.5.0        |


