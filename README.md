### AWS roles anywhere Credential Helper(100% programmatic)

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
    <version>0.3</version>
</dependency>
```