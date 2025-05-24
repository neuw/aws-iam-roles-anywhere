package in.neuw.aws.rolesanywhere.utils;

import in.neuw.aws.rolesanywhere.credentials.models.AssumedRoleUser;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnywhereSessionsResponse;
import in.neuw.aws.rolesanywhere.credentials.models.CredentialSet;
import in.neuw.aws.rolesanywhere.credentials.models.Credentials;

import java.util.ArrayList;

public class MockAwsRolesAnywhereSessionsResponseGenerator {

    public static AwsRolesAnywhereSessionsResponse mockAwsRolesAnywhereSessionsResponse() {
        var listCredentialSet = new ArrayList<CredentialSet>();

        var assumedRole = new AssumedRoleUser().setAssumedRoleId("test").setArn("test");

        var creds = new Credentials()
                .setAccessKeyId("test")
                .setSecretAccessKey("test")
                .setExpiration("2053-05-17T03:43:42Z")
                .setSessionToken("test");

        var credentialSet = new CredentialSet()
                .setRoleArn("test")
                .setPackedPolicySize(71)
                .setAssumedRoleUser(assumedRole)
                .setCredentials(creds)
                .setSourceIdentity("CN=test");

        listCredentialSet.add(credentialSet);

        return new AwsRolesAnywhereSessionsResponse()
                .setSubjectArn("test")
                .setCredentialSet(listCredentialSet);
    }

}
