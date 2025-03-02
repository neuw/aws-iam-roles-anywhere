package in.neuw.aws.rolesanywhere.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnyWhereRequesterDetails;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnywhereSessionsRequest;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnywhereSessionsResponse;
import in.neuw.aws.rolesanywhere.credentials.models.X509CertificateChain;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.annotations.NotThreadSafe;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.builder.ToCopyableBuilder;

import java.security.PrivateKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

import static in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper.*;
import static in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader.extractPrivateKey;
import static in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader.resolveCertificateChain;

@Slf4j
public class IAMRolesAnywhereSessionsCredentialsProvider
        extends RolesAnywhereCredentialsProvider
        implements ToCopyableBuilder<IAMRolesAnywhereSessionsCredentialsProvider.Builder, IAMRolesAnywhereSessionsCredentialsProvider> {

    private ObjectMapper objectMapper;
    private AwsRolesAnywhereSessionsRequest awsRolesAnywhereSessionsRequest;
    private AwsRolesAnyWhereRequesterDetails requesterDetails;

    @SneakyThrows
    private IAMRolesAnywhereSessionsCredentialsProvider(Builder builder) {
        super(builder, "iam-r-aw-thread");

        log.info("setting up the rest client for 'roles anywhere AWS service', with host = {} based on region = {}", builder.host, builder.region);
        this.objectMapper = builder.objectMapper;
        this.awsRolesAnywhereSessionsRequest = builder.awsRolesAnywhereSessionsRequest;
        this.requesterDetails = builder.requesterDetails;
        //getUpdatedCredentials();
        prefetchCredentials();
    }

    private Instant getInstantFromResponseExpiry(final String expiry) {
        return LocalDateTime.parse(expiry,DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"))
                .atZone(ZoneId.of("UTC"))
                .toInstant();
    }

    @Override
    AwsSessionCredentials getUpdatedCredentials() {
        var response = refreshCredentials();
        // reckon, it will be just one credential
        var credentials = response.getCredentialSet().get(0);
        log.info("fetched credentials at epoch seconds = {} with expiry epoch seconds = {}",
                Instant.now().getEpochSecond(),
                getInstantFromResponseExpiry(credentials.getCredentials().getExpiration()).getEpochSecond());
        return AwsSessionCredentials.builder()
                .sessionToken(credentials.getCredentials().getSessionToken())
                .accessKeyId(credentials.getCredentials().getAccessKeyId())
                .secretAccessKey(credentials.getCredentials().getSecretAccessKey())
                .expirationTime(getInstantFromResponseExpiry(credentials.getCredentials().getExpiration()))
                .build();
    }

    @Override
    String providerName() {
        return "rolesanywhere-provider";
    }

    public AwsRolesAnywhereSessionsResponse refreshCredentials() {
        return fetchCredentials(awsRolesAnywhereSessionsRequest, requesterDetails, sdkHttpClient, objectMapper);
    }

    private AwsRolesAnywhereSessionsResponse fetchCredentials(final AwsRolesAnywhereSessionsRequest awsRolesAnywhereSessionsRequest,
                                                              final AwsRolesAnyWhereRequesterDetails requesterDetails,
                                                              final SdkHttpClient sdkHttpClient,
                                                              final ObjectMapper objectMapper) {
        return getIamRolesAnywhereSessions(awsRolesAnywhereSessionsRequest, requesterDetails, sdkHttpClient, objectMapper);
    }

    @Override
    public Builder toBuilder() {
        return null;
    }

    @Override
    public IAMRolesAnywhereSessionsCredentialsProvider copy(Consumer<? super Builder> modifier) {
        return ToCopyableBuilder.super.copy(modifier);
    }

    @NotThreadSafe
    public static final class Builder extends BaseBuilder<Builder, IAMRolesAnywhereSessionsCredentialsProvider> {
        private AwsRolesAnywhereSessionsRequest awsRolesAnywhereSessionsRequest;
        private AwsRolesAnywhereProperties awsRolesAnywhereProperties;
        private ObjectMapper objectMapper;
        private String roleArn;
        private String profileArn;
        private String trustAnchorArn;
        private String region;
        private Integer durationSeconds;
        private String roleSessionName;
        private String encodedX509Certificate;
        private String encodedPrivateKey;
        private X509CertificateChain x509CertificateChain;
        private PrivateKey privateKey;
        private Region awsRegion;
        private String host;
        // a wrapper, passed on to utilities
        private AwsRolesAnyWhereRequesterDetails requesterDetails;

        public Builder(final ObjectMapper objectMapper) {
            // unused as of now.
            super(IAMRolesAnywhereSessionsCredentialsProvider::new);
            this.objectMapper = objectMapper;
            this.objectMapper(objectMapper);
        }

        @SneakyThrows
        public Builder(final AwsRolesAnywhereProperties awsRolesAnywhereProperties,
                       final ObjectMapper objectMapper) {
            super(IAMRolesAnywhereSessionsCredentialsProvider::new);
            this.awsRegion = Region.of(awsRolesAnywhereProperties.getRegion());
            // the awsRegion has to be initialized first for the Rest Client
            this.initRestClientBasedOnRegion();
            // the following setters are dormant, there is a wrapper AwsRolesAnyWhereRequesterDetails, wrapping all the values.
            this.awsRolesAnywhereProperties = awsRolesAnywhereProperties;
            this.objectMapper = objectMapper;
            this.objectMapper(objectMapper);
            this.region = awsRolesAnywhereProperties.getRegion();
            this.durationSeconds = awsRolesAnywhereProperties.getDurationSeconds();
            this.roleArn = awsRolesAnywhereProperties.getRoleArn();
            this.profileArn = awsRolesAnywhereProperties.getProfileArn();
            this.trustAnchorArn = awsRolesAnywhereProperties.getTrustAnchorArn();
            this.encodedPrivateKey = awsRolesAnywhereProperties.getEncodedPrivateKey();
            this.encodedX509Certificate = awsRolesAnywhereProperties.getEncodedX509Certificate();
            this.x509CertificateChain = resolveCertificateChain(awsRolesAnywhereProperties.getEncodedX509Certificate());
            this.privateKey = extractPrivateKey(this.awsRolesAnywhereProperties.getEncodedPrivateKey());
            this.host = resolveHostBasedOnRegion(this.awsRegion);
            initRequest();
        }

        public Builder region(final String region) {
            this.region = region;
            this.awsRegion = Region.of(region);
            // the awsRegion has to be initialized first for the Rest Client
            this.initRestClientBasedOnRegion();
            return this;
        }

        public Builder durationSeconds(final int durationSeconds) {
            this.durationSeconds = durationSeconds;
            return this;
        }

        public Builder roleArn(final String roleArn) {
            this.roleArn = roleArn;
            return this;
        }

        public Builder profileArn(final String profileArn) {
            this.profileArn = profileArn;
            return this;
        }

        public Builder trustAnchorArn(final String trustAnchorArn) {
            this.trustAnchorArn = trustAnchorArn;
            return this;
        }

        public Builder roleSessionName(final String roleSessionName) {
            this.roleSessionName = roleSessionName;
            return this;
        }

        @SneakyThrows
        public Builder encodedX509Certificate(final String encodedX509Certificate) {
            this.encodedX509Certificate = encodedX509Certificate;
            this.x509CertificateChain = resolveCertificateChain(encodedX509Certificate);
            return this;
        }

        public Builder encodedPrivateKey(final String encodedPrivateKey) {
            this.encodedPrivateKey = encodedPrivateKey;
            this.privateKey = extractPrivateKey(encodedPrivateKey);
            return this;
        }

        private void initRequest() {
            this.awsRolesAnywhereSessionsRequest = awsRolesAnywhereSessionsRequest(
                    this.roleArn,
                    this.profileArn,
                    this.trustAnchorArn,
                    this.durationSeconds
            );
        }

        private void initRestClientBasedOnRegion() {
            this.sdkHttpClient(
                    ApacheHttpClient.builder()
                            .maxConnections(100).build()
            );
        }

        @Override
        public IAMRolesAnywhereSessionsCredentialsProvider build() {
            var requesterDetails = AwsRolesAnyWhereRequesterDetails.builder()
                    .durationSeconds(durationSeconds)
                    .certificateChain(this.x509CertificateChain)
                    .privateKey(this.privateKey)
                    .encodedPrivateKey(this.encodedPrivateKey)
                    .encodedX509Certificate(this.encodedX509Certificate)
                    .host(this.host)
                    .region(this.awsRegion)
                    .trustAnchorArn(this.trustAnchorArn)
                    .roleArn(this.roleArn)
                    .profileArn(this.profileArn)
                    .roleSessionName(this.roleSessionName)
                    .build();
            initRequest();
            this.requesterDetails = requesterDetails;
            return super.build();
        }
    }
}
