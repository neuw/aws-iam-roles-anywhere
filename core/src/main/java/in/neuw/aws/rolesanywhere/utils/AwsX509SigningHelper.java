package in.neuw.aws.rolesanywhere.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnyWhereRequesterDetails;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnywhereSessionsRequest;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnywhereSessionsResponse;
import in.neuw.aws.rolesanywhere.credentials.models.X509CertificateChain;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.entity.ContentType;
import software.amazon.awssdk.http.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.ServiceEndpointKey;
import software.amazon.awssdk.regions.servicemetadata.RolesanywhereServiceMetadata;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.awssdk.utils.IoUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader.*;
import static software.amazon.awssdk.auth.signer.internal.SignerConstant.AUTHORIZATION;
import static software.amazon.awssdk.auth.signer.internal.SignerConstant.AWS4_TERMINATOR;
import static software.amazon.awssdk.http.Header.CONTENT_TYPE;
import static software.amazon.awssdk.http.Header.HOST;
import static software.amazon.awssdk.http.auth.aws.internal.signer.util.SignerConstant.X_AMZ_DATE;

@Slf4j
public class AwsX509SigningHelper {

    private static final SimpleDateFormat dateTimeFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
    private static final String LINE_SEPARATOR = "\n";
    private static final String SEMI_COLON = ";";
    public static final String X_AMZ_X509 = "X-Amz-X509";
    public static final String X_AMZ_X509_CHAIN = "X-Amz-X509-Chain";
    private static final String SHA_256 = "SHA-256";
    public static final String SESSIONS_URI = "/sessions";
    public static final String ROLES_ANYWHERE_SERVICE = "rolesanywhere";
    public static final String AWS4_X509_PREFIX = "AWS4-X509-";
    public static final String AWS4_X509_SUFFIX = "-SHA256";
    public static final String CREDENTIAL_PREFIX = "Credential=";
    public static final String CREDENTIALS_DE_LIMITER = ", ";
    public static final String SIGNED_HEADERS_PREFIX = "SignedHeaders=";
    public static final String SIGNATURE_PREFIX = "Signature=";
    // empty in case of AWS x509 based roles anywhere sessions endpoint
    public static final String EMPTY_STRING = "";

    static {
        dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public static String getDateAndTime(final Date date) {
        return dateTimeFormat.format(date);
    }

    public static String getDate(final Date date) {
        return dateFormat.format(date);
    }

    public static byte[] hash(final String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(SHA_256);
        return digest.digest(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String signedHeaders() {
        return CONTENT_TYPE + SEMI_COLON + HOST + SEMI_COLON + X_AMZ_DATE + SEMI_COLON + X_AMZ_X509;
    }

    public static String signedHeadersWithChain() {
        return signedHeaders() + SEMI_COLON + X_AMZ_X509_CHAIN;
    }

    public static String canonicalRequest(final Date date,
                                          final String host,
                                          final String method,
                                          final String uri,
                                          final String body,
                                          final X509CertificateChain x509CertificateChain) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
        String dateAndTime = getDateAndTime(date);
        String canonicalHeaders;
        StringBuilder canonicalRequestBuilder = new StringBuilder();
        canonicalRequestBuilder.append(method).append(LINE_SEPARATOR)
                .append(uri).append(LINE_SEPARATOR)
                .append(EMPTY_STRING).append(LINE_SEPARATOR);
        if (x509CertificateChain.getIntermediateCACertificate() == null) {
            canonicalHeaders = buildCanonicalHeaders(
                    host,
                    ContentType.APPLICATION_JSON.getMimeType(),
                    dateAndTime,
                    x509CertificateChain.getBase64EncodedCertificate()
            );
            canonicalRequestBuilder
                    .append(canonicalHeaders).append(LINE_SEPARATOR)
                    .append(signedHeaders().toLowerCase()).append(LINE_SEPARATOR);
        } else {
            var chainCerts = convertToBase64PEMString(x509CertificateChain.getIntermediateCACertificate());
            canonicalHeaders = buildCanonicalHeaders(
                    host,
                    ContentType.APPLICATION_JSON.getMimeType(),
                    dateAndTime,
                    convertToBase64PEMString(x509CertificateChain.getLeafCertificate()),
                    chainCerts
            );
            canonicalRequestBuilder
                    .append(canonicalHeaders).append(LINE_SEPARATOR)
                    .append(signedHeadersWithChain().toLowerCase()).append(LINE_SEPARATOR);
        }
        log.debug("canonicalHeaders = {}", canonicalHeaders);
        log.debug("sessions request = {}", body);
        canonicalRequestBuilder.append(hashContent(body));
        return canonicalRequestBuilder.toString();
    }

    public static String hashContent(final String canonicalRequest) throws NoSuchAlgorithmException {
        return BinaryUtils.toHex(hash(canonicalRequest));
    }

    public static Map<String, String> canonicalHeaders(final String host,
                                                       final String contentType,
                                                       final String date,
                                                       final String derX509) {
        Map<String, String> headers = new TreeMap<>();
        headers.put(CONTENT_TYPE.toLowerCase(), contentType);
        headers.put(HOST.toLowerCase(), host);
        headers.put(X_AMZ_DATE.toLowerCase(), date);
        headers.put(X_AMZ_X509.toLowerCase(), derX509);
        return headers;
    }

    public static String buildCanonicalHeaders(final String host,
                                               final String contentType,
                                               final String date,
                                               final String derX509) {
        Map<String, String> headers = canonicalHeaders(host, contentType, date, derX509);
        return headers.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining(LINE_SEPARATOR)) + LINE_SEPARATOR;
    }

    public static String buildCanonicalHeaders(final String host,
                                               final String contentType,
                                               final String date,
                                               final String derX509,
                                               final String chainDerX509CommaSeparated) {
        Map<String, String> headers = canonicalHeaders(host, contentType, date, derX509);
        headers.put(X_AMZ_X509_CHAIN.toLowerCase(), chainDerX509CommaSeparated);
        return headers.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining(LINE_SEPARATOR)) + LINE_SEPARATOR;
    }

    public static AwsRolesAnywhereSessionsRequest awsRolesAnywhereSessionsRequest(final String roleArn,
                                                                                  final String profileArn,
                                                                                  final String trustAnchorArn,
                                                                                  final Integer sessionDuration) {
        return new AwsRolesAnywhereSessionsRequest()
                .setRoleArn(roleArn)
                .setProfileArn(profileArn)
                .setTrustAnchorArn(trustAnchorArn)
                .setDurationSeconds(sessionDuration);
    }

    public static String resolveHostBasedOnRegion(final Region region) {
        return new RolesanywhereServiceMetadata().endpointFor(ServiceEndpointKey.builder().region(region).build()).getPath();
    }

    public static String resolveHostEndpoint(final Region region) {
        return "https://"+resolveHostBasedOnRegion(region);
    }

    public static String resolveAwsAlgorithm(final PrivateKey key) {
        return AWS4_X509_PREFIX + resolveAndValidateAlgorithm(key) + AWS4_X509_SUFFIX;
    }

    public static String credentialScope(final Date date,
                                         final Region region) {
        String credentialScope = getDate(date) + "/" + region.id() + "/" + ROLES_ANYWHERE_SERVICE + "/" + AWS4_TERMINATOR;
        log.debug("credentialScope: {}", credentialScope);
        return credentialScope;
    }

    public static String contentToSign(final Date date,
                                       final Region region,
                                       final String algorithm,
                                       final String canonicalRequest) throws IOException, NoSuchAlgorithmException {
        log.debug("canonicalRequest: \n{}", canonicalRequest);
        String contentToSign = algorithm + '\n' +
                getDateAndTime(date) + '\n' +
                credentialScope(date, region) + '\n' +
                hashContent(canonicalRequest);
        return contentToSign;
    }

    public static String sign(final String contentToSign,
                              final PrivateKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance(resolveSignatureAlgorithm(key));
        signature.initSign(key);

        signature.update(contentToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return BinaryUtils.toHex(signatureBytes);
    }

    public static String awsSignedAuthHeader(final Date date,
                                             final Region region,
                                             final String contentToSign,
                                             final String algorithm,
                                             final String signedHeaders,
                                             final X509Certificate cert,
                                             final PrivateKey key) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
        var certId = cert.getSerialNumber().toString();
        var credentialPart = certId+"/"+credentialScope(date, region);
        var signedContent = sign(contentToSign, key);

        StringBuilder builder = new StringBuilder();
        builder.append(algorithm)
                .append(" ")
                .append(CREDENTIAL_PREFIX)
                .append(credentialPart)
                .append(CREDENTIALS_DE_LIMITER)
                .append(SIGNED_HEADERS_PREFIX)
                .append(signedHeaders)
                .append(CREDENTIALS_DE_LIMITER)
                .append(SIGNATURE_PREFIX)
                .append(signedContent);
        return builder.toString();
    }

    public static AwsRolesAnywhereSessionsResponse getIamRolesAnywhereSessions(
            final AwsRolesAnywhereSessionsRequest sessionsRequest,
            final AwsRolesAnyWhereRequesterDetails requesterDetails,
            final SdkHttpClient sdkHttpClient,
            final ObjectMapper om) {

        try {
            var request = om.writeValueAsString(sessionsRequest);
            var awsRegion = requesterDetails.getRegion();
            var host = resolveHostBasedOnRegion(awsRegion);
            var x509CertificateChain = resolveCertificateChain(requesterDetails.getEncodedX509Certificate());

            log.debug("request: {}", request);

            var date = new Date();

            var canonicalRequest = canonicalRequest(date,
                    host,
                    SdkHttpMethod.POST.name(),
                    SESSIONS_URI,
                    request,
                    x509CertificateChain);

            var signingAlgorithm = resolveAwsAlgorithm(requesterDetails.getPrivateKey());
            var contentToSign = contentToSign(date, awsRegion, signingAlgorithm, canonicalRequest);

            var requestSpec = executeHttpRequest(date, sessionsRequest, sdkHttpClient, requesterDetails, contentToSign, signingAlgorithm);

            // Print status code
            log.debug("Status Code is {} for AWS roles anywhere session endpoint", requestSpec.httpResponse().statusCode());

            // Read and print response body
            if (requestSpec.responseBody().isPresent()) {
                try (InputStream content = requestSpec.responseBody().get()) {
                    String responseBody = IoUtils.toUtf8String(content);
                    log.debug("Response Body from AWS roles anywhere sessions endpoint: {}", responseBody);
                    return om.readValue(responseBody, AwsRolesAnywhereSessionsResponse.class);
                } catch (IOException e) {
                    log.error("Error reading response body for AWS roles anywhere sessions endpoint: {}", e.getMessage());
                    throw new RuntimeException("Error reading response body for AWS roles anywhere sessions endpoint");
                }
            } else {
                log.error("Error reading response body for AWS roles anywhere sessions endpoint: NO response body");
                throw new RuntimeException("Error reading response body for AWS roles anywhere sessions endpoint");
            }

        } catch (NoSuchAlgorithmException | IOException | NoSuchProviderException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @SneakyThrows
    private static HttpExecuteResponse executeHttpRequest(final Date date,
                                                          final AwsRolesAnywhereSessionsRequest sessionsRequest,
                                                          final SdkHttpClient sdkHttpClient,
                                                          final AwsRolesAnyWhereRequesterDetails requesterDetails,
                                                          final String contentToSign,
                                                          final String signingAlgorithm) {

        String jsonBody = new ObjectMapper().writeValueAsString(sessionsRequest);
        InputStream requestBodyStream = new ByteArrayInputStream(jsonBody.getBytes(StandardCharsets.UTF_8));

        var awsRegion = requesterDetails.getRegion();
        var host = resolveHostBasedOnRegion(awsRegion);

        SdkHttpFullRequest.Builder sdkHttpFullRequestBuilder = (SdkHttpFullRequest.Builder) SdkHttpFullRequest.builder()
                .uri("https://" + host + SESSIONS_URI)
                .method(SdkHttpMethod.POST)
                .putHeader(CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                .putHeader(X_AMZ_X509, convertToBase64PEMString(requesterDetails.getCertificateChain().getLeafCertificate()))
                .putHeader(X_AMZ_DATE, getDateAndTime(date));

        var cert = requesterDetails.getCertificateChain().getLeafCertificate();
        var key = requesterDetails.getPrivateKey();

        String authHeader;
        if (requesterDetails.getCertificateChain().getIntermediateCACertificate() != null) {
            authHeader = awsSignedAuthHeader(date, requesterDetails.getRegion(), contentToSign, signingAlgorithm, signedHeadersWithChain(), cert, key);
            sdkHttpFullRequestBuilder
                    .putHeader(X_AMZ_X509_CHAIN, convertToBase64PEMString(requesterDetails.getCertificateChain().getIntermediateCACertificate()))
                    .putHeader(AUTHORIZATION, authHeader);
        } else {
            authHeader = awsSignedAuthHeader(date, requesterDetails.getRegion(), contentToSign, signingAlgorithm, signedHeaders(), cert, key);
            sdkHttpFullRequestBuilder.putHeader(AUTHORIZATION, authHeader);
        }

        HttpExecuteRequest request = HttpExecuteRequest.builder()
                .request(sdkHttpFullRequestBuilder.build())
                .contentStreamProvider(() -> requestBodyStream)
                .build();

        var requestSpec = sdkHttpClient.prepareRequest(request).call();

        log.debug("authHeader: {}", authHeader);
        return requestSpec;
    }

}
