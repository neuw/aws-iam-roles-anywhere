package in.neuw.aws.rolesanywhere.utils;

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
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.awssdk.utils.StringUtils;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader.*;
import static software.amazon.awssdk.http.Header.CONTENT_TYPE;
import static software.amazon.awssdk.http.Header.HOST;
import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.*;

@Slf4j
public class AwsX509SigningHelper {

    private AwsX509SigningHelper() {}

    private static final JsonMapper OBJECT_MAPPER = new JsonMapper();
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
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

    public static String getDateAndTime(final Instant instant) {
        return dateTimeFormatter.format(instant);
    }

    public static String getDate(final Instant instant) {
        return getDateAndTime(instant).substring(0, 8);
    }

    @SneakyThrows
    public static byte[] hash(final String text) {
        MessageDigest digest = MessageDigest.getInstance(SHA_256);
        return digest.digest(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String signedHeaders() {
        return CONTENT_TYPE + SEMI_COLON + HOST + SEMI_COLON + X_AMZ_DATE + SEMI_COLON + X_AMZ_X509;
    }

    public static String signedHeadersWithChain() {
        return signedHeaders() + SEMI_COLON + X_AMZ_X509_CHAIN;
    }

    public static String canonicalRequest(final Instant instant,
                                          final String host,
                                          final String method,
                                          final String uri,
                                          final String body,
                                          final X509CertificateChain x509CertificateChain) throws NoSuchAlgorithmException, CertificateException {
        String dateAndTime = getDateAndTime(instant);
        String canonicalHeaders = "";
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
            String chainCerts = convertToBase64PEMString(x509CertificateChain.getIntermediateCACertificate());
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

    public static String hashContent(final String canonicalRequest) {
        return BinaryUtils.toHex(hash(canonicalRequest));
    }

    public static SortedMap<String, String> canonicalHeaders(final String host,
                                                       final String contentType,
                                                       final String date,
                                                       final String derX509) {
        SortedMap<String, String> headers = new TreeMap<>();
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
        SortedMap<String, String> headers = canonicalHeaders(host, contentType, date, derX509);
        return headers.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining(LINE_SEPARATOR)) + LINE_SEPARATOR;
    }

    public static String buildCanonicalHeaders(final String host,
                                               final String contentType,
                                               final String date,
                                               final String derX509,
                                               final String chainDerX509CommaSeparated) {
        SortedMap<String, String> headers = canonicalHeaders(host, contentType, date, derX509);
        headers.put(X_AMZ_X509_CHAIN.toLowerCase(), chainDerX509CommaSeparated);
        return headers.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining(LINE_SEPARATOR)) + LINE_SEPARATOR;
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

    public static String credentialScope(final Instant instant,
                                         final Region region) {
        String credentialScope = getDate(instant) + "/" + region.id() + "/" + ROLES_ANYWHERE_SERVICE + "/" + AWS4_TERMINATOR;
        log.debug("credentialScope: {}", credentialScope);
        return credentialScope;
    }

    public static String contentToSign(final Instant instant,
                                       final Region region,
                                       final String algorithm,
                                       final String canonicalRequest) {
        log.debug("canonicalRequest: \n{}", canonicalRequest);
        return algorithm + '\n' +
                getDateAndTime(instant) + '\n' +
                credentialScope(instant, region) + '\n' +
                hashContent(canonicalRequest);
    }

    public static String sign(final String contentToSign,
                              final PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(resolveSignatureAlgorithm(key));
        signature.initSign(key);

        signature.update(contentToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return BinaryUtils.toHex(signatureBytes);
    }

    public static String awsSignedAuthHeader(final Instant instant,
                                             final Region region,
                                             final String contentToSign,
                                             final String algorithm,
                                             final String signedHeaders,
                                             final X509Certificate cert,
                                             final PrivateKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String certId = cert.getSerialNumber().toString();
        String credentialPart = certId+"/"+credentialScope(instant, region);
        String signedContent = sign(contentToSign, key);

        return algorithm +
                " " +
                CREDENTIAL_PREFIX +
                credentialPart +
                CREDENTIALS_DE_LIMITER +
                SIGNED_HEADERS_PREFIX +
                signedHeaders +
                CREDENTIALS_DE_LIMITER +
                SIGNATURE_PREFIX +
                signedContent;
    }

    public static AwsRolesAnywhereSessionsResponse getIamRolesAnywhereSessions(
            final AwsRolesAnywhereSessionsRequest sessionsRequest,
            final AwsRolesAnyWhereRequesterDetails requesterDetails,
            final SdkHttpClient sdkHttpClient,
            final JsonMapper jm) {

        try {
            String request = jm.writeValueAsString(sessionsRequest);
            Region awsRegion = requesterDetails.getRegion();
            String host = resolveHostBasedOnRegion(awsRegion);
            X509CertificateChain x509CertificateChain = resolveCertificateChain(requesterDetails.getEncodedX509Certificate());

            log.debug("request: {}", request);

            Instant instant = Instant.now();

            String canonicalRequest = canonicalRequest(instant,
                    host,
                    SdkHttpMethod.POST.name(),
                    SESSIONS_URI,
                    request,
                    x509CertificateChain);

            String signingAlgorithm = resolveAwsAlgorithm(requesterDetails.getPrivateKey());
            String contentToSign = contentToSign(instant, awsRegion, signingAlgorithm, canonicalRequest);

            HttpExecuteResponse requestSpec = executeHttpRequest(instant, sessionsRequest, sdkHttpClient, requesterDetails, contentToSign, signingAlgorithm);

            // Print status code
            log.debug("Status Code is {} for AWS roles anywhere session endpoint", requestSpec.httpResponse().statusCode());

            // Read and print response body
            return getAwsRolesAnywhereSessionsResponse(jm, requestSpec);
        } catch (NoSuchAlgorithmException | IOException | CertificateException | NoSuchProviderException |
                 SignatureException | InvalidKeyException | IamException e) {
            throw IamException.builder()
                    .message("Error while trying to connect to AWS ROLES ANYWHERE")
                    .build();
        }
    }

    private static AwsRolesAnywhereSessionsResponse getAwsRolesAnywhereSessionsResponse(JsonMapper jm, HttpExecuteResponse requestSpec) throws IOException {
        log.info("AWS Roles anywhere sessions endpoint response status: {}", requestSpec.httpResponse().statusCode());
        Optional<String> responseBody = Optional.empty();
        if (requestSpec.responseBody().isPresent()) {
            responseBody = Optional.of(IoUtils.toUtf8String(requestSpec.responseBody().get()));
        }
        if (requestSpec.httpResponse().statusCode() == 201
                && responseBody.isPresent() && StringUtils.isNotBlank(responseBody.get())) {
            // enable complete response log via debug only
            log.debug("Successful Response from AWS roles anywhere sessions endpoint: {}", responseBody.get());
            return jm.readValue(responseBody.get(), AwsRolesAnywhereSessionsResponse.class);
        } else {
            log.debug("Failed! Error Response from AWS roles anywhere sessions endpoint is: {}", responseBody);
            log.error("failed response for the AWS ROLES ANYWHERE SESSION endpoint");
            throw IamException.builder()
                    .message("failed response for the AWS ROLES ANYWHERE SESSION endpoint")
                    .build();
        }
    }

    public static String resolveUri(final Region region) {
        return resolveHostEndpoint(region) + SESSIONS_URI;
    }

    private static HttpExecuteResponse executeHttpRequest(final Instant instant,
                                                          final AwsRolesAnywhereSessionsRequest sessionsRequest,
                                                          final SdkHttpClient sdkHttpClient,
                                                          final AwsRolesAnyWhereRequesterDetails requesterDetails,
                                                          final String contentToSign,
                                                          final String signingAlgorithm) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        String jsonBody = OBJECT_MAPPER.writeValueAsString(sessionsRequest);
        InputStream requestBodyStream = new ByteArrayInputStream(jsonBody.getBytes(StandardCharsets.UTF_8));

        Region awsRegion = requesterDetails.getRegion();

        SdkHttpFullRequest.Builder sdkHttpFullRequestBuilder = (SdkHttpFullRequest.Builder) SdkHttpFullRequest.builder()
                .uri(resolveUri(awsRegion))
                .method(SdkHttpMethod.POST)
                .putHeader(CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                .putHeader(X_AMZ_X509, convertToBase64PEMString(requesterDetails.getCertificateChain().getLeafCertificate()))
                .putHeader(X_AMZ_DATE, getDateAndTime(instant));

        X509Certificate cert = requesterDetails.getCertificateChain().getLeafCertificate();
        PrivateKey key = requesterDetails.getPrivateKey();

        String authHeader;
        if (requesterDetails.getCertificateChain().getIntermediateCACertificate() != null) {
            authHeader = awsSignedAuthHeader(instant, requesterDetails.getRegion(), contentToSign, signingAlgorithm, signedHeadersWithChain(), cert, key);
            sdkHttpFullRequestBuilder
                    .putHeader(X_AMZ_X509_CHAIN, convertToBase64PEMString(requesterDetails.getCertificateChain().getIntermediateCACertificate()))
                    .putHeader(AUTHORIZATION, authHeader);
        } else {
            authHeader = awsSignedAuthHeader(instant, requesterDetails.getRegion(), contentToSign, signingAlgorithm, signedHeaders(), cert, key);
            sdkHttpFullRequestBuilder.putHeader(AUTHORIZATION, authHeader);
        }

        HttpExecuteRequest request = HttpExecuteRequest.builder()
                .request(sdkHttpFullRequestBuilder.build())
                .contentStreamProvider(() -> requestBodyStream)
                .build();

        HttpExecuteResponse requestSpec = sdkHttpClient.prepareRequest(request).call();

        log.debug("authHeader: {}", authHeader);
        return requestSpec;
    }

}
