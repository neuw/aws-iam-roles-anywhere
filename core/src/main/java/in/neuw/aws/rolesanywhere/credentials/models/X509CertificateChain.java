package in.neuw.aws.rolesanywhere.credentials.models;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.security.cert.X509Certificate;

/**
 * This class is primarily needed for chain of certs in case of the client cert was signed by an intermediate instead of root
 */
@Getter
@Setter
@Accessors(chain = true)
public class X509CertificateChain {

    private String base64EncodedCertificate;
    private X509Certificate rootCACertificate;
    private X509Certificate intermediateCACertificate;
    private X509Certificate leafCertificate;

}
