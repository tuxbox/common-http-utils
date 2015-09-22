package me.sniggle.common.http;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Helper class to calculate the Hash to verify the certificate with
 */
public class CalculateCertificateHash {

  private String certificatePath;
  private Certificate certificate;

  /**
   *
   * @param path
   *    the path to the certificate
   */
  public CalculateCertificateHash(String path) {
    super();
    this.certificatePath = path;
  }

  /**
   * validates that the given certificate path exists and the Certificate could be read
   *
   * @return true if Certificate read successfully from path
   */
  public boolean validateCertificate() {
    boolean result = false;
    if( certificatePath != null ) {
      Path certificateDirectory = Paths.get(certificatePath);
      if( Files.exists(certificateDirectory) ) {
        try {
          certificate = CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(certificateDirectory));
          result = true;
        } catch( CertificateException | IOException e) {
          e.printStackTrace();
        }
      }
    }
    return result;
  }

  /**
   * calculates the SHA-256 hash and converts it to a Hex String
   *
   * @return the Hex String or null
   */
  public String calculateHash() {
    String result = null;
    if( certificate != null ) {
      try {
        result = DigestUtils.sha256Hex(certificate.getEncoded());
      } catch( CertificateException e ){

      }
    }
    return result;
  }

  /**
   * main method to be called from command line
   *
   * @param args
   *    takes the absolute path to the certificate to fingerprint
   * @throws Exception
   */
  public static void main(String[] args) throws Exception {
    if( args.length == 1 ) {
      CalculateCertificateHash calculateCertificateHash = new CalculateCertificateHash(args[0]);
      if( calculateCertificateHash.validateCertificate() ) {
        System.out.print(calculateCertificateHash.calculateHash());
      }
    }
  }

}
