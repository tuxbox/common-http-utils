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
 * Created by iulius on 24/06/15.
 */
public class CalculateCertificateHash {

  private String certificatePath;
  private Certificate certificate;

  public CalculateCertificateHash(String path) {
    super();
    this.certificatePath = path;
  }

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

  public static void main(String[] args) throws Exception {
    if( args.length == 0 ) {
      CalculateCertificateHash calculateCertificateHash = new CalculateCertificateHash(args[0]);
      if( calculateCertificateHash.validateCertificate() ) {
        System.out.print(calculateCertificateHash.calculateHash());
      }
    }
  }

}
