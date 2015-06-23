package me.sniggle.common.http;

import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CertificateFingerprintHostnameVerifierSteps {

  private CertificateFactory certificateFactory;
  private Map<String, String> hostnames;
  private CertificateFingerprintHostnameVerifier hostnameVerifier;
  private boolean actualResult = false;

  public CertificateFingerprintHostnameVerifierSteps() {
    try {
      certificateFactory = CertificateFactory.getInstance("X.509");
    } catch(Exception e) {
      certificateFactory = null;
    }
  }

  @Given("^I have the following fingerprints and hosts$")
  public void i_have_the_following_fingerprints_and_hosts(Map<String, String> hostnames) throws Throwable {
    this.hostnames = hostnames;
    hostnameVerifier = new CertificateFingerprintHostnameVerifier(hostnames);
  }

  @When("^I verify the certificate for the hostname$")
  public void i_verify_the_certificate_for_the_hostname() throws Throwable {
    Object[] hostnames = this.hostnames.keySet().toArray();
    try {
      final Certificate certificate = certificateFactory.generateCertificate(Files.newInputStream(Paths.get("src/test/resources/" + hostnames[0] + ".pem")));
      actualResult = hostnameVerifier.verify(hostnames[0].toString(), new SSLSession() {
        @Override
        public byte[] getId() {
          return new byte[0];
        }

        @Override
        public SSLSessionContext getSessionContext() {
          return null;
        }

        @Override
        public long getCreationTime() {
          return 0;
        }

        @Override
        public long getLastAccessedTime() {
          return 0;
        }

        @Override
        public void invalidate() {

        }

        @Override
        public boolean isValid() {
          return false;
        }

        @Override
        public void putValue(String s, Object o) {

        }

        @Override
        public Object getValue(String s) {
          return null;
        }

        @Override
        public void removeValue(String s) {

        }

        @Override
        public String[] getValueNames() {
          return new String[0];
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
          return new Certificate[] {certificate};
        }

        @Override
        public Certificate[] getLocalCertificates() {
          return new Certificate[0];
        }

        @Override
        public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
          return new X509Certificate[0];
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
          return null;
        }

        @Override
        public Principal getLocalPrincipal() {
          return null;
        }

        @Override
        public String getCipherSuite() {
          return null;
        }

        @Override
        public String getProtocol() {
          return null;
        }

        @Override
        public String getPeerHost() {
          return null;
        }

        @Override
        public int getPeerPort() {
          return 0;
        }

        @Override
        public int getPacketBufferSize() {
          return 0;
        }

        @Override
        public int getApplicationBufferSize() {
          return 0;
        }
      });
    } catch(Exception e){

    }
  }

  @Then("^I expect the validation to (succeed|fail)$")
  public void i_expect_the_validation_to_mode(String mode) throws Throwable {
    if( "succeed".equals(mode) ) {
      assertTrue(actualResult);
    } else if( "fail".equals(mode) ) {
      assertFalse(actualResult);
    }
  }

}