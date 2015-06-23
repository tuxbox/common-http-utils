package me.sniggle.common.http;

import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Created by iulius on 24/06/15.
 */
public class CalculateCertificateHashSteps {

  private CalculateCertificateHash calculateCertificateHash;
  private String calculatedFingerprint;

  @Given("^I have the certificate for ([a-zA-Z0-9\\-\\.]+) in (DER|PEM|PKCS)$")
  public void i_have_the_certificate_for_host_in_format(String host, String format) throws Throwable {
    calculateCertificateHash = new CalculateCertificateHash("src/test/resources/"+host +"."+ format.toLowerCase());
  }

  @When("^I calculate the fingerprint for the given certificate$")
  public void i_calculate_the_fingerprint_for_the_given_certificate() throws Throwable {
    if( calculateCertificateHash.validateCertificate() ) {
      calculatedFingerprint = calculateCertificateHash.calculateHash();
    } else {
      fail("Certificate validation failed");
    }
  }

  @Then("^I expect the fingerprint to match ([a-zA-Z0-9\\:]+)")
  public void i_expect_the_fingerprint_to_match_fingerprint(String expectedFingerprint) throws Throwable {
    assertEquals(expectedFingerprint.replaceAll("[^a-zA-Z0-9]", "").toLowerCase(), calculatedFingerprint);
  }

}
