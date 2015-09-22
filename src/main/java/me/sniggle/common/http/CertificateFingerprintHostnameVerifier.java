package me.sniggle.common.http;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.conn.util.DomainType;
import org.apache.http.conn.util.InetAddressUtils;
import org.apache.http.conn.util.PublicSuffixMatcher;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Created by iulius on 22/06/15.
 *
 * Copy of the Apache HTTPComponents DefaultHostnameVerifier with
 * additional functionality in order to support Certificate Pinning
 */
public class CertificateFingerprintHostnameVerifier implements HostnameVerifier {

  private final Map<String, String> fingerprints = new HashMap<>();
  private final PublicSuffixMatcher publicSuffixMatcher;

  /**
   *
   * @param fingerprints
   *          key: hostname, value: SHA256-Hex Hash
   */
  public CertificateFingerprintHostnameVerifier(Map<String, String> fingerprints) {
    this(fingerprints, null);
  }

  /**
   *
   * @param fingerprints
   *          key: hostname, value: SHA256-Hex Hash
   * @param publicSuffixMatcher
   */
  public CertificateFingerprintHostnameVerifier(Map<String, String> fingerprints, PublicSuffixMatcher publicSuffixMatcher) {
    super();
    if( fingerprints != null ) {
      for( Map.Entry<String, String> e : fingerprints.entrySet() ) {
        add(e.getKey(), e.getValue());
      }
    }
    this.publicSuffixMatcher = publicSuffixMatcher;
  }

  /**
   *
   * @param hostname
   *  the host to add
   * @param fingerprint
   *  the SHA256-Hex Hash
   * @return the instance of the hostname verifier
   */
  public CertificateFingerprintHostnameVerifier add(String hostname, String fingerprint) {
    String lhostname = (hostname != null) ? hostname.toLowerCase(Locale.ROOT) : null;
    if( lhostname != null && fingerprint != null ) {
      this.fingerprints.put(lhostname, fingerprint.replaceAll("[^a-zA-Z0-9]","").toLowerCase(Locale.ROOT));
    }
    return this;
  }

  /**
   *
   * @param sslSession
   * @return
   */
  protected Certificate extractCertificate(SSLSession sslSession) {
    Certificate result = null;
    try {
      if (sslSession != null) {
        Certificate[] cs = sslSession.getPeerCertificates();
        if( cs != null && cs.length > 0 ) {
          result = cs[0];
        }
      }
    } catch(SSLException e) {

    }
    return result;
  }

  /**
   *
   * @param host
   * @param cert
   * @throws SSLException
   */
  protected void verify(String host, X509Certificate cert) throws SSLException {
    boolean ipv4 = InetAddressUtils.isIPv4Address(host);
    boolean ipv6 = InetAddressUtils.isIPv6Address(host);
    int subjectType = !ipv4 && !ipv6?2:7;
    List subjectAlts = extractSubjectAlts(cert, subjectType);
    if(subjectAlts != null && !subjectAlts.isEmpty()) {
      if(ipv4) {
        matchIPAddress(host, subjectAlts);
      } else if(ipv6) {
        matchIPv6Address(host, subjectAlts);
      } else {
        matchDNSName(host, subjectAlts, this.publicSuffixMatcher);
      }
    } else {
      X500Principal subjectPrincipal = cert.getSubjectX500Principal();
      String cn = extractCN(subjectPrincipal.getName("RFC2253"));
      if(cn == null) {
        throw new SSLException("Certificate subject for <" + host + "> doesn\'t contain " + "a common name and does not have alternative names");
      }

      matchCN(host, cn, this.publicSuffixMatcher);
    }

  }

  /**
   *
   * @param host
   * @param subjectAlts
   * @throws SSLException
   */
  protected void matchIPAddress(String host, List<String> subjectAlts) throws SSLException {
    for(int i = 0; i < subjectAlts.size(); ++i) {
      String subjectAlt = (String)subjectAlts.get(i);
      if(host.equals(subjectAlt)) {
        return;
      }
    }

    throw new SSLException("Certificate for <" + host + "> doesn\'t match any " + "of the subject alternative names: " + subjectAlts);
  }

  /**
   *
   * @param host
   * @param subjectAlts
   * @throws SSLException
   */
  protected void matchIPv6Address(String host, List<String> subjectAlts) throws SSLException {
    String normalisedHost = normaliseAddress(host);

    for(int i = 0; i < subjectAlts.size(); ++i) {
      String subjectAlt = (String)subjectAlts.get(i);
      String normalizedSubjectAlt = normaliseAddress(subjectAlt);
      if(normalisedHost.equals(normalizedSubjectAlt)) {
        return;
      }
    }

    throw new SSLException("Certificate for <" + host + "> doesn\'t match any " + "of the subject alternative names: " + subjectAlts);
  }

  /**
   *
   * @param host
   * @param subjectAlts
   * @param publicSuffixMatcher
   * @throws SSLException
   */
  protected void matchDNSName(String host, List<String> subjectAlts, PublicSuffixMatcher publicSuffixMatcher) throws SSLException {
    String normalizedHost = host.toLowerCase(Locale.ROOT);

    for(int i = 0; i < subjectAlts.size(); ++i) {
      String subjectAlt = (String)subjectAlts.get(i);
      String normalizedSubjectAlt = subjectAlt.toLowerCase(Locale.ROOT);
      if(matchIdentityStrict(normalizedHost, normalizedSubjectAlt, publicSuffixMatcher)) {
        return;
      }
    }

    throw new SSLException("Certificate for <" + host + "> doesn\'t match any " + "of the subject alternative names: " + subjectAlts);
  }

  /**
   *
   * @param host
   * @param cn
   * @param publicSuffixMatcher
   * @throws SSLException
   */
  protected void matchCN(String host, String cn, PublicSuffixMatcher publicSuffixMatcher) throws SSLException {
    if(!matchIdentityStrict(host, cn, publicSuffixMatcher)) {
      throw new SSLException("Certificate for <" + host + "> doesn\'t match " + "common name of the certificate subject: " + cn);
    }
  }

  /**
   *
   * @param subjectPrincipal
   * @return
   * @throws SSLException
   */
  protected String extractCN(String subjectPrincipal) throws SSLException {
    if(subjectPrincipal == null) {
      return null;
    } else {
      try {
        LdapName e = new LdapName(subjectPrincipal);
        List rdns = e.getRdns();

        for(int i = rdns.size() - 1; i >= 0; --i) {
          Rdn rds = (Rdn)rdns.get(i);
          Attributes attributes = rds.toAttributes();
          Attribute cn = attributes.get("cn");
          if(cn != null) {
            try {
              Object ignore = cn.get();
              if(ignore != null) {
                return ignore.toString();
              }
            } catch (NoSuchElementException var8) {
              ;
            } catch (NamingException var9) {
              ;
            }
          }
        }

        return null;
      } catch (InvalidNameException var10) {
        throw new SSLException(subjectPrincipal + " is not a valid X500 distinguished name");
      }
    }
  }

  /**
   *
   * @param cert
   * @param subjectType
   * @return
   */
  protected List<String> extractSubjectAlts(X509Certificate cert, int subjectType) {
    Collection c = null;

    try {
      c = cert.getSubjectAlternativeNames();
    } catch (CertificateParsingException var9) {
      ;
    }

    ArrayList subjectAltList = null;
    if(c != null) {
      Iterator i$ = c.iterator();

      while(i$.hasNext()) {
        List aC = (List)i$.next();
        int type = ((Integer)aC.get(0)).intValue();
        if(type == subjectType) {
          String s = (String)aC.get(1);
          if(subjectAltList == null) {
            subjectAltList = new ArrayList();
          }

          subjectAltList.add(s);
        }
      }
    }

    return subjectAltList;
  }

  /**
   *
   * @param hostname
   * @return
   */
  protected String normaliseAddress(String hostname) {
    if(hostname == null) {
      return hostname;
    } else {
      try {
        InetAddress unexpected = InetAddress.getByName(hostname);
        return unexpected.getHostAddress();
      } catch (UnknownHostException var2) {
        return hostname;
      }
    }
  }

  /**
   *
   * @param host
   * @param domainRoot
   * @return
   */
  protected boolean matchDomainRoot(String host, String domainRoot) {
    return domainRoot == null?false:host.endsWith(domainRoot) && (host.length() == domainRoot.length() || host.charAt(host.length() - domainRoot.length() - 1) == 46);
  }

  /**
   *
   * @param host
   * @param identity
   * @param publicSuffixMatcher
   * @param strict
   * @return
   */
  protected boolean matchIdentity(String host, String identity, PublicSuffixMatcher publicSuffixMatcher, boolean strict) {
    if(publicSuffixMatcher != null && host.contains(".") && !matchDomainRoot(host, publicSuffixMatcher.getDomainRoot(identity, DomainType.ICANN))) {
      return false;
    } else {
      int asteriskIdx = identity.indexOf(42);
      if(asteriskIdx != -1) {
        String prefix = identity.substring(0, asteriskIdx);
        String suffix = identity.substring(asteriskIdx + 1);
        if(!prefix.isEmpty() && !host.startsWith(prefix)) {
          return false;
        } else if(!suffix.isEmpty() && !host.endsWith(suffix)) {
          return false;
        } else {
          if(strict) {
            String remainder = host.substring(prefix.length(), host.length() - suffix.length());
            if(remainder.contains(".")) {
              return false;
            }
          }

          return true;
        }
      } else {
        return host.equalsIgnoreCase(identity);
      }
    }
  }

  /**
   *
   * @param host
   * @param identity
   * @param publicSuffixMatcher
   * @return
   */
  protected boolean matchIdentity(String host, String identity, PublicSuffixMatcher publicSuffixMatcher) {
    return matchIdentity(host, identity, publicSuffixMatcher, false);
  }

  /**
   *
   * @param host
   * @param identity
   * @return
   */
  protected boolean matchIdentity(String host, String identity) {
    return matchIdentity(host, identity, (PublicSuffixMatcher)null, false);
  }

  /**
   *
   * @param host
   * @param identity
   * @param publicSuffixMatcher
   * @return
   */
  protected boolean matchIdentityStrict(String host, String identity, PublicSuffixMatcher publicSuffixMatcher) {
    return matchIdentity(host, identity, publicSuffixMatcher, true);
  }

  /**
   *
   * @param host
   * @param identity
   * @return
   */
  protected boolean matchIdentityStrict(String host, String identity) {
    return matchIdentity(host, identity, (PublicSuffixMatcher)null, true);
  }

  /**
   *
   * @param hostname
   * @param c
   * @return
   * @throws CertificateEncodingException
   */
  protected boolean verifyFingerprint(String hostname, Certificate c) throws CertificateEncodingException {
    boolean result = false;
    if( !fingerprints.isEmpty() ) {
      String actualFingerprint = DigestUtils.sha256Hex(c.getEncoded());
      String expectedFingerprint = fingerprints.get(hostname);
      result |= actualFingerprint.equals(expectedFingerprint);
    }
    return result;
  }

  @Override
  public boolean verify(String s, SSLSession sslSession) {
    Certificate c = extractCertificate(sslSession);
    boolean result = false;
    if( c != null ) {
      try {
        verify(s, (X509Certificate) c);
        if( !verifyFingerprint(s, c) ) {
          throw new SSLException("known fingerprint for the known certificate for host " + s + " does not match with actual");
        }
        result = true;
      } catch(SSLException e) {
        result &= false;
      } catch (CertificateEncodingException e) {
        result &= false;
      }
    }
    return result;
  }
}
