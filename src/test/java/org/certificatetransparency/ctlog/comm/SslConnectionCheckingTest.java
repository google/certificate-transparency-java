package org.certificatetransparency.ctlog.comm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;
import org.certificatetransparency.ctlog.CertificateInfo;
import org.certificatetransparency.ctlog.LogInfo;
import org.certificatetransparency.ctlog.LogSignatureVerifier;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.utils.VerifySignature;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test checks that SSL connections to servers with a known good certificate can be verified
 * and connections without can be rejected. It serves as a programming example on how to use the
 * ctlog library.
 *
 * <p>There are three ways that certificate transparency information can be exchanged in the
 * connection handshake:
 *
 * <ul>
 *   <li>X509v3 certificate extension
 *   <li>TLS extension
 *   <li>OSCP stapling This test
 * </ul>
 *
 * only demonstrates how to validate using the first approach.
 *
 * @author Warwick Hunter
 * @since 0.1.3
 */
@RunWith(JUnit4.class)
public class SslConnectionCheckingTest {

  /** I want at least two different CT logs to verify the certificate */
  private static final int MIN_VALID_SCTS = 2;

  /** A CT log's Id is created by using this hash algorithm on the CT log public key */
  private static final String LOG_ID_HASH_ALGORITHM = "SHA-256";

  private static final Boolean VERBOSE = false;

  private Map<String, LogSignatureVerifier> verifiers = new HashMap<String, LogSignatureVerifier>();

  public SslConnectionCheckingTest() throws NoSuchAlgorithmException, InvalidKeySpecException {
    buildLogSignatureVerifiers();
  }

  @Test
  public void test() {
    checkConnection("https://github.com", true);
    checkConnection("https://letsencrypt.org", true);
    checkConnection("https://invalid-expected-sct.badssl.com/", false);
  }

  /**
   * Check if the certificates provided by a server have good certificate transparency information
   * in them that can be verified against a trusted certificate transparency log.
   *
   * @param urlString the URL of the server to check.
   * @param shouldPass true if the server will give good certificates, false otherwise.
   */
  private void checkConnection(String urlString, boolean shouldPass) {
    HttpsURLConnection con = null;
    try {
      URL url = new URL(urlString);
      con = (HttpsURLConnection) url.openConnection();
      con.connect();

      v(urlString);
      assertEquals(isGood(con.getServerCertificates()), shouldPass);

      int statusCode = con.getResponseCode();
      switch (statusCode) {
        case 200:
        case 403:
          break;
        default:
          fail(String.format("Unexpected HTTP status code: %d", statusCode));
      }
    } catch (IOException e) {
      fail(e.toString());
    } finally {
      if (con != null) {
        con.disconnect();
      }
    }
  }

  /**
   * Check if the certificates provided by a server contain Signed Certificate Timestamps from a
   * trusted CT log.
   *
   * @param certificates the certificate chain provided by the server
   * @return true if the certificates can be trusted, false otherwise.
   */
  private boolean isGood(Certificate[] certificates) {

    if (!(certificates[0] instanceof X509Certificate)) {
      v("  This test only supports SCTs carried in X509 certificates, of which there are none.");
      return false;
    }

    X509Certificate leafCertificate = (X509Certificate) certificates[0];

    if (!CertificateInfo.hasEmbeddedSCT(leafCertificate)) {
      v("  This certificate does not have any Signed Certificate Timestamps in it.");
      return false;
    }

    try {
      List<Ct.SignedCertificateTimestamp> sctsInCertificate =
          VerifySignature.parseSCTsFromCert(leafCertificate);
      if (sctsInCertificate.size() < MIN_VALID_SCTS) {
        v("  Two few SCTs are present, I want at least 2 CT logs to be nominated.");
        return false;
      }

      List<Certificate> certificateList = Arrays.asList(certificates);

      int validSctCount = 0;
      for (Ct.SignedCertificateTimestamp sct : sctsInCertificate) {
        String logId = Base64.toBase64String(sct.getId().getKeyId().toByteArray());
        if (verifiers.containsKey(logId)) {
          v("  SCT trusted log " + logId);
          if (verifiers.get(logId).verifySignature(sct, certificateList)) {
            ++validSctCount;
          }
        } else {
          v("  SCT untrusted log " + logId);
        }
      }

      if (validSctCount < MIN_VALID_SCTS) {
        v("  Two few trusted SCTs are present, I want at least 2 trusted CT logs.");
      }
      return validSctCount >= MIN_VALID_SCTS;

    } catch (IOException e) {
      if (VERBOSE) {
        e.printStackTrace();
      }
      return false;
    }
  }

  // A tiny collection of CT logs that are trusted for the purposes of this test. Derived from
  // https://www.certificate-transparency.org/known-logs -> https://www.gstatic.com/ct/log_list/log_list.json
  private static String[] TRUSTED_LOG_KEYS = {
    // Comodo 'Sabre' CT log : https://ct.grahamedgecombe.com/logs/34
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
    // Google 'Icarus' log : https://ct.grahamedgecombe.com/logs/25
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==",
    // Google Pilot log : https://ct.grahamedgecombe.com/logs/1
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==",
    // Google Skydiver log : https://ct.grahamedgecombe.com/logs/24
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==",
    // Cloudflare 'Nimbus2018' Log : https://ct.grahamedgecombe.com/logs/52
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAsVpWvrH3Ke0VRaMg9ZQoQjb5g/xh1z3DDa6IuxY5DyPsk6brlvrUNXZzoIg0DcvFiAn2kd6xmu4Obk5XA/nRg==",
    // DigiCert Yeti 2018 https://ct.grahamedgecombe.com/logs/56
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESYlKFDLLFmA9JScaiaNnqlU8oWDytxIYMfswHy9Esg0aiX+WnP/yj4O0ViEHtLwbmOQeSWBGkIu9YK9CLeer+g==",
  };

  /**
   * Construct LogSignatureVerifiers for each of the trusted CT logs.
   *
   * @throws InvalidKeySpecException the CT log key isn't RSA or EC, the key is probably corrupt.
   * @throws NoSuchAlgorithmException the crypto provider couldn't supply the hashing algorithm or
   *     the key algorithm. This probably means you are using an ancient or bad crypto provider.
   */
  private void buildLogSignatureVerifiers()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    MessageDigest hasher = MessageDigest.getInstance(LOG_ID_HASH_ALGORITHM);
    for (String trustedLogKey : TRUSTED_LOG_KEYS) {
      hasher.reset();
      byte[] keyBytes = Base64.decode(trustedLogKey);
      String logId = Base64.toBase64String(hasher.digest(keyBytes));
      KeyFactory keyFactory = KeyFactory.getInstance(determineKeyAlgorithm(keyBytes));
      PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
      verifiers.put(logId, new LogSignatureVerifier(new LogInfo(publicKey)));
    }
  }

  /** Parses a key and determines the key algorithm (RSA or EC) based on the ASN1 OID. */
  private static String determineKeyAlgorithm(byte[] keyBytes) {
    ASN1Sequence seq = ASN1Sequence.getInstance(keyBytes);
    DLSequence seq1 = (DLSequence) seq.getObjects().nextElement();
    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq1.getObjects().nextElement();
    if (oid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
      return "RSA";
    } else if (oid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
      return "EC";
    } else {
      throw new IllegalArgumentException("Unsupported key type " + oid);
    }
  }

  private void v(String message) {
    if (VERBOSE) {
      System.out.println(message);
    }
  }
}
