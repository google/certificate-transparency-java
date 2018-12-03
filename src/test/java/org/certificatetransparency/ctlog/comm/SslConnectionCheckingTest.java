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
 *   <li>OCSP stapling
 * </ul>
 *
 * This test only demonstrates how to validate using the first approach.
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
        v("  Too few SCTs are present, I want at least " + MIN_VALID_SCTS + " CT logs to vouch for this certificate.");
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
        v("  Too few SCTs are present, I want at least " + MIN_VALID_SCTS + " CT logs to vouch for this certificate.");
      }
      return validSctCount >= MIN_VALID_SCTS;

    } catch (IOException e) {
      if (VERBOSE) {
        e.printStackTrace();
      }
      return false;
    }
  }

  // A collection of CT logs that are trusted for the purposes of this test. Derived from
  // https://www.certificate-transparency.org/known-logs -> https://www.gstatic.com/ct/log_list/log_list.json
  private static final String[] TRUSTED_LOG_KEYS = {
    // Comodo 'Sabre' CT log : https://ct.grahamedgecombe.com/logs/34
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
    //"Comodo 'Mammoth' CT log", https://mammoth.ct.comodo.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==",
    // Google 'Icarus' log : https://ct.grahamedgecombe.com/logs/25
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==",
    // Google Pilot log : https://ct.grahamedgecombe.com/logs/1
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==",
    // Google Skydiver log : https://ct.grahamedgecombe.com/logs/24
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==",
    //"Google 'Argon2018' log",https://ct.googleapis.com/logs/argon2018/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp37MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA==",
    //"Google 'Argon2019' log", https://ct.googleapis.com/logs/argon2019/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI3MQm+HzXvaYa2mVlhB4zknbtAT8cSxakmBoJcBKGqGwYS0bhxSpuvABM1kdBTDpQhXnVdcq+LSiukXJRpGHVg==",
    //"Google 'Argon2020' log", https://ct.googleapis.com/logs/argon2020/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==",
    //"Google 'Argon2021' log", https://ct.googleapis.com/logs/argon2021/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw==",
    //"Google 'Aviator' log", https://ct.googleapis.com/aviator/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==",
    //"Google 'Rocketeer' log", https://ct.googleapis.com/rocketeer/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
    // Cloudflare 'Nimbus2018' Log : https://ct.grahamedgecombe.com/logs/52
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAsVpWvrH3Ke0VRaMg9ZQoQjb5g/xh1z3DDa6IuxY5DyPsk6brlvrUNXZzoIg0DcvFiAn2kd6xmu4Obk5XA/nRg==",
    //"Cloudflare 'Nimbus2019' Log", https://ct.cloudflare.com/logs/nimbus2019/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZHz1v5r8a9LmXSMegYZAg4UW+Ug56GtNfJTDNFZuubEJYgWf4FcC5D+ZkYwttXTDSo4OkanG9b3AI4swIQ28g==",
    //"Cloudflare 'Nimbus2020' Log", https://ct.cloudflare.com/logs/nimbus2020/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE01EAhx4o0zPQrXTcYjgCt4MVFsT0Pwjzb1RwrM0lhWDlxAYPP6/gyMCXNkOn/7KFsjL7rwk78tHMpY8rXn8AYg==",
    //"Cloudflare 'Nimbus2021' Log", https://ct.cloudflare.com/logs/nimbus2021/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExpon7ipsqehIeU1bmpog9TFo4Pk8+9oN8OYHl1Q2JGVXnkVFnuuvPgSo2Ep+6vLffNLcmEbxOucz03sFiematg==",
    //"DigiCert Log Server", https://ct1.digicert-ct.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==",
    //"DigiCert Log Server 2", https://ct2.digicert-ct.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA==",
    // DigiCert Yeti 2018 https://ct.grahamedgecombe.com/logs/56
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESYlKFDLLFmA9JScaiaNnqlU8oWDytxIYMfswHy9Esg0aiX+WnP/yj4O0ViEHtLwbmOQeSWBGkIu9YK9CLeer+g==",
    //"DigiCert Yeti2019 Log", https://yeti2019.ct.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZd/ow8X+FSVWAVSf8xzkFohcPph/x6pS1JHh7g1wnCZ5y/8Hk6jzJxs6t3YMAWz2CPd4VkCdxwKexGhcFxD9A==",
    //"DigiCert Yeti2020 Log", https://yeti2020.ct.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEURAG+Zo0ac3n37ifZKUhBFEV6jfcCzGIRz3tsq8Ca9BP/5XUHy6ZiqsPaAEbVM0uI3Tm9U24RVBHR9JxDElPmg==",
    //"DigiCert Yeti2021 Log", https://yeti2021.ct.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6J4EbcpIAl1+AkSRsbhoY5oRTj3VoFfaf1DlQkfi7Rbe/HcjfVtrwN8jaC+tQDGjF+dqvKhWJAQ6Q6ev6q9Mew==",
    //"DigiCert Yeti2022 Log", https://yeti2022.ct.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn/jYHd77W1G1+131td5mEbCdX/1v/KiYW5hPLcOROvv+xA8Nw2BDjB7y+RGyutD2vKXStp/5XIeiffzUfdYTJg==",
    //"Symantec log", https://ct.ws.symantec.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==",
    //"Symantec 'Vega' log", https://vega.ws.symantec.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==",
    //"Symantec 'Sirius' log", https://sirius.ws.symantec.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEowJkhCK7JewN47zCyYl93UXQ7uYVhY/Z5xcbE4Dq7bKFN61qxdglnfr0tPNuFiglN+qjN2Syxwv9UeXBBfQOtQ==",
    //"Certly.IO log", https://log.certly.io/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==",
    //"WoSign log", https://ctlog.wosign.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQvAdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ==",
    //"Venafi log", https://ctlog.api.venafi.com/",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB",
    //"Venafi Gen2 CT log", https://ctlog-gen2.api.venafi.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjicnerZVCXTrbEuUhGW85BXx6lrYfA43zro/bAna5ymW00VQb94etBzSg4j/KS/Oqf/fNN51D8DMGA2ULvw3AQ==",
    //"CNNIC CT log", https://ctserver.cnnic.cn/",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXhhuAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhsHq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLaypvurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYtNQIDAQAB",
    //"StartCom log", https://ct.startssl.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajWTOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ==",
    //"Izenpe log", https://ct.izenpe.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==",
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
