package io.robbtsang.demo;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Component
public class CertVerficationHelper implements VerificationHelper<String> {
    static final Certificate CA;
    static {
        Certificate ca;
        try {
            String caCert =
"-----BEGIN CERTIFICATE-----\n" +
"MIIDmzCCAoOgAwIBAgIJAKNYq8TT+0EkMA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNV\n" +
"BAYTAnBoMQwwCgYDVQQIDANuY3IxDzANBgNVBAcMBm1ha2F0aTEMMAoGA1UECgwD\n" +
"c21lMQwwCgYDVQQLDANyJmQxGjAYBgNVBAMMESouc21laW50ZXJuZXQuY29tMB4X\n" +
"DTE4MDcyNjA2NTExNFoXDTI4MDcyMzA2NTExNFowZDELMAkGA1UEBhMCcGgxDDAK\n" +
"BgNVBAgMA25jcjEPMA0GA1UEBwwGbWFrYXRpMQwwCgYDVQQKDANzbWUxDDAKBgNV\n" +
"BAsMA3ImZDEaMBgGA1UEAwwRKi5zbWVpbnRlcm5ldC5jb20wggEiMA0GCSqGSIb3\n" +
"DQEBAQUAA4IBDwAwggEKAoIBAQDBgfi3aj8r17nvdigg4rsZAM+gu7KLW77Jtp0w\n" +
"mBwuqSuXq57rZQOHQyHDn4g9E2U/VQPs5YOImmwFMGnRqryA5QgmwqZ2Z+Sk/uQY\n" +
"pWfkbvOwlXIUIqwU8EKB7QzJ8RpMnccod91Ngp5Mm+HZoZmA54mwFaiEYc/Ydyxz\n" +
"eb526lZN81TzYRm+JoONnDDW7afKDExQDJYXT0nl5TvO+3qaC11vANmQSVY8zruB\n" +
"eUGmD9Tdgr9ol9mVWeIFrASZeg1+TthrLHEsSDe8nXBwvJLH2g+6yMVwwqRG3w7I\n" +
"IAqly2SQRiqie5CjC8fJJLCSJXgima226qQT6Xn7oN5UvcE7AgMBAAGjUDBOMB0G\n" +
"A1UdDgQWBBR4bnckLOma/eoNxS7SljEgzLxf1jAfBgNVHSMEGDAWgBR4bnckLOma\n" +
"/eoNxS7SljEgzLxf1jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAS\n" +
"V/FAfIJZd7TdW2oSaFns+mZm7yjdAmsK3Qh6MqvntFW/ufKZgovKwV5NDANjqmDj\n" +
"O2LVHV3oftu3Nv2fuDzMktLMGcQHk2SXHXxpdsNvOOCf+GOAeNBMJJWPqJ1acj4J\n" +
"SaT3NoN2s6TZu8y68rzTh5UKcAlotQHLZeMReScak/iwk4UN2Q6aw58JJQE6zl52\n" +
"Yyz5uC1brb/q1nPbhx3xEycH1Am1PvNN03jBXl5t8Eo9BUmNIRcLpnJmyV/Euqsz\n" +
"XSQRBtX9sdIJYFPOPFWOlgGaq643b9BAvwE4tpQhzSywDmReBgpffitEHaiALeyH\n" +
"zi/p48HPo3aqGoOsvR6a\n" +
"-----END CERTIFICATE-----"
            ;

            ByteArrayInputStream bin = new ByteArrayInputStream(caCert.getBytes("UTF-8"));

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ca = cf.generateCertificate(bin);
        } catch (Exception ex) {
            ca = null;
        }
        CA = ca;
    }

    @Override
    public boolean verify(String ... paths) {
        System.out.println("===== certificates verification begin =====");
        boolean pass = true;
        CertificateFactory cf = null;
        for (String path:paths) {
            System.out.println("--- " + path + " ---");
            try {
                if( null == cf ) {
                    cf = CertificateFactory.getInstance("X.509");
                }

                X509Certificate crt;
                try(FileInputStream in = new FileInputStream(new ClassPathResource(path).getFile())){
                    crt = (X509Certificate)cf.generateCertificate(in);
                } catch (Throwable e) {
                    throw e;
                }

                CA.verify(CA.getPublicKey());
                crt.verify(CA.getPublicKey());

                System.out.println(crt.getNotBefore() + " ~ " + crt.getNotAfter());

                crt.checkValidity();
                System.out.println(path + ": pass");
            } catch (Throwable e) {
                // e.printStackTrace();
                pass = false;
                System.out.println(path + ": not pass");
            }
        }
        System.out.println("===== certificates verification end =====");

        return pass;
    }
}
