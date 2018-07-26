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
"MIIDmzCCAoOgAwIBAgIJAPhtOrdAIq6kMA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNV\n" +
"BAYTAnBoMQwwCgYDVQQIDANuY3IxDzANBgNVBAcMBm1ha2F0aTEMMAoGA1UECgwD\n" +
"c21lMQwwCgYDVQQLDANyJmQxGjAYBgNVBAMMESouc21laW50ZXJuZXQuY29tMB4X\n" +
"DTE4MDcyNjA2MDQzM1oXDTI4MDcyMzA2MDQzM1owZDELMAkGA1UEBhMCcGgxDDAK\n" +
"BgNVBAgMA25jcjEPMA0GA1UEBwwGbWFrYXRpMQwwCgYDVQQKDANzbWUxDDAKBgNV\n" +
"BAsMA3ImZDEaMBgGA1UEAwwRKi5zbWVpbnRlcm5ldC5jb20wggEiMA0GCSqGSIb3\n" +
"DQEBAQUAA4IBDwAwggEKAoIBAQD2U29cltxbovYmXA0ZkWEqvx59AdPAN9ezdiUm\n" +
"n9QirMnC1M6/HPtjTqUmwvrBJPEb/a3a/uGD/srvwrFXqzH2ftrHeWFAXiofhrij\n" +
"XeFy3o6SmfBcGGglc3/ZNk2896IJQBDHpXp9ACUTkYjJKF1sqIeiZw6MF9tfNklV\n" +
"SWDyeeBasaMNNJTLJw+7d/IiGGOSgZiopGy6EjMfnMbnk+I0kZCNAx9inMDqvKdL\n" +
"Tc60sbfY2eVZpkJg839Cx3j3jx4Yxdizhgxigv5Digle9faxyhdPs6ovquTcirlP\n" +
"qEDJ3LeCFdgdgUS9tvbWN6yINdAgXjnOh1/Su3kHNM7McWszAgMBAAGjUDBOMB0G\n" +
"A1UdDgQWBBSWhHWzQu7y24H+X/n0Evc3eVRtbDAfBgNVHSMEGDAWgBSWhHWzQu7y\n" +
"24H+X/n0Evc3eVRtbDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDK\n" +
"D0Yb/CVN56iekzwuL9GfA5gYxWh8NNNsdvX940y7D40D9S2oitA4CIFlTt7+iAQr\n" +
"/mlfBBZoKXWCaBmUxn2HovuOdOc5b7q7zIOGdWMscwHTTYOD0ScTY2bsmYDMabhu\n" +
"2P6WcMK/fCplneLzaJOI1ba32OCY33SaVAVvwIJ9V0B5jclR0woKtXgp7ArNkezC\n" +
"mWWrNiIaq4gFj3AyMaULGdXZ6tYlheFyuANDXAr0faIkkk+6DF8O1Xc7apFYfXo9\n" +
"vGEOXPw+si5OnahvBhFaCpvhzXardrVddh7ISDuZBZu0EIJUJOi6jIanGUpfRKj+\n" +
"iOSoyrAs5SHXK9GEkJ+E\n" +
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
