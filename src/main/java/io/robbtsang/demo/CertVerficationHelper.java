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
"MIIDmzCCAoOgAwIBAgIJAK/aT2fBdrB2MA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNV\n" +
"BAYTAnBoMQwwCgYDVQQIDANuY3IxDzANBgNVBAcMBm1ha2F0aTEMMAoGA1UECgwD\n" +
"c21lMQwwCgYDVQQLDANyJmQxGjAYBgNVBAMMESouc21laW50ZXJuZXQuY29tMB4X\n" +
"DTE4MDcyNjA2NTUxM1oXDTI4MDcyMzA2NTUxM1owZDELMAkGA1UEBhMCcGgxDDAK\n" +
"BgNVBAgMA25jcjEPMA0GA1UEBwwGbWFrYXRpMQwwCgYDVQQKDANzbWUxDDAKBgNV\n" +
"BAsMA3ImZDEaMBgGA1UEAwwRKi5zbWVpbnRlcm5ldC5jb20wggEiMA0GCSqGSIb3\n" +
"DQEBAQUAA4IBDwAwggEKAoIBAQDNPuRvxBd0T+JSRdOiN5DTe1Rb6uzLh+ocHXfA\n" +
"trZC2DuP7cqqzmCnWJltNOT5t/Lt2X1BIzmzNWWsVD/Sr53fHDLpJ89izcuB2Y2S\n" +
"L1xzacUfXLCPoMkG5ZRmf/O4xz+Ov0HvwS7qfdmtyfeL7bgLMxTo4IuJVvJeSIBq\n" +
"BysQgBy4P2TUC8LlosDgqJ96S7V83ULGAjK0XTPYYK0SEI79oZnhup84OtDpYy+6\n" +
"YJGt0IvbzOyQg+9AWBZsA2I0U2mmuR3zLsfqy9Pn8MaHjLOPAv60N56H25adK+m0\n" +
"L2nw/rIT2T4oZgQuIxJob06vDwegkhe8wR8K2T+tTNb4mR5PAgMBAAGjUDBOMB0G\n" +
"A1UdDgQWBBT5u3ggofvo6NXXM5I5bEC/xqq+djAfBgNVHSMEGDAWgBT5u3ggofvo\n" +
"6NXXM5I5bEC/xqq+djAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAS\n" +
"KkAwTmjOIMgvOEovKRYQrGAfY03ddM+uL2S1goMmq8UJxd2g4YkpgKzmGjM+V0Fu\n" +
"i8VkAor7oKkd7BxLO82pVxCAoFS/OHC/45jHpgcjjUcxSv0TzbAxB3WB0xeKTZ1H\n" +
"m8Oj8P3dfA1lZo4Ek5rihFNVIzBDyA72zrH3ge5vmBy9AzD0RY9L11R6KQJUpJGi\n" +
"p8l1hgcmlM5FWLDIeh9D5Ee+Fb940XCu6VIaNq7BiChN0dK0paYJOOQ2Ycb9WQVS\n" +
"UtL69DfnKaOg+J7dn80YXHMRMbv4Sw2GNyJt1vRuqoU54WPwDWxrJmcoaWdnwy5g\n" +
"23/yFHEnCjXoPrvN/z4o\n" +
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
