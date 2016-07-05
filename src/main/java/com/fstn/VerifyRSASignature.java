package com.fstn;

/**
 *
 */

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Signature;

public class VerifyRSASignature
{
    private static KeyPair keyPair;

    public static KeyPair getKeyPair() {
        return keyPair;
    }

    public static void setKeyPair(KeyPair keyPair) {
        VerifyRSASignature.keyPair = keyPair;
    }

    /**
     *
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] genSignature(String input) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(keyPair.getPrivate());

        byte[] buffer = new byte[1024];
        InputStream in =  new ByteArrayInputStream(input.getBytes());
        int n;
        while ((n = in.read(buffer)) >= 0) {
            s.update(buffer, 0, n);
        }
        in.close();

        return s.sign();
    }

    /**
     *
     * @param sig
     * @param input
     * @return
     * @throws Exception
     */
    public static boolean checkSignature(byte[] sig, String input) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(keyPair.getPublic());

        byte[] buffer = new byte[1024];
        InputStream in = new ByteArrayInputStream(input.getBytes());
        int n;
        while ((n = in.read(buffer)) >= 0) {
            s.update(buffer, 0, n);
        }
        in.close();

        return s.verify(sig);
    }
}