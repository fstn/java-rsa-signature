package com.fstn;

/**
 *
 */

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VerifyRSASignature
{
    private static KeyPair keyPair;

    public static KeyPair getKeyPair() {
        return keyPair;
    }

    public static void setKeyPair(KeyPair keyPair) {
        VerifyRSASignature.keyPair = keyPair;
    }

    private static Logger logger = Logger.getLogger(VerifyRSASignature.class.getName());

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
     * checkSignature with string
     * @param sig
     * @param input
     * @return
     * @throws Exception
     */
    public static boolean checkSignature(String sig, String input) throws Exception {
        if(sig != null && !sig.isEmpty() ) {
            return VerifyRSASignature.checkSignature(Base64.getDecoder().decode(sig), input);
        }else{
            logger.log(Level.WARNING,"empty signature");
            return false;
        }
    }

    /**
     * checkSignature with byte[]
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