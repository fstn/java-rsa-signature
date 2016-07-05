package com.fstn;

import com.fstn.exception.UnableToCreateKeysException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by SZA on 05/07/2016.
 */
public class KeyManager
{

    private KeyPair keys = null;
    private static KeyManager instance;
    private static Logger logger = Logger.getLogger(KeyManager.class.getName());

    private KeyManager()  {
        try {
            keys =  generateKeyPair(999);
        } catch (Exception e) {
            logger.log(Level.WARNING, "Unable to create keys",e);
            throw new UnableToCreateKeysException();
        }
    }

    /**
     * Get keys to use for application
     * @return
     */
    public static KeyManager getInstance() {
        if(instance == null){
            instance = new KeyManager();
        }
        return instance;
    }

    /**
     *
     * @param seed
     * @return
     * @throws Exception
     */
    private KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
    }

    public KeyPair getKeys() {
        return keys;
    }

    public void setKeys(KeyPair keys) {
        this.keys = keys;
    }
}
