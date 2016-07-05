import com.fstn.KeyManager;
import com.fstn.VerifyRSASignature;
import org.junit.Assert;
import org.junit.Test;

import java.util.Base64;

/**
 * Created by SZA on 05/07/2016.
 */
public class VerifyRSASignTest
{
    //language=json
    String json = "{\"name\":\"admin\",\"principals\":[{\"repositoryname\":\"dss-default\",\"name\":\"admin\"," +
        "\"nativeprincipal\":{\"authenticated\":true,\"name\":\"admin\",\"anonymous\":false," +
        "\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine.client.TenantIdentifier\",\"java.io" +
        ".Serializable\"]},\"id\":\"18a6b5bc-528d-4071-8694-0f017708e4b8\"," +
        "\"useridentifier\":{\"name\":\"admin\",\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine" +
        ".client.TenantIdentifier\",\"java.io.Serializable\"]},\"id\":1,\"class\":[\"eu.w4.engine.client" +
        ".UserIdentifier\",\"java.io.Serializable\"]},\"class\":[\"eu.w4.engine.client.EnginePrincipal\",\"java" +
        ".io.Serializable\"]},\"id\":\"33b1eadf-fd77-402f-b181-9ae2256a0e93\",\"class\":[\"eu.w4.engine.client" +
        ".eci.EciPrincipal\",\"java.io.Serializable\"]},{\"authenticated\":true,\"name\":\"admin\"," +
        "\"anonymous\":false,\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine.client" +
        ".TenantIdentifier\",\"java.io.Serializable\"]},\"id\":\"18a6b5bc-528d-4071-8694-0f017708e4b8\"," +
        "\"useridentifier\":{\"name\":\"admin\",\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine" +
        ".client.TenantIdentifier\",\"java.io.Serializable\"]},\"id\":1,\"class\":[\"eu.w4.engine.client" +
        ".UserIdentifier\",\"java.io.Serializable\"]},\"class\":[\"eu.w4.engine.client.EnginePrincipal\",\"java" +
        ".io.Serializable\"],\"languageidentifier\":{\"id\":500,\"locale\":{\"country\":\"\"," +
        "\"displaylanguage\":\"English\",\"iso3country\":\"\",\"iso3language\":\"eng\"," +
        "\"isolanguages\":{\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"]}," +
        "\"unicodelocaleattributes\":[],\"language\":\"en\",\"extensionkeys\":[],\"unicodelocalekeys\":[]," +
        "\"script\":\"\",\"default\":{\"country\":\"US\",\"displaylanguage\":\"English\",\"iso3country\":\"USA\"," +
        "\"iso3language\":\"eng\",\"isolanguages\":{\"class\":[\"java.lang.Cloneable\",\"java.io" +
        ".Serializable\"]},\"unicodelocaleattributes\":[],\"language\":\"en\",\"extensionkeys\":[]," +
        "\"unicodelocalekeys\":[],\"script\":\"\",\"displayvariant\":\"\",\"availablelocales\":{\"class\":[\"java" +
        ".lang.Cloneable\",\"java.io.Serializable\"]},\"displayname\":\"English (United States)\"," +
        "\"variant\":\"\",\"displayscript\":\"\",\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"]," +
        "\"displaycountry\":\"United States\",\"isocountries\":{\"class\":[\"java.lang.Cloneable\",\"java.io" +
        ".Serializable\"]}},\"displayvariant\":\"\",\"availablelocales\":{\"class\":[\"java.lang.Cloneable\"," +
        "\"java.io.Serializable\"]},\"displayname\":\"English\",\"variant\":\"\",\"displayscript\":\"\"," +
        "\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"],\"displaycountry\":\"\"," +
        "\"isocountries\":{\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"]}},\"class\":[\"eu.w4" +
        ".engine.client.LanguageIdentifier\",\"java.io.Serializable\"]}}," +
        "{\"repositoryname\":\"filesystem-default\",\"name\":\"admin\"," +
        "\"nativeprincipal\":{\"authenticated\":true,\"name\":\"admin\",\"anonymous\":false," +
        "\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine.client.TenantIdentifier\",\"java.io" +
        ".Serializable\"]},\"id\":\"18a6b5bc-528d-4071-8694-0f017708e4b8\"," +
        "\"useridentifier\":{\"name\":\"admin\",\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine" +
        ".client.TenantIdentifier\",\"java.io.Serializable\"]},\"id\":1,\"class\":[\"eu.w4.engine.client" +
        ".UserIdentifier\",\"java.io.Serializable\"]},\"class\":[\"eu.w4.engine.client.EnginePrincipal\",\"java" +
        ".io.Serializable\"]},\"id\":\"d173d529-c3e3-4a5f-b14d-5ccedc374e5d\",\"class\":[\"eu.w4.engine.client" +
        ".eci.EciPrincipal\",\"java.io.Serializable\"]}],\"class\":[\"eu.w4.common.security.CompoundPrincipal\"," +
        "\"java.io.Serializable\"]}";

    /**
     * Simple test
     *
     * @throws Exception
     */
    @Test
    public void simplePrincipalTest() throws Exception {
        VerifyRSASignature.setKeyPair(KeyManager.getInstance().getKeys());
        //to add in login
        byte[] sig = VerifyRSASignature.genSignature(json);
        Assert.assertEquals(sig.length, 128);
        //to add inside after principal
        byte[] encryptedByteValue = Base64.getEncoder().encode(sig);
        String signatureAsString = new String(encryptedByteValue, "UTF-8");

        boolean isPrincipalUntouched = VerifyRSASignature.checkSignature(sig, json);
        Assert.assertTrue(isPrincipalUntouched);
    }

    /**
     * Trying to manipulate signature
     *
     * @throws Exception
     */
    @Test
    public void simpleSignatureManipulationTest() throws Exception {
        VerifyRSASignature.setKeyPair(KeyManager.getInstance().getKeys());

        byte[] sig = VerifyRSASignature.genSignature(json);
        Assert.assertEquals(sig.length, 128);

        byte[] encryptedByteValue = Base64.getEncoder().encode(sig);
        String signatureAsString = new String(encryptedByteValue, "UTF-8");

        Assert.assertEquals("Bj/Jykb7f+bW1Lu/oKQDHnt1+i9gl5iO8Y1/txiuFoM+NUnQZpe/gZsz8lo8qExgMEahEXZuDnfxpdnv" +
                                "+9WjBcXjiXy12zf0VfZROrZ+UjlqB+S9EWCMG0jp1GyyO3Qo0pXpAL4pJ0wdOOPi4JkenhDsKzUSSTPY4ljILDP7i50=",
                            signatureAsString);

        boolean isPrincipalUntouched = VerifyRSASignature.checkSignature(Base64.getDecoder().decode(signatureAsString),
                                                                         json);
        Assert.assertTrue("signature is ok", isPrincipalUntouched);

        /**
         * Trying to modify signature
         */
        signatureAsString = "Bj/Jykb7f+bW1Lu/oKQDHnt1+i9gl5iO8Y1/txiuFoM+NUnQZpe/gZsz8lo8qExgMEahEXZuDnfxpdnv"
            + "+9WjBcXjiXy12zf0VfZROrZ+UjlqB+S9EWCMG0jp1GyyO3Qo0pXpAL4pJ0wdOOPi4JkenhDsKzUSSTPY4ljILDP7i49=";
        isPrincipalUntouched = VerifyRSASignature.checkSignature(signatureAsString, json);
        Assert.assertFalse("signature is ko, validate must not be validate", isPrincipalUntouched);
    }

    /**
     * Trying to manipulate content
     *
     * @throws Exception
     */
    @Test
    public void simpleHackTest() throws Exception {
        //language=json
        String hackedJson = "{\"name\":\"admin\",\"principals\":[{\"repositoryname\":\"dss-default\"," +
            "\"name\":\"admin\"," +
            "\"nativeprincipal\":{\"authenticated\":true,\"name\":\"admin\",\"anonymous\":false," +
            "\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine.client.TenantIdentifier\",\"java.io" +
            ".Serializable\"]},\"id\":\"18a6b5bc-528d-4071-8694-0f017708e4b8\"," +
            "\"useridentifier\":{\"name\":\"admin\",\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine" +
            ".client.TenantIdentifier\",\"java.io.Serializable\"]},\"id\":1,\"class\":[\"eu.w4.engine.client" +
            ".UserIdentifier\",\"java.io.Serializable\"]},\"class\":[\"eu.w4.engine.client.EnginePrincipal\",\"java" +
            ".io.Serializable\"]},\"id\":\"33b1eadf-fd77-402f-b181-9ae2256a0e93\",\"class\":[\"eu.w4.engine.client" +
            ".eci.EciPrincipal\",\"java.io.Serializable\"]},{\"authenticated\":true,\"name\":\"admin\"," +
            "\"anonymous\":false,\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine.client" +
            ".TenantIdentifier\",\"java.io.Serializable\"]},\"id\":\"18a6b5bc-528d-4071-8694-0f017708e4b8\"," +
            "\"useridentifier\":{\"name\":\"admin\",\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine" +
            ".client.TenantIdentifier\",\"java.io.Serializable\"]},\"id\":1,\"class\":[\"eu.w4.engine.client" +
            ".UserIdentifier\",\"java.io.Serializable\"]},\"class\":[\"eu.w4.engine.client.EnginePrincipal\",\"java" +
            ".io.Serializable\"],\"languageidentifier\":{\"id\":500,\"locale\":{\"country\":\"\"," +
            "\"displaylanguage\":\"English\",\"iso3country\":\"\",\"iso3language\":\"eng\"," +
            "\"isolanguages\":{\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"]}," +
            "\"unicodelocaleattributes\":[],\"language\":\"en\",\"extensionkeys\":[],\"unicodelocalekeys\":[]," +
            "\"script\":\"\",\"default\":{\"country\":\"US\",\"displaylanguage\":\"English\",\"iso3country\":\"USA\"," +
            "\"iso3language\":\"eng\",\"isolanguages\":{\"class\":[\"java.lang.Cloneable\",\"java.io" +
            ".Serializable\"]},\"unicodelocaleattributes\":[],\"language\":\"en\",\"extensionkeys\":[]," +
            "\"unicodelocalekeys\":[],\"script\":\"\",\"displayvariant\":\"\",\"availablelocales\":{\"class\":[\"java" +
            ".lang.Cloneable\",\"java.io.Serializable\"]},\"displayname\":\"English (United States)\"," +
            "\"variant\":\"\",\"displayscript\":\"\",\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"]," +
            "\"displaycountry\":\"United States\",\"isocountries\":{\"class\":[\"java.lang.Cloneable\",\"java.io" +
            ".Serializable\"]}},\"displayvariant\":\"\",\"availablelocales\":{\"class\":[\"java.lang.Cloneable\"," +
            "\"java.io.Serializable\"]},\"displayname\":\"English\",\"variant\":\"\",\"displayscript\":\"\"," +
            "\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"],\"displaycountry\":\"\"," +
            "\"isocountries\":{\"class\":[\"java.lang.Cloneable\",\"java.io.Serializable\"]}},\"class\":[\"eu.w4" +
            ".engine.client.LanguageIdentifier\",\"java.io.Serializable\"]}}," +
            "{\"repositoryname\":\"filesystem-default\",\"name\":\"admin\"," +
            "\"nativeprincipal\":{\"authenticated\":true,\"name\":\"admin\",\"anonymous\":false," +
            "\"tenantidentifier\":{\"id\":-101,\"class\":[\"eu.w4.engine.client.TenantIdentifier\",\"java.io" +
            ".Serializable\"]},\"id\":\"18a6b5bc-528d-4071-8694-0f017708e4b8\"," +
            "\"useridentifier\":{\"name\":\"admin\",\"tenantidentifier\":{\"id\":-100,\"class\":[\"eu.w4.engine" +
            ".client.TenantIdentifier\",\"java.io.Serializable\"]},\"id\":1,\"class\":[\"eu.w4.engine.client" +
            ".UserIdentifier\",\"java.io.Serializable\"]},\"class\":[\"eu.w4.engine.client.EnginePrincipal\",\"java" +
            ".io.Serializable\"]},\"id\":\"d173d529-c3e3-4a5f-b14d-5ccedc374e5d\",\"class\":[\"eu.w4.engine.client" +
            ".eci.EciPrincipal\",\"java.io.Serializable\"]}],\"class\":[\"eu.w4.common.security.CompoundPrincipal\"," +
            "\"java.io.Serializable\"]}";

        VerifyRSASignature.setKeyPair(KeyManager.getInstance().getKeys());
        //deplace inside login
        byte[] sig = VerifyRSASignature.genSignature(json);
        Assert.assertEquals(sig.length, 128);

        boolean isPrincipalUntouched = VerifyRSASignature.checkSignature(sig, hackedJson);
        Assert.assertFalse("Hacked principal must not be validate", isPrincipalUntouched);
    }

    /**
     * Simple test
     *
     * @throws Exception
     */
    @Test
    public void emptySignatureTest() throws Exception {
        boolean isPrincipalUntouched = VerifyRSASignature.checkSignature("", json);
        Assert.assertFalse("Empty signature must invalidate principal",isPrincipalUntouched);
    }

}
