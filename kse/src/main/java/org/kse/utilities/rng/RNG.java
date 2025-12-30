package org.kse.utilities.rng;

import org.kse.gui.preferences.data.RngTypeSetting;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Provides {@link SecureRandom} instances
 */
public final class RNG {

    private static RngTypeSetting rngTypeSetting = RngTypeSetting.strong;

    private static final SecureRandom RANDOM = newInstanceDefault();

    private RNG() {
    }

    public static SecureRandom newInstanceForLongLivedSecrets() {
        return switch (rngTypeSetting) {
            case strong -> {
                try {
                    yield SecureRandom.getInstanceStrong();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
            case _default -> RANDOM;
        };
    }

    public static SecureRandom newInstanceDefault() {
        return new SecureRandom();
    }

    public static void setType(RngTypeSetting rngTypeSetting) {
        RNG.rngTypeSetting = rngTypeSetting;
    }

    /**
     * Generate random bytes
     *
     * @param numberOfBytes Number of random bytes to generate
     * @return Byte array with random bytes
     */
    public static byte[] generate(int numberOfBytes) {
        byte[] randomBytes = new byte[numberOfBytes];
        RANDOM.nextBytes(randomBytes);
        return randomBytes;
    }

}
