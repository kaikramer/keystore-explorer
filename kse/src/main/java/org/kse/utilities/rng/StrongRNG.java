package org.kse.utilities.rng;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Provides a strong {@link SecureRandom} instance
 */
public final class StrongRNG {

    private static final SecureRandom RANDOM = newInstance();

    private StrongRNG() {
    }

    public static SecureRandom newInstance() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
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
