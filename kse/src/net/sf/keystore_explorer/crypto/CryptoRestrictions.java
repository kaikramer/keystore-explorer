/*
 * Copyright 2016 Kevin Herron
 */

package net.sf.keystore_explorer.crypto;

import java.lang.reflect.Field;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;

public class CryptoRestrictions {

    private static volatile boolean removed = false;

    static {
        removed = removeCryptographyRestrictions();
    }

    /**
     * Attempt to remove cryptography restrictions.
     *
     * @return {@code true} if this is an Oracle JRE/JDK and restrictions were removed.
     */
    public static synchronized boolean remove() {
        return removed;
    }

    /**
     * Do the following, but with reflection to bypass access checks:
     * <p>
     * JceSecurity.isRestricted = false;
     * JceSecurity.defaultPolicy.perms.clear();
     * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
     */
    private static boolean removeCryptographyRestrictions() {
        if (isRestrictedCryptography()) {
            try {
                final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
                final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
                final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

                final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
                isRestrictedField.setAccessible(true);
                isRestrictedField.set(null, false);

                final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
                defaultPolicyField.setAccessible(true);
                final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

                final Field perms = cryptoPermissions.getDeclaredField("perms");
                perms.setAccessible(true);
                ((Map<?, ?>) perms.get(defaultPolicy)).clear();

                final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
                instance.setAccessible(true);
                defaultPolicy.add((Permission) instance.get(null));

                System.out.println("Successfully removed cryptography restrictions.");
                return true;
            } catch (final Exception e) {
                System.err.println("Failed to remove cryptography restrictions." + e);
                return false;
            }
        }

        return true;
    }

    private static boolean isRestrictedCryptography() {
        // This simply matches the Oracle JRE, but not OpenJDK.
        return "Java(TM) SE Runtime Environment".equals(System.getProperty("java.runtime.name"));
    }

}
