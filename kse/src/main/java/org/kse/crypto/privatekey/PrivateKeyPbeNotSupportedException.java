/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.kse.crypto.privatekey;

import org.kse.crypto.CryptoException;

/**
 * Thrown when an encrypted private key is encrypted with an unsupported PBE
 * algorithm.
 */
public class PrivateKeyPbeNotSupportedException extends CryptoException {
    private static final long serialVersionUID = 1L;
    private String unsupportedPbe;

    /**
     * Creates a new PrivateKeyPbeNotSupportedException.
     *
     * @param unsupportedPbe Unsupported PBE algorithm
     */
    public PrivateKeyPbeNotSupportedException(String unsupportedPbe) {
        super();
        this.unsupportedPbe = unsupportedPbe;
    }

    /**
     * Creates a new PrivateKeyPbeNotSupportedException with the specified
     * message.
     *
     * @param unsupportedPbe Unsupported PBE algorithm
     * @param message        Exception message
     */
    public PrivateKeyPbeNotSupportedException(String unsupportedPbe, String message) {
        super(message);
        this.unsupportedPbe = unsupportedPbe;
    }

    /**
     * Creates a new PrivateKeyPbeNotSupportedException with the specified
     * message and cause throwable.
     *
     * @param unsupportedPbe Unsupported PBE algorithm
     * @param message        Exception message
     * @param causeThrowable The throwable that caused this exception to be thrown
     */
    public PrivateKeyPbeNotSupportedException(String unsupportedPbe, String message, Throwable causeThrowable) {
        super(message, causeThrowable);
        this.unsupportedPbe = unsupportedPbe;
    }

    /**
     * Creates a new PrivateKeyPbeNotSupportedException with the specified cause
     * throwable.
     *
     * @param unsupportedPbe Unsupported PBE algorithm
     * @param causeThrowable The throwable that caused this exception to be thrown
     */
    public PrivateKeyPbeNotSupportedException(String unsupportedPbe, Throwable causeThrowable) {
        super(causeThrowable);
        this.unsupportedPbe = unsupportedPbe;
    }

    /**
     * Get unsupported Pbe algorithm.
     *
     * @return Unsupported PBE algorithm
     */
    public String getUnsupportedPbe() {
        return unsupportedPbe;
    }
}
