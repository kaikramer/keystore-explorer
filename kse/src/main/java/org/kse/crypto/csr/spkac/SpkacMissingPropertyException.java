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
package org.kse.crypto.csr.spkac;

/**
 * Represents an SpkacMissingPropertyException exception.
 */
public class SpkacMissingPropertyException extends SpkacException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new SpkacMissingPropertyException.
     */
    public SpkacMissingPropertyException() {
        super();
    }

    /**
     * Creates a new SpkacMissingPropertyException with the specified message.
     *
     * @param message Exception message
     */
    public SpkacMissingPropertyException(String message) {
        super(message);
    }

    /**
     * Creates a new SpkacMissingPropertyException with the specified message
     * and cause throwable.
     *
     * @param message        Exception message
     * @param causeThrowable The throwable that caused this exception to be thrown
     */
    public SpkacMissingPropertyException(String message, Throwable causeThrowable) {
        super(message, causeThrowable);
    }

    /**
     * Creates a new SpkacMissingPropertyException with the specified cause
     * throwable.
     *
     * @param causeThrowable The throwable that caused this exception to be thrown
     */
    public SpkacMissingPropertyException(Throwable causeThrowable) {
        super(causeThrowable);
    }
}
