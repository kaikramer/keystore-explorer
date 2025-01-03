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
package org.kse.crypto.jwk;

import java.text.MessageFormat;

/** Thrown when export to JWK is not possible.
 *
 */
public class JwkExporterException extends RuntimeException {

    private JwkExporterException(String message, Throwable cause) {
        super(message, cause);
    }
    private JwkExporterException(String message) {
        super(message);
    }
    public static JwkExporterException keyExportFailed(String keyAlias, Throwable throwable){
        return new JwkExporterException(MessageFormat.format("Key \"{0}\" export failed", keyAlias), throwable);
    }
    public static JwkExporterException notSupported(String notSupportedItem, Throwable throwable) {
        String message = MessageFormat.format("Not supported: \"{0}\"", notSupportedItem);
        if (throwable == null) {
            return new JwkExporterException(message);
        } else {
            return new JwkExporterException(message, throwable);
        }
    }
}
