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
package org.kse.utilities.pem;

/**
 * Information contained in a PEM including type, header attributes and content.
 */
public class PemInfo {
    private String type;
    private PemAttributes attributes;
    private byte[] content;

    /**
     * Construct PEM.
     *
     * @param type       Type
     * @param attributes Header attributes
     * @param content    Content
     */
    public PemInfo(String type, PemAttributes attributes, byte[] content) {
        this.type = type;
        this.attributes = attributes;
        this.content = content;
    }

    /**
     * Get type.
     *
     * @return Type
     */
    public String getType() {
        return type;
    }

    /**
     * Get header attributes.
     *
     * @return Header attributes
     */
    public PemAttributes getAttributes() {
        return attributes;
    }

    /**
     * Get content.
     *
     * @return Content
     */
    public byte[] getContent() {
        return content;
    }
}
