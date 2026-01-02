/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.version;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.kse.utilities.net.URLs;

/**
 * A utility class for retrieving the latest KSE version from the web site.
 */
public class VersionCheck {

    // Utility pattern
    private VersionCheck() {}

    /**
     * Gets the latest version of KSE from the web site.
     * @return The latest version of KSE.
     * @throws IOException If fetching the version file from the web site failed
     */
    public static Version getLatestVersion() throws IOException {
        // Get the version number of the latest KeyStore Explorer from its web site
        URL latestVersionUrl = new URL(URLs.LATEST_VERSION_ADDRESS);
        try (InputStream is = latestVersionUrl.openStream()) {
            return new Version(new String(is.readAllBytes(), StandardCharsets.US_ASCII));
        }
    }
}
