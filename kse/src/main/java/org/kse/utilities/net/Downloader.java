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

package org.kse.utilities.net;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * A utility class for downloading content.
 */
public class Downloader {

    // Utility pattern
    private Downloader() {}

    /**
     * Downloads the contents of a URL following any redirects.
     *
     * @param url The URL.
     * @return A byte array of the URL contents.
     * @throws IOException If an I/O error occurs during download.
     * @throws URISyntaxException If the URL is invalid.
     */
    public static byte[] download(URL url) throws IOException, URISyntaxException {
        HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
        int status = urlConn.getResponseCode();
        if (isRedirect(status)) {
            String newUrl = urlConn.getHeaderField("Location");
            url = new URI(newUrl).toURL();
            urlConn = (HttpURLConnection) url.openConnection();
        }
        try (InputStream is = urlConn.getInputStream()) {
            return is.readAllBytes();
        }
    }

    private static boolean isRedirect(int status) {
        // normally, 3xx is redirect
        if (status != HttpURLConnection.HTTP_OK) {
            return status == HttpURLConnection.HTTP_MOVED_TEMP || status == HttpURLConnection.HTTP_MOVED_PERM ||
                   status == HttpURLConnection.HTTP_SEE_OTHER;
        }
        return false;
    }

}
