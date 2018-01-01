/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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

/**
 * Contains constants for all URLs used by KSE
 */
public class URLs {

	// general project URLs
	public static final String KSE_WEB_SITE = "http://www.keystore-explorer.org";
	public static final String GITHUB_PROJECT = "https://github.com/kaikramer/keystore-explorer";
	public static final String GITHUB_ISSUE_TRACKER = "https://github.com/kaikramer/keystore-explorer/issues";

	// for update checks and download of latest version
	public static final String LATEST_VERSION_ADDRESS = "http://www.keystore-explorer.org/version.txt";
	public static final String DOWNLOADS_WEB_ADDRESS = "http://www.keystore-explorer.org/downloads.html";

	// URL of page that forwards to unlimited strength policy download site for the respective Java version
	public static final String JCE_POLICY_DOWNLOAD_URL =
			"http://www.keystore-explorer.org/jcePolicyDownload.html?jreversion={0}";

	// list of contributors
	public static final String KSE_WEBSITE_CONTRIBUTORS = "http://keystore-explorer.org/contribute.html#contributions";
}
