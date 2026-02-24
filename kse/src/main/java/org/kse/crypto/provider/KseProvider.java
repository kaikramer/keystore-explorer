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

package org.kse.crypto.provider;

import java.security.Provider;

import org.kse.KSE;

/**
 * A KSE specific Java Security Provider. Provides the PEM KeyStore.
 */
public class KseProvider extends Provider {

    private static final long serialVersionUID = -8266987543617481929L;

    // Change these to match your provider
    private static final String PROVIDER_NAME = "KSE";
    private static final String PROVIDER_VERSION = KSE.getApplicationVersion().toString();
    private static final String PROVIDER_INFO = "KeyStore Explorer Security Provider v" + PROVIDER_VERSION;

    /**
     * Construct a new instance of the KSE security provider.
     */
    public KseProvider() {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

        putService(new Service(this, "KeyStore", "PEM", PemKeyStoreSpi.class.getCanonicalName(), null, null));
    }

}
