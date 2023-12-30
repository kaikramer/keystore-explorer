/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

package org.kse.gui.preferences.data;

import org.kse.AuthorityCertificates;

/**
 * Config bean for storing settings for cacerts (trust anchors) related options
 */
public class CaCertsSettings {

    private boolean useCaCertificates = false;
    private String caCertificatesFile = AuthorityCertificates.getDefaultCaCertificatesLocation().toString();
    private boolean useWindowsTrustedRootCertificates = false;
    private boolean importTrustedCertTrustCheckEnabled = false;
    private boolean importCaReplyTrustCheckEnabled = false;


    public boolean isUseCaCertificates() {
        return useCaCertificates;
    }

    public void setUseCaCertificates(boolean useCaCertificates) {
        this.useCaCertificates = useCaCertificates;
    }

    public String getCaCertificatesFile() {
        return caCertificatesFile;
    }

    public void setCaCertificatesFile(String caCertificatesFile) {
        this.caCertificatesFile = caCertificatesFile;
    }

    public boolean isUseWindowsTrustedRootCertificates() {
        return useWindowsTrustedRootCertificates;
    }

    public void setUseWindowsTrustedRootCertificates(boolean useWindowsTrustedRootCertificates) {
        this.useWindowsTrustedRootCertificates = useWindowsTrustedRootCertificates;
    }

    public boolean isImportTrustedCertTrustCheckEnabled() {
        return importTrustedCertTrustCheckEnabled;
    }

    public void setImportTrustedCertTrustCheckEnabled(boolean importTrustedCertTrustCheckEnabled) {
        this.importTrustedCertTrustCheckEnabled = importTrustedCertTrustCheckEnabled;
    }

    public boolean isImportCaReplyTrustCheckEnabled() {
        return importCaReplyTrustCheckEnabled;
    }

    public void setImportCaReplyTrustCheckEnabled(boolean importCaReplyTrustCheckEnabled) {
        this.importCaReplyTrustCheckEnabled = importCaReplyTrustCheckEnabled;
    }
}
