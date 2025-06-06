/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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
package org.kse.gui;

import java.util.Objects;
import java.util.stream.Stream;

import org.kse.crypto.digest.DigestType;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * POJO class to configure the cells shown in the KeyStore table of KeyStore Explorer.
 */
public class KeyStoreTableColumns {

    private boolean enableEntryName = true;
    private boolean enableAlgorithm = true;
    private boolean enableKeySize = true;
    private boolean enableCertificateValidityStart = false;
    private boolean enableCertificateExpiry = true;
    private boolean enableLastModified = true;
    private boolean enableSKI = false;
    private boolean enableAKI = false;
    private boolean enableIssuerDN = false;
    private boolean enableSubjectDN = false;
    private boolean enableCurve = false;
    private boolean enableIssuerCN = false;
    private boolean enableSubjectCN = false;
    private boolean enableIssuerO = false;
    private boolean enableSubjectO = false;
    private boolean enableSerialNumberHex = false;
    private boolean enableSerialNumberDec = false;
    private boolean enableFingerprint = false;
    private DigestType fingerprintAlg;

    /**
     * Get number of activated columns. The actual table has 3 columns more, as the first 3 are fixed.
     *
     * @return number of columns selected
     */
    @JsonIgnore
    public int getNofColumns() {
        return Stream.of(enableEntryName, enableAlgorithm, enableKeySize, enableCertificateValidityStart,
                         enableCertificateExpiry, enableLastModified, enableSKI, enableAKI, enableIssuerDN,
                         enableSubjectDN, enableCurve, enableIssuerCN, enableSubjectCN, enableIssuerO, enableSubjectO,
                         enableSerialNumberHex, enableSerialNumberDec, enableFingerprint
        ).mapToInt(b -> b ? 1 : 0).sum();
    }

    private int calculateActualColumnIndex(int originalIndex) {
        // convert from original index of column to index for actually enabled columns; columns 0-2 are fixed
        return 2 + Stream.of(enableEntryName, enableAlgorithm, enableKeySize, enableCurve,
                             enableCertificateValidityStart, enableCertificateExpiry, enableLastModified, enableAKI,
                             enableSKI, enableIssuerDN, enableSubjectDN, enableIssuerCN, enableSubjectCN, enableIssuerO,
                             enableSubjectO, enableSerialNumberHex, enableSerialNumberDec, enableFingerprint)
                         .mapToInt(b -> b ? 1 : 0)
                         .limit(originalIndex)
                         .sum();
    }

    public int colIndexEntryName() {
        return calculateActualColumnIndex(1);
    }

    public int colIndexAlgorithm() {
        return calculateActualColumnIndex(2);
    }

    public int colIndexKeySize() {
        return calculateActualColumnIndex(3);
    }

    public int colIndexCurve() {
        return calculateActualColumnIndex(4);
    }

    public int colIndexCertificateValidityStart() {
        return calculateActualColumnIndex(5);
    }

    public int colIndexCertificateExpiry() {
        return calculateActualColumnIndex(6);
    }

    public int colIndexLastModified() {
        return calculateActualColumnIndex(7);
    }

    public int colIndexAKI() {
        return calculateActualColumnIndex(8);
    }

    public int colIndexSKI() {
        return calculateActualColumnIndex(9);
    }

    public int colIndexIssuerDN() {
        return calculateActualColumnIndex(10);
    }

    public int colIndexSubjectDN() {
        return calculateActualColumnIndex(11);
    }

    public int colIndexIssuerCN() {
        return calculateActualColumnIndex(12);
    }

    public int colIndexSubjectCN() {
        return calculateActualColumnIndex(13);
    }

    public int colIndexIssuerO() {
        return calculateActualColumnIndex(14);
    }

    public int colIndexSubjectO() {
        return calculateActualColumnIndex(15);
    }

    public int colIndexSerialNumberHex() {
        return calculateActualColumnIndex(16);
    }

    public int colIndexSerialNumberDec() {
        return calculateActualColumnIndex(17);
    }

    public int colIndexFingerprint() {
        return calculateActualColumnIndex(18);
    }


    public boolean getEnableEntryName() {
        return enableEntryName;
    }

    public boolean getEnableAlgorithm() {
        return enableAlgorithm;
    }

    public boolean getEnableKeySize() {
        return enableKeySize;
    }

    public boolean getEnableCertificateValidityStart() {
        return enableCertificateValidityStart;
    }

    public boolean getEnableCertificateExpiry() {
        return enableCertificateExpiry;
    }

    public boolean getEnableLastModified() {
        return enableLastModified;
    }

    public boolean getEnableSKI() {
        return enableSKI;
    }

    public boolean getEnableAKI() {
        return enableAKI;
    }

    public boolean getEnableCurve() {
        return enableCurve;
    }

    public boolean getEnableIssuerDN() {
        return enableIssuerDN;
    }

    public boolean getEnableSubjectDN() {
        return enableSubjectDN;
    }

    public boolean getEnableIssuerCN() {
        return enableIssuerCN;
    }

    public boolean getEnableSubjectCN() {
        return enableSubjectCN;
    }

    public boolean getEnableIssuerO() {
        return enableIssuerO;
    }

    public boolean getEnableSubjectO() {
        return enableSubjectO;
    }

    public boolean getEnableSerialNumberHex() {
        return enableSerialNumberHex;
    }

    public boolean getEnableSerialNumberDec() {
        return enableSerialNumberDec;
    }

    public boolean getEnableFingerprint() {
        return enableFingerprint;
    }

    public DigestType getFingerprintAlg() {
        return fingerprintAlg;
    }

    public void setEnableEntryName(boolean enableEntryName) {
        this.enableEntryName = enableEntryName;
    }

    public void setEnableAlgorithm(boolean enableAlgorithm) {
        this.enableAlgorithm = enableAlgorithm;
    }

    public void setEnableKeySize(boolean enableKeySize) {
        this.enableKeySize = enableKeySize;
    }

    public void setEnableCertificateValidityStart(boolean enableCertificateValidityStart) {
        this.enableCertificateValidityStart = enableCertificateValidityStart;
    }

    public void setEnableCertificateExpiry(boolean enableCertificateExpiry) {
        this.enableCertificateExpiry = enableCertificateExpiry;
    }

    public void setEnableLastModified(boolean enableLastModified) {
        this.enableLastModified = enableLastModified;
    }

    public void setEnableSKI(boolean enableSKI) {
        this.enableSKI = enableSKI;
    }

    public void setEnableAKI(boolean enableAKI) {
        this.enableAKI = enableAKI;
    }

    public void setEnableIssuerDN(boolean enableIssuerDN) {
        this.enableIssuerDN = enableIssuerDN;
    }

    public void setEnableSubjectDN(boolean enableSubjectDN) {
        this.enableSubjectDN = enableSubjectDN;
    }

    public void setEnableCurve(boolean enableCurve) {
        this.enableCurve = enableCurve;
    }

    public void setEnableIssuerCN(boolean enableIssuerCN) {
        this.enableIssuerCN = enableIssuerCN;
    }

    public void setEnableSubjectCN(boolean enableSubjectCN) {
        this.enableSubjectCN = enableSubjectCN;
    }

    public void setEnableIssuerO(boolean enableIssuerO) {
        this.enableIssuerO = enableIssuerO;
    }

    public void setEnableSubjectO(boolean enableSubjectO) {
        this.enableSubjectO = enableSubjectO;
    }

    public void setEnableSerialNumberHex(boolean enableSerialNumberHex) {
        this.enableSerialNumberHex = enableSerialNumberHex;
    }

    public void setEnableSerialNumberDec(boolean enableSerialNumberDec) {
        this.enableSerialNumberDec = enableSerialNumberDec;
    }

    public void setEnableFingerprint(boolean enableFingerprint) {
        this.enableFingerprint = enableFingerprint;
    }

    public void setFingerprintAlg(DigestType fingerprintAlg) {
        this.fingerprintAlg = fingerprintAlg;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        KeyStoreTableColumns that = (KeyStoreTableColumns) o;

        if (enableEntryName != that.enableEntryName) {
            return false;
        }
        if (enableAlgorithm != that.enableAlgorithm) {
            return false;
        }
        if (enableKeySize != that.enableKeySize) {
            return false;
        }
        if (enableCertificateValidityStart != that.enableCertificateValidityStart) {
            return false;
        }
        if (enableCertificateExpiry != that.enableCertificateExpiry) {
            return false;
        }
        if (enableLastModified != that.enableLastModified) {
            return false;
        }
        if (enableSKI != that.enableSKI) {
            return false;
        }
        if (enableAKI != that.enableAKI) {
            return false;
        }
        if (enableIssuerDN != that.enableIssuerDN) {
            return false;
        }
        if (enableSubjectDN != that.enableSubjectDN) {
            return false;
        }
        if (enableCurve != that.enableCurve) {
            return false;
        }
        if (enableIssuerCN != that.enableIssuerCN) {
            return false;
        }
        if (enableSubjectCN != that.enableSubjectCN) {
            return false;
        }
        if (enableIssuerO != that.enableIssuerO) {
            return false;
        }
        if (enableSubjectO != that.enableSubjectO) {
            return false;
        }
        if (enableSerialNumberHex != that.enableSerialNumberHex) {
            return false;
        }
        if (enableSerialNumberDec != that.enableSerialNumberDec) {
            return false;
        }
        if (enableFingerprint != that.enableFingerprint) {
            return false;
        }
        return Objects.equals(fingerprintAlg, that.fingerprintAlg);
    }

    @Override
    public int hashCode() {
        int result = (enableEntryName ? 1 : 0);
        result = 31 * result + (enableAlgorithm ? 1 : 0);
        result = 31 * result + (enableKeySize ? 1 : 0);
        result = 31 * result + (enableCertificateValidityStart ? 1 : 0);
        result = 31 * result + (enableCertificateExpiry ? 1 : 0);
        result = 31 * result + (enableLastModified ? 1 : 0);
        result = 31 * result + (enableSKI ? 1 : 0);
        result = 31 * result + (enableAKI ? 1 : 0);
        result = 31 * result + (enableIssuerDN ? 1 : 0);
        result = 31 * result + (enableSubjectDN ? 1 : 0);
        result = 31 * result + (enableCurve ? 1 : 0);
        result = 31 * result + (enableIssuerCN ? 1 : 0);
        result = 31 * result + (enableSubjectCN ? 1 : 0);
        result = 31 * result + (enableIssuerO ? 1 : 0);
        result = 31 * result + (enableSubjectO ? 1 : 0);
        result = 31 * result + (enableSerialNumberHex ? 1 : 0);
        result = 31 * result + (enableSerialNumberDec ? 1 : 0);
        result = 31 * result + (enableFingerprint ? 1 : 0);
        result = 31 * result + (fingerprintAlg == null ? 0 : fingerprintAlg.hashCode());
        return result;
    }
}
