package org.kse.crypto.privatekey;

import com.nimbusds.jose.JOSEException;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;

import static org.junit.jupiter.api.Assertions.assertThrows;

class JwkPrivateKeyExporterTest {

    private static RSAPrivateCrtKey testRsaPrivateKey;
    private final String expectedJwk =
            "{\n"+
                "\"p\" : \"uaoJ56P-gRGRcJnkEwX0C0OX3-Nk4XUqG0kwUpxzQx9y4tWhfPVQ3W1JOT8UiNmTEs9JKw\",\n"+
                "\"kty\" : \"RSA\",\n"+
                "\"q\" : \"K4WNfODwFNumkDkmKV1y0uKFcwpRFpvRZDcKZzjjM5HyiBdFm9FOyQ_Vd9Q4IjZ8j1zd\",\n"+
                "\"d\" : \"c5Q7yaaHojmwXPNw9UR3nDlaL2RSC_T8QE8499zCJ8yYVadW_gPoQFizfTbvhGODUExqCvSmyCaLoNK2VQ4S1G5t29do054-zXr4bXUVeHxHOtLo3dAJ3Owuuh4QQn_PIWfP3j8eN-ZRs9_z_tCRyZPlNnXxlH_s06FVJvUB7cE\",\n"+
                "\"e\" : \"AQAB\",\n"+
                "\"kid\" : \"alias\",\n"+
                "\"qi\" : \"MyGthx89UnbzoyRhQxkLctJGFg7rW5e2eCl37IdO6IFp_mmGpQHY1ybnzZyWLdIN9GZIKw\",\n"+
                "\"dp\" : \"TZeMvYe1p9dxEdDY6ayAhVcXt2yS6Es8u5uLxRWIThlbkub0DY6cDjUJyiMohQCupcS-hQ\",\n"+
                "\"dq\" : \"FY7qOmK0nWgJs-QNgZFqqN5Lz5aG7j3zKaiyq762vMkOxaCc0loSbKiOO2od3B6-BKAB\",\n"+
                "\"n\" : \"AOlUA-YezpKq4KCQeSa38Y9JlFFeYpvUZDRugvOzFnaq2Y6up7_LiI3n93SRTXGLGxv5dfA3YgB-_xaod4EGQe9sOROg4sf1s4aBzbCjB4gl5iVES9F73tw12D5aLkWlhGw6PfveTxusvhWA9Y80m_i4Jj54Fy4qAD6hgdU4L2Bf\"\n"+
            "}";

    @BeforeAll
    static void beforeAll() throws Exception {
        BigInteger n = new BigInteger(
                "163848623215722573335289836290296380412600155169274542756345123525431136485103332108140966186957962358607966816937336373975517262686919727031911213273434467263220165629066576551436849585929539697852639506556574744932441880932740785492524179462275479949333856745765569341268928807012350302362205570952334368863");
        BigInteger e = new BigInteger("65537");
        BigInteger d = new BigInteger(
                "81162360104056367444041882273685533022608067258951749282561205052664337647413783849573620812056810889784984274619756416027199837912278433433854087061507142355364653690001337610110670204774550710530299556779525306616051247642876289624719232867435836251485874089121819535380161331921146955132661141083099622849");
        BigInteger p = new BigInteger(
                "122734436614797484015276528291786391292815307418847457882419065193890573226768384141673744961572404667732960146628556486560043");
        BigInteger q = new BigInteger(
                "112383879168171019021288484133164825686900629756358597762781058537871128411671231241861769924742254727413603248493558717661");
        BigInteger dp = new BigInteger(
                "51292648964209133170344456603196539129849777424887014274422094802525675770368384598278293051187555434638021173107662275264133");
        BigInteger dq = new BigInteger(
                "55668818224887815696812473861368312212583125550674272064933768218054019051908255830472755309012818345502448274493724205057");
        BigInteger qi = new BigInteger(
                "33800819014409014162527712312738217473191730864466927822214453530136540809553950561832440871643016047324557330030961453582379");

        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        testRsaPrivateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
    }

    @Test
    void shouldExportRSAPrivateKeyAndUseAliasWhenProvided() throws JOSEException, JSONException {
        JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(testRsaPrivateKey, "alias");
        JSONAssert.assertEquals(expectedJwk, new String(exporter.get()), JSONCompareMode.STRICT);
    }

    @Test
    void shouldExportRSAPrivateKeyAndGenerateAliasIfNotProvided() throws JOSEException, JSONException {
        JwkPrivateKeyExporter exporter = JwkPrivateKeyExporter.from(testRsaPrivateKey, null);
        JSONAssert.assertEquals(
                expectedJwk.replace("alias", "VvKXLBWz54q6mlHpf_WR6AFLSOd2UV53kASJK2UWYH4"),
                new String(exporter.get()),
                JSONCompareMode.STRICT);
    }
    @Test
    void shouldThrowIllegalArgumentExceptionWhenKeyIsNotSupported() {
        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> JwkPrivateKeyExporter.from(new RSAPrivateKey() {

                    @Override
                    public BigInteger getModulus() {
                        return null;
                    }

                    @Override
                    public String getAlgorithm() {
                        return "";
                    }

                    @Override
                    public String getFormat() {
                        return "";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return new byte[0];
                    }

                    @Override
                    public BigInteger getPrivateExponent() {
                        return BigInteger.ZERO;
                    }
                }, null),
                "Expected JwkPrivateKeyExporter.from() to throw, but it didn't"
        );
    }
}