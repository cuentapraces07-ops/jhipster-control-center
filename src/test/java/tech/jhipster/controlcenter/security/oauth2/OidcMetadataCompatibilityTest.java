package tech.jhipster.controlcenter.security.oauth2;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;

class OidcMetadataCompatibilityTest {

    @Test
    void parsesKeycloakMtlsEndpointAliasesFromSpringDiscoveryMap() throws Exception {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", "http://localhost:8080/realms/test");
        metadata.put("authorization_endpoint", "http://localhost:8080/realms/test/protocol/openid-connect/auth");
        metadata.put("token_endpoint", "http://localhost:8080/realms/test/protocol/openid-connect/token");
        metadata.put("jwks_uri", "http://localhost:8080/realms/test/protocol/openid-connect/certs");
        metadata.put("response_types_supported", List.of("code"));
        metadata.put("subject_types_supported", List.of("public"));
        metadata.put("id_token_signing_alg_values_supported", List.of("RS256"));

        // RestTemplate deserializes nested discovery objects as Map instances.
        metadata.put("mtls_endpoint_aliases", new LinkedHashMap<String, Object>());

        OIDCProviderMetadata parsed = OIDCProviderMetadata.parse(new JSONObject(metadata));

        assertEquals("http://localhost:8080/realms/test", parsed.getIssuer().getValue());
        assertEquals(0, parsed.getMtlsEndpointAliases().toJSONObject().size());
    }
}
