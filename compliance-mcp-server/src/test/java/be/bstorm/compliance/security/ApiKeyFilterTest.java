package be.bstorm.compliance.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApiKeyFilterTest {

    private static final String KEY = "a".repeat(64);

    @Test
    void refuseDeDemarrerAvecUneCleTropCourte() {
        assertThatThrownBy(() -> new ApiKeyFilter("trop-courte", List.of()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("COMPLIANCE_MCP_API_KEY");
    }

    @Test
    void empreinteDeterministeSurHuitCaracteresHexa() {
        String f1 = ApiKeyFilter.fingerprint(KEY.getBytes(StandardCharsets.UTF_8));
        String f2 = ApiKeyFilter.fingerprint(KEY.getBytes(StandardCharsets.UTF_8));
        assertThat(f1).isEqualTo(f2).matches("[0-9a-f]{8}");
    }

    @Test
    void empreinteNeRevelePasLaCle() {
        String f = ApiKeyFilter.fingerprint(KEY.getBytes(StandardCharsets.UTF_8));
        assertThat(KEY).doesNotContain(f);
    }

    @Test
    void deuxClesDifferentesOntDesEmpreintesDifferentes() {
        assertThat(ApiKeyFilter.fingerprint("b".repeat(64).getBytes(StandardCharsets.UTF_8)))
                .isNotEqualTo(ApiKeyFilter.fingerprint(KEY.getBytes(StandardCharsets.UTF_8)));
    }
}
