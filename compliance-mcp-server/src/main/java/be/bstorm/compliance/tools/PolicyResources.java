package be.bstorm.compliance.tools;

import org.springframework.ai.mcp.annotation.McpResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/** Ressource MCP : contexte passif que l'agent lit avant de coder. */
@Component
public class PolicyResources {

    @McpResource(uri = "policy://secure-sdlc",
            name = "secure-sdlc",
            title = "Secure SDLC NIS2 / RGPD / AI Act",
            description = "Règles de développement sécurisé de l'équipe Java + Angular",
            mimeType = "text/markdown")
    public String secureSdlc() {
        try {
            return new ClassPathResource("policies/secure-sdlc.md").getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
