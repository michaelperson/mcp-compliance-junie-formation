package be.bstorm.compliance.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * Authentification par clé API pour la démo locale.
 * En production : OAuth 2.1 (Entra ID) via org.springaicommunity:mcp-server-security,
 * conforme à la section Authorization de la spec MCP (2026-07-28 : CIMD, émetteur iss vérifié, RFC 9207).
 */
public class ApiKeyFilter extends OncePerRequestFilter {

    static final String HEADER = "X-API-Key";
    private static final Logger SECURITY = LoggerFactory.getLogger("SECURITY_AUDIT");

    private final byte[] expectedKey;
    private final List<String> allowedOrigins;

    public ApiKeyFilter(String expectedKey, List<String> allowedOrigins) {
        if (expectedKey == null || expectedKey.length() < 32) {
            // Fail fast : pas de démarrage sans secret robuste
            throw new IllegalStateException("COMPLIANCE_MCP_API_KEY manquante ou < 32 caractères");
        }
        this.expectedKey = expectedKey.getBytes(StandardCharsets.UTF_8);
        this.allowedOrigins = allowedOrigins;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // Spec MCP : valider l'en-tête Origin pour contrer le DNS rebinding
        String origin = request.getHeader("Origin");
        if (origin != null && !allowedOrigins.contains(origin)) {
            reject(request, "ORIGIN_NOT_ALLOWED", "origin=" + sanitize(origin));
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        String provided = request.getHeader(HEADER);
        if (provided != null && MessageDigest.isEqual(expectedKey, provided.getBytes(StandardCharsets.UTF_8))) {
            var auth = UsernamePasswordAuthenticationToken.authenticated(
                    "junie-agent", null, List.of(new SimpleGrantedAuthority("ROLE_MCP_CLIENT")));
            SecurityContextHolder.getContext().setAuthentication(auth);
        } else if (provided == null || provided.isBlank()) {
            reject(request, "API_KEY_MISSING", "");
        } else {
            // Jamais la clé dans les logs : une empreinte courte suffit à comparer avec celle du server
            reject(request, "API_KEY_INVALID", "fingerprint=" + fingerprint(provided.getBytes(StandardCharsets.UTF_8))
                    + " expected=" + fingerprint(expectedKey));
        }
        chain.doFilter(request, response);   // la requête non authentifiée sera refusée par l'autorisation (deny by default)
    }

    /** NIS2 art. 21 : journaliser les échecs d'authentification (qui, d'où, pourquoi), sans secret. */
    private static void reject(HttpServletRequest request, String reason, String detail) {
        SECURITY.warn("AUTH_REJECTED reason={} remote={} uri={} {}",
                reason, request.getRemoteAddr(), sanitize(request.getRequestURI()), detail);
    }

    /** 8 premiers caractères hexadécimaux du SHA-256 : identifie une clé sans la révéler. */
    static String fingerprint(byte[] secret) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(secret);
            return HexFormat.of().formatHex(h, 0, 4);
        } catch (java.security.NoSuchAlgorithmException e) {
            return "n/a";
        }
    }

    /** Anti log injection : pas de retour à la ligne, longueur bornée. */
    private static String sanitize(String v) {
        String s = v.replaceAll("[\\r\\n\\t]", "_");
        return s.length() > 120 ? s.substring(0, 120) + "…" : s;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/actuator/health");
    }
}
