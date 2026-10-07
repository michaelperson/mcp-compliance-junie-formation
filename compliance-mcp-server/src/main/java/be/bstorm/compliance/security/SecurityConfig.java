package be.bstorm.compliance.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.DispatcherType;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain mcpSecurity(HttpSecurity http,
                                    @Value("${mcp.security.api-key}") String apiKey,
                                    @Value("${mcp.security.allowed-origins:}") List<String> allowedOrigins) throws Exception {
        return http
                // API machine-to-machine sans cookie de session : CSRF non pertinent
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new ApiKeyFilter(apiKey, allowedOrigins), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // Streamable HTTP = réponse asynchrone (SSE) : Tomcat refait passer la requête dans la
                        // chaîne en dispatch ASYNC, puis ERROR. Le contexte de sécurité n'y est plus (stateless,
                        // ApiKeyFilter ignore l'async) -> "Access Denied" alors que l'outil a déjà répondu.
                        // Ces dispatchs ne concernent qu'une requête DÉJÀ autorisée lors du dispatch REQUEST.
                        .dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR).permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().hasRole("MCP_CLIENT"))   // deny by default
                .build();
    }

    /**
     * Aucun compte utilisateur : l'accès se fait uniquement par clé API (puis OAuth en prod).
     * Sans ce bean, Spring Boot crée un utilisateur "user" avec un mot de passe généré
     * affiché dans les logs : un secret en clair dans les journaux, à proscrire.
     */
    @Bean
    UserDetailsService noUserAccounts() {
        return username -> { throw new UsernameNotFoundException("Aucun compte local"); };
    }
}
