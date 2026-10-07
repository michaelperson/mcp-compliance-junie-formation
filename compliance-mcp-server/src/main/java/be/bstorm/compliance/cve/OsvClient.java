package be.bstorm.compliance.cve;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.List;

/**
 * Adaptateur sortant vers l'API OSV.dev (POST /v1/query).
 * Données envoyées : nom de paquet + version uniquement — aucune donnée personnelle (RGPD OK),
 * mais cela révèle votre stack à un tiers : à mentionner dans l'analyse de risques NIS2.
 */
@Component
public class OsvClient {

    private final RestClient rest;
    private final OsvProperties props;

    @Autowired
    public OsvClient(OsvProperties props) {
        this(RestClient.builder().requestFactory(requestFactory(props)), props);
    }

    /** Constructeur ouvert aux tests : MockRestServiceServer.bindTo(builder) fournit la fausse requestFactory. */
    OsvClient(RestClient.Builder builder, OsvProperties props) {
        this.rest = builder
                .baseUrl(props.baseUrl())
                .defaultHeader(HttpHeaders.USER_AGENT, "bstorm-compliance-mcp/0.2")
                .build();
        this.props = props;
    }

    private static JdkClientHttpRequestFactory requestFactory(OsvProperties props) {
        var http = HttpClient.newBuilder()
                .connectTimeout(props.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)   // pas de redirection vers un hôte non prévu
                .build();
        var factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(props.readTimeout());
        return factory;
    }

    /** Retourne toutes les vulnérabilités connues pour (écosystème, paquet, version), pagination bornée. */
    List<OsvModel.Vuln> query(String ecosystem, String packageName, String version) {
        List<OsvModel.Vuln> all = new ArrayList<>();
        String pageToken = null;
        int page = 0;
        do {
            var body = new OsvModel.Query(new OsvModel.Package(packageName, ecosystem), version, pageToken);
            var response = rest.post()
                    .uri("/v1/query")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(OsvModel.Response.class);
            if (response == null) break;
            if (response.vulns() != null) all.addAll(response.vulns());
            pageToken = response.nextPageToken();
        } while (pageToken != null && !pageToken.isBlank() && ++page < props.maxPages());
        return all;
    }
}
