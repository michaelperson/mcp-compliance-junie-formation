package be.bstorm.compliance.intel;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Catalogue CISA Known Exploited Vulnerabilities, chargé en mémoire et rafraîchi périodiquement.
 * Choix d'architecture : on télécharge le flux complet (~1-2 Mo) plutôt que d'interroger
 * à chaque appel -> lookup en O(1), aucune dépendance réseau sur le chemin critique de l'agent,
 * et le dernier catalogue valide reste servi si CISA est indisponible.
 */
@Component
public class KevCatalog implements ExploitationIntel {

    private static final Logger log = LoggerFactory.getLogger(KevCatalog.class);
    private static final String SOURCE = "CISA KEV";

    public record Feed(String catalogVersion, String dateReleased, Integer count, List<Entry> vulnerabilities) { }

    public record Entry(@JsonProperty("cveID") String cveId, String vendorProject, String product,
                 String dateAdded, String dueDate, String requiredAction, String knownRansomwareCampaignUse) { }

    /** Snapshot immuable remplacé atomiquement : lectures concurrentes sans verrou. */
    private record Snapshot(Map<String, ExploitInfo> byCve, String version, Instant loadedAt) { }

    private final RestClient rest;
    private final KevProperties props;
    private final Clock clock;
    private volatile Snapshot snapshot;

    @Autowired
    public KevCatalog(KevProperties props) {
        this(RestClient.builder().requestFactory(requestFactory(props)), props, Clock.systemUTC());
    }

    KevCatalog(RestClient.Builder builder, KevProperties props, Clock clock) {
        this.rest = builder.defaultHeader(HttpHeaders.USER_AGENT, "bstorm-compliance-mcp/0.3").build();
        this.props = props;
        this.clock = clock;
    }

    private static JdkClientHttpRequestFactory requestFactory(KevProperties props) {
        var http = HttpClient.newBuilder()
                .connectTimeout(props.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        var factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(props.readTimeout());
        return factory;
    }

    /** Au démarrage puis toutes les 6 h. Un échec conserve le snapshot précédent. */
    @Scheduled(initialDelay = 0, fixedDelayString = "${kev.refresh-interval:PT6H}")
    public void refresh() {
        try {
            Feed feed = rest.get().uri(props.feedUrl()).retrieve().body(Feed.class);
            if (feed == null || feed.vulnerabilities() == null || feed.vulnerabilities().isEmpty()) {
                log.warn("Flux KEV vide ou invalide : snapshot précédent conservé");
                return;
            }
            Map<String, ExploitInfo> index = new HashMap<>(feed.vulnerabilities().size() * 2);
            for (Entry e : feed.vulnerabilities()) {
                if (e.cveId() == null) continue;
                String cve = e.cveId().trim().toUpperCase(Locale.ROOT);
                index.put(cve, new ExploitInfo(SOURCE, cve, date(e.dateAdded()), date(e.dueDate()),
                        "Known".equalsIgnoreCase(e.knownRansomwareCampaignUse()),
                        sanitize(e.requiredAction())));
            }
            snapshot = new Snapshot(Map.copyOf(index), feed.catalogVersion(), clock.instant());
            log.info("Catalogue KEV chargé : version={} entrées={}", feed.catalogVersion(), index.size());
        } catch (RestClientException e) {
            log.warn("Rafraîchissement KEV impossible ({}) : snapshot précédent conservé",
                    e.getClass().getSimpleName());
        }
    }

    @Override
    public String name() {
        return SOURCE;
    }

    @Override
    public Optional<ExploitInfo> lookup(String cveId) {
        var s = snapshot;
        if (s == null || cveId == null) return Optional.empty();
        return Optional.ofNullable(s.byCve().get(cveId.trim().toUpperCase(Locale.ROOT)));
    }

    @Override
    public SourceStatus status() {
        var s = snapshot;
        if (s == null) return new SourceStatus(SOURCE, Availability.UNAVAILABLE, null, null, 0);
        boolean stale = s.loadedAt().plus(props.maxStaleness()).isBefore(clock.instant());
        return new SourceStatus(SOURCE, stale ? Availability.STALE : Availability.AVAILABLE,
                s.loadedAt(), s.version(), s.byCve().size());
    }

    private static LocalDate date(String iso) {
        try {
            return iso == null ? null : LocalDate.parse(iso);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** Texte externe renvoyé au LLM : neutralisé et tronqué (injection de prompt indirecte). */
    private static String sanitize(String s) {
        if (s == null) return "";
        String clean = s.replaceAll("\\p{Cntrl}", " ").replaceAll("\\s+", " ").trim();
        return clean.length() > 200 ? clean.substring(0, 200) + "…" : clean;
    }
}
