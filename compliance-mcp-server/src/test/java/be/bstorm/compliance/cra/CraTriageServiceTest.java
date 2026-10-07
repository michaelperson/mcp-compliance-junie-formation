package be.bstorm.compliance.cra;

import be.bstorm.compliance.audit.AiAuditLog;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CraTriageServiceTest {

    private final Instant now = Instant.parse("2026-10-01T08:00:00Z");
    private final CraTriageService service =
            new CraTriageService(List.of(), new AiAuditLog(), Clock.fixed(now, ZoneOffset.UTC));

    @Test
    void computesArticle14Deadlines() {
        var t = service.open("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", "portail-client", "test");

        assertThat(t.earlyWarningDueBy()).isEqualTo(Instant.parse("2026-10-02T08:00:00Z"));   // 24 h
        assertThat(t.notificationDueBy()).isEqualTo(Instant.parse("2026-10-04T08:00:00Z"));   // 72 h
        assertThat(t.disclaimer()).contains("ne constitue pas une notification");
    }

    @Test
    void rejectsMalformedInput() {
        assertThatThrownBy(() -> service.open("log4shell", "x:y", "1", "p", "test"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.open("CVE-2021-44228", "x:y\nINJECT", "1", "p", "test"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
