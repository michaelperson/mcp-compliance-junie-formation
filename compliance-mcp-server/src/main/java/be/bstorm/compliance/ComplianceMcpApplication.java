package be.bstorm.compliance;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling   // rafraîchissement du catalogue CISA KEV
public class ComplianceMcpApplication {

    public static void main(String[] args) {
        SpringApplication.run(ComplianceMcpApplication.class, args);
    }
}
