package capston2024.bustracker;

import capston2024.bustracker.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
@PropertySource("classpath:env.properties")
public class BustrackerApplication {

	public static void main(String[] args) {
		SpringApplication.run(BustrackerApplication.class, args);
	}

}
