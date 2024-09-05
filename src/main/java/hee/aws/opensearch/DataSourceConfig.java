package hee.aws.opensearch;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import javax.sql.DataSource;
import java.util.Properties;

@Configuration
@RequiredArgsConstructor
public class DataSourceConfig {


    private final SecretsManagerClient secretsClient;
    private final Logger log = LoggerFactory.getLogger(OpenSearchConnectService.class);

    public DataSourceConfig() {
        this.secretsClient = SecretsManagerClient.builder()
                .region(Region.of("ap-northeast-2")) // AWS Region 설정
                .build();
    }

    public String getSecret(String secretName) {
        GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();

        GetSecretValueResponse getSecretValueResponse = secretsClient.getSecretValue(getSecretValueRequest);
        String result = getSecretValueResponse.secretString();

        log.info("initial source info!========================================================================================\n : {}\n===========================================================================================", result);

        return result;
    }

    @Bean
    public DataSource dataSource() throws JsonProcessingException {
        String secretData = getSecret("heeye");

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode secretJson = objectMapper.readTree(secretData);

        String url = secretJson.get("jdbcUrl").asText();
        String username = secretJson.get("username").asText();
        String password = secretJson.get("password").asText();

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        Properties prop = new Properties();
        prop.put("user", username);
        prop.put("password", password);
        prop.put("logLevel", "DEBUG");
        prop.put("auth", "BASIC");
        prop.put("useSSL", "true");
        prop.put("trustSelfSigned", "true");
        prop.put("hostnameVerification", "false");
        prop.put("tunnelHost", "https://vpc-yr-vtr-kk66ndzelsd5nyucwx7h2dvkoi.ap-northeast-2.es.amazonaws.com");

        dataSource.setDriverClassName("org.opensearch.jdbc.Driver");
        dataSource.setUrl(url);
        dataSource.setConnectionProperties(prop);

        return dataSource;
    }
}
