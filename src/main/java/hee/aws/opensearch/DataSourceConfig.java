package hee.aws.opensearch;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Configuration
public class DataSourceConfig {

    @Autowired
    private OpenSearchConnectService secretManagerService;

    @Bean
    public DataSource dataSource() throws Exception {
        String secretName = "heeye"; // Secrets Manager에 저장된 시크릿 이름
        String secret = secretManagerService.getSecret(secretName);

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode secretJson = objectMapper.readTree(secret);

        String url = secretJson.get("jdbcUrl").asText();
        String username = secretJson.get("username").asText();
        String password = secretJson.get("password").asText();

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.opensearch.jdbc.Driver");
        dataSource.setUrl(url);
        dataSource.setUsername(username);
        dataSource.setPassword(password);

        return dataSource;
    }
}