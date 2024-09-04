package hee.aws.opensearch;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

@Service
@RequiredArgsConstructor
public class OpenSearchConnectService {

    private final SecretsManagerClient secretsClient;
    private final Logger log = LoggerFactory.getLogger(OpenSearchConnectService.class);

    public OpenSearchConnectService() {
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

        log.info("result : {}", result);

        return result;
    }

    // Use
}
