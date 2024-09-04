package hee.aws.opensearch;

import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

@Service
public class OpenSearchConnectService {

    private final SecretsManagerClient secretsClient;

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
        return getSecretValueResponse.secretString();
    }

    // Use
}
