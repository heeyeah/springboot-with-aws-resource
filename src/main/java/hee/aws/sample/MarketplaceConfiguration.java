package hee.aws.sample;

import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.spring.boot.autoconfigure.RestClientBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.elasticsearch.repository.config.EnableElasticsearchRepositories;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.regions.Region;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

@Configuration
@EnableElasticsearchRepositories(basePackageClasses = MarketplaceRepository.class)
@ComponentScan(basePackageClasses = MarketplaceConfiguration.class)
public class MarketplaceConfiguration {
    /**
     * Allow to connect to the OpenSearch instance which uses self-signed certificates
     */
    @Bean
    RestClientBuilderCustomizer customizer() {


        return new RestClientBuilderCustomizer() {
            @Override
            public void customize(HttpAsyncClientBuilder builder) {
                try {
                    builder.setSSLContext(new SSLContextBuilder()
                            .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                            .build());

                    // AWS 자격증명 설정
                    builder.addInterceptorLast(new AWSRequestSigningApacheInterceptor(
                            "es", // OpenSearch 서비스 이름
                            Aws4Signer.create(),
                            DefaultCredentialsProvider.create(),
                            Region.of("ap-northeast-2") // 리전 설정
                    ));
                } catch (final KeyManagementException | NoSuchAlgorithmException | KeyStoreException ex) {
                    throw new RuntimeException("Failed to initialize SSL Context instance", ex);
                }
            }

            @Override
            public void customize(RestClientBuilder builder) {
                // No additional customizations needed
            }
        };
    }
}
