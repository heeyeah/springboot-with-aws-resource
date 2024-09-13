package hee.aws.sample;

import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.signer.Signer;
import software.amazon.awssdk.regions.Region;



public class AWSRequestSigningApacheInterceptor implements HttpRequestInterceptor {
    private final String serviceName;
    private final AwsCredentialsProvider credentialsProvider;
    private final Signer signer;
    private final Region region;
    private final static Logger log = LoggerFactory.getLogger(AWSRequestSigningApacheInterceptor.class);

    public AWSRequestSigningApacheInterceptor(String serviceName, Signer signer, AwsCredentialsProvider credentialsProvider, Region region) {
        this.serviceName = serviceName;
        this.credentialsProvider = credentialsProvider;
        this.signer = signer;
        this.region = region;
    }

    @Override
    public void process(HttpRequest request, HttpContext context) {

        log.info(" process !!!!!!!");
        log.info("request = {}", request);

//        ApacheHttpRequest sdkRequest = new ApacheHttpRequest(request);
//        signer.sign(sdkRequest, credentialsProvider.resolveCredentials());
    }
}