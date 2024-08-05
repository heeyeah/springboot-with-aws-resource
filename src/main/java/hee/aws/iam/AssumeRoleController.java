package hee.aws.iam;

import hee.aws.iam.dto.IAMUserKey;
import hee.aws.iam.dto.IAMUserKeyWithRole;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.concurrent.CompletableFuture;

@RestController
@RequiredArgsConstructor
public class AssumeRoleController {

    private final static Logger log = LoggerFactory.getLogger(AssumeRoleController.class);


    private String getAmzDate() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormat.format(new Date());
    }

    private String getDateStamp() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormat.format(new Date());
    }

    private String sha256Hex(String data) throws NoSuchAlgorithmException {
        return Hex.encodeHexString(java.security.MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8)));
    }

    private byte[] hmacSHA256(String data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kDate = hmacSHA256(dateStamp, ("AWS4" + key).getBytes(StandardCharsets.UTF_8));
        byte[] kRegion = hmacSHA256(regionName, kDate);
        byte[] kService = hmacSHA256(serviceName, kRegion);
        return hmacSHA256("aws4_request", kService);
    }


    @PostMapping("/describe/vpcs/with-role")
    public ResponseEntity<?> callApi(@RequestBody IAMUserKeyWithRole info) throws Exception {
        String[] credentials = assumeRole(info);
        String accessKeyId = credentials[0];
        String secretAccessKey = credentials[1];
        String sessionToken = credentials[2];

        describeVpcs(accessKeyId, secretAccessKey, sessionToken, info.getProxyEndpoint());
        return ResponseEntity.ok().build();
    }

    private  String[] assumeRole(IAMUserKeyWithRole info) throws Exception {
        String amzDate = getAmzDate();
        String dateStamp = getDateStamp();

         String SECRET_KEY = info.getSecretKey();
         String ACCESS_KEY = info.getAccessKey();
         String ROLE_ARN = info.getRoleArn();
         String SESSION_NAME = "heeye-session";
        String REGION = "ap-northeast-2";
         String SERVICE = "sts";
         String HOST = "sts.ap-northeast-2.amazonaws.com";
//        String ENDPOINT = info.getProxyEndpoint();
        String ENDPOINT = "https://" + HOST;
        String method = "POST";
        String canonicalUri = "/";
        String canonicalQueryString = "";
        String canonicalHeaders = "host:" + HOST + "\n" + "x-amz-date:" + amzDate + "\n";
        String signedHeaders = "host;x-amz-date";
        String payload = "Action=AssumeRole&Version=2011-06-15&RoleArn=" + ROLE_ARN + "&RoleSessionName=" + SESSION_NAME;
        String payloadHash = sha256Hex(payload);
        String canonicalRequest = method + '\n' +
            canonicalUri + '\n' +
            canonicalQueryString + '\n' +
            canonicalHeaders + '\n' +
            signedHeaders + '\n' +
            payloadHash;

        String algorithm = "AWS4-HMAC-SHA256";
        String credentialScope = dateStamp + '/' + REGION + '/' + SERVICE + '/' + "aws4_request";
        String stringToSign = algorithm + '\n' +
            amzDate + '\n' +
            credentialScope + '\n' +
            sha256Hex(canonicalRequest);

        byte[] signingKey = getSignatureKey(SECRET_KEY, dateStamp, REGION, SERVICE);
        String signature = Hex.encodeHexString(hmacSHA256(stringToSign, signingKey));

        String authorizationHeader = algorithm + ' ' +
            "Credential=" + ACCESS_KEY + '/' + credentialScope + ", " +
            "SignedHeaders=" + signedHeaders + ", " +
            "Signature=" + signature;

        HttpPost httpPost = new HttpPost(ENDPOINT);
        if(ENDPOINT.endsWith("18443")) {
            httpPost.setHeader("x-cmp-url", "sts");
        }
        httpPost.setHeader("x-amz-date", amzDate);
        httpPost.setHeader("Authorization", authorizationHeader);
        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");
        httpPost.setEntity(new StringEntity(payload));

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
            CloseableHttpResponse response = httpClient.execute(httpPost)) {
            String responseBody = EntityUtils.toString(response.getEntity());
            System.out.println("AssumeRole Response Body: " + responseBody);
            // Extract credentials from responseBody
            // (use a proper XML parser in real code)
            String accessKeyId = extractXmlValue(responseBody, "<AccessKeyId>", "</AccessKeyId>");
            String secretAccessKey = extractXmlValue(responseBody, "<SecretAccessKey>", "</SecretAccessKey>");
            String sessionToken = extractXmlValue(responseBody, "<SessionToken>", "</SessionToken>");
            return new String[]{accessKeyId, secretAccessKey, sessionToken};
        }
    }

    private  void describeVpcs(String accessKeyId, String secretAccessKey, String sessionToken, String proxyEndpoint) throws Exception {
        String amzDate = getAmzDate();
        String dateStamp = getDateStamp();
        String region = "ap-northeast-2";
        String service = "ec2";
        String host = "ec2." + region + ".amazonaws.com";
        String endpoint = proxyEndpoint;// "https://" + host;

        String method = "POST";
        String canonicalUri = "/";
        String canonicalQueryString = "";
        String canonicalHeaders = "host:" + host + "\n" + "x-amz-date:" + amzDate + "\n" + "x-amz-security-token:" + sessionToken + "\n";
        String signedHeaders = "host;x-amz-date;x-amz-security-token";
        String payload = "Action=DescribeVpcs&Version=2016-11-15";
        String payloadHash = sha256Hex(payload);
        String canonicalRequest = method + '\n' +
            canonicalUri + '\n' +
            canonicalQueryString + '\n' +
            canonicalHeaders + '\n' +
            signedHeaders + '\n' +
            payloadHash;

        String algorithm = "AWS4-HMAC-SHA256";
        String credentialScope = dateStamp + '/' + region + '/' + service + '/' + "aws4_request";
        String stringToSign = algorithm + '\n' +
            amzDate + '\n' +
            credentialScope + '\n' +
            sha256Hex(canonicalRequest);

        byte[] signingKey = getSignatureKey(secretAccessKey, dateStamp, region, service);
        String signature = Hex.encodeHexString(hmacSHA256(stringToSign, signingKey));

        String authorizationHeader = algorithm + ' ' +
            "Credential=" + accessKeyId + '/' + credentialScope + ", " +
            "SignedHeaders=" + signedHeaders + ", " +
            "Signature=" + signature;

        HttpPost httpPost = new HttpPost(endpoint);
        if(endpoint.endsWith("18443")) {
            httpPost.setHeader("x-cmp-url", "ec2");
        }
        httpPost.setHeader("x-amz-date", amzDate);
        httpPost.setHeader("x-amz-security-token", sessionToken);
        httpPost.setHeader("Authorization", authorizationHeader);
        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");
        httpPost.setEntity(new StringEntity(payload));

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
            CloseableHttpResponse response = httpClient.execute(httpPost)) {
            System.out.println("DescribeVpcs Response Code: " + response.getStatusLine().getStatusCode());
            String responseBody = EntityUtils.toString(response.getEntity());
            System.out.println("DescribeVpcs Response Body: " + responseBody);
        }
    }

    private String extractXmlValue(String xml, String startTag, String endTag) {
        int startIndex = xml.indexOf(startTag) + startTag.length();
        int endIndex = xml.indexOf(endTag);
        return xml.substring(startIndex, endIndex);
    }

        @PostMapping("/describe/vpcs")
    public ResponseEntity<?> callApi(@RequestBody IAMUserKey userKey) throws Exception {

        String AWS_ACCESS_KEY = userKey.getAccessKey();
        String AWS_SECRET_KEY = userKey.getSecretKey();

        String REGION = "ap-northeast-2";
        String SERVICE = "ec2";

        String HOST = "ec2.ap-northeast-2.amazonaws.com";
        String ENDPOINT = userKey.getProxyEndpoint();
//        String HOST = "ec2." + REGION + ".amazonaws.com";
//        String ENDPOINT = "https://" + HOST;

        String amzDate = getAmzDate();
        String dateStamp = getDateStamp();

        // Canonical request
        String method = "GET";
        String canonicalUri = "/";
//        String canonicalQueryString = "Action=DescribeInstances&Version=2016-11-15";
        String canonicalQueryString = "Action=DescribeVpcs&Version=2016-11-15";
        String canonicalHeaders = "host:" + HOST + "\n" + "x-amz-date:" + amzDate + "\n";
        String signedHeaders = "host;x-amz-date";
        String payloadHash = sha256Hex("");
        String canonicalRequest = method + '\n' +
                canonicalUri + '\n' +
                canonicalQueryString + '\n' +
                canonicalHeaders + '\n' +
                signedHeaders + '\n' +
                payloadHash;

        // String to sign
        String algorithm = "AWS4-HMAC-SHA256";
        String credentialScope = dateStamp + '/' + REGION + '/' + SERVICE + '/' + "aws4_request";
        String stringToSign = algorithm + '\n' +
                amzDate + '\n' +
                credentialScope + '\n' +
                sha256Hex(canonicalRequest);

        // Calculate the signature
        byte[] signingKey = getSignatureKey(AWS_SECRET_KEY, dateStamp, REGION, SERVICE);
        String signature = Hex.encodeHexString(hmacSHA256(stringToSign, signingKey));

        // Authorization header
        String authorizationHeader = algorithm + ' ' +
                "Credential=" + AWS_ACCESS_KEY + '/' + credentialScope + ", " +
                "SignedHeaders=" + signedHeaders + ", " +
                "Signature=" + signature;

        // Send the HTTP request
        URI uri = new URI(ENDPOINT + "?" + canonicalQueryString);
        HttpGet httpGet = new HttpGet(uri);
        if(ENDPOINT.endsWith("18443")) {
            log.info("!!!!!!!!!!! set x-cml-url");
            httpGet.setHeader("x-cmp-url", "ec2");
        }
        httpGet.setHeader("x-amz-date", amzDate);
        httpGet.setHeader("Authorization", authorizationHeader);

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(httpGet)) {
            System.out.println("Response Code: " + response.getStatusLine().getStatusCode());
            String responseBody = EntityUtils.toString(response.getEntity());
            System.out.println("Response Body: " + responseBody);
        }

        return ResponseEntity.ok().build();
    }

    @PostMapping("/describe/instances")
    public ResponseEntity<?> callAwsResource(@RequestBody IAMUserKey userKey) {

        String accessKey = userKey.getAccessKey();
        String secretKey = userKey.getSecretKey();
        String proxyEndpoint = userKey.getProxyEndpoint();

        log.info("Request accessKey : [{}]", accessKey);
        log.info("Request secretKey : [{}]", secretKey);
        log.info(" proxyEndpoint : {}", proxyEndpoint);
        // 자격 증명 설정
        AwsBasicCredentials awsCreds = AwsBasicCredentials.create(accessKey, secretKey);

        Ec2Client ec2Client = Ec2Client.builder()
                .region(Region.AP_NORTHEAST_2)
                .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .build();

        // DescribeInstancesRequest 생성
//        DescribeInstancesRequest request = DescribeInstancesRequest.builder().build();

        DescribeVpcsRequest describeVpcsRequest = DescribeVpcsRequest.builder().build();

        // 인스턴스 설명
        DescribeVpcsResponse response = ec2Client.describeVpcs(describeVpcsRequest);

        // 결과 출력
        for (Vpc vpc : response.vpcs()) {
            log.info("vpc id ={} / cidr ={} / owner id={} / state={}", vpc.vpcId(), vpc.cidrBlock(), vpc.ownerId(), vpc.stateAsString());
//            reservation.instances().forEach(instance -> {
//                System.out.printf("Instance Id: %s, Instance Type: %s, State: %s%n",
//                        instance.instanceId(), instance.instanceType(), instance.state().name());
//            });
        }

        return ResponseEntity.ok().build();
    }

    @GetMapping("/iam/test")
    public ResponseEntity<?> getIAMKeyAndRole(@RequestParam String accessKey, @RequestParam String secretKey, @RequestParam String roleArn, @RequestParam String sessionName) {

        log.info("Request accessKey : [{}]", accessKey);
        log.info("Request secretKey : [{}]", secretKey);
        log.info("Request roleArn : [{}]", roleArn);
        log.info("Request sessionName : [{}]", sessionName);


        AwsBasicCredentials credentials = AwsBasicCredentials.create(accessKey, secretKey);
        AwsCredentialsProvider awsCredentialsProvider = StaticCredentialsProvider.create(credentials);
        StsAsyncClient stsAsyncClient = StsAsyncClient.builder().credentialsProvider(awsCredentialsProvider).region(Region.AP_NORTHEAST_2).build();
        AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder().roleArn(roleArn).roleSessionName(sessionName).durationSeconds(3600).build();


        CompletableFuture<AssumeRoleResponse> assumeRoleResponse = stsAsyncClient.assumeRole(assumeRoleRequest);

        assumeRoleResponse.thenCompose(response -> {
            AwsSessionCredentials sessionCredentials = AwsSessionCredentials.create(
                    response.credentials().accessKeyId(),
                    response.credentials().secretAccessKey(),
                    response.credentials().sessionToken()
            );

            AwsCredentialsProvider sessionProvider = StaticCredentialsProvider.create(sessionCredentials);

            Ec2AsyncClient ec2AsyncClient = Ec2AsyncClient.builder()
                    .credentialsProvider(sessionProvider)
                    .region(Region.AP_NORTHEAST_2)
                    .build();

            DescribeVpcsRequest describeVpcsRequest = DescribeVpcsRequest.builder().build();
            return ec2AsyncClient.describeVpcs(describeVpcsRequest);
        }).thenAccept(describeVpcsResponse -> {
            describeVpcsResponse.vpcs().forEach(vpc -> {
                System.out.println("VPC ID(IP): " + vpc.vpcId());
                System.out.println("VPC State: " + vpc.state());
                System.out.println("VPC CIDR Block: " + vpc.cidrBlock());
            });
        }).join();  // wait for the chain to complete
        return ResponseEntity.ok().build();
    }
}
