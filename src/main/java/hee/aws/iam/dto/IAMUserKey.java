package hee.aws.iam.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class IAMUserKey {
    String accessKey;
    String secretKey;
    String proxyEndpoint;
}
