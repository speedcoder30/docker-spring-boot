package com.mkyong.bean;

import lombok.Data;

@Data
public class AWSCred {
    private String accessKey;
    private String secretKey;
    private String sessionToken;

}
