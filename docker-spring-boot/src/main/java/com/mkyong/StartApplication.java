package com.mkyong;

import com.amazonaws.DefaultRequest;
import com.amazonaws.SignableRequest;
import com.amazonaws.auth.*;
import com.amazonaws.http.HttpMethodName;
import com.amazonaws.services.finspacedata.model.AwsCredentials;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mkyong.bean.AWSCred;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.GetMapping;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import uk.co.lucasweb.aws.v4.signer.Signer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

@SpringBootApplication
@Controller
public class StartApplication {


    private static String EKS_WEB_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc2MTcyNmY5ODJjOTgzMWU1MzYyYjUzODY0YjFkM2YyNjE1NDE5MGYifQ.eyJhdWQiOlsic3RzLmFtYXpvbmF3cy5jb20iXSwiZXhwIjoxNjk3ODE2MjYzLCJpYXQiOjE2OTc3Mjk4NjMsImlzcyI6Imh0dHBzOi8vb2lkYy5la3MudXMtZWFzdC0yLmFtYXpvbmF3cy5jb20vaWQvMjVCQkE5OUNFRjU0QkQ1NjQ4OTZGMkRBRThBQjUyNTkiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImhlbG0tZGVwbG95bWVudCIsInBvZCI6eyJuYW1lIjoibXktYXBwLTc1NzRmYjVmZDUtaHNxcXoiLCJ1aWQiOiJkMDcwMDFmZS04Njk4LTQ4NTItOTBhNC05Y2RkZDQ5ZGU5NzcifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImVrcy1zdmMtdGVzdCIsInVpZCI6ImYyZDg4YjRiLTdlNzYtNGYyNS1iOWQyLTgxNDBlZTNmNzliZSJ9fSwibmJmIjoxNjk3NzI5ODYzLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6aGVsbS1kZXBsb3ltZW50OmVrcy1zdmMtdGVzdCJ9.Q6gDM4aKAzcwJGSeJ-FEt48vzWfJyIRhyj4WwRxamfEcLc4_q9_z-v8cH3inpqElmH6d_As6xOUNVTylF_3qC2PLDwkPMWHbLK_jtqoT16wGlMtfMFHJGPEk468-9ct_mnCW8WIUIPuqP8zeHLcyWr-7rlxBMcWF2-18HGtMsWBA-rljhod6bNolwurQJeefq5eZQiJyYQQx0VRA7BFVXgntBYIeG4_60qnhxpNzmJOzvH3WENJ5j81Cv-1V17IsSBrzL0TqNtEvTjGa1_452Phc_7Ww8KSVtvsvTnELDKgn-zja_Dst2GKx52c3WUYyiBkMI2VimR4o2gG3KmJpjg";
    private static String ACCESS_KEY_EXPRESSION = "/AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult/Credentials/AccessKeyId";
    private static String ACCESS_SECRET_EXPRESSION = "/AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult/Credentials/SecretAccessKey";
    private static String ACCESS_SESSION_TOKEN_EXPRESSION = "/AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult/Credentials/SessionToken";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String REQUEST_BODY = "Action=GetCallerIdentity&Version=2011-06-15";

    private static final String REQUEST_BODY_BASE64_ENCODED = Base64Utils.encodeToString(REQUEST_BODY.getBytes());

    @GetMapping("/")
    public String index(final Model model) {





        model.addAttribute("title", "Docker + Spring Boot");
        model.addAttribute("msg", "Welcome to the docker container!");
        return "index";
    }

    @GetMapping("/hashicorpToken")
    public String index() throws IOException, ParserConfigurationException, SAXException, XPathExpressionException, URISyntaxException {

        Map<String, String> login = new HashMap<>();

        String tempCredContent=getTempIAMCredentials();


        Document document=parseXmlFromString(tempCredContent);
        AWSCred awsCred=extractTempCreds(document);
        AWSSessionCredentials credentials =new BasicSessionCredentials(awsCred.getAccessKey(),awsCred.getSecretKey(),awsCred.getSessionToken());
        String headerJson=getSignedHeaders(credentials);
        login.put("iam_http_request_method", "POST");
        login.put("iam_request_url", Base64Utils.encodeToString(new URI("https://sts.us-east-2.amazonaws.com").toString().getBytes(StandardCharsets.UTF_8)));
        login.put("iam_request_body", REQUEST_BODY_BASE64_ENCODED);
        login.put("iam_request_headers", Base64Utils.encodeToString(headerJson.getBytes()));
        login.put("role","eks-test-role");
        System.out.println(OBJECT_MAPPER.writeValueAsString(login));


 /*       AWSV4Auth.Builder builder = new AWSV4Auth.Builder(accessKey,secretKey).httpMethodName("POST").canonicalURI("https://sts.us-east-2.amazonaws.com").
                 regionName("us-east-2").serviceName("sts").awsHeaders()

        HttpRequest request = new HttpRequest("POST", new URI("https://sts.amazonaws.com?"));
        String signature = Signer.builder()
                .awsCredentials(new AwsCredentials(accessKey, secretKey))
                .header("Host", "sts.amazonaws.com")
                .header("x-amz-date", "20130524T000000Z")
                .header("x-amz-content-sha256", contentSha256)
                .build(request, contentSha256)
                .getSignature();*/

        return "Token";
    }


    public static void main(String[] args) {
        SpringApplication.run(StartApplication.class, args);
    }

    public Document parseXmlFromString(String xmlString) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        ByteArrayInputStream input = new ByteArrayInputStream(xmlString.getBytes("UTF-8"));
        Document doc = builder.parse(input);
        return doc;
    }

    private static Map<String, String> createIamRequestHeaders() {

        Map<String, String> headers = new LinkedHashMap<>();

        headers.put(HttpHeaders.CONTENT_LENGTH, "" + REQUEST_BODY.length());
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.put(HttpHeaders.ACCEPT_ENCODING,"identity");

        return headers;
    }

    private static String getTempIAMCredentials() throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("Action", "AssumeRoleWithWebIdentity");
        parameters.put("DurationSeconds","3600");
        parameters.put("RoleSessionName","my-app");
        parameters.put("RoleArn","arn:aws:iam::358391284566:role/eks-svc-account-role");
        parameters.put("WebIdentityToken",EKS_WEB_TOKEN);
        parameters.put("Version","2011-06-15");
        parameters.put("Region","us-east-2");

        URL url = new URL("https://sts.amazonaws.com/");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setDoOutput(true);
        DataOutputStream out = new DataOutputStream(con.getOutputStream());
        out.writeBytes(ParameterStringBuilder.getParamsString(parameters));
        out.flush();
        out.close();

        int status = con.getResponseCode();

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer content = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        System.out.println(content);
        in.close();

        return content.toString();

    }

    private static AWSCred extractTempCreds(Document xmlCredDocument) throws XPathExpressionException {
        AWSCred awsCred = new AWSCred();
        XPath xPath =  XPathFactory.newInstance().newXPath();

        NodeList accessKeyNodeList = (NodeList) xPath.compile(ACCESS_KEY_EXPRESSION).evaluate(
                xmlCredDocument, XPathConstants.NODESET);
        awsCred.setAccessKey(accessKeyNodeList.item(0).getTextContent());



        NodeList secretKeyNodeList = (NodeList) xPath.compile(ACCESS_SECRET_EXPRESSION).evaluate(
                xmlCredDocument, XPathConstants.NODESET);
        awsCred.setSecretKey(secretKeyNodeList.item(0).getTextContent());

        NodeList sessionTokenNodeList = (NodeList) xPath.compile(ACCESS_SESSION_TOKEN_EXPRESSION).evaluate(
                xmlCredDocument, XPathConstants.NODESET);
        awsCred.setSessionToken(sessionTokenNodeList.item(0).getTextContent());
        return awsCred;
    }

    private static String getSignedHeaders(AWSCredentials awsCredentials) throws URISyntaxException {
        AWS4Signer signer = new AWS4Signer();
        Map<String, String> headers = createIamRequestHeaders();

        DefaultRequest<String> request = new DefaultRequest<>("sts");

        request.setContent(new ByteArrayInputStream(REQUEST_BODY.getBytes()));
        request.setHeaders(headers);
        request.setHttpMethod(HttpMethodName.POST);
        request.setEndpoint(new URI("https://sts.us-east-2.amazonaws.com"));

        signer.setServiceName(request.getServiceName());
        signer.sign(request, awsCredentials);


        Map<String, Object> map = new LinkedHashMap<>();

        for (Map.Entry<String, String> entry : request.getHeaders().entrySet()) {
            map.put(entry.getKey(), Collections.singletonList(entry.getValue()));
        }

        try {
            return OBJECT_MAPPER.writeValueAsString(map);
        }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialize headers to JSON", e);
        }


    }
}
