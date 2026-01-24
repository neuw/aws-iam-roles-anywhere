package in.neuw.aws.rolesanywhere.mocks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.ResponseTransformerV2;
import com.github.tomakehurst.wiremock.http.HttpHeader;
import com.github.tomakehurst.wiremock.http.HttpHeaders;
import com.github.tomakehurst.wiremock.http.Response;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import lombok.extern.slf4j.Slf4j;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper.SESSIONS_URI;
import static in.neuw.aws.rolesanywhere.utils.MockAwsRolesAnywhereSessionsResponseGeneratorTestUtil.mockAwsRolesAnywhereSessionsResponse;

@Slf4j
public class MockAwsServer {

    private static final ObjectMapper jsonMapper = new ObjectMapper();
    private static WireMockServer instance;

    public static void stopInstance() {
        instance.stop();
    }

    public static void main(String[] args) {
        init();
    }

    public static void init() {
        init(28090);
    }

    public static void init(int port) {
        // start mock server
        instance = new WireMockServer(
                WireMockConfiguration
                        .options()
                        .port(port)
                        .extensions(
                                new AWSRolesAnywhereMockTransformer(),
                                new AWSRolesAnywhereMockTransformerError(),
                                new AWSRolesAnywhereMockTransformerNoBody()
                        )
        );
        instance.start();

        log.info("started mock server on port = {}", instance.port());

        instance.stubFor(post(urlPathEqualTo(SESSIONS_URI))
                .willReturn(
                        aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withTransformers("aws-rolesanywhere-mock"))
        );

        instance.stubFor(post(urlPathEqualTo(SESSIONS_URI+"-success-empty-response"))
                .willReturn(
                        aResponse()
                                .withStatus(201)
                                .withTransformers("aws-rolesanywhere-mock-empty-response"))
        );

        instance.stubFor(post(urlPathEqualTo(SESSIONS_URI+"-empty-response"))
                .willReturn(
                        aResponse()
                                .withStatus(204)
                                .withTransformers("aws-rolesanywhere-mock-empty-response"))
        );

        instance.stubFor(post(urlPathEqualTo(SESSIONS_URI+"-error-response"))
                .willReturn(
                        aResponse()
                                .withStatus(500)
                                .withHeader("Content-Type", "application/json")
                                .withTransformers("aws-rolesanywhere-mock-error-response"))
        );
        // stop mock server
        Runtime.getRuntime().addShutdownHook(new Thread(instance::stop));
    }

    public static class AWSRolesAnywhereMockTransformer implements ResponseTransformerV2 {
        @Override
        public Response transform(Response response, ServeEvent serveEvent) {
            System.out.println("request body received = "+serveEvent.getRequest().getBodyAsString());
            var data = mockAwsRolesAnywhereSessionsResponse();
            try {
                return Response.Builder.like(response)
                        .body(jsonMapper.writeValueAsString(data))
                        .build();
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public boolean applyGlobally() {
            return false;
        }

        @Override
        public String getName() {
            return "aws-rolesanywhere-mock";
        }
    }

    public static class AWSRolesAnywhereMockTransformerError implements ResponseTransformerV2 {
        @Override
        public Response transform(Response response, ServeEvent serveEvent) {
            System.out.println("request body received = "+serveEvent.getRequest().getBodyAsString());
            return Response.Builder.like(response)
                    .body("{\"message\":\"A message\"}")
                    .build();
        }

        @Override
        public boolean applyGlobally() {
            return false;
        }

        @Override
        public String getName() {
            return "aws-rolesanywhere-mock-error-response";
        }
    }

    // why would this happen? do not know! but only for unit test condition!
    public static class AWSRolesAnywhereMockTransformerNoBody implements ResponseTransformerV2 {
        @Override
        public Response transform(Response response, ServeEvent serveEvent) {
            System.out.println("request body received mocked empty response = "+serveEvent.getRequest().getBodyAsString());
            return Response.Builder
                    .like(response)
                    .headers(new HttpHeaders().plus(new HttpHeader("Connection", "Close")))
                    .build();
        }

        @Override
        public boolean applyGlobally() {
            return false;
        }

        @Override
        public String getName() {
            return "aws-rolesanywhere-mock-empty-response";
        }
    }

}
