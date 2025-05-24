package in.neuw.aws.rolesanywhere.mocks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.ResponseTransformerV2;
import com.github.tomakehurst.wiremock.http.Response;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import lombok.extern.slf4j.Slf4j;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper.SESSIONS_URI;
import static in.neuw.aws.rolesanywhere.utils.MockAwsRolesAnywhereSessionsResponseGenerator.mockAwsRolesAnywhereSessionsResponse;

@Slf4j
public class MockAwsServer {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static WireMockServer instance;

    public static void stopInstance() {
        instance.stop();
    }

    public static void init() {
        init(8090);
    }

    public static void init(int port) {
        // start mock server
        instance = new WireMockServer(
                WireMockConfiguration
                        .options()
                        .port(port)
                        .extensions(new AWSRolesAnywhereMockTransformer())
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
                        .body(objectMapper.writeValueAsString(data))
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

}
