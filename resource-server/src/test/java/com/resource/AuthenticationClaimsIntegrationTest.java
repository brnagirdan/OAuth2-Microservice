package com.resource;


import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.Response;


@SpringBootTest(classes = ResourceApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthenticationClaimsIntegrationTest {

    @Autowired
    private JwtTokenStore tokenStore;


    @Test
    public void whenTokenDoesNotContainIssuer_thenSuccess() {
        String tokenValue = obtainAccessToken("fooClientIdPassword", "john", "123");
        System.out.println("token "+tokenValue);
        OAuth2Authentication auth = tokenStore.readAuthentication(tokenValue);
        Map<String, Object> details = (Map<String, Object>) auth.getDetails();

        System.out.println(auth);
        assertTrue(auth.isAuthenticated());
        System.out.println(auth.getDetails());
      //  assertTrue(details.containsKey("organization"));
    }

    private String obtainAccessToken(String clientId, String username, String password) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("grant_type", "password");
        params.put("client_id", clientId);
        params.put("username", username);
        params.put("password", password);
        final Response response = RestAssured.given()
                .auth()
                .preemptive()
                .basic(clientId, "secret")
                .and()
                .with()
                .params(params)
                .when()
                .post("http://localhost:8081/oauth/token");
        return response.jsonPath()
                .getString("access_token");
    }


}
