package com.sjgs.gateway.security.oauth2;

import com.sjgs.gateway.config.oauth2.OAuth2Properties;
import io.github.jhipster.config.JHipsterProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Default base class for an OAuth2TokenEndpointClient.
 * Individual implementations for a particular OAuth2 provider can use this as a starting point.
 */
public abstract class OAuth2TokenEndpointClientAdapter implements OAuth2TokenEndpointClient {
    private final Logger log = LoggerFactory.getLogger(OAuth2TokenEndpointClientAdapter.class);
    protected final JHipsterProperties jHipsterProperties;
    protected final OAuth2Properties oAuth2Properties;

    @Value("${jhipster.security.client-authorization.token-service-id}")
    protected  String tokenServiceId; //uaa

    public OAuth2TokenEndpointClientAdapter(JHipsterProperties jHipsterProperties, OAuth2Properties oAuth2Properties) {
        this.jHipsterProperties = jHipsterProperties;
        this.oAuth2Properties = oAuth2Properties;
    }

    /**
     * Sends a password grant to the token endpoint.
     *
     * @param username the username to authenticate.
     * @param password his password.
     * @return the access token.
     */
    @Override
    public Mono<OAuth2AccessToken> sendPasswordGrant(String username, String password) {
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.set("username", username);
        formParams.set("password", password);
        formParams.set("grant_type", "password");
        log.debug("contacting OAuth2 token endpoint to login user: {}", username);
        Mono<OAuth2AccessToken> oAuth2AccessTokenMono = WebClient.create().post()
                .uri(getTokenEndpoint())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("Authorization",getAuthorizationHeader())
                .body(BodyInserters.fromFormData(formParams))
                .retrieve()
                .onStatus(HttpStatus::is5xxServerError, clientResponse -> { throw new HttpClientErrorException(clientResponse.statusCode());})
                .bodyToMono(OAuth2AccessToken.class);

        return oAuth2AccessTokenMono;
    }

    protected abstract String getAuthorizationHeader();


    /**
     *
     * @param username
     * @param password
     * @return
     */
    public Mono<OAuth2AccessToken> sendMobileGrant(String username, String password) {

        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.set("phone", username);
        formParams.set("captcha", password);
        formParams.set("grant_type", "mobile");

        String mobileTokenEndpoint = String.format("http://%s/mobile/token",tokenServiceId);
        Mono<OAuth2AccessToken> oAuth2AccessTokenMono = WebClient.create().post()
                .uri(mobileTokenEndpoint)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formParams))
                .retrieve()
                .onStatus(HttpStatus::is5xxServerError, clientResponse -> { throw new HttpClientErrorException(clientResponse.statusCode());})
                .bodyToMono(OAuth2AccessToken.class);

        return Mono.just(oAuth2AccessTokenMono.block());
    }
    /**
     * Sends a refresh grant to the token endpoint using the current refresh token to obtain new tokens.
     *
     * @param refreshTokenValue the refresh token to use to obtain new tokens.
     * @return the new, refreshed access token.
     */
    @Override
    public Mono<OAuth2AccessToken> sendRefreshGrant(String refreshTokenValue) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshTokenValue);
        HttpHeaders headers = new HttpHeaders();
        addAuthentication(headers, params);

        Mono<OAuth2AccessToken> oAuth2AccessTokenMono = WebClient.create().post()
                .uri(getTokenEndpoint())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(params))
                .retrieve()
                .onStatus(HttpStatus::is5xxServerError, clientResponse -> { throw new HttpClientErrorException(clientResponse.statusCode());})
                .bodyToMono(OAuth2AccessToken.class);

        return Mono.just(oAuth2AccessTokenMono.block());
    }

    protected abstract void addAuthentication(HttpHeaders reqHeaders, MultiValueMap<String, String> formParams);

    protected String getClientSecret() {
        String clientSecret = oAuth2Properties.getWebClientConfiguration().getSecret();
        if (clientSecret == null) {
            throw new InvalidClientException("no client-secret configured in application properties");
        }
        return clientSecret;
    }

    protected String getClientId() {
        String clientId = oAuth2Properties.getWebClientConfiguration().getClientId();
        if (clientId == null) {
            throw new InvalidClientException("no client-id configured in application properties");
        }
        return clientId;
    }

    /**
     * Returns the configured OAuth2 token endpoint URI.
     *
     * @return the OAuth2 token endpoint URI.
     */
    protected String getTokenEndpoint() {
        String tokenEndpointUrl = jHipsterProperties.getSecurity().getClientAuthorization().getAccessTokenUri();
        if (tokenEndpointUrl == null) {
            throw new InvalidClientException("no token endpoint configured in application properties");
        }
        return tokenEndpointUrl;
    }

}
