package com.sjgs.gateway.security.oauth2;

//import com.sjgs.gateway.web.errors.BadRequestAlertException;
//import com.sjgs.gateway.web.errors.LoginFailException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Manages authentication cases for OAuth2 updating the cookies holding access and refresh tokens accordingly.
 * <p>
 * It can authenticate users, refresh the token cookies should they expire and log users out.
 */
@Service
public class OAuth2AuthenticationService {

    private final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationService.class);

    @Value("${jhipster.security.client-authorization.token-service-id}")
    protected String tokenServiceId; //uaa
    /**
     * Number of milliseconds to cache refresh token grants so we don't have to repeat them in case of parallel requests.
     */
    private static final long REFRESH_TOKEN_VALIDITY_MILLIS = 10000l;

    /**
     * Used to contact the OAuth2 token endpoint.
     */
    private final OAuth2TokenEndpointClient authorizationClient;

    /**
     * Helps us with cookie handling.
     */
    /**
     * Caches Refresh grant results for a refresh token value so we can reuse them.
     * This avoids hammering UAA in case of several multi-threaded requests arriving in parallel.
     */

    public OAuth2AuthenticationService(OAuth2TokenEndpointClient authorizationClient ) {
        this.authorizationClient = authorizationClient;
//        this.restTemplate = restTemplate;
    }

    /**
     * Authenticate the user by username and password.
     *
     * @param request  the request coming from the client.
     * @param response the response going back to the server.
     * @param params   the params holding the username, password and rememberMe.
     * @return the OAuth2AccessToken as a ResponseEntity. Will return OK (200), if successful.
     * If the UAA cannot authenticate the user, the status code returned by UAA will be returned.
     */
    public Mono<OAuth2AccessToken> authenticate(ServerHttpRequest request, ServerHttpResponse response,
                                                Map<String, String> params) throws Exception {
        String username = null;
        try {
            username = params.get("username");
            String password = params.get("password");
            boolean rememberMe = Boolean.valueOf(params.get("rememberMe"));
            Mono<OAuth2AccessToken> accessToken = authorizationClient.sendPasswordGrant(username, password);
            if (log.isDebugEnabled()) {
                log.debug("successfully authenticated user {}", params.get("username"));
            }
            //logLogin(username, true, null);
            return accessToken;
        } catch (HttpClientErrorException ex) {
            log.error("failed to get OAuth2 tokens from UAA", ex);
            logLogin(username, false, ex.getMessage());
            //throw LoginFailException.getInstance(ex);
            throw new Exception(ex);
        }
    }

    /**
     * @param request
     * @param response
     * @param params
     * @return
     * @author qxx
     */
    public Mono<OAuth2AccessToken> authenticateByMobile(ServerHttpRequest request, ServerHttpResponse response,
                                                        Map<String, String> params) throws Exception {
        String username = null;
        try {
            username = params.get("phone");
            String password = params.get("captcha");
            boolean rememberMe = Boolean.valueOf(params.get("rememberMe"));
            Mono<OAuth2AccessToken> accessToken = ((OAuth2TokenEndpointClientAdapter) authorizationClient).sendMobileGrant(username, password);
            if (log.isDebugEnabled()) {
                log.debug("authenticateByMobiel successfully authenticated user {}", username);
            }
            //logLogin(username, true, null);
            return accessToken;
        } catch (HttpClientErrorException ex) {
            log.error("failed to get OAuth2 tokens from UAA", ex);
            logLogin(username, false, ex.getMessage());
            //throw LoginFailException.getInstance(ex);
            throw new Exception(ex);
        }
    }

    private void logLogin(String username, boolean isSuccess, String message) {
        try {
            //isssLogService.logLogin(username, isSuccess, message);
            log.debug("登录日志保存成功");
        } catch (Exception e) {
            log.debug("登录日志保存错误");
            e.printStackTrace();
        }
    }


    public Mono<String> getCaptchaByLogin(ServerHttpRequest request, ServerHttpResponse response, Map<String, String> params) throws Exception {
        try {
            Mono<OAuth2AccessToken> oAuth2AccessTokenResponseEntity = authenticate(request, response, params);
            String token = oAuth2AccessTokenResponseEntity.block().getValue();
            String url = String.format("http://%s/api/account", tokenServiceId);
            HttpHeaders reqHeaders = new HttpHeaders();
            reqHeaders.add("Authorization", "Bearer " + token);
            HttpEntity<Object> httpEntity = new HttpEntity<>(reqHeaders);
            WebClient.ResponseSpec userDTOResponseEntity = WebClient.create(url).get().header("Authorization","Bearer " + token).retrieve();
            String phone = userDTOResponseEntity.bodyToMono(String.class).block();
            if (StringUtils.isBlank(phone)) {
                //throw new BadRequestAlertException("该用户未绑定手机", "", "");
            }
            getMobelCaptcha(phone);
            return userDTOResponseEntity.bodyToMono(String.class);
        } catch (HttpServerErrorException ex) {
            throw new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR, "uaa INTERNAL_SERVER_ERROR");
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public Flux<Void> getMobelCaptcha(String phone) {
        log.info("loggingg getMobelCaptcha {}", phone);
        if (StringUtils.isBlank(phone)) {
            //throw new BadRequestAlertException("手机号不能为空", "", "");
        }
        try {
            String url = String.format("http://%s/mobile/captcha?phone=%s", tokenServiceId, phone);
            return WebClient.create(url).get().retrieve().bodyToFlux(Void.class);
        } catch (HttpClientErrorException e) {
            throw e;
        } catch (HttpServerErrorException e) {
            throw new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR, "uaa INTERNAL_SERVER_ERROR");
        }
    }
}
