package com.sjgs.gateway.web.rest;

import com.sjgs.gateway.security.oauth2.OAuth2AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.util.Map;

/**
 * Authentication endpoint for web client.
 * Used to authenticate a user using OAuth2 access tokens or log him out.
 *
 * @author markus.oellinger
 */
@RestController
@RequestMapping("/auth")
public class AuthResource {

    @Value("${jhipster.security.client-authorization.token-service-id}")
    protected String tokenServiceId; //uaa

    private final Logger log = LoggerFactory.getLogger(AuthResource.class);

    private OAuth2AuthenticationService authenticationService;

    public AuthResource(OAuth2AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * Authenticates a user setting the access and refresh token cookies.
     *
     * @param request  the ServerHttpRequest holding - among others - the headers passed from the client.
     * @param response the ServerHttpResponse getting the cookies set upon successful authentication.
     * @param params   the login params (username, password, rememberMe).
     * @return the access token of the authenticated user. Will return an error code if it fails to authenticate the user.
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST, consumes = MediaType
            .APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<OAuth2AccessToken> authenticate(ServerHttpRequest request, ServerHttpResponse response, @RequestBody
            Map<String, String> params) throws Exception {
        return authenticationService.authenticate(request, response, params);
    }

    /**
     * 提交用户名和密码, 验证成功就发送验证码到手机;
     *
     * @param request  the ServerHttpRequest holding - among others - the headers passed from the client.
     * @param response the ServerHttpResponse getting the cookies set upon successful authentication.
     * @param params   the login params (username, password, rememberMe).
     * @return 返回用户的信息;
     */
    @RequestMapping(value = "/username-captcha", method = RequestMethod.POST, consumes = MediaType
            .APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<String> getUserInfo(ServerHttpRequest request, ServerHttpResponse response, @RequestBody
            Map<String, String> params) throws Exception {
        return authenticationService.getCaptchaByLogin(request, response, params);
    }

    /**
     * Logout current user deleting his cookies.
     *
     * @param request  the ServerHttpRequest holding - among others - the headers passed from the client.
     * @param response the ServerHttpResponse getting the cookies set upon successful authentication.
     * @return an empty response entity.
     */
    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public ResponseEntity<?> logout(ServerHttpRequest request, ServerHttpResponse response) {
        log.info("logging out user {}", SecurityContextHolder.getContext().getAuthentication().getName());
        //authenticationService.logout(request, response);
        return ResponseEntity.noContent().build();
    }


    /**
     * mobile Authenticates a user setting the access and refresh token cookies.
     *
     * @param request  the ServerHttpRequest holding - among others - the headers passed from the client.
     * @param response the ServerHttpResponse getting the cookies set upon successful authentication.
     * @param params   the login params (username, password, rememberMe).
     * @return the access token of the authenticated user. Will return an error code if it fails to authenticate the user.
     * @author qxx
     */
    @RequestMapping(value = "/mobile/token", method = RequestMethod.POST, consumes = MediaType
            .APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<OAuth2AccessToken> authenticateByMobile(ServerHttpRequest request, ServerHttpResponse response, @RequestBody
            Map<String, String> params) throws Exception {
        log.info("loggingg mobileLogin");
        return authenticationService.authenticateByMobile(request, response, params);
    }

    @RequestMapping(value = "/mobile/captcha", method = RequestMethod.GET)
    public Flux<Void> getMobelCaptcha(@RequestParam(value = "phone") String phone) {
        log.info("loggingg getMobelCaptcha {}", phone);
        return authenticationService.getMobelCaptcha(phone);
    }


    /**
     * 处理restTemaplate调用其他接口时返回的4xx消息;
     * 全局的ControllerAdvice调试时有用, 打包的时候失效; 所以改用这个方法;
     * @param e
     * @return
     */
    @ExceptionHandler(HttpClientErrorException.class)
    @ResponseBody
    public ResponseEntity test(HttpClientErrorException e) {
        log.debug("OAuth2AuthenticationService ExceptionHandler");
        String body = new String(e.getResponseBodyAsByteArray(), Charset.forName("utf-8"));
        return ResponseEntity.status(e.getStatusCode()).body(body);
    }
}
