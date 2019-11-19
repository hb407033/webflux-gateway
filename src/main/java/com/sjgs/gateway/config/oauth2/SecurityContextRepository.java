package com.sjgs.gateway.config.oauth2;

import com.sjgs.gateway.security.oauth2.OAuth2JwtAccessTokenConverter;
import com.sjgs.gateway.security.oauth2.UaaSignatureVerifierClient;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
public class SecurityContextRepository implements ServerSecurityContextRepository {

    private static final Logger logger = LoggerFactory.getLogger(SecurityContextRepository.class);

    private final UaaSignatureVerifierClient uaaSignatureVerifierClient;

    private OAuth2JwtAccessTokenConverter oAuth2JwtAccessTokenConverter;

    public SecurityContextRepository(OAuth2JwtAccessTokenConverter oAuth2JwtAccessTokenConverter, UaaSignatureVerifierClient uaaSignatureVerifierClient) {
        this.oAuth2JwtAccessTokenConverter = oAuth2JwtAccessTokenConverter;
        this.uaaSignatureVerifierClient = uaaSignatureVerifierClient;
    }


    @Override
    public Mono<Void> save(ServerWebExchange serverWebExchange, SecurityContext securityContext) {
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange serverWebExchange) {
        // 获取Token
        String authHeader = serverWebExchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) {
            logger.warn("not find AUTHORIZATION");
            return Mono.empty();
        }
        String token = authHeader.replace("Bearer ", "").trim();
        try {
            Map<String,Object> cliams = oAuth2JwtAccessTokenConverter.decode(token);
            //TODO: 校验Token是否有效
            Authentication authentication = oAuth2JwtAccessTokenConverter.extractAuthentication(cliams);
            authentication.setAuthenticated(true);
            return Mono.justOrEmpty(new SecurityContextImpl(authentication));
        } catch (SignatureException e) {
            // 验证错误
            logger.warn("jwt token parse error: {}", e.getCause());
        } catch (ExpiredJwtException e) {
            // token 超时
            logger.warn("jwt token is expired");
        } catch (MalformedJwtException e) {
            // token Malformed
            logger.warn("jwt token is malformed");
        }
        return Mono.empty();
    }
}
