package com.sjgs.gateway.config;

import com.sjgs.gateway.config.oauth2.SecurityContextRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * @title:
 * @author: houbin-hy
 * @date: 2019/11/18 12:35
 * @Description:
 * @lastModified by:
 * @lastModified at: 2019/11/18 12:35
 */
@Configuration
@EnableWebFluxSecurity
public class WebSecurityConfig {

    @Autowired
    private SecurityContextRepository securityContextRepository;


    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                // config auth
                .securityContextRepository(securityContextRepository)
                // Disable authentication for `/oauth/**` routes.
                .authorizeExchange()
                .pathMatchers("/oauth/**").permitAll()
                .anyExchange().authenticated()
                ;
        return http.build();
    }
}
