///*
// *      Copyright (c) 2018-2028, Chill Zhuang All rights reserved.
// *
// *  Redistribution and use in source and binary forms, with or without
// *  modification, are permitted provided that the following conditions are met:
// *
// *  Redistributions of source code must retain the above copyright notice,
// *  this list of conditions and the following disclaimer.
// *  Redistributions in binary form must reproduce the above copyright
// *  notice, this list of conditions and the following disclaimer in the
// *  documentation and/or other materials provided with the distribution.
// *  Neither the name of the dreamlu.net developer nor the names of its
// *  contributors may be used to endorse or promote products derived from
// *  this software without specific prior written permission.
// *  Author: Chill 庄骞 (smallchill@163.com)
// */
//package com.sjgs.gateway.web.filter;
//
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.cloud.gateway.filter.GatewayFilterChain;
//import org.springframework.cloud.gateway.filter.GlobalFilter;
//import org.springframework.core.Ordered;
//import org.springframework.core.io.buffer.DataBuffer;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.ReactiveSecurityContextHolder;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Flux;
//import reactor.core.publisher.Mono;
//import java.nio.charset.StandardCharsets;
//
///**
// * 鉴权认证
// *
// * @author Chill
// */
//@Slf4j
//@Component
//public class AuthFilter implements GlobalFilter, Ordered {
//
//	public static final String AUTHORIZATION_HEADER = "Authorization";
//
//	private OAuth2JwtAccessTokenConverter tokenConverter;
//
//	public AuthFilter(OAuth2JwtAccessTokenConverter tokenConverter) {
//		this.tokenConverter = tokenConverter;
//	}
//
//	@Override
//	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//		String jwt = resolveToken(exchange.getRequest());
////		if (org.springframework.util.StringUtils.hasText(jwt) && this.tokenProvider.validateToken(jwt)) {
////			Authentication authentication = this.tokenProvider.getAuthentication(jwt);
////			return chain.filter(exchange).subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));
////		}
//
//        if (org.springframework.util.StringUtils.hasText(jwt) && this.tokenConverter.validateToken(jwt)) {
//			Authentication authentication = this.tokenConverter.getAuthentication(jwt);
//			return chain.filter(exchange).subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));
//		}
//		return chain.filter(exchange);
//	}
//
//	private String resolveToken(ServerHttpRequest request){
//		String bearerToken = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
//		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
//			return bearerToken.substring(7);
//		}
//		return null;
//	}
//
//	private Mono<Void> unAuth(ServerHttpResponse resp, String msg) {
//		resp.setStatusCode(HttpStatus.UNAUTHORIZED);
//		resp.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
//		String result = "";
//		try {
//			//result = objectMapper.writeValueAsString(ResponseProvider.unAuth(msg));
//			result = "";
//		} catch (Exception e) {
//			//log.error(e.getMessage(), e);
//		}
//		DataBuffer buffer = resp.bufferFactory().wrap(result.getBytes(StandardCharsets.UTF_8));
//		return resp.writeWith(Flux.just(buffer));
//	}
//
//
//	@Override
//	public int getOrder() {
//		return HIGHEST_PRECEDENCE;
//	}
//
//}
