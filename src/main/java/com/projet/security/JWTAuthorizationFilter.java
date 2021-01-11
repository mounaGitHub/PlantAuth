package com.projet.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier; 
public class JWTAuthorizationFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		System.out.println("doFilterInternal");
		response.addHeader("Access-Control-Allow-Origin", "*");
		response.addHeader("Access-Control-Allow-Headers","Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, authorization");
		response.addHeader("Access-Control-Expose-Headers","Access-Control-Allow-Origin, Access-Control-Allow-Credentials, authorization");
		response.addHeader("Access-Control-Allow-Methods","GET, POST, PUT, DELETE, PATCH");
		if(request.getMethod().equals("OPTIONS")) {
			System.out.println("OPTIONS"+request.getMethod()+"jjj"+request.getRequestURI());
			response.setStatus(HttpServletResponse.SC_OK);
		}
		else if (request.getRequestURI().equals("/login"))
		{
			System.out.println("login"+request.getMethod());
			filterChain.doFilter(request, response);
			return;
		}
		else
		{
			System.out.println("moun");
			String jwtToken = request.getHeader(SecurityParams.headerName);
			System.out.println("jwtToken="+jwtToken);
			if((jwtToken == null ) ||(!jwtToken.startsWith(SecurityParams.HEADER_PREFIX)))
			{
				filterChain.doFilter(request, response);
				return;
			}
			JWTVerifier jwtVerifier =  JWT.require(Algorithm.HMAC256(SecurityParams.secret)).build();
			System.out.println("verify"+jwtToken.substring(SecurityParams.HEADER_PREFIX.length()));
			DecodedJWT decodeJWT = jwtVerifier.verify(jwtToken.substring(SecurityParams.HEADER_PREFIX.length()));
			String userName = decodeJWT.getSubject();
			List<String> roles = decodeJWT.getClaims().get("roles").asList(String.class);
			System.out.println("userName"+userName);
			System.out.println("rules"+roles);
			Collection<GrantedAuthority> authorities = new ArrayList<>();
			roles.forEach(role ->{
				authorities.add(new SimpleGrantedAuthority(role));
			});
			UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(userName, null, authorities);
			SecurityContextHolder.getContext().setAuthentication(user);
			filterChain.doFilter(request, response);
		}


	}


}
