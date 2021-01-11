package com.projet.security;

public interface SecurityParams {
	
	public static final String headerName = "authorization";
	public static final String secret ="secret";
	public static final long EXPIRATION = 10*24*3600*1000;
	public static final String HEADER_PREFIX="bearer ";

}
