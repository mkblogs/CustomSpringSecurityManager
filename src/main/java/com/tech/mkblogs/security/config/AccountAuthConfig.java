package com.tech.mkblogs.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@ConfigurationProperties
@Data
@Configuration
public class AccountAuthConfig {

	private Boolean encyprted;
	private String authType;
	
}
