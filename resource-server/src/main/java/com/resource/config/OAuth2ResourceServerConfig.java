package com.resource.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.apache.commons.io.IOUtils;;

import java.io.IOException;


@Configuration
@EnableResourceServer
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private CustomAccessTokenConverter customAccessTokenConverter;

    @Override
    public void configure(ResourceServerSecurityConfigurer config) throws Exception {
        config.tokenServices(tokenServices());
    }

    @Override
    public void configure(final HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                .authorizeRequests().anyRequest().permitAll();
    }

    @Bean
    public TokenStore tokenStore(){
        return new JwtTokenStore(accessTokenConverter());    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter(){
        JwtAccessTokenConverter converter=new JwtAccessTokenConverter();
        //converter.setAccessTokenConverter(customAccessTokenConverter);
       // converter.setSigningKey("123");
        Resource resource = new ClassPathResource("public.txt");
        String publicKey=null;
        try{
            publicKey = IOUtils.toString(resource.getInputStream());
        }
        catch (final IOException e){
            throw new RuntimeException(e);
        }
        converter.setVerifierKey(publicKey);
        return converter;
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        return defaultTokenServices;
    }
}
