package com.example.resourceserver.converter;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * @author Rob Winch
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtAuthenticationConverter implements Converter {
    private Converter jwtGrantedAuthoritiesConverter
			= new JwtGrantedAuthoritiesConverter();


    @Override
    public AbstractAuthenticationToken convert(Object source) {
        Jwt jwt = (Jwt) source;
        Collection authorities = extractAuthorities(jwt);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /**
     * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a {@link Jwt}
     *
     * @param jwt The token
     * @return The collection of {@link GrantedAuthority}s found on the token
     * @deprecated Since 5.2. Use your own custom converter instead
     * @see JwtGrantedAuthoritiesConverter
     * @see #setJwtGrantedAuthoritiesConverter(Converter)
     */
    @Deprecated
    protected Collection extractAuthorities(Jwt jwt) {
        return (Collection) this.jwtGrantedAuthoritiesConverter.convert(jwt);
    }

    /**
     * Sets the {@link Converter Converter<Jwt, Collection<GrantedAuthority>>} to use.
     * Defaults to {@link JwtGrantedAuthoritiesConverter}.
     *
     * @param jwtGrantedAuthoritiesConverter The converter
     * @since 5.2
     * @see JwtGrantedAuthoritiesConverter
     */
    public void setJwtGrantedAuthoritiesConverter(Converter jwtGrantedAuthoritiesConverter) {
        Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
    }

}
