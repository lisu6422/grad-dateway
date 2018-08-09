package com.thoughtworks.gradgateway.filters;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.thoughtworks.gradgateway.login.JwtUser;
import org.apache.commons.codec.binary.Base64;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class PreZuulFilter extends ZuulFilter {

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        JwtUser user = getUser();
        //ctx.addZuulRequestHeader("Authorization", "Basic " + getBase64Credentials(user.getUsername(), user.getPassword()));
        ctx.addZuulRequestHeader("userId", user.getId().toString());
        System.out.println(getBase64Credentials(user.getUsername(), user.getPassword()));
        return null;
    }

    @Override
    public String filterType() {
        return FilterConstants.PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    private String getBase64Credentials(String username, String password) {
        String plainCreds = username + ":" + password;
        byte[] plainCredsBytes = plainCreds.getBytes();
        byte[] base64CredsBytes = Base64.encodeBase64(plainCredsBytes);
        return new String(base64CredsBytes);
    }

    private JwtUser getUser() {
        return (JwtUser) SecurityContextHolder.getContext()
                .getAuthentication()
                .getPrincipal();
    }
}
