package org.example;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthenticatingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = authenticationToken.getPrincipal().toString();
        if ("ryan".equals(principal)) {
            String pwdDb = "d1b129656359e35e95ebd56a63d7b9e0";
            return new SimpleAuthenticationInfo(authenticationToken.getPrincipal(), pwdDb,
                    ByteSource.Util.bytes("salt"), this.getName());
        }
        return null;
    }
}
