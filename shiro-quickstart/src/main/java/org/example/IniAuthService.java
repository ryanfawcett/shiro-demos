package org.example;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IniAuthService implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(IniAuthService.class);

    @SuppressWarnings("deprecation")
    private final IniSecurityManagerFactory iniSecurityManagerFactory = new IniSecurityManagerFactory("classpath:shiro.ini");

    @Override
    public Subject login(String username, String password) {
        SecurityManager securityManager = iniSecurityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken(username, password);
        try {
            subject.login(token);
            logger.info("{} login successfully", username);
        } catch (UnknownAccountException e) {
            logger.error("The user - [{}] NOT exists", username);
        } catch (IncorrectCredentialsException e) {
            logger.error("The USERNAME/PASSWORD incorrect");
        }
        return subject;
    }

    @Override
    public boolean hasRole(String username, String password, String role) {
        Subject subject = this.login(username, password);
        return subject.hasRole(role);
    }

    @Override
    public boolean isPermitted(String username, String password, String resource) {
        Subject subject = this.login(username, password);
        return subject.isPermitted(resource);
    }

    @Override
    public String encryptMD5(String password) {
        return new Md5Hash(password).toHex();
    }

    @Override
    public String encryptWithSalt(String originalPassword, String salt) {
        return new Md5Hash(originalPassword, salt).toHex();
    }

    @Override
    public String multipleEncrypt(String originalPassword, String salt, int times) {
        return new Md5Hash(originalPassword, salt, times).toHex();
    }

    @Override
    public String simpleHashEncrypt(String originalPassword, String salt, int times) {
        return new SimpleHash("MD5", originalPassword, salt, times).toHex();
    }

}
