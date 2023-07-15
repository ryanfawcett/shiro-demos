package org.example;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 登录
 * <p>
 * 从ini配置文件中获取配置的用户信息进行登录
 *
 * @author ryanfawcett
 * @since 2023/07/15
 */
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    @SuppressWarnings("deprecation")
    private static final IniSecurityManagerFactory securityManagerFactory =
            new IniSecurityManagerFactory("classpath:shiro.ini");

    public void login(String username, String password) {
        SecurityManager securityManager = securityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();

        log.info("用户[{}]正在登录...", username);
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        try {
            subject.login(token);
            log.info("用户[{}]登录成功!", username);
        } catch (AuthenticationException e) {
            log.error("用户名/密码错误");
        }
    }

}
