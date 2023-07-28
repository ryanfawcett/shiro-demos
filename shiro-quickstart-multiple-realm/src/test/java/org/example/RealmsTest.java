package org.example;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("deprecation")
class RealmsTest {

    private static final Logger log = LoggerFactory.getLogger(RealmsTest.class);

    @Test
    void testFooRealm() {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-multiple-realm.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        Subject subject = SecurityUtils.getSubject();
        AuthenticationToken token = new UsernamePasswordToken("ryan", "123");

        String username = (String) token.getPrincipal();
        try {
            subject.login(token);
            log.info("用户[{}]登录成功", username);
        } catch (UnknownAccountException e) {
            log.error("用户[{}]不存在", username);
        } catch (IncorrectCredentialsException e) {
            log.error("用户[{}]密码错误", username); // 返回给前端的错误提示信息最好使用 "用户名/密码错误", 防止一些用户非法扫描账号库
        } catch (AuthenticationException e) {
            log.error("用户[{}]登录失败", username);
        }
        log.info("username - [{}]", subject.getPrincipal());
    }

    @Test
    void testBazRealm() {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-multiple-realm.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        Subject subject = SecurityUtils.getSubject();
        AuthenticationToken token = new UsernamePasswordToken("ryan", "1234");

        String username = (String) token.getPrincipal();
        try {
            subject.login(token);
            log.info("用户[{}]登录成功", username);
        } catch (UnknownAccountException e) {
            log.error("用户[{}]不存在", username);
        } catch (IncorrectCredentialsException e) {
            log.error("用户[{}]密码错误", username); // 返回给前端的错误提示信息最好使用 "用户名/密码错误", 防止一些用户非法扫描账号库
        } catch (AuthenticationException e) {
            log.error("用户[{}]登录失败", username);
        }
        log.info("username - [{}]", subject.getPrincipal());
    }
}