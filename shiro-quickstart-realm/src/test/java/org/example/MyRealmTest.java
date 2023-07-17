package org.example;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * 自定义登录规则测试
 *
 * @author ryanfawcett
 * @see UnknownAccountException 未知用户
 * @see IncorrectCredentialsException 密码错误
 * @see org.apache.shiro.authc.DisabledAccountException 账号已禁用
 * @see org.apache.shiro.authc.LockedAccountException 账号被锁定
 * @see org.apache.shiro.authc.ExcessiveAttemptsException 登录失败次数过多
 * @see org.apache.shiro.authc.ExpiredCredentialsException 凭证过期
 * @since 2023/07/17
 */
@SuppressWarnings("deprecation")
class MyRealmTest {

    private static final Logger log = LoggerFactory.getLogger(MyRealmTest.class);

    @Test
    void testCustomRealm() {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-realm.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("ryan", "123");

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
        // 验证完毕, 退出登录
        subject.logout();
    }

}