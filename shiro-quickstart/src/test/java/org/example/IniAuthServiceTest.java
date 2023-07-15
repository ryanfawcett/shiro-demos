package org.example;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class IniAuthServiceTest {

    private static final Logger logger = LoggerFactory.getLogger(IniAuthServiceTest.class);

    private final IniAuthService iniAuthService = new IniAuthService();

    @Test
    void login() {
        iniAuthService.login("ryan", "123456");
    }

    @Test
    void hasRole() {
        String username = "ryan";
        String password = "123456";
        String role = "user";
        Assertions.assertTrue(iniAuthService.hasRole(username, password, role));
    }

    @Test
    void isPermitted() {
        String username = "ryan";
        String password = "123456";
        String resource = "user:select";
        Assertions.assertTrue(iniAuthService.isPermitted(username, password, resource));

        String noAccess = "user:update";
        Assertions.assertFalse(iniAuthService.isPermitted(username, password, noAccess));
    }

    @Test
    void encryptMD5() {
        String original = "123456";
        String encryptPassword = iniAuthService.encryptMD5(original);
        logger.info("加密后的密码为：{}", encryptPassword);
    }

    @Test
    void encryptWithSalt() {
        String originalPassword = "123456";
        String salt = "salt";
        String encrypted = iniAuthService.encryptWithSalt(originalPassword, salt);
        logger.info("加密后的密码为：{}", encrypted);
    }

    @Test
    void multipleEncrypt() {
        String originalPassword = "123456";
        String salt = "salt";
        int times = 3;

        String encrypted = iniAuthService.multipleEncrypt(originalPassword, salt, times);
        logger.info("多次加密后的密码：{}", encrypted);
    }

    @Test
    void simpleHashEncrypt() {
        String originalPassword = "123456";
        String salt = "salt";
        int times = 3;

        String encrypted = iniAuthService.simpleHashEncrypt(originalPassword, salt, times);
        logger.info("使用MD5Hash的父类加密后的密码：{}", encrypted);
    }
}