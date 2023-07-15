package org.example;

import org.junit.jupiter.api.Test;

class LoginServiceTest {

    private final LoginService loginService = new LoginService();

    @Test
    void login() {
        String username = "ryan";
        String password = "123456";
        loginService.login(username, password);
    }

    @Test
    void LoginFailed() {
        String username = "fawcett";
        String password = "123456";
        loginService.login(username, password);
    }
}