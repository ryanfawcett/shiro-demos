package org.example;

import org.apache.shiro.subject.Subject;

public interface AuthService {

    Subject login(String username, String password);

    boolean hasRole(String username, String password, String role);

    boolean isPermitted(String username, String password, String resource);

    String encryptMD5(String password);

    String encryptWithSalt(String originalPassword, String salt);

    String multipleEncrypt(String originalPassword, String salt, int times);

    String simpleHashEncrypt(String originalPassword, String salt, int times);

}
