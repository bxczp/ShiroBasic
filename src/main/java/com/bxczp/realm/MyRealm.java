package com.bxczp.realm;

import java.sql.Connection;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import com.bxczp.dao.UserDao;
import com.bxczp.entity.User;
import com.bxczp.util.DbUtil;

public class MyRealm extends AuthorizingRealm {

    private UserDao userDao = new UserDao();
    private DbUtil dbUtil = new DbUtil();

    /**
     * 为当前登录的用户授予角色和权限
     */
    @Override
    // 参数 principals 为登录成功后的用户信息的封装
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 获取用户名
        String userName = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        Connection con = null;
        try {
            con = dbUtil.getCon();
            // 根据userName 查询数据库中的 role表 和permission表， 并且封装成 authorizationInfo 返回
            authorizationInfo.setRoles(userDao.getRoles(con, userName));
            authorizationInfo.setStringPermissions(userDao.getPermissions(con, userName));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                dbUtil.closeCon(con);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return authorizationInfo;
    }

    /**
     * 验证当前登录的用户
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // token 封装了来自前台的用户信息（用户名密码等）， 然后把token中的数据与数据库进行比较，判断登录信息是否正确
        String userName = (String) token.getPrincipal();
        Connection con = null;
        try {
            con = dbUtil.getCon();
            User user = userDao.getByUserName(con, userName);
            if (user != null) {
                // 根据用户名查询数据库中的数据，如果有用户名正确，即查找到该用户信息，返回用户名和密码（封装成AuthenticationInfo）
                AuthenticationInfo authcInfo = new SimpleAuthenticationInfo(user.getUserName(), user.getPassword(),
                        // 第三个参数是 realmName 随意写
                        "xx");
                return authcInfo;
            } else {
                // 没有查找的对应用户名的信息
                // 登录失败
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                dbUtil.closeCon(con);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return null;
    }

}
