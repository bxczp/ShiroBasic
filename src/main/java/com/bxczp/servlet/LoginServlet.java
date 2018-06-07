package com.bxczp.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.swing.plaf.synth.SynthSeparatorUI;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

public class LoginServlet extends HttpServlet{

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        //轉發
        req.getRequestDispatcher("login.jsp").forward(req, resp);
//        重定向
//        resp.sendRedirect(req.getContextPath()+"/login.jsp");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String userName = req.getParameter("userName");
        String password = req.getParameter("password");
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        Session session=subject.getSession();
        try {
            subject.login(token);
            System.out.println("sessionId:"+session.getId());
            System.out.println("sessionHost:"+session.getHost());
//            session的有效时间 默认是半小时
            System.out.println("sessionTimeout:"+session.getTimeout());
            session.setAttribute("info", "session的数据");
            resp.sendRedirect("success.jsp");
        } catch (Exception e) {
            System.out.println("Login Fail");
            session.setAttribute("errorInfo", "用户名或者密码错误");
//          重定向
          resp.sendRedirect(req.getContextPath()+"/login");
        }
    }
    
    

}
