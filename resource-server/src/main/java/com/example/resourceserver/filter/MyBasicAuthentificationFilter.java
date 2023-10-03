package com.example.resourceserver.filter;


import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyBasicAuthentificationFilter implements Filter {
        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
                                                                                throws IOException, ServletException {
                servletResponse.getOutputStream().print("Hello from filter ... ");
                servletResponse.getOutputStream().flush();

                HttpServletRequest request = (HttpServletRequest) servletRequest;
                HttpServletResponse response =(HttpServletResponse) servletResponse;

                String authHeader =  request.getHeader("Authorization");
                System.out.printf(" !!!!!!!!! " + authHeader);

              filterChain.doFilter(servletRequest, servletResponse);
        }

}
