package com.token.commons.Jwt;


import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtTokenInterceptor implements HandlerInterceptor {

  private final TokenUtils tokenUtils;

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws IOException {

    System.out.println("토큰 불러오기");
    String accessToken = request.getHeader("ACCESS_TOKEN");
    System.out.println("AccessToken:" + accessToken);
    String refreshToken = request.getHeader("REFRESH_TOKEN");
    System.out.println("RefreshToken:" + refreshToken);


    if (accessToken != null) { //null이 아니면 istValidtoken
      if (tokenUtils.isValidToken(accessToken)) {
        return true;
      }
    }
    response.setStatus(401);
    response.setHeader("ACCESS_TOKEN", accessToken);
    response.setHeader("REFRESH_TOKEN", refreshToken);
    response.setHeader("msg", "토큰 체크");
    return false;
  }
}
