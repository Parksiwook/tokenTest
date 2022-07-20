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

    System.out.println("JwtToken 호출");
    String accessToken = request.getHeader("ACCESS_TOKEN"); // 클라이언트가  key(accesstoken)값으로 회원가입 때 생성하여 보관하던
                                                                  // token을 보내주면 그 value값을 가져와서 null인지 확인
    System.out.println("AccessToken:" + accessToken);
    String refreshToken = request.getHeader("REFRESH_TOKEN");
    System.out.println("RefreshToken:" + refreshToken);

    // null이 아닐 경우 isValidToken에서 해당 token이 서버에서 생성한 token인지, 유효기간이 지났는지 확인
    if (accessToken != null) {
      if (tokenUtils.isValidToken(accessToken)) {
        return true;
      }
    }

    response.setStatus(401);
    response.setHeader("ACCESS_TOKEN", accessToken);
    response.setHeader("REFRESH_TOKEN", refreshToken);
    response.setHeader("msg", "Check the tokens");
    return false;
  }
}
