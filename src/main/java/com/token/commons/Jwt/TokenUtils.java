package com.token.commons.Jwt;


import com.token.domains.users.application.dto.UserRequest;
import com.token.domains.users.domain.UsersEntity;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Service
public class TokenUtils {

  private final String SECRET_KEY = "secretKey";
  private final String REFRESH_KEY = "refreshKey";
  private final String DATA_KEY = "userId";

  public String a = null;



  public String generateJwtToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setSubject(usersEntity.getUserId())
        .setHeader(createHeader())//header 부분설정
        .setClaims(createClaims(usersEntity)) // 정보저장
        .setExpiration(createExpireDate(1000L * 60 * 5))  //5분 설정
        .signWith(SignatureAlgorithm.HS256, createSigningKey(SECRET_KEY))
        .compact();// access 토큰 생성
  }

  public String saveRefreshToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setSubject(usersEntity.getUserId())
        .setHeader(createHeader())
        .setClaims(createClaims(usersEntity))
        .setExpiration(createExpireDate(1000L * 60 * 10)) // 10분 설정
        .signWith(SignatureAlgorithm.HS256, createSigningKey(REFRESH_KEY))
        .compact(); //refreshtoken 생성
  }



  public boolean isValidToken(String token) { // 토큰 정보 보기
    System.out.println("Token : " +token);
    try {
      Claims accessClaims = getClaimsFormToken(token);
      System.out.println("token : " + accessClaims.getExpiration()); // 토큰 만료시간
      System.out.println("userId: " + accessClaims.get("userId"));
      a = (String) accessClaims.get("userId"); // map<> userid 키로 토큰에서 유저아이디
      return true;
      //try catch 예외 처리코드
    } catch (ExpiredJwtException exception) {
      System.out.println("Token UserID : " + exception.getClaims().getSubject());
      return false;
    } catch (JwtException exception) {
      System.out.println("Token Tampered");
      return false;
    } catch (NullPointerException exception) {
      System.out.println("Token null");
      return false;
    }
  }
  public boolean isValidRefreshToken(String token) {// refresh토큰 유효성 검사
    try {
      Claims accessClaims = getClaimsToken(token);

      System.out.println("token : " + accessClaims.getExpiration()); // 토큰 만료시간
      System.out.println("Access userIdd: " + accessClaims.get("userId"));


      return true;
    } catch (ExpiredJwtException exception) {
      System.out.println("TokenUserID : " + exception.getClaims().getSubject());
      return false;
    } catch (JwtException exception) {
      System.out.println("Token");
      return false;
    } catch (NullPointerException exception) { //객체가 없는 상태일때
      System.out.println("Token null");
      return false;
    }

  }


  private Date createExpireDate(long expireDate) {//유효시간 설정
    long curTime = System.currentTimeMillis();
    return new Date(curTime + expireDate);
  }

  private Map<String, Object> createHeader() {// 토큰 만들때 header부분 지정
    Map<String, Object> header = new HashMap<>();

    header.put("typ", "ACCESS_TOKEN");
    header.put("alg", "HS256");
    header.put("regDate", System.currentTimeMillis());

    return header;
  }

  private Map<String, Object> createClaims(UsersEntity usersEntity) {// 토큰 만들때 payload 지정
    Map<String, Object> claims = new HashMap<>(); //map key value
    claims.put(DATA_KEY, usersEntity.getUserId());
    return claims;
  }

  private Key createSigningKey(String key) { // key 암호화
    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(key);
    return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());  // HS256 방식으로 암호화 방식 설정
  }

  private Claims getClaimsFormToken(String token) {
    return Jwts.parser()
        .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
        .parseClaimsJws(token)
        .getBody(); //token 에서 페이로드 추출
  }
  private Claims getClaimsToken(String token) {
    return Jwts.parser()
            .setSigningKey(DatatypeConverter.parseBase64Binary(REFRESH_KEY)) //
            .parseClaimsJws(token)
            .getBody(); //token 에서 페이로드 추출
  }
}
