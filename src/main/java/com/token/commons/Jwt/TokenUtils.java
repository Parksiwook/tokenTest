package com.token.commons.Jwt;

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

// JWT(Json Web Token)구조 - 헤더(Header). 내용(Payload). 서명(Signature)
@RequiredArgsConstructor
@Service
public class TokenUtils {
  // 토큰 생성 시 사용 될 암호
  private final String SECRET_KEY = "secretKey";
  private final String REFRESH_KEY = "refreshKey";
  private final String DATA_KEY = "userId"; // Payload 내용
  public String user_id = null;

  // HS256 : 대칭키 알고리즘 / 2개 이상의 영역에서 키 값 공유 (RS256 : 비대칭형 알고리즘 / 공개키와 개인키 2개의 키를 활용)
  // 원본 메시지가 변하면 그 해시값도 변하는 해싱의 특징을 활용하며 메시지의 변조 여부를 확인하여 무결성 및 기밀성을 제공하는 기술

  // AccessToken 생성
  public String generateJwtToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setHeader(createHeader())                      // 토큰 생성 시 header 지정
        .setClaims(createClaims(usersEntity))           // 토큰 생성 시 payload 지정
        .setSubject(usersEntity.getUserId())
        .setExpiration(createExpireDate(1000 * 60 * 5)) // 토큰 유효 시간 (5분)
        .signWith(SignatureAlgorithm.HS256, createSigningKey(SECRET_KEY)) // 해싱 알고리즘과 secret 키 설정
        .compact();     // jwt 토큰 생성
  }
  // RefreshToken 생성
  public String saveRefreshToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setHeader(createHeader())
        .setClaims(createClaims(usersEntity))
        .setSubject(usersEntity.getUserId())
        .setExpiration(createExpireDate(1000 * 60 * 10)) // (10분)
        .signWith(SignatureAlgorithm.HS256, createSigningKey(REFRESH_KEY))  // 해싱 알고리즘과 refresh 키 설정
        .compact();     // refresh 토큰 생성
  }

  // 해당 토큰의 유효성 확인
  public boolean isValidToken(String token) {
    System.out.println("isValidToken is : " +token);
    try {
      Claims accessClaims = getClaimsFormToken(token);
      System.out.println("Access token: " + accessClaims.getExpiration());
      System.out.println("Access userId: " + accessClaims.get("userId"));
      user_id = (String) accessClaims.get("userId");

      return true;
    } catch (ExpiredJwtException exception) {         // 유효기간이 지난 jwt 수신한 경우
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

  // 해당 토큰의 유효성 확인
  public boolean isValidRefreshToken(String token) {
    try {
      Claims accessClaims = getClaimsToken(token);

      System.out.println("Access token: " + accessClaims.getExpiration());
      System.out.println("Access userIdd: " + accessClaims.get("userId"));

      return true;
    } catch (ExpiredJwtException exception) {
      System.out.println("TokenUserID : " + exception.getClaims().getSubject());
      return false;
    } catch (JwtException exception) {
      System.out.println("Token");
      return false;
    } catch (NullPointerException exception) {
      System.out.println("Token null");
      return false;
    }
  }


  private Date createExpireDate(long expireDate) {  // 만료시간
    long curTime = System.currentTimeMillis();      // 현재시간 (표준)
    return new Date(curTime + expireDate);          // 현재시간 + 유효시간
  }

  private Map<String, Object> createHeader() {
    Map<String, Object> header = new HashMap<>();

    header.put("typ", "ACCESS_TOKEN");
    header.put("alg", "HS256");           // signature 해싱하기 위한 알고리즘 지정(HS256) 해시 256 암호화
    header.put("regDate", System.currentTimeMillis());

    return header;
  }

  private Map<String, Object> createClaims(UsersEntity usersEntity) {
    Map<String, Object> claims = new HashMap<>();
    claims.put(DATA_KEY, usersEntity.getUserId());    // payload
    return claims;
  }

  // 해당 Key 암호화
  private Key createSigningKey(String key) {
    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(key);
    return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
  }

  // 유효성 검색을 위해 토큰 정보 읽기
  private Claims getClaimsFormToken(String token) {
    return Jwts.parser()
        .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
        .parseClaimsJws(token)
        .getBody();
  }

  // 유효성 검색을 위해 토큰 정보 읽기
  private Claims getClaimsToken(String token) {
    return Jwts.parser()
            .setSigningKey(DatatypeConverter.parseBase64Binary(REFRESH_KEY))
            .parseClaimsJws(token)
            .getBody();
  }
}
