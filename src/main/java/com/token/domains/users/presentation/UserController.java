package com.token.domains.users.presentation;

import com.token.commons.Jwt.TokenUtils;
import com.token.domains.users.application.UserService;
import com.token.domains.users.application.dto.TokenResponse;
import com.token.domains.users.application.dto.UserRequest;
import com.token.domains.users.domain.UsersEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequiredArgsConstructor //생성자 생성
@RestController
public class UserController {

  private final UserService userService;

  // @RequestBody body내용을 통째로 자바 객체로 변환해서 맵핑된 메소드 파라미터로 전달
  @PostMapping("/user/signUp")
  public ResponseEntity signUp(@RequestBody UserRequest userRequest) {
    return userService.findByUserId(userRequest.getUserId()).isPresent() ? ResponseEntity.badRequest().build()
        : ResponseEntity.ok(userService.signUp(userRequest));
  }

  @PostMapping("/user/signIn")
  public ResponseEntity<TokenResponse> signIn(@RequestBody UserRequest userRequest) throws Exception {

    return ResponseEntity.ok().body(userService.signIn(userRequest));
  }

  @GetMapping("/info")
  public ResponseEntity<List<UsersEntity>> findUser() {
    return ResponseEntity.ok().body(userService.findUsers());
  }
}
