package toyproject.springsecurityjwt.user.web;


import toyproject.springsecurityjwt.other.SecurityUtil;
import toyproject.springsecurityjwt.tokenjwt.TokenService;
import toyproject.springsecurityjwt.tokenjwt.dto.TokenRequestDto;
import toyproject.springsecurityjwt.user.UserService;
import toyproject.springsecurityjwt.user.web.dto.UserRequestDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import toyproject.springsecurityjwt.user.web.dto.UserResponseDto;
import toyproject.springsecurityjwt.user.web.dto.UserSignupRequestDto;

@Slf4j
@RestController
@RequestMapping("/user")
public class UserRestController {


    @Autowired
    private UserService userService;

    @Autowired
    private TokenService userTokenRelatedService;

    @PostMapping("/signup")
    public ResponseEntity<UserResponseDto> signup(@RequestBody UserSignupRequestDto userSignupRequestDto){
        return ResponseEntity.ok(userService.signup(userSignupRequestDto));
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequestDto userRequestDto){
        return ResponseEntity.ok(userTokenRelatedService.login(userRequestDto));
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@RequestBody TokenRequestDto tokenRequestDto){
        return ResponseEntity.ok(userTokenRelatedService.reissue(tokenRequestDto));
    }

    @GetMapping("/findid")
    public ResponseEntity<?> findUserInfoById(){
        return ResponseEntity.ok(userService.findUserInfoById(SecurityUtil.getCurrentMemberId()));
    }

    @GetMapping("/{email}")
    public ResponseEntity<?> findUserInfoByEmail(@PathVariable String email){
        return ResponseEntity.ok(userService.findUserInfoByEmail(email));
    }
}
