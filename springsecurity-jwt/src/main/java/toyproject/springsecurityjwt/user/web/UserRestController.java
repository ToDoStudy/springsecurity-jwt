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

@Slf4j
@RestController
@RequestMapping("/user")
public class UserRestController {


    @Autowired
    private UserService userService;

    @Autowired
    private TokenService userTokenRelatedService;

    @GetMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody UserRequestDto userRequestDto){
        return ResponseEntity.ok(userService.signup(userRequestDto));
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
