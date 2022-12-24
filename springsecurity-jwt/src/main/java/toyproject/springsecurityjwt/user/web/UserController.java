package toyproject.springsecurityjwt.user.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/user")
public class UserController {

    // service


    // 로그인 페이지로 이동
    @GetMapping("/login")
    public String login(){
        log.info("로그인 실행되는지 확인");
        return "/login";
    }





}
