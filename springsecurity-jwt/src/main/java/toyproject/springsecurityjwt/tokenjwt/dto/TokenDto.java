package toyproject.springsecurityjwt.tokenjwt.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenDto {

    private String grantType; // 고객
    private String accessToken;
    private String refreshToken;
    private Long accessTokenExpiresIn; // 액세스 토큰 만료기간
}
