package toyproject.springsecurityjwt.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    @Query("select count(u.email) from User u where u.email = ?1 and u.password = ?2")
    int loginByIdAndPassword(String id, String password);


    // 이메일을 통해 사용자 조회
    Optional<User> findByEmail(String email);

    // 현재 가입된 email인지 확인
    boolean existsByEmail(String email);
}
