package com.auth.session.Repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.auth.session.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);
}
