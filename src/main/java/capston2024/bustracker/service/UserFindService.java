
package capston2024.bustracker.service;

import capston2024.bustracker.domain.User;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ErrorCode;
import capston2024.bustracker.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Slf4j
public class UserFindService {
    @Autowired
    UserRepository userRepository;

    @Transactional
    public Optional<User> findUserByEmail(String email){
        try {
            return userRepository.findByEmail(email);
        } catch (RuntimeException e){
            throw new BusinessException(ErrorCode.GENERAL_ERROR);
        }
    }
}
