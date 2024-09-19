package capston2024.bustracker.service;

import capston2024.bustracker.config.auth.dto.OAuthAttributes;
import capston2024.bustracker.domain.User;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ErrorCode;
import capston2024.bustracker.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserRegisterService {
    @Autowired
    private UserRepository userRepository;

    @Transactional
    public User registerUser(OAuthAttributes oAuthAttributes){
        User newUser = oAuthAttributes.toEntity();
        try {
            return userRepository.save(newUser);
        } catch (RuntimeException e){
            throw new BusinessException(ErrorCode.GENERAL_ERROR);
        }
    }
}
