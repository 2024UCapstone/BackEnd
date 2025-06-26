package capston2024.bustracker.service;


import capston2024.bustracker.domain.Auth;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ErrorCode;
import capston2024.bustracker.repository.StationRepository;
import capston2024.bustracker.repository.UserRepository;
import com.mongodb.DBRef;
import com.mongodb.client.result.UpdateResult;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bson.types.ObjectId;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@Slf4j
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final StationRepository stationRepository;
    private final MongoTemplate mongoTemplate;
    private final MongoOperations mongoOperations;

    //내 정류장 조회
    public List<Station> getMyStationList(String email) {
        log.info("Email {} 사용자의 내 정류장 목록 조회를 시작합니다.", email);

        Auth auth = userRepository.findByEmail(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        List<DBRef> stationRefs = auth.getMyStations();
        log.info("stationRefs : {}", stationRefs);

        List<ObjectId> objectIds = stationRefs.stream()
                .map(ref -> new ObjectId(ref.getId().toString()))
                .collect(Collectors.toList());

        log.info("objectIds : {}", objectIds);

        Query query = new Query(Criteria.where("_id").in(objectIds));
        log.info("Executing query: {}", query.toString());

        List<Station> stations = mongoOperations.find(query, Station.class);

        log.info("stations : {}", stations);

        // 원래 순서 유지를 위한 정렬
        Map<ObjectId, Station> stationMap = stations.stream()
                .collect(Collectors.toMap(s -> new ObjectId(s.getId()), station -> station));

        List<Station> orderedStations = objectIds.stream()
                .map(stationMap::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        log.info("사용자 {}의 내 정류장 목록 조회 완료. 총 {} 개의 정류장이 있습니다.", email, orderedStations.size());

        return orderedStations;
    }

    public boolean addMyStation(String email, String stationId) {
        log.info("{} 사용자의 내 정류장 목록에 {}를 추가 중...", email, stationId);

        // 정류장 존재 여부 확인
        if (!stationRepository.existsById(stationId)) {
            log.warn("존재하지 않는 정류장입니다: {}", stationId);
            throw new BusinessException(ErrorCode.ENTITY_NOT_FOUND);
        }

        // 사용자 존재 여부와 중복 정류장 확인을 동시에 수행
        Query query = new Query(Criteria.where("email").is(email)
                .and("myStations").not().elemMatch(Criteria.where("$id").is(stationId)));
        Update update = new Update().addToSet("myStations", new DBRef("stations", stationId));

        UpdateResult result = mongoTemplate.updateFirst(query, update, Auth.class);

        if (result.getMatchedCount() == 0) {
            log.warn("사용자를 찾을 수 없거나 이미 등록된 정류장입니다: {} - {}", email, stationId);
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }

        if (result.getModifiedCount() == 0) {
            log.warn("이미 {} 사용자가 등록한 정류장입니다: {}", email, stationId);
            throw new BusinessException(ErrorCode.DUPLICATE_ENTITY);
        }

        log.info("사용자의 내 정류장 목록에 {}를 성공적으로 추가했습니다.", stationId);
        return true;
    }

    // 내 정류장 삭제
    public boolean deleteMyStation(String email, String stationId) {
        log.info("사용자 {}의 내 정류장 {} 삭제를 시작합니다.", email, stationId);

        Query query = new Query(Criteria.where("email").is(email)
                .and("myStations").elemMatch(Criteria.where("$id").is(stationId)));
        Update update = new Update().pull("myStations", new DBRef("stations", stationId));

        var result = mongoOperations.updateFirst(query, update, Auth.class);

        if (result.getModifiedCount() == 0) {
            log.warn("사용자 {}의 내 정류장 목록에서 정류장 {}을 찾을 수 없습니다.", email, stationId);
            throw new BusinessException(ErrorCode.ENTITY_NOT_FOUND);
        }

        log.info("사용자 {}의 내 정류장 {} 삭제가 완료되었습니다.", email, stationId);
        return true;
    }

}
