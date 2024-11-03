package capston2024.bustracker.service;

import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.repository.BusRepository;
import capston2024.bustracker.repository.StationRepository;
import com.mongodb.DBRef;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StationServiceTest {

    @Mock
    private StationRepository stationRepository;

    @Mock
    private BusRepository busRepository;

    @InjectMocks
    private StationService stationService;

    private Station testStation;
    private Bus testBus1;
    private Bus testBus2;

    @BeforeEach
    void setUp() {
        // 테스트용 정류장 생성
        testStation = Station.builder()
                .id("station123")
                .name("Test Station")
                .location(new GeoJsonPoint(37.5665, 126.9780))
                .build();

        // 테스트용 StationInfo 생성
        DBRef stationRef = new DBRef("stations", testStation.getId());
        Bus.StationInfo stationInfo = new Bus.StationInfo(stationRef, testStation.getName());

        // 테스트용 버스1 생성 - ArrayList 사용
        ArrayList<Bus.StationInfo> stations1 = new ArrayList<>();
        stations1.add(stationInfo);
        testBus1 = Bus.builder()
                .id("bus123")
                .busNumber("1234")
                .stations(stations1)
                .build();

        // 테스트용 버스2 생성 - ArrayList 사용
        ArrayList<Bus.StationInfo> stations2 = new ArrayList<>();
        stations2.add(stationInfo);
        testBus2 = Bus.builder()
                .id("bus456")
                .busNumber("5678")
                .stations(stations2)
                .build();
    }

    @Test
    @DisplayName("정류장 삭제 시 연관된 버스 노선에서도 제거되어야 한다")
    void deleteStation_ShouldRemoveStationFromBusRoutes() {
        // given
        String stationId = testStation.getId();
        ArrayList<Bus> busesWithStation = new ArrayList<>(Arrays.asList(testBus1, testBus2));

        when(stationRepository.findById(stationId)).thenReturn(Optional.of(testStation));
        when(busRepository.findByStationsContaining(testStation)).thenReturn(busesWithStation);

        // Bus의 getStations() 메소드가 수정 가능한 리스트를 반환하도록 설정
        when(testBus1.getStations()).thenReturn(new ArrayList<>(testBus1.getStations()));
        when(testBus2.getStations()).thenReturn(new ArrayList<>(testBus2.getStations()));

        // when
        stationService.deleteStation(stationId);

        // then
        verify(busRepository, times(2)).save(any(Bus.class));
        verify(stationRepository).delete(testStation);

        // 실제로 stations 리스트가 수정되었는지 확인
        verify(busRepository, times(2)).save(argThat((Bus bus) ->
                bus.getStations().stream()
                        .noneMatch((Bus.StationInfo stationInfo) ->
                                stationInfo.getStationRef().getId().toString().equals(stationId))
        ));
    }

    @Test
    @DisplayName("존재하지 않는 정류장 삭제 시 예외가 발생해야 한다")
    void deleteStation_ShouldThrowException_WhenStationNotFound() {
        // given
        String nonExistentStationId = "nonexistent123";
        when(stationRepository.findById(nonExistentStationId)).thenReturn(Optional.empty());

        // when & then
        assertThrows(BusinessException.class, () ->
                stationService.deleteStation(nonExistentStationId));
        verify(stationRepository, never()).delete(any(Station.class));
    }

    @Test
    @DisplayName("정류장 삭제 시 연관된 버스가 없는 경우")
    void deleteStation_ShouldDeleteStation_WhenNoBusesAssociated() {
        // given
        String stationId = testStation.getId();
        when(stationRepository.findById(stationId)).thenReturn(Optional.of(testStation));
        when(busRepository.findByStationsContaining(testStation)).thenReturn(new ArrayList<>());

        // when
        stationService.deleteStation(stationId);

        // then
        verify(busRepository, never()).save(any(Bus.class));
        verify(stationRepository).delete(testStation);
    }
}