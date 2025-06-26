package capston2024.bustracker.handler;

import capston2024.bustracker.service.BusLocationService;
import capston2024.bustracker.service.BusService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 실시간 버스 위치정보를 받아오는 아두이노 웹소켓 핸들러
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class BusLocationWebSocketCsvHandler extends TextWebSocketHandler {

    private final BusLocationService busLocationService;
    private final ObjectMapper objectMapper; // JSON 변환을 위해 추가
    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.add(session);
        log.info("New WebSocket connection established: {}", session.getId());
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
        log.info("WebSocket connection closed: {}", session.getId());
    }

    @Override
    public void handleTextMessage(WebSocketSession session, TextMessage message) {
        String csvData = message.getPayload();

        // IoT 디바이스로부터 받은 데이터 처리
        busLocationService.processBusLocationAsync(csvData)
                .thenAccept(v -> {
                    try {
                        // IoT 디바이스에게 처리 요청이 접수되었음을 알림 (선택 사항)
                        session.sendMessage(new TextMessage("CSV data received and is being processed."));
                    } catch (IOException e) {
                        log.error("Error sending confirmation message", e);
                    }
                })
                .exceptionally(ex -> {
                    handleException(session, "Error processing bus location", ex);
                    return null;
                });
    }

    /**
     * BusService에서 발생하는 BusStatusUpdateEvent를 리스닝하여
     * 모든 클라이언트에게 업데이트된 버스 상태 정보를 브로드캐스트합니다.
     * @param event 버스 상태 업데이트 이벤트
     */
    @EventListener
    public void busStatusUpdateListener(BusService.BusStatusUpdateEvent event) {
        try {
            // DTO를 JSON 문자열로 변환
            String busStatusJson = objectMapper.writeValueAsString(event.busStatus());
            TextMessage updateMessage = new TextMessage(busStatusJson);

            // 모든 세션에 브로드캐스트
            for (WebSocketSession clientSession : sessions) {
                try {
                    if (clientSession.isOpen()) {
                        clientSession.sendMessage(updateMessage);
                    }
                } catch (IOException e) {
                    log.error("Error broadcasting location update to client: {}",
                            clientSession.getId(), e);
                }
            }
        } catch (Exception e) {
            log.error("Failed to serialize or broadcast bus status update.", e);
        }
    }


    private void handleException(WebSocketSession session, String message, Throwable ex) {
        log.error(message, ex);
        try {
            session.sendMessage(new TextMessage("Error: " + message));
        } catch (IOException e) {
            log.error("Failed to send error message to client", e);
        }
    }
}