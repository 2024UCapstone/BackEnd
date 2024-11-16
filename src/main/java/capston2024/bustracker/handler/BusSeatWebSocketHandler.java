package capston2024.bustracker.handler;

import capston2024.bustracker.service.BusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 실시간 버스 좌석정보를 받아오는 아두이노 웹소켓 핸들러
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class BusSeatWebSocketHandler extends TextWebSocketHandler {

    private final BusService busService;
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
        busService.processBusSeatAsync(csvData)
                .thenAccept(bus -> {
                    try {
                        // IoT 디바이스에게 처리 완료 메시지 전송
                        session.sendMessage(new TextMessage("Location processed"));

                        // 모든 연결된 클라이언트에게 새로운 위치 데이터 브로드캐스트
                        broadcastLocationUpdate(csvData);
                    } catch (IOException e) {
                        log.error("Error sending confirmation", e);
                    }
                })
                .exceptionally(ex -> {
                    handleException(session, "Error processing bus location", ex);
                    return null;
                });
    }

    private void broadcastLocationUpdate(String csvData) {
        TextMessage updateMessage = new TextMessage(csvData);

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