package capston2024.bustracker.controller;

import capston2024.bustracker.service.AuthService;
import capston2024.bustracker.service.BusService;
import capston2024.bustracker.service.RouteService;
import capston2024.bustracker.service.StationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

@Controller
@RequestMapping("/staff")
@RequiredArgsConstructor
public class StaffController {

    private final AuthService authService;
    private final BusService busService;
    private final RouteService routeService;
    private final StationService stationService;

    @GetMapping("/login")
    public String loginPage() {
        return "staff/login";
    }


    @GetMapping("/dashboard")
    public String dashboard(@RequestParam(required = false) String token, @AuthenticationPrincipal OAuth2User principal, Model model) {
        if (principal == null) {
            return "redirect:staff/login"; // Or a generic error page
        }
        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");
        model.addAttribute("user", userInfo);
        model.addAttribute("token", token);
        if (organizationId != null && !organizationId.isEmpty()) {
            model.addAttribute("buses", busService.getAllBusStatusByOrganizationId(organizationId));
            model.addAttribute("routes", routeService.getAllRoutesByOrganizationId(organizationId));
            model.addAttribute("stations", stationService.getAllStations(organizationId));
        }
        return "staff/dashboard";
    }
}