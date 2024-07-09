package dk.friisjakobsen.security.controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

	@RequestMapping("/error")
	public String handleError(HttpServletRequest request, Model model) {
		Object status = request.getAttribute("jakarta.servlet.error.status_code");

		if (status != null) {
			int statusCode = Integer.parseInt(status.toString());
			HttpStatus httpStatus = HttpStatus.valueOf(statusCode);
			model.addAttribute("httpStatus", httpStatus);
			model.addAttribute("statusCode", statusCode);
		}

		return "error";
	}
}