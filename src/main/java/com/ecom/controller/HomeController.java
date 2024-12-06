package com.ecom.controller;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import com.ecom.model.Category;
import com.ecom.model.Product;
import com.ecom.model.UserDtls;
import com.ecom.service.CartService;
import com.ecom.service.CategoryService;
import com.ecom.service.ProductService;
import com.ecom.service.UserService;
import com.ecom.util.CommonUtil;

import io.micrometer.common.util.StringUtils;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {

	@Autowired
	private CategoryService categoryService;

	@Autowired
	private ProductService productService;

	@Autowired
	private UserService userService;

	@Autowired
	private CommonUtil commonUtil;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	private CartService cartService;

	@ModelAttribute
	public void getUserDetails(Principal p, Model m) {
		if (p != null) {
			String email = p.getName();
			//UserDtls userDtls = userService.getUserByEmail(email);
			UserDtls userDtls = userService.getUserByName(email);
			m.addAttribute("user", userDtls);
			Integer countCart = cartService.getCountCart(userDtls.getId());
			m.addAttribute("countCart", countCart);
		}

		List<Category> allActiveCategory = categoryService.getAllActiveCategory();
		m.addAttribute("categorys", allActiveCategory);
	}

	@GetMapping("/")
	public String index(Model m) {

		List<Category> allActiveCategory = categoryService.getAllActiveCategory().stream()
				.sorted((c1, c2) -> c2.getId().compareTo(c1.getId())).limit(6).toList();
		List<Product> allActiveProducts = productService.getAllActiveProducts("").stream()
				.sorted((p1, p2) -> p2.getId().compareTo(p1.getId())).limit(8).toList();
		m.addAttribute("category", allActiveCategory);
		m.addAttribute("products", allActiveProducts);
		return "index";
	}

	@GetMapping("/signin")
	public String login() {
		return "login";
	}

	@GetMapping("/register")
	public String register() {
		return "register";
	}

	@GetMapping("/products")
	public String products(HttpServletRequest req, Model m, @RequestParam(value = "category", defaultValue = "") String category,
			@RequestParam(name = "pageNo", defaultValue = "0") Integer pageNo,
			@RequestParam(name = "pageSize", defaultValue = "12") Integer pageSize,
			@RequestParam(defaultValue = "") String ch) {

		String authServiceUrl = "http://localhost:8093/signin";
		String paramSessionId = "";
		HttpSession session = req.getSession(false);
    	if(session != null) {
    		paramSessionId = (String) session.getAttribute("sessionId");
    		paramSessionId = paramSessionId != null ? paramSessionId : "";
    	}
    	RestTemplate restTemplate = new RestTemplate();
		String validateUrl = authServiceUrl + "/validate-session/" + paramSessionId;
		ResponseEntity<UserDtls> validateResponse = restTemplate.getForEntity(validateUrl, UserDtls.class);
        if (validateResponse.getStatusCode().is2xxSuccessful() && validateResponse.getBody() != null) {
        	System.out.println("Session is valid. Login is successful");
        	HttpHeaders httpHeaders = validateResponse.getHeaders();
            if (httpHeaders.containsKey(HttpHeaders.SET_COOKIE)) {
                for (String cookie : httpHeaders.get(HttpHeaders.SET_COOKIE)) {
                    if (cookie.startsWith("sessionId=")) {
                        String sessionId = cookie.split(";")[0].split("=")[1];
                        System.out.println("sessionId: " + sessionId);
                        req.getSession().setAttribute("sessionId", sessionId);
                    }
                }
            }
        }
        
		List<Category> categories = categoryService.getAllActiveCategory();
		m.addAttribute("paramValue", category);
		m.addAttribute("categories", categories);

		Page<Product> page = null;
		if (StringUtils.isEmpty(ch)) {
			page = productService.getAllActiveProductPagination(pageNo, pageSize, category);
		} else {
			page = productService.searchActiveProductPagination(pageNo, pageSize, category, ch);
		}

		List<Product> products = page.getContent();
		m.addAttribute("products", products);
		m.addAttribute("productsSize", products.size());

		m.addAttribute("pageNo", page.getNumber());
		m.addAttribute("pageSize", pageSize);
		m.addAttribute("totalElements", page.getTotalElements());
		m.addAttribute("totalPages", page.getTotalPages());
		m.addAttribute("isFirst", page.isFirst());
		m.addAttribute("isLast", page.isLast());

		return "product";
	}

	@GetMapping("/product/{id}")
	public String product(@PathVariable int id, Model m) {
		Product productById = productService.getProductById(id);
		m.addAttribute("product", productById);
		return "view_product";
	}

	@PostMapping("/saveUser")
	public String saveUser(@ModelAttribute UserDtls user, @RequestParam("img") MultipartFile file, HttpSession session)
			throws IOException {

		Boolean existsEmail = userService.existsEmail(user.getEmail());

		if (existsEmail) {
			session.setAttribute("errorMsg", "Email already exist");
		} else {
			String imageName = file.isEmpty() ? "default.jpg" : file.getOriginalFilename();
			user.setProfileImage(imageName);
			UserDtls saveUser = userService.saveUser(user);

			if (!ObjectUtils.isEmpty(saveUser)) {
				if (!file.isEmpty()) {
					File saveFile = new ClassPathResource("static/img").getFile();

					Path path = Paths.get(saveFile.getAbsolutePath() + File.separator + "profile_img" + File.separator
							+ file.getOriginalFilename());

//					System.out.println(path);
					Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
				}
				session.setAttribute("succMsg", "Register successfully");
			} else {
				session.setAttribute("errorMsg", "something wrong on server");
			}
		}

		return "redirect:/register";
	}

//	Forgot Password Code 

	@GetMapping("/forgot-password")
	public String showForgotPassword() {
		return "forgot_password.html";
	}

	@PostMapping("/forgot-password")
	public String processForgotPassword(@RequestParam String email, HttpSession session, HttpServletRequest request)
			throws UnsupportedEncodingException, MessagingException {

		UserDtls userByEmail = userService.getUserByEmail(email);

		if (ObjectUtils.isEmpty(userByEmail)) {
			session.setAttribute("errorMsg", "Invalid email");
		} else {

			String resetToken = UUID.randomUUID().toString();
			userService.updateUserResetToken(email, resetToken);

			// Generate URL :
			// http://localhost:8080/reset-password?token=sfgdbgfswegfbdgfewgvsrg

			String url = CommonUtil.generateUrl(request) + "/reset-password?token=" + resetToken;

			Boolean sendMail = commonUtil.sendMail(url, email);

			if (sendMail) {
				session.setAttribute("succMsg", "Please check your email..Password Reset link sent");
			} else {
				session.setAttribute("errorMsg", "Somethong wrong on server ! Email not send");
			}
		}

		return "redirect:/forgot-password";
	}

	@GetMapping("/reset-password")
	public String showResetPassword(@RequestParam String token, HttpSession session, Model m) {

		UserDtls userByToken = userService.getUserByToken(token);

		if (userByToken == null) {
			m.addAttribute("msg", "Your link is invalid or expired !!");
			return "message";
		}
		m.addAttribute("token", token);
		return "reset_password";
	}

	@PostMapping("/reset-password")
	public String resetPassword(@RequestParam String token, @RequestParam String password, HttpSession session,
			Model m) {

		UserDtls userByToken = userService.getUserByToken(token);
		if (userByToken == null) {
			m.addAttribute("errorMsg", "Your link is invalid or expired !!");
			return "message";
		} else {
			userByToken.setPassword(passwordEncoder.encode(password));
			userByToken.setResetToken(null);
			userService.updateUser(userByToken);
			// session.setAttribute("succMsg", "Password change successfully");
			m.addAttribute("msg", "Password change successfully");

			return "message";
		}

	}

	@GetMapping("/search")
	public String searchProduct(@RequestParam String ch, Model m) {
		List<Product> searchProducts = productService.searchProduct(ch);
		m.addAttribute("products", searchProducts);
		List<Category> categories = categoryService.getAllActiveCategory();
		m.addAttribute("categories", categories);
		return "product";

	}
	
	@PostMapping("/authenticate")
	public String authenticate(@RequestParam String username, @RequestParam String password, Model model, HttpServletRequest request) {
		String authServiceUrl = "http://localhost:8093/signin";
		
		RestTemplate restTemplate = new RestTemplate();
		try {
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

	        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
	        body.add("username", username);
	        body.add("password", password);

	        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

	        ResponseEntity<String> response = restTemplate.postForEntity(authServiceUrl, requestEntity, String.class);

	        if (response.getStatusCode().is3xxRedirection()) {
	        	
	        	List<String> cookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
	            if (cookies != null && !cookies.isEmpty()) {
	                String sessionCookie = cookies.get(0).substring(10, 46); // Fetch the first cookie
	                System.out.println("Extracted Cookie: " + sessionCookie);
	                
	                
	                String validateUrl = authServiceUrl + "/validate-session/" + sessionCookie;
	                ResponseEntity<UserDtls> validateResponse = restTemplate.getForEntity(validateUrl, UserDtls.class);
	                if (validateResponse.getStatusCode().is2xxSuccessful() && validateResponse.getBody() != null) {
	                    System.out.println("Session is valid. Login is successful");
	                    
	                    HttpHeaders httpHeaders = validateResponse.getHeaders();
	                    if (httpHeaders.containsKey(HttpHeaders.SET_COOKIE)) {
	                        for (String cookie : httpHeaders.get(HttpHeaders.SET_COOKIE)) {
	                            if (cookie.startsWith("sessionId=")) {
	                                String sessionId = cookie.split(";")[0].split("=")[1];
	                               
	                                request.getSession().setAttribute("sessionId", sessionId);
	                                return "redirect:/user/home";
	                            }
	                        }
	                    }
	                    return "redirect:/user/home";
	                } else {
	                    model.addAttribute("error", "Session validation failed");
	                    return "login";
	                }
	                
	            } else {
	                System.out.println("No cookies found in the response headers.");
	            }
	        	
	        	System.out.println("Login is successful");
	            return "redirect:user/home";
	        } else {
	            model.addAttribute("error", "Invalid Credentials");
	            return "login";
	        }
	    }catch (Exception e) {
			model.addAttribute("error", "Invalid Credentials");
			System.out.println("Invalid creds " + e.getMessage());
			return "login";
		}
	}
}
