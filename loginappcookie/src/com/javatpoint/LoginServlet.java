package com.javatpoint;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class LoginServlet extends HttpServlet {
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		PrintWriter out=response.getWriter();
		
		//Como no hay base de datos se utiliza este archivo para evitar que el usuario y la passwd esten en el codigo
		File file = new File("/home/jack/credentials.txt");  
		BufferedReader br = new BufferedReader(new FileReader(file));
		//Se usan expresiones regulares para verificar que las cadenas intoducidas por el usuario cumplen unos
		//requisitos de longitud y caracteres y asi se evitan ataques como inyecciones de codigo y bufferoverflow 
		String pattern = "^[a-zA-Z][a-zA-Z0-9\\-\\_]{8,12}";
		char[] name = null;
		char[] password = null;
		
		//Se usan char[] paraevitar que las credenciales permanezcan en memoria
		char[] userStored = (br.readLine()).toCharArray();
		char[] passwordStored = (br.readLine()).toCharArray();
		
		br.close();
		request.getRequestDispatcher("link.html").include(request, response);
		
		if(request.getParameter("name").matches(pattern) && request.getParameter("password").matches(pattern)) {
			name=(request.getParameter("name")).toCharArray();
			password=(request.getParameter("password")).toCharArray();
		}
		
		if(Arrays.equals(password, passwordStored) &&  Arrays.equals(userStored, name) && request.getParameter("name").matches(pattern)
				&& request.getParameter("password").matches(pattern)){
			out.print("You are successfully logged in!");
			out.print("<br>Welcome, "+ String.copyValueOf(name));
			
			//Se calcula un hasch con el nombre de usuario y la passwd para evitar enviar al cliente estos datos en la cookie
			//de sesion, ademas esta comunicacion deberia estar encriptada
			int nameHash = name.hashCode();
			int passHash = password.hashCode();
			Cookie ck=new Cookie("name", Integer.toString(nameHash + passHash));
			response.addCookie(ck);
		}else{
			out.print("sorry, username or password error!");
			request.getRequestDispatcher("login.html").include(request, response);
		}
		
		out.close();
	}

}
