<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<script type="text/javascript">
function redirect() {

	var host = "${masterportal}"
	var volist = document.getElementById("volist");
	var vo = volist.options[volist.selectedIndex].text
	
	window.location = host + "?voms_fqan=" + vo;
}
</script>
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>VO Portal</title>
</head>

<body>

<h1>Welcome to the VO Portal!</h1>

<br><br><br>

Choose your vo from the list: 

<select name="volist" id="volist">
    <c:forEach var="vo" items="${vomses}">
           <option value="${vo}">${vo}</option>
    </c:forEach>
</select>

<br>

<button onclick="redirect()">Go Go!</button>

</body>
</html>