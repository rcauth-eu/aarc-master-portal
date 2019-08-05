<%@ page contentType="text/plain;charset=UTF-8" language="java" %><%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
{<c:if test="${not empty message}">
  "Message" : "${message}",</c:if><c:if test="${not empty cause}">
  "Cause" : "${cause}",</c:if><c:if test="${not empty error}">
  "Error" : "${error}",</c:if><c:if test="${not empty error_description}">
  "Error description": "${error_description}",</c:if><c:if test="${not empty state}">
  "State" : "${state}"</c:if>
}
