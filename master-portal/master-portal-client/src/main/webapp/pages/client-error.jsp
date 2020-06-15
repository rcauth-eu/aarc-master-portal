<%@ page trimDirectiveWhitespaces="true" contentType="text/plain;charset=UTF-8" language="java" %><%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>{<c:if test="${not empty message}">
  "message" : "${message}",</c:if><c:if test="${not empty cause}">
  "cause" : "${cause}",</c:if><c:if test="${not empty error}">
  "error" : "${error}",</c:if><c:if test="${not empty error_description}">
  "error_description": "${error_description}",</c:if><c:if test="${not empty state}">
  "state" : "${state}"</c:if>
}
