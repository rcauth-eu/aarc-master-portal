<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head><title>Delegation Service Error Page</title></head>
<style type="text/css">
    .hidden {
        display: none;
    }

    .unhidden {
        display: block;
    }
</style>
<script type="text/javascript">
    function unhide(divID) {
        var item = document.getElementById(divID);
        if (item) {
            item.className = (item.className == 'hidden') ? 'unhidden' : 'hidden';
        }
    }
</script>
<body>
<h2>Uh-oh!</h2>
There was a problem servicing your request. <br><br>
Message: <i>${message}</i>
<br><br>
Reason:<i>${cause}</i>
<br><br>
You should contact your Master Portal's support and
have them check the server logs in order to investigate this
error further. <br><br>

<form name="input" action="${client.homeUri}" method="get">
    <input type="submit" value="return to client"/>
</form>
<ul>
    <li><a href="javascript:unhide('showStackTrace');">Show/Hide stack trace</a></li>
    <div id="showStackTrace" class="hidden">
        <p>
        <pre style="white-space: pre-wrap; width: 50%;" >${stackTrace}</pre>
    </div>
</ul>
</body>
</html>          