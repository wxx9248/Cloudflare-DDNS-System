:: Cloudflare DDNS System v4-0.1
:: Using Cloudflare API documentation v4 (Last modified: April 30th, 2019)
:: Written by wxx9248
:: 5/2/2019 15:47 CST (GMT +8:00)

:: Attention: This system needs cURL, which is not included
:: 			  in this program, please make manual configurations
::			  before using this system.

@ECHO off

CLS
TITLE Cloudflare DDNS System    by wxx9248

:: Fill this field with your own information
SET EMAIL=user@example.com
SET ZONEID=
SET DELAYMIN=30
SET DOMAINNAME=www.example.com
:: End user-editable field

:: For security, everytime this system starts, API key should be entered manually.
SET /P KEY="Please enter your Cloudflare API key: "
CLS


:: Program start
SET /A DELAYMS=%DELAYMIN%*60*1000

:: Environment check
ECHO [INFO]  Performing environment check...

curl >NUL 2>NUL
IF ERRORLEVEL 9009 (
	ECHO [ERROR] cURL isn't present at this console! Program will exit...
	GOTO Exit
)

Sleep >NUL 2>NUL
IF ERRORLEVEL 9009 (
	ECHO [ERROR] Sleep.exe isn't present at this console! Program will exit...
	GOTO Exit
)

isIPv4OK >NUL 2>NUL
IF ERRORLEVEL 9009 (
	ECHO [ERROR] isIPv4OK.exe isn't present at this console! Program will exit...
	GOTO Exit
)

:: Loop
:Do

:: Get DNS Record and its ID
FOR /F "tokens=1 delims=," %%i IN ('curl -s -X GET "https://api.cloudflare.com/client/v4/zones/%ZONEID%/dns_records?type=A&name=%DOMAINNAME%" -H "X-Auth-Email: %EMAIL%" -H "X-Auth-Key: %KEY%" -H "Content-Type: application/json"') DO SET DNSRecID=%%i
SET DNSRecID=%DNSRecID:~12%
IF ERRORLEVEL 2 (
	ECHO [ERROR] cURL returned a false value, please check your connection!
	GOTO EndOfDo
)
FOR /F "tokens=2 delims=:" %%i IN ('ECHO %DNSRecID%') DO SET DNSRecID=%%i
SET DNSRecID=%DNSRecID:~1,-1%
ECHO [INFO]  The ID of DNS record is %DNSRecID%.

FOR /F "tokens=4 delims=," %%i IN ('curl -s -X GET "https://api.cloudflare.com/client/v4/zones/%ZONEID%/dns_records?type=A&name=%DOMAINNAME%" -H "X-Auth-Email: %EMAIL%" -H "X-Auth-Key: %KEY%" -H "Content-Type: application/json"') DO SET DNSRecIP=%%i
IF ERRORLEVEL 2 (
	ECHO [ERROR] cURL returned a false value, please check your connection!
	GOTO EndOfDo
)
FOR /F "tokens=2 delims=:" %%i IN ('ECHO %DNSRecIP%') DO SET DNSRecIP=%%i
SET DNSRecIP=%DNSRecIP:~1,-1%
isIPv4OK %DNSRecIP%
IF ERRORLEVEL 1 (
	ECHO [ERROR] Error parsing the IP Cloudflare API has returned!
	GOTO EndOfDo
) ELSE (
	ECHO [INFO]  The IP in the DNS record is %DNSRecIP%.
)

:: Get current IP address
FOR /F "skip=1 tokens=1 delims=," %%i IN ('curl -s http://www.geoplugin.net/json.gp') DO (
	SET CurIP=%%i
	GOTO Out
)
:Out
IF ERRORLEVEL 2 (
	ECHO [ERROR] cURL returned a false value, please check your connection!
	GOTO EndOfDo
)
FOR /F "tokens=2 delims=:" %%i IN ('ECHO %CurIP%') DO SET CurIP=%%i
SET CurIP=%CurIP:~1,-1%
isIPv4OK %CurIP%
IF ERRORLEVEL 1 (
	ECHO [ERROR] Error parsing the IP Geoplugin API has returned!
	GOTO EndOfDo
) ELSE (
	ECHO [INFO]  The current public IP of this unit is %CurIP%.
)

IF %DNSRecIP%==%CurIP% (
	ECHO [INFO]  IPs match. Nothing to do.
) ELSE (
	ECHO [INFO]  It seems that IP has changed, calling Cloudflare API to sync...
	:: Change DNS record
	curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/%ZONEID%/dns_records/%DNSRecID%" -H "X-Auth-Email: %EMAIL%" -H "X-Auth-Key: %KEY%" -H "Content-Type: application/json" --data {"""type""":"""A""","""name""":"""%DOMAINNAME%""","""content""":"""%CurIP%"""} >nul
	IF ERRORLEVEL 2 (
		ECHO [ERROR] cURL returned a false value, please check your connection!
		GOTO EndOfDo
	)
)

ECHO [INFO]  Sleep for %DELAYMIN% minute(s).
Sleep %DELAYMS%

:EndOfDo
GOTO Do

:Exit
PAUSE
EXIT
