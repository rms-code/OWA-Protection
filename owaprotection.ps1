#Data from our IIS exported as json into a var for later use
$owainfo = Get-Content \\YOUREXCHANGE\data\owaiis.json | ConvertFrom-Json | Select EventReceivedTime, @{ N = "ClientIP"; E = { $_."c-ip" } }, @{ N = "UserName"; E = { $_."cs-username" } }, @{N = "ConnectionType"; E = { $_."cs-uri-stem" }}, csuser-agent, cs-referrer | Where-Object {$_.ClientIP -NotLike "YOURSERVERVLAN" }

#Data from json export for new data
$owasort = Get-Content \\YOUREXCHANGE\data\owaiis.json | ConvertFrom-Json | Where-Object {
	$_.'cs-username' -NotMatch '-' -and $_.'cs-uri-stem' -Match '/owa/logoff.owa' -or $_.'cs-uri-stem' -Match '/owa/auth.owa' -or $_.'cs-uri-stem' -Match '/owa/auth/error.aspx'
} | Select EventReceivedTime, cs-referrer, @{ N = "ClientIP"; E = { $_."c-ip" } }, @{ N = "UserName"; E = { $_."cs-username" } } | Where-Object { $_.ClientIP -NotLike "SERVERVLAN" } | Sort EventReceivedTime

#Lets get some logs for graylog/analysis 
$owainfo | Export-Csv 'C:\logs\fullowalog.csv' -Append -Force

#csv data used for each run
$owasort | Export-Csv 'C:\logs\owanewsort.csv'

#Run some object selection and removal of domain @ or FQDN for get-aduser later
$owanewsorted = Get-Content 'C:\logs\owanewsort.csv' | ConvertFrom-CSV | Select EventReceivedTime, UserName, ClientIP, cs-referrer | ForEach-Object {$_.UserName = ($_.UserName) -replace {\@YOURDOMAIN\.com|YOURDOMAIN\.com|YOURDOMAIN\/|YOURDOMAIN\\|YOURDOMAIN}; $_ } | sort EventReceivedTime

#run to sort good logins vs bad logins[user or pass], also export bad/good logins for later reference.
foreach ($line in $owanewsorted)
{
	if ($line.'cs-referrer' -match '302')
	{
		$owanewsorted | Where-Object {$_.'cs-referrer' -eq 302} | Sort EventReceivedTime -unique | Export-Csv 'C:\logs\gooduserindex.csv' -append
	}
	elseif ($line.'cs-referrer' -match '401')
	{
		$users = $line.UserName
		if ([bool] (Get-ADUser -Filter { samaccountname -eq $users }))
		{
			$line | Sort EventReceivedTime | Export-Csv 'C:\logs\gooduserbadpwd.csv' -Append
			$line | Sort EventReceivedTime | Export-Csv 'C:\logs\gooduserbadpwd_log.csv' -Append
			
		}
		else
		{
			$line | Sort EventReceivedTime | Export-Csv 'C:\logs\baduser.csv' -Append
			$line | Sort EventReceivedTime | Export-Csv 'C:\logs\baduser_log.csv' -Append
		}
	}
}

#Comparing Variables Gooduser/Badpass
$gooduserbadpass = Get-Content 'C:\logs\gooduserbadpwd.csv' | ConvertFrom-Csv
$owaguserindex = Get-Content 'C:\logs\gooduserindex.csv' | ConvertFrom-Csv | Select-Object ClientIP

#loop run through checking ip gooduser IP matches index and what to do with it
foreach ($guduser in $gooduserbadpass)
{
	$userMatch = $owaguserindex | where { $_.ClientIP -eq $guduser.ClientIP }
	if ($userMatch)
	{
		$guduser | Export-Csv 'C:\logs\gooduserbadpwdmatchip.csv' -Append
		$guduser | Export-Csv 'C:\logs\gooduserbadpwdmatchip_log.csv' -Append
	}
	else
	{
		$guduser | Export-Csv 'C:\logs\gooduserbadpwdNOMATCH.csv' -Append
		$guduser | Export-Csv 'C:\logs\gooduserbadpwdNOMATCH_log.csv' -Append
		
		#Lets see if the same IP matches other USERS in our NOMATCH index, this would be a good sign for spraying/bruteforce in slow-mode
		$daspray = Get-Content C:\logs\gooduserbadpwdNOMATCH_log.csv | ConvertFrom-Csv 
		$daspray2 = Get-Content C:\logs\gooduserbadpwdNOMATCH.csv | ConvertFrom-Csv
		foreach ($dasprayuser in $daspray2)
		{
			$das = $daspray | where { $_.ClientIP -eq $dasprayuser.ClientIP -and $_.UserName -ne $dasprayuser.UserName} | Sort UserName -Unique
			if ($das)
			{
				#add to auto-ip ban list 
				Send-MailMessage -From "someone@YOURDOMAIN.com" -To "youradmins@YOURDOMAIN.com" -Subject "[INDEX-CHECK] SAME IP MULTI-USER, OWA SPRAYING/BRUTEFORCE" -Body "The Current User(s) also match other users in the NOMATCH index!`n`n $dasprayuser" -SmtpServer "YOUREXCHANGE.YOURDOMAIN.com"
			}
		}
		
		#Lets see if the same IP matches other USERS in current run, this would be spraying/bruteforce by a bot or someone not trying to be quiet
		$bar = Import-Csv C:\logs\gooduserbadpwdNOMATCH.csv
		$barr = $bar | Group ClientIP | ? { $_.Count -ge 2 } | Select -ExpandProperty Group
		$barr2 = $barr | Group UserName | ? { $_.Count -eq 1 } | Select -ExpandProperty Group
		foreach($derp in $barr2)
		{
			#Add these IPs to AutoBan Layer
			$cidr = "/32"
			$derp2 = $derp | Select ClientIP | ForEach-Object { $_.ClientIP + $cidr }
			
			##### This can be tied into the SMTP IP banning part for the firewall
			#Add-Content -Path "\\YOUREXCHANGE\data\notld.txt" -Value $derp2
			
			#Send an email alert
			Send-MailMessage -From "someone@YOURDOMAIN.com" -To "youradmins@YOURDOMAIN.com" -Subject "[LIVE] SAME IP MULTI-USER, OWA SPRAYING/BRUTEFORCE" -Body "The Current User(s) also match other users in the LIVE NOMATCH index!`n`n $derp" -SmtpServer "YOUREXCHANGE.YOURDOMAIN.com"
		}
		
		# > 4 tries, lets disable OWA, import exchange cmdlets -- you can change or just disable this depending how strict etc.
		$da = Get-Content C:\logs\gooduserbadpwdNOMATCH.csv | ConvertFrom-CSV | Sort EventReceivedTime | group UserName, ClientIP | Select Name, Count | Where-Object { $_.Count -ge 4 }
		if ($da)
		{
			$dagud = ($da.Name) -replace '(.+?),.+', '$1'
				foreach ($dagudusr in $dagud)
				{
				$ex2 = New-PSSession -ConnectionUri http://YOUREXCHANGE/powershell -ConfigurationName Microsoft.Exchange
				Import-PSSession $ex2 -WarningAction SilentlyContinue
				Set-CASMailbox "$dagudusr" -OWAEnabled $false
				Send-MailMessage -From "someone@YOURDOMAIN.com" -To "youradmins@YOURDOMAIN.com" -Subject "GOOD USERNAME(S) - OWA NO IP MATCH +4 ATTEMPTS, DISABLING" -Body "$da" -SmtpServer "YOUREXCHANGE.YOURDOMAIN.com"
				}
		}
		Remove-PSSession $ex2
	}
}

#Comparing Variables Bad User
$baduser = Get-Content 'C:\logs\baduser.csv' | ConvertFrom-Csv

#loop run through checking ip baduser IP matches index and what to do with it
foreach ($buser in $baduser)
{
	$userMatch2 = $owaguserindex | where { $_.ClientIP -eq $buser.ClientIP }
	if ($userMatch2)
	{
		$buser | Export-Csv 'C:\logs\badusermatchip.csv' -Append
		$buser | Export-Csv 'C:\logs\badusermatchip_log.csv' -Append
	}
	else
	{
		$buser | Export-Csv 'C:\logs\baduserNOMATCH.csv' -Append
		$buser | Export-Csv 'C:\logs\baduserNOMATCH_log.csv' -Append
		
		#Alert Var+Condition
		$da2 = Get-Content C:\logs\baduserNOMATCH.csv | ConvertFrom-CSV | Sort EventReceivedTime | group UserName, ClientIP | Select Name, Count | Where-Object { $_.Count -ge 1 }
		if ($da2)
		{
			Send-MailMessage -From "someone@YOURDOMAIN.com" -To "youradmins@YOURDOMAIN.com" -Subject "YELLOW - BAD USERNAME - OWA NO IP MATCH 1 TRY" -Body "$da2" -SmtpServer "YOUREXCHANGE.YOURDOMAIN.com"
		}
		
		#Ban IP Var+Condition
		$da3 = Get-Content C:\logs\baduserNOMATCH.csv | ConvertFrom-CSV | Sort EventReceivedTime | group UserName, ClientIP | Select Name, Count | Where-Object { $_.Count -ge 4 }
		if ($da3)
		{
			$cidr = "/32"
			$da4 = Get-Content C:\logs\baduserNOMATCH.csv | ConvertFrom-CSV | Select ClientIP | ForEach-Object { $_.ClientIP + $cidr } | Sort -unique
			
			#Lets pass this IP over to the Auto-IP ban layer
			#####Add-Content -Path "\\YOUREXCHANGE\data\notld.txt" -Value $da4
			
			#Send an email alert
			Send-MailMessage -From "someone@YOURDOMAIN.com" -To "youradmins@YOURDOMAIN.com" -Subject "RED - BAD USERNAME - OWA NO IP MATCH, 4+ TRIES, BANNING IP" -Body "$da3" -SmtpServer "YOUREXCHANGE.YOURDOMAIN.com"
		}
	}
}

#Clearing Content for each next run
Clear-Content "\\YOUREXCHANGE\data\owaiis.json"
Clear-Content 'C:\logs\owanewsort.csv'
Clear-Content 'C:\logs\baduser.csv'
Clear-Content 'C:\logs\gooduserbadpwd.csv'
Clear-Content 'C:\logs\gooduserbadpwdNOMATCH.csv'
Clear-Content 'C:\logs\gooduserbadpwdmatchip.csv'
Clear-Content 'C:\logs\baduserNOMATCH.csv'
Clear-Content 'C:\logs\badusermatchip.csv'