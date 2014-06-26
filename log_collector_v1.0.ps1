<#
Title: log_collector_v1.0.ps1
Description: Windows EventLog Clear and Parser
Date: 06/05/2014
Author: Ryan Clark
Company:Northrop Grumman (IS)
Email: william.clark@ngc.com
Version: 1.0     Initial Release
#>

#Script Config
$psHost = (get-host).UI.RawUI
$psHost.WindowTitle = "Windows Log Collector 1.0"
$ErrorActionPreference = "SilentlyContinue"
#Run script as admin
if   (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
} #end if


#Variables 
#$Computers = get-content "C:\Audit_Logs\Systems.txt"      #Use if you have a list of systems
$LogFolder = "Audit_Logs"                                  #Specify audit log folder for local system
$LogsArchive = "E:\Audit_Logs"                             #Specify audit log folder for network storage


#Color Function For Screen Output
function color-Write
{
    #Local Variables
    $allColors = ("-Black",   "-DarkBlue","-DarkGreen","-DarkCyan","-DarkRed","-DarkMagenta","-DarkYellow","-Gray",
                  "-Darkgray","-Blue",    "-Green",    "-Cyan",    "-Red",    "-Magenta",    "-Yellow",    "-White")
    $foreground = (Get-Host).UI.RawUI.ForegroundColor # current foreground
    $color = $foreground
    [bool]$nonewline = $false
    $sofar = ""
    $total = ""
    
    #Function Body
    foreach($arg in $args)
    {
        if ($arg -eq "-nonewline") { $nonewline = $true }
        elseif ($arg -eq "-foreground")
        {
            if ($sofar) { Write-Host $sofar -foreground $color -nonewline }
            $color = $foregrnd
            $sofar = ""
        } #end elseif
        elseif ($allColors -contains $arg)
        {
            if ($sofar) { Write-Host $sofar -foreground $color -nonewline }
            $color = $arg.substring(1)
            $sofar = ""
        } #end elseif
        else
        {
            $sofar += "$arg "
            $total += "$arg "
        } #end else
    } #end foreach
    #last bit done special
    if (!$nonewline)
    {
        Write-Host $sofar -foreground $color
    } #end if
    elseif($sofar)
    {
        Write-Host $sofar -foreground $color -nonewline
    } #end elseif
} #end color-Write function


Function Get-ADComputers
{
 $ds = New-Object DirectoryServices.DirectorySearcher
 $ds.Filter = "ObjectCategory=Computer"
 $ds.FindAll() | 
     ForEach-Object { $_.Properties['dnshostname']}
} #end Get-AdComputers function


Function Test-ComputerConnection
{
 ForEach($System in $Computers)
 {
  $Result = Get-WmiObject -Class win32_pingstatus -Filter "address='$System'"
  $computer = $System | %{$_.split('.')[0]} 
  If($Result.Statuscode -eq 0)
   {
     if($computer.length -ge 1) 
        { 
         color-write -green "+ Processing $Computer"
         Get-BackUpFolder
	     Copy-ArchivedLogs 
        }
   } #end if
   else { color-write -yellow "- Skipping $computer .. not accessible" }
 } #end Foreach
} #end Test-ComputerConnection


Function Get-BackUpFolder
{
 $folder = $computer
  New-Item "$LogsArchive\$folder" -type Directory -force  | out-Null
  If(!(Test-Path "\\$computer\c$\$LogFolder"))
    {
      New-Item "\\$computer\c$\$LogFolder" -type Directory -force | out-Null
    } #end if
 Backup-EventLogs($Folder)
} #end Get-BackUpFolder function


Function Backup-EventLogs
{
 $dateTime = "{0:MM-dd-yyyy_hh-mm-ss}" -f [DateTime]::now
 $Eventlogs = Get-WmiObject -Class Win32_NTEventLogFile -ComputerName $computer
 Foreach($log in $EventLogs)
        {
        if ($log.LogfileName -eq "Application" -or $log.LogfileName -eq "Security" -or $log.LogfileName -eq "System")
            {
            $path = "\\{1}\c$\$LogFolder\{0}_{1}_{2}.evt" -f $dateTime,$computer,$log.LogFileName
            $logName = "{0}_{1}_{2}.evt" -f $dateTime,$computer,$log.LogFileName
            $ErrBackup = ($log.BackupEventLog($path)).ReturnValue
                if($ErrBackup -eq 0)
                  {
                   $errClear = ($log.ClearEventLog()).ReturnValue
                  } #end if
                else
                  { 
                    color-write -red "- Unable to clear event log because backup failed" 
                    color-write -red "- Backup Error was " + $ErrBackup
                  } #end else
            Copy-EventLogsToArchive -path $path -Folder $Folder
            } #end if
        } #end foreach log
} #end Backup-EventLogs function


Function Copy-EventLogsToArchive($path, $folder)
{
if ($path.contains("Security"))
	{
	Copy-Item -path $path -dest "$LogsArchive" -force
    $localLogsize = ((get-childitem $path).Length / 1MB)
    $netLogsize = ((get-childitem "$LogsArchive\$logName").Length / 1MB)
    $testLogpath = test-path "$LogsArchive\$logName"
    if ($testLogpath -eq "True" -and $netLogsize -eq $localLogsize)
        {
        remove-item $path
        } #end if
    else
        {
        color-write -red "- Could not determine if the log was successfully copied to the network location. Check $path and $LogsArchive\$logName"
        } #end else
	} #end if
else	
	{
 	Copy-Item -path $path -dest "$LogsArchive\$folder" -force
    $localLogsize = ((get-childitem $path).Length / 1MB)
    $netLogsize = ((get-childitem "$LogsArchive\$folder\$logName").Length / 1MB)
    $testLogpath = test-path "$LogsArchive\$folder\$logName"
    if ($testLogpath -eq "True" -and $netLogsize -eq $localLogsize)
        {
        remove-item $path
        } #end if
    else
        {
        color-write -red "Could not determine if the log was successfully copied to the network location. Check $path and $LogsArchive\$logName"
        } #end else
	} #end else
    
} #end Copy-EventLogsToArchive function


Function Copy-ArchivedLogs
{
$archivedLogs = get-childitem "\\$computer\C$\Windows\System32\winevt\Logs\Archive*" | foreach {$_.Name}
$logPath = "\\$computer\C$\Windows\System32\winevt\Logs"
    #Look for rotated logs
    if ($archivedLogs -ne $null)
       {
        color-write -green "+ Processing Archived Logs on $computer ....Copying to $LogsArchive\$folder"
        foreach ($log in $archivedLogs)
                {
                $archivedLog = "$logPath\$log"
		        $date = $log | %{$_.split('-')[3,4,2]}
                $time = $log | %{$_.split('-')[5,6,7]}
                $logType = $log | %{$_.split('-')[1]}
                $joinDate = $date -join "-"
                $joinTime = $time -join "-"
                $renameLog = "{0}_{1}_{2}_{3}.evt" -f $joinDate,$joinTime,$computer,$logType
		        if ($archivedLog.contains("Security"))
			       {
                	copy-item -path $archivedLog -dest "$LogsArchive\$renameLog" -force
                    $testlogPath = test-path "$LogsArchive\$renameLog"
                    $locallogSize = ((get-childitem $archivedLog).Length / 1MB)
                    $netlogSize = ((get-childitem "$LogsArchive\$renameLog").Length / 1MB)
                    if ($testlogPath -eq "True" -and $locallogSize -eq $netlogSize)
                       {
                        remove-item $archivedLog
                       } #end if
                    else
                       {
                        color-write -red "-Could not determine if the archived logs were successfully copied to the network location. Check $logPath and $LogsArchive\$folder for the logs." 
                       } #end else
	               } #end if
                else
	               {
			        copy-item -path $archivedLog -dest "$LogsArchive\$folder\$renameLog" -force
                    $testPath = test-path "$LogsArchive\$folder\$renameLog" 
                    $localSize = ((get-childitem $archivedLog).Length / 1MB)
                    $netSize = ((get-childitem "$LogsArchive\$folder\$renameLog").Length / 1MB)  
                    if ($testPath -eq "True" -and $localSize -eq $netSize)
                       {
                        remove-item $archivedLog
                       } #end if
                    else
                       {
                        color-write -red "-Could not determine if the archived logs were successfully copied to the network location. Check $logPath and $LogsArchive\$folder for the logs." 
                       } #end else
			       } #end else
                } #foreach
       } #end if
} #end Copy-ArchivedLogs function


# Script Main
$Computers = Get-ADComputers; Test-ComputerConnection;
$shell = new-object -comobject "WScript.Shell"
$result = $shell.popup("Do you want quit?",0,"Script Completed",4+32)
if ($result -eq 6)
   {
    exit
   } #end if
else
   {
    start-sleep 100000
   } #end else
