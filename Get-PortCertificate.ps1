function Get-PortCertificate {
    <#
    .SYNOPSIS
        Retrieves a certificate from a TLS/SSL port.
     
    .DESCRIPTION
        Retrieves a certificate that is being presented on a listening TLS/SSL port.
     
    .PARAMETER ComputerName
        Hostname(s) or IP Address(es) of the target system (Default: localhost).
     
    .PARAMETER Port
        Port to retrieve SSL certificate (Default: 443).
     
    .PARAMETER Path
        Directory path to save SSL certificate(s).
    
    .INPUTS
        Adding the Verbose flag will immediatley run certutil.exe on the retrieved certificate
        
    .OUTPUTS
        Important Certificate Details
        Base64 Encoded Certificate (.cer)
     
    .EXAMPLE
        PS> Get-PortCertificate -ComputerName localhost -Port 3389 -Path "<path/to/folder>"
    
    .EXAMPLE
        PS> Get-PortCertificate -ComputerName localhost -Port 3389 -Path "<path/to/folder>" -Verbose
     
    .EXAMPLE
        PS> "localhost","localhost2","localhost3","127.0.0.2" | Get-PortCertificate -Path "<path/to/folder>"
    
    .NOTES
        Filename:       Get-PortCertificate.ps1
        Author:         https://github.com/himbojo
        Modified date:  26-01-2023
        Version:        1.0
    
    .LINK
        https://github.com/himbojo/WindowsScripts
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [Alias('IPAddress', 'Server', 'Computer')]              
        [string]$ComputerName = $env:COMPUTERNAME,  
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(1, 65535)]
        [int]$Port = 443,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Path
    )
    
    Begin {
        function Get-Extension {
            param (
                [Parameter(Mandatory = $true)]
                [Security.Cryptography.X509Certificates.X509ExtensionCollection]$Extensions,
                [Parameter(Mandatory = $true)]
                [string]$SearchString
            )
            $ext = $Extensions | Where-Object { $_.Oid.FriendlyName -eq $SearchString }
            if ($ext) {
                return $ext.Format(0)
            }
            else {
                return ""
            }
        }
    
        # Ensure $Path is set to a valid container
        if (!(Test-Path -PathType Container $Path)) {
            Write-Error "The path provided is not valid '$Path'" -ErrorAction Stop
        }
        $i = 0
    }
    Process {
        # Test the port is open
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $tcpClient.Connect($ComputerName, $Port)
        }
        catch {
            Write-Host "Could not connect to ComputerName: $ComputerName on Port: $Port."
            Write-Error $_
            return
        }
        finally {
            $tcpClient.Dispose()
        }
        # Make an HTTPS connection to a server
        $request = [System.Net.WebRequest]::Create("https://${ComputerName}:$Port")
        $request.Method = "GET"
        $request.Timeout = 2000
        try {
            $response = $request.GetResponse()
        }
        catch {
        }
        finally {
            if ($response) {
                $response.Close()
            }
            $request.Abort()
        }
    
        # Get the certificate from the request
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]$request.ServicePoint.Certificate
        # If the certificate does not exist
        if (!$certificate) {
            Write-Error "No certificate was found on Port $Port for $ComputerName."
            return
        }
    
        # Extract Extensions from Certificate
        $KeyUsages = Get-Extension -Extensions $certificate.Extensions -SearchString "Key Usage"
        $EnhancedKeyUsages = Get-Extension -Extensions $certificate.Extensions -SearchString "Enhanced Key Usage"
        $SubjectAlternativeName = Get-Extension -Extensions $certificate.Extensions -SearchString "Subject Alternative Name"
        
        # Create FullPath to File
        $FullPath = "$Path\${ComputerName}_${Port}.cer"
        # Create a PSCustomObject to hold the certificate data to display
        $certificateInfo = [PSCustomObject]@{
            'Serial Number'            = $certificate.SerialNumber
            'Thumbprint'               = $certificate.Thumbprint
            'Subject'                  = $certificate.Subject
            'Issuer'                   = $certificate.Issuer
            'NotBefore'                = $certificate.NotBefore
            'NotAfter'                 = $certificate.NotAfter
            'PublicKey'                = "$($certificate.PublicKey.Oid.FriendlyName) ($($certificate.PublicKey.Key.KeySize) Bits)"
            'SignatureAlgorithm'       = ([System.Security.Cryptography.Oid]$certificate.SignatureAlgorithm).FriendlyName
            'KeyUsages'                = $KeyUsages
            'ExtendedKeyUsages'        = $EnhancedKeyUsages
            'Subject Alternative Name' = $SubjectAlternativeName
            'Export Location'          = $FullPath
        }

        $i++
        $info = "$i        ${ComputerName}:${Port}"
        $Separator = "=" * ($info.Length * 1.5)
        Write-Output "$Separator`n$info`n$Separator"
        # Display the Data to the User
        Write-Output ($certificateInfo | Format-List | Out-String)
        if ( $VerbosePreference -ne 'SilentlyContinue') {
            certutil.exe $FullPath
        }
            
        # Export the Certificate
        $bytes = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $base64 | Out-File -FilePath "$Path\${ComputerName}_${Port}.cer"
    }
}
