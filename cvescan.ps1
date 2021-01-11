##########################################################################
# CVESCANtie
# Version 1.iscisc0
# Assess an inventoried infrastructure from pre-inventoried CPEs and published CVEs
#
# Hosted at https://github.com/robvandenbrink/CVEScan
#
# Further documentation at:
#         https://isc.sans.edu/forums/diary/Using+the+NIST+Database+and+API+to+Keep+Up+with+Vulnerabilities+and+Patches+Part+1+of+3/26958/
#         https://isc.sans.edu/forums/diary/Using+the+NIST+Database+and+API+to+Keep+Up+with+Vulnerabilities+and+Patches+Playing+with+Code+Part+2+of+3/26964/
#         https://isc.sans.edu/forums/diary/Using+the+NVD+Database+and+API+to+Keep+Up+with+Vulnerabilities+and+Patches+Tool+Drop+CVEScan+Part+3+of+3/26974/
#
# Syntax:
#         CVEScan.ps1  -i <input file> -d <how many days back to look>
##########################################################################

param (
[alias("i")]
$infile,
[alias("d")]
$daterange
)

function helpsyntax {
write-host "CVESCAN: Assess a known inventory against current CVEs"
write-host "Parameters:"
write-host "    -i          <input file name>"
write-host "Optional Parameters:"
write-host "    -d          <CVEs for last "n" days>"
write-host "cvescan -i perimeterdevices.in -d 60"
exit
}

if ($daterange -eq 0) { write-host "ERROR: Must specify input filename and date range`n" ; helpsyntax }

# setup
$allCVEs = @()
$CVEDetails = @()

$apps = Import-Csv -path $infile
$now = get-date 
$outfile = $infile.replace(".in",$now.tostring("yyyy-MM-dd_hh-mm")+"_"+$daterange+"-days.html")
$StartDate = $now.adddays(-$daterange).tostring("yyyy-MM-dd")+ "T00:00:00:000%20UTC-00:00"

# Collect host to CVEs table
foreach ($app in $apps) {
    $request = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=" + $StartDate + "&cpeMatchString=" + $app.cpe
    $CVEs = (invoke-webrequest $request | ConvertFrom-Json).result.CVE_items.cve.CVE_data_meta.id
    foreach ($CVE in $CVEs) {
        $tempobj = [pscustomobject]@{
            Hostname = $app.hostname
            CVE = $CVE
           }
        $allCVEs += $tempobj
        }
    }

$Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;VERTICAL-ALIGN: TOP; font-size: 15px}
</style>
"@

$filepath = gci $infile

$Title = @()
$Title += [pscustomobject]@{ Organization="Scope";bbb=$filepath.basename.split(".")[1] } 
$Title += [pscustomobject]@{ Organization="From Date:"; bbb=($now.adddays(-$daterange).tostring("yyyy-MM-dd")) }
$Title += [pscustomobject]@{ Organization="To Date:";bbb=$now.tostring("yyyy-MM-dd") }

(($Title | convertto-HTML -title "CVE Summary" -Head $header) + "<br><br><br>").replace("bbb",$filepath.basename.split(".")[0]) | out-file  $outfile

(($allCVEs | Convertto-HTML -Head $header) + "<br><br>") | out-file -append $outfile

#parse out just the CVEs
$justCVEs = $allCVEs | select CVE | Sort-Object | Get-Unique -AsString

# collect CVE info
foreach ($CVE in $justCVEs) {
    $h = ""
    $request = "https://services.nvd.nist.gov/rest/json/cve/1.0/" + $CVE.CVE
    $cvemetadata = (invoke-webrequest $request) | convertfrom-json
    $CVEURLs = $cvemetadata.result.cve_items.cve.references.reference_data.url
    $affectedApps = ($cvemetadata.result.CVE_items.configurations.nodes.children.cpe_match) | where {$_.vulnerable -eq "true" } | select cpe23Uri,versionendincluding

    # add the affected hosts back into the detailed listing
    # write-host $CVE.CVE
    foreach ($ac in $allCVEs) {
        if ($ac.CVE -eq $CVE.CVE) { 
            $h += ($ac.Hostname + "<br>") 
            }
        }

    $tempobj = [pscustomobject]@{
        CVE = $CVE.CVE
        Hosts = $h
        # Just the datestamp, remove the clock time
        "Published Date" = ($cvemetadata.result.cve_items.publishedDate).split("T")[0]
        "CVE Description" = $cvemetadata.result.cve_items.cve.description.description_data.value
        Vector = $cvemetadata.result.CVE_items.impact.basemetricv3.cvssv3.attackVector
        "Attack Complexity" = $cvemetadata.result.CVE_items.impact.basemetricv3.cvssv3.attackComplexity
        "User Interaction" = $cvemetadata.result.CVE_items.impact.basemetricv3.cvssv3.userInteraction
        "Base Score" = $cvemetadata.result.CVE_items.impact.basemetricv3.cvssv3.baseScore
        "Severity" = $cvemetadata.result.CVE_items.impact.basemetricv3.cvssv3.baseSeverity
        "Reference URLs" = ($CVEURLs | ft -hidetableheaders | out-string).replace("`n","`n<br>")
        "Affected Apps" = ($affectedapps | ft -HideTableHeaders | out-string).replace("`n","`n<br>")
        }
    $CVEDetails += $tempobj
    }

# to just view the detailed output
# $CVEDetails | out-gridview

# to output to HTML
$Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;VERTICAL-ALIGN: TOP; font-size: 15px}
</style>
"@

# Note that the <br> tags get escaped, these are un-escaped below
# this is a horrible hack, but I can't find a decent "elegant" way to do this
# ... in less than 5x the time it took me to do it the ugly way  :-) 

(($CVEDetails | sort -descending -property "Base Score" )| Convertto-HTML -Head $header) -replace '&lt;br&gt;', '<br>' | out-file  -append $outfile
