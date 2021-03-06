# CVEScan 
List CVEs and details that apply to your infrastructure (pre-inventoried).  
Documentation is on the Internet Storm Center site: https://isc.sans.edu, for 7,8,11 Jan 2021:

https://isc.sans.edu/forums/diary/Using+the+NIST+Database+and+API+to+Keep+Up+with+Vulnerabilities+and+Patches+Part+1+of+3/26958/

https://isc.sans.edu/forums/diary/Using+the+NIST+Database+and+API+to+Keep+Up+with+Vulnerabilities+and+Patches+Playing+with+Code+Part+2+of+3/26964/

https://isc.sans.edu/forums/diary/Using+the+NVD+Database+and+API+to+Keep+Up+with+Vulnerabilities+and+Patches+Tool+Drop+CVEScan+Part+3+of+3/26974/

<pre>
Syntax:
cvescan.ps1 -i CustomerName.Perimeter.in -d 90
    where:
       -i  CustomerName.Perimeter.in is a pre-inventoried infrastructure input file
                   typically: CustomerName.Scope.in  (.in for input)
                   one example Customer's perimeter is provided as an example
                   
       -d n        indicates how many days to pull CVE's for 
                   (typically 7/30/60/90 days, depending on requirements)
</pre>       
I find this most useful to run for pre-inventoried customer subnets, to let them know when critical CVEs are posted that they should evaluate.  This saves me from manually parsing every one of hundreds of CVEs that get posted regularly, and likely missing the 1,2,3 that are critical to my clients

The output file matches the input filename (note where the dots are)

I typicaly do not include MS Windows of any version or MS Office, as those should be taken care of - you need to go to a lot of effort to turn off all the update mechanisms for these, and you deserve what you get if so (sorry).

However, SQL, Exchange, SCCM and so are on definitely good to include, as well as Oracle, Adobe or any other applications or infrastructure.  Typically I break customer inventories into multiple "scopes":
- hosts on internet perimeters (or other clear trust boundaries)
- hosts on Server subnets
- hosts on workstation subnets
- hosts on IoT subnets (especially HealthCare and ICS / SCADA environments)
