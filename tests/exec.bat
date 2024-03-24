@echo off

set argc=0
for %%x in (%*) do (
   set /a argc+=1
)

if %argc% lss 6 (
    echo "not enough arguments"
    goto end
)

set loc_ip=%1
set loc_port=%2
set map_ip=%3
set map_port=%4
set rem_ip=%5
set rem_port=%6
set ifconfig=

set lhs=%map_ip%%map_port%
set rhs=%rem_ip%%rem_port%

if "%lhs%" GTR "%rhs%" (
    set ifconfig=10.0.0.3 255.255.255.0
) else (
    set ifconfig=10.0.0.2 255.255.255.0
)

"C:/Program Files/OpenVPN/bin/openvpn.exe" --dev tap --ifconfig %ifconfig% --local %loc_ip% --lport %loc_port% --remote %rem_ip% --rport %rem_port%

:end
