#!/bin/bash

###############################################################################
# Network and Security Scanner
#
# Scans the internal 192.168.1.0/24 network via nmap and produces a result file.
# The result file is encrypted via AES-256 and emailed to relevant parties.
#
# NOTE: Supply your own email function.
#
# @author: Danny Cheun
###############################################################################

# arguments
arg0=$0
tcp_opt=$1
udp_opt=$2

# default argument
if [[ -z "$@" ]]; then
    tcp_opt="tcp"
fi

function check_filter() {
    ip=$1
    port=$2
    # Example to filter out check for IP and port.
    if [ $ip == "192.168.1.221" -a $port == 25 ]; then
        return 0
    fi
    # Example to filter out check for range of IPs and ports.
    for p in 192.168.1.203 192.168.1.204 192.168.1.205 192.168.1.207
    do
        if [[ $ip == $p && ( $port == 21 || $port == 23 ) ]]; then
            return 0
        fi
    done
    return 1
}

ts=$(date +%Y%m%dT%H%M%S)
outfile=/tmp/scan_results_$ts.txt
encrypted_file=/tmp/scan_results_$ts.zip
>$outfile

# tcp and udp flag lists: 135, 139, 445 were removed from original flag list
tcp=(0 21 22 23 25 79 80 110 113 119 137 143 389 443 555 666 1001 1002 1025 1026 1027 1028 1029 1030 1031 1032 1033 1034 1035 1036 1037 1038 1039 1040 1041 1042 1043 1044 1045 1046 1047 1048 1049 1050 1243 1720 2000 5000 6667 6670 6711 6776 6969 7000 8080 12345 12346 21554 22222 27374 29559 31337 31338)
udp=(0 25 137 389 1024 1025 1026 1027 1028 1029 1030 1031 1032 1033 1034 1035 1036 1037 1038 1039 1040 1041 1042 1043 1044 1045 1046 1047 1048 1049 1050 1900 31337 31338)

flags=$'Below is a list of flagged ports; the complete results are attached.'
echo "Network and Security Scanner - Report" >>$outfile
echo "Scan started: `date`" >>$outfile

for x in 192.168.1.{1..254}
do
    echo -e "\n================================================================" >>$outfile
    echo "Scanning $x" >>$outfile
    tcp_results=""
    udp_results=""
    if [ "$tcp_opt" ]; then
        tcp_results=$(sudo nmap -A -Pn --open --host-timeout 240 $x)
    fi
    if [ "$udp_opt" ]; then
        udp_results=$(sudo nmap -sU -A -Pn --open $x)
    fi
    tcp_vulnerable=$(egrep "^[0-9]+\S+\s+open\s+" <<<"$tcp_results" | \
                                    egrep -v 'ssh|rdp|http|https')
    udp_vulnerable=$(egrep "^[0-9]+\S+\s+open\s+" <<<"$udp_results" | \
                                    egrep -v 'ssh|rdp|http|https')
    
    tcpflags=""
    if [ "$tcp_vulnerable" ]; then
        echo "$tcp_results" >>$outfile
        name=$(grep 'Nmap scan report for' <<<"$tcp_results" | awk '{print $5}')
        tcps=$(grep '/tcp' <<<"$tcp_vulnerable")
        for y in ${tcp[@]};
        do
            tcps_check=$(grep ^$y/ <<<"$tcps")
            if [ "$tcps_check" ]; then
                if check_filter "$x" "$y"; then
                    continue
                else
                    tcpflags+="$y, "
                fi
            fi
        done
    fi
    
    udpflags=""
    if [ "$udp_vulnerable" ]; then
        echo "$udp_results" >>$outfile
        name=$(grep 'Nmap scan report for' <<<"$udp_results" | awk '{print $5}')
        udps=$(grep '/udp' <<<"$udp_vulnerable")
        for z in ${udp[@]};
        do
            udps_check=$(grep ^$z/ <<<"$udps")
            if [ "$udps_check" ]; then
                if check_filter "$x" "$z"; then
                    continue
                else
                    udpflags+="$z, "
                fi
            fi
        done
    fi
    if [ "$tcpflags" -o "$udpflags" ] ; then
        flags+=$'\n\n'"$x ($name)"
    fi
    if [ "$tcpflags" ] ; then
        flags+=$'\nTCP: '"$tcpflags"
    fi
    if [ "$udpflags" ] ; then
        flags+=$'\nUDP: '"$udpflags"
    fi
    sleep 3
done
echo "Scan completed: `date`" >>$outfile

# Encrypt output file.
7za a -tzip -p$(rev <<<"n01t98d0r7" | tr '789' 'puc') -mem=AES256 $encrypted_file $outfile >/dev/null
# Email address here...
# Email function here...
# Remove files
command rm $outfile $encrypted_file
