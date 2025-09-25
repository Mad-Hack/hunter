#!/bin/bash

echo -e "\e[1;33m"
echo -e " _  _  _  _  __  _  _____  ___  ___  " 
echo -e "| || || || ||  \| ||_   _|| __|| _ \ "
echo -e "| >< || \/ || | ' |  | |  | _| | v / "
echo -e "|_||_| \__/ |_|\__|  |_|  |___||_|_\ "
echo -e "\e[0m"

read -p $'\e[1;36m[x] Enter the IP range: \e[0m' ip_range
echo ""

safe_ip_range=$(echo "$ip_range" | sed 's|/.*||')
RESULTS_DIR="./results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/${safe_ip_range}.txt"

masscan -p80,443,3000,8000,8080,8443,8888 --rate 5000 --output-format json --output-filename masscan_output.json $ip_range
echo ""

BLOCKLIST=(
  "BlackBerry.htm"
  "go.microsoft.com"
  "webplugin.exe"
  "google.com"
  "onvif.org"
  "apple.com"
  "nginx-proxy-manager"
  "centos.org"
  "nginx.org"
  "nginx.com"
  "defaultwebpage.cgi"
  "/webif/system-info.sh"
  "/mod/mod_userdir.html"
  "globalurl.fortinet.net"
  "manpages.debian.org"
  "www.redhat.com/docs/"
  "www.parallels.com/intro"
  "docs.plesk.com"
  "owncloud.org"
  "nextcloud.com"
  "livedns.co.il"
  "www.f5.com"
  "?wtd="
  "/camera/index.html"
  "/aca/index.html"
  "/cgi-bin/MANGA/index.cgi"
  "castecnologia.com.br"
  "/cgi-bin/luci"
  "ver10"
  "/static/loading/loading.html"
  "mikrotik"
  "space.htm"
  "Home/ChangeLanguage?lang=he&url="
  "/wizard_new/?responsive=1"
  "/views/pwdReset/pwdReset.html"
  "www.tp-link.com"
  "/download/WEBConfig.exe"
  "/unsubscribe.php"
  "/NetVideo.exe"
  "/Support/toolbox"
  "/rivhitweb2015"
  "/admin/{{el.url}}"
  "whois.domaintools.com"
  "tomcat.apache.org/bugreport.html"
  "blog.openresty.com"
  "/js/.js_check.html"
  "/views/common/pwdreset.html"
  "/cgi-sys/defaultwebpage.cgi"
)

should_ignore_ip() {
  local content="$1"
  for pattern in "${BLOCKLIST[@]}"; do
    if echo "$content" | grep -q "$pattern"; then
      return 0
    fi
  done
  return 1
}

print_with_color() {
    local status="$1"
    local message="$2"
    case "$status" in
        200)
            echo -e "\e[32m$message\e[0m"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

spinner() {
    local pid=$1
    local url=$2
    local delay=0.1
    local chars='|/-\\'
    local i=0

    tput civis
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r[%c] Extracting [%s]" "${chars:i++%${#chars}:1}" "$url"
        sleep "$delay"
    done
    tput cnorm
}

{
  echo "===== Scan Summary ====="
  echo "Date       : $(date)"
  echo "IP Range   : $ip_range"
  echo "========================"
  echo ""
} >> "$RESULTS_FILE"

masscan_count=$(jq length masscan_output.json)
positive_count=0

while read -r ip port; do

    if [ "$port" -eq 443 ] || [ "$port" -eq 8443 ]; then
        url="https://$ip:$port"
    else
        url="http://$ip:$port"
    fi

    output_file=$(mktemp)

    timeout 6 lynx -dump -listonly -unique_urls "$url" 2>/dev/null | grep -Eo 'https?://[^ ]+' > "$output_file" &
    lynx_pid=$!

    spinner "$lynx_pid" "$url"
    wait "$lynx_pid" 2>/dev/null

    echo -ne "\r\033[K"

    links=$(<"$output_file")

    if should_ignore_ip "$links"; then
        rm -f "$output_file"
        continue
    fi

    rm -f "$output_file"
    rm -f temp_content.html 2>/dev/null

    if [ -n "$links" ]; then
        ((positive_count++))
        echo -e "\e[1;93m[+] LINKS FOUND at [$url]:\e[0m"
        echo "$links" | while read -r link; do
            echo " → $link"
        done

        echo ""
        {
            echo "IP: $ip:$port"
            echo "URL: $url"
            echo "$links" | sed 's/^/ → /'
            echo ""
        } >> "$RESULTS_FILE"

    else
        response=$(curl -sk --max-time 4 --connect-timeout 4 -D temp_headers.txt -w "%{http_code} %{size_download}\n" -o temp_content.html "$url")
        status=$(echo "$response" | awk '{print $1}')
        size=$(echo "$response" | awk '{print $2}')

        if [[ "$size" == "480" || "$size" == "1722" || "$size" == "131" || "$size" == "334" ]]; then
            continue
        fi

        if [[ "$status" == "403" ]]; then
            continue
        fi

        if [[ "$status" =~ ^2|3 ]] && [ "$size" -gt 100 ]; then
            if ! grep -iqE "not found|404|error" temp_content.html; then
                ((positive_count++))
                echo -e "\e[90m[+] PAGE USED / NO LINKS at [$url]\e[0m"
                echo ""
                {
                    echo "IP: $ip:$port"
                    echo "URL: $url"
                    echo " → Page responded with $status, size: $size bytes (no links found)"
                    echo ""
                    echo "=== HEADERS ==="
                    cat temp_headers.txt
                    echo "==============="
                    echo ""
                } >> "$RESULTS_FILE"
            fi
        fi

        rm -f temp_content.html
    fi

done < <(jq -r '.[] | .ip + " " + (.ports[0].port | tostring)' masscan_output.json)

echo -e "\e[1;33m[✓]\e[0m Scan complete. Results saved to $RESULTS_FILE"
echo -e "\e[1;33m[✓]\e[0m Masscan found $masscan_count IP:port combos"
echo -e "\e[1;33m[✓]\e[0m Found $positive_count URLs with extractable links"
