#!/bin/bash

# Function to print messages in color
print_msg() {
    local color="$1"
    local msg="$2"
    case "$color" in
        red) printf "\e[31m%s\e[0m\n" "$msg" ;;
        green) printf "\e[32m%s\e[0m\n" "$msg" ;;
        yellow) printf "\e[33m%s\e[0m\n" "$msg" ;;
        blue) printf "\e[34m%s\e[0m\n" "$msg" ;;
        *) printf "%s\n" "$msg" ;;
    esac
}

# Function to install a Go tool
install_go_tool() {
    local tool="$1"
    local install_cmd="$2"
    if ! command -v "$tool" &> /dev/null; then
        print_msg red "$tool - not installed"
        print_msg yellow "Attempting to install $tool"
        eval "$install_cmd"
    else
        print_msg green "$tool - installed"
    fi
}

# Function to install urldedupe
install_urldedupe() {
    if ! command -v urldedupe &> /dev/null; then
        print_msg red "urldedupe - not installed"
        print_msg yellow "Attempting to install urldedupe"
        git clone https://github.com/ameenmaali/urldedupe.git
        cd urldedupe
        sudo apt install -y cmake
        cmake CMakeLists.txt
        make
        sudo mv urldedupe /bin/
        cd ..
    else
        print_msg green "urldedupe - installed"
    fi
}

# Function to install naabu
install_naabu() {
    if ! command -v naabu &> /dev/null; then
        print_msg red "naabu - not installed"
        print_msg yellow "Attempting to install naabu"
        sudo apt-get install -y libpcap-dev
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    else
        print_msg green "naabu - installed"
    fi
}

# Function to install massdns
install_massdns() {
    if ! command -v massdns &> /dev/null; then
        print_msg red "massdns - not installed"
        print_msg yellow "Attempting to install massdns"
        git clone https://github.com/blechschmidt/massdns.git
        cd massdns
        make
        sudo make install
        cd ..
    else
        print_msg green "massdns - installed"
    fi
}

# Function to install nuclei templates
install_nuclei_templates() {
    if [[ ! -d "nuclei_templates" ]]; then
        print_msg red "nuclei templates - not installed"
        print_msg yellow "Attempting to install nuclei templates"
        git clone https://github.com/h0tak88r/nuclei_templates.git
        git clone https://github.com/projectdiscovery/nuclei-templates.git
    else
        print_msg green "nuclei templates - installed"
    fi
}

# Function to install Python tools
install_python_tool() {
    local tool="$1"
    local install_cmd="$2"
    if ! pip show "$tool" &> /dev/null; then
        print_msg red "$tool - not installed"
        print_msg yellow "Attempting to install $tool"
        eval "$install_cmd"
    else
        print_msg green "$tool - installed"
    fi
}

# Function to install JSFinder
install_jsfinder() {
    if [[ ! -d "JSFinder" ]]; then
        print_msg red "JSFinder - not installed"
        print_msg yellow "Attempting to install JSFinder"
        go install -v github.com/kacakb/jsfinder@latest
    else
        print_msg green "JSFinder - installed"
    fi
}

# Function to check and install required tools
check_and_install_tools() {
    install_go_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool "kxss" "go install github.com/Emoe/kxss@latest"
    install_go_tool "ffuf" "go install github.com/ffuf/ffuf/v2@latest"
    install_go_tool "subov88r" "go install github.com/h0tak88r/subov88r@latest"
    install_go_tool "qsreplace" "go install github.com/tomnomnom/qsreplace@latest"
    install_go_tool "dalfox" "go install github.com/hahwul/dalfox/v2@latest"
    install_go_tool "paramx" "go install github.com/cyinnove/paramx/cmd/paramx@latest"
    install_go_tool "JsLeaks" "go install github.com/channyein1337/jsleak@latest"
    install_urldedupe
    install_naabu
    install_massdns
    install_nuclei_templates
    install_jsfinder
    install_python_tool "waymore" "sudo pip install waymore"
    if ! command -v interlace &> /dev/null; then
        print_msg red "interlace - not installed"
        print_msg yellow "Attempting to install interlace"
        git clone https://github.com/codingo/Interlace.git
        cd Interlace
        sudo python3 setup.py install
        cd ..
    else
        print_msg green "interlace - installed"
    fi
}

# Main setup function
setup() {
    check_and_install_tools
}

# Run the setup
setup

print_msg green "Setup complete."
