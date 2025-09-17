# 1) Base deps + Go PATH
sudo apt-get update -y && sudo apt-get install -y git curl unzip zip python3-pip build-essential
if ! command -v go >/dev/null; then sudo apt-get install -y golang; fi
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
export GOPATH=$HOME/go
export PATH=$PATH:$HOME/go/bin

# 2) ProjectDiscovery tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 3) Common recon tools
go install github.com/ffuf/ffuf@latest
go install github.com/tomnomnom/hacks/kxss@latest || true   # ignore if module issue
pip3 install --user dnsreaper

# 4) Verify
which subfinder dnsx httpx nuclei ffuf kxss || true
